// Command broker lets the admin portal sign Bridge in to Proton, without the
// portal ever seeing the Bridge password or Bridge's CLI.
//
// It runs inside the Bridge container as the process the entrypoint
// supervises. It starts Bridge's daemon and keeps it running. When the
// portal asks to sign in, it stops the daemon (the CLI and the daemon can't
// share Bridge's vault), drives `bridge --cli` through the same prompts as
// scripts/bridge-signin.sh, saves the IMAP credentials Bridge generates to
// the bridge-credential volume (read by imap-proxy only), and starts the
// daemon again.
//
// API: HTTP/1.1 + JSON on a Unix socket (BROKER_SOCKET, default
// /run/broker/broker.sock, mode 0660, group BROKER_GID). Only peers whose
// UID is in BROKER_PEER_UIDS (SO_PEERCRED) are served.
//
//	GET  /status                 -> Status
//	POST /login                  {username, password}
//	POST /2fa                    {code}
//	POST /mailbox-password       {password}
//	POST /human-verification     {}
//	POST /logout                 {}
//	POST /cancel                 {}
//
// Every POST answers with Status. 400 bad field, 403 wrong peer, 409 step
// doesn't match the state, 413 body over 4 KiB, 429 rate-limited.
//
// Never logged, never returned: the Proton password, the 2FA code, the
// mailbox password, the Bridge password, and any CLI output.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// States, as the portal sees them.
const (
	SignedOut       = "signed_out"
	SigningIn       = "signing_in"
	Waiting2FA      = "waiting_2fa"
	WaitingMailbox  = "waiting_mailbox_password"
	WaitingHuman    = "waiting_human"
	SignedIn        = "signed_in"
	StateError      = "error"
	maxBody         = 4 << 10
	stepTimeout     = 5 * time.Minute
	cliTimeout      = 2 * time.Minute // between CLI outputs when nobody is waiting on a person
	lockedWait      = 5 * time.Minute // `info` may say "currently locked" this long
	loginWindow     = 15 * time.Minute
	loginsPerWindow = 5
	codesPerSignIn  = 5
)

// Status is the one shape every endpoint returns.
type Status struct {
	State       string `json:"state"`
	Account     string `json:"account"`
	Error       string `json:"error"`
	HVURL       string `json:"hv_url"`
	StepExpires *int64 `json:"step_expires"`
}

type config struct {
	socket   string
	gid      int
	peers    map[int]bool
	credDir  string
	credGID  int
	bridge   string
	runArgs  []string
	logLevel string
}

// answer is what a waiting step gets from the portal (or a cancel).
type answer struct {
	text   string
	cancel bool
}

type broker struct {
	cfg config

	mu       sync.Mutex
	st       Status
	before   Status // to go back to on cancel or failure
	answers  chan answer
	busy     bool // a sign-in or sign-out is running
	logins   []time.Time
	codes    int
	daemon   *exec.Cmd
	exited   chan struct{} // closed when the current daemon has exited
	stopping bool          // we are stopping the daemon on purpose
	died     chan error
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("[broker] ")
	cfg := config{
		socket:   env("BROKER_SOCKET", "/run/broker/broker.sock"),
		gid:      envInt("BROKER_GID", -1),
		peers:    map[int]bool{},
		credDir:  env("BROKER_CRED_DIR", "/run/bridge-credential"),
		credGID:  envInt("BROKER_CRED_GID", -1),
		bridge:   env("BRIDGE_BIN", "/usr/local/lib/proton-bridge/bridge"),
		runArgs:  strings.Fields(env("BRIDGE_RUN_ARGS", "--noninteractive")),
		logLevel: env("BRIDGE_LOG_LEVEL", "info"),
	}
	for _, f := range strings.Fields(strings.ReplaceAll(env("BROKER_PEER_UIDS", "10003"), ",", " ")) {
		if n, err := strconv.Atoi(f); err == nil {
			cfg.peers[n] = true
		}
	}
	b := newBroker(cfg)
	if err := b.startDaemon(); err != nil {
		log.Fatalf("cannot start Bridge: %v", err)
	}
	ln, err := listen(cfg)
	if err != nil {
		log.Printf("sign-in from the portal is off: %v", err)
	} else {
		srv := &http.Server{Handler: b.routes(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
			ConnContext: withPeer}
		go func() { _ = srv.Serve(ln) }()
		log.Printf("listening on %s", cfg.socket)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	select {
	case <-sig:
		b.stopDaemon()
		os.Exit(0)
	case err := <-b.died:
		// Bridge stopped on its own: exit so the container restarts.
		log.Printf("Bridge exited: %v", err)
		os.Exit(1)
	}
}

func newBroker(cfg config) *broker {
	b := &broker{cfg: cfg, died: make(chan error, 1)}
	b.st = b.restingStatus()
	return b
}

// restingStatus: signed in if we hold credentials, else signed out.
func (b *broker) restingStatus() Status {
	user, err := os.ReadFile(filepath.Join(b.cfg.credDir, "bridge_username"))
	if _, perr := os.Stat(filepath.Join(b.cfg.credDir, "bridge_password")); err == nil && perr == nil && len(user) > 0 {
		return Status{State: SignedIn, Account: clean(string(user))}
	}
	return Status{State: SignedOut}
}

// --- the daemon -------------------------------------------------------------

func (b *broker) startDaemon() error {
	args := append(append([]string{}, b.cfg.runArgs...), "--log-level", b.cfg.logLevel)
	cmd := exec.Command(b.cfg.bridge, args...)
	cmd.Stdin = nil
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr // Bridge's own log lines
	if err := cmd.Start(); err != nil {
		return err
	}
	exited := make(chan struct{})
	b.mu.Lock()
	b.daemon, b.exited, b.stopping = cmd, exited, false
	b.mu.Unlock()
	log.Printf("Bridge started (pid %d)", cmd.Process.Pid)
	go func() {
		err := cmd.Wait()
		close(exited)
		b.mu.Lock()
		onPurpose := b.stopping && b.daemon == cmd
		b.mu.Unlock()
		if !onPurpose {
			if err == nil {
				err = errors.New("exit status 0")
			}
			b.died <- err
		}
	}()
	return nil
}

func (b *broker) stopDaemon() {
	b.mu.Lock()
	cmd, done := b.daemon, b.exited
	b.stopping = true
	b.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
	log.Printf("Bridge stopped")
}

// --- HTTP -------------------------------------------------------------------

type peerKey struct{}

func withPeer(ctx context.Context, c net.Conn) context.Context {
	uid := -1
	if uc, ok := c.(*net.UnixConn); ok {
		if raw, err := uc.SyscallConn(); err == nil {
			_ = raw.Control(func(fd uintptr) {
				if cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED); err == nil {
					uid = int(cred.Uid)
				}
			})
		}
	}
	return context.WithValue(ctx, peerKey{}, uid)
}

func listen(cfg config) (net.Listener, error) {
	// The folder is ours (2750 bridge:<socket group>): the portal may enter it
	// and connect, never add, remove or replace a file in it. Re-apply that in
	// case the volume was created with other modes.
	dir := filepath.Dir(cfg.socket)
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a folder", dir)
	}
	if err := os.Chmod(dir, 0o2750); err != nil {
		return nil, fmt.Errorf("chmod %s: %w", dir, err)
	}
	_ = os.Remove(cfg.socket)
	old := syscall.Umask(0o117) // the socket is born 0660
	ln, err := net.Listen("unix", cfg.socket)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	// Never follow a link: only change the socket we just made.
	if fi, err := os.Lstat(cfg.socket); err != nil || fi.Mode().Type() != os.ModeSocket {
		ln.Close()
		return nil, fmt.Errorf("%s is not our socket", cfg.socket)
	}
	if cfg.gid >= 0 {
		if err := os.Lchown(cfg.socket, -1, cfg.gid); err != nil {
			ln.Close()
			return nil, fmt.Errorf("chgrp %s: %w", cfg.socket, err)
		}
	}
	return ln, nil
}

func (b *broker) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", b.handle(http.MethodGet, nil))
	mux.HandleFunc("/login", b.handle(http.MethodPost, b.login))
	mux.HandleFunc("/2fa", b.handle(http.MethodPost, b.step(Waiting2FA, "code", validCode)))
	mux.HandleFunc("/mailbox-password", b.handle(http.MethodPost, b.step(WaitingMailbox, "password", validSecret)))
	mux.HandleFunc("/human-verification", b.handle(http.MethodPost, b.step(WaitingHuman, "", nil)))
	mux.HandleFunc("/logout", b.handle(http.MethodPost, b.logout))
	mux.HandleFunc("/cancel", b.handle(http.MethodPost, b.cancel))
	return mux
}

type httpErr struct {
	code int
	msg  string
	wait time.Duration
}

func (e *httpErr) Error() string { return e.msg }

type action func(body map[string]any) error

func (b *broker) handle(method string, act action) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if uid, _ := r.Context().Value(peerKey{}).(int); !b.cfg.peers[uid] {
			writeErr(w, &httpErr{code: http.StatusForbidden, msg: "not allowed"})
			return
		}
		if r.Method != method {
			writeErr(w, &httpErr{code: http.StatusMethodNotAllowed, msg: "method not allowed"})
			return
		}
		if act != nil {
			body := map[string]any{}
			raw, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
			if err != nil {
				writeErr(w, &httpErr{code: http.StatusBadRequest, msg: "unreadable body"})
				return
			}
			if len(raw) > maxBody {
				writeErr(w, &httpErr{code: http.StatusRequestEntityTooLarge, msg: "body too large"})
				return
			}
			if len(strings.TrimSpace(string(raw))) > 0 {
				if err := json.Unmarshal(raw, &body); err != nil {
					writeErr(w, &httpErr{code: http.StatusBadRequest, msg: "body must be a JSON object"})
					return
				}
			}
			if err := act(body); err != nil {
				var he *httpErr
				if errors.As(err, &he) {
					writeErr(w, he)
					return
				}
				writeErr(w, &httpErr{code: http.StatusInternalServerError, msg: "internal error"})
				return
			}
		}
		_ = json.NewEncoder(w).Encode(b.status())
	}
}

func writeErr(w http.ResponseWriter, e *httpErr) {
	if e.wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(e.wait.Seconds())+1))
	}
	w.WriteHeader(e.code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": e.msg})
}

func (b *broker) status() Status {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.st
}

func field(body map[string]any, name string, ok func(string) bool) (string, error) {
	v, present := body[name]
	s, isStr := v.(string)
	if !present || !isStr || s == "" {
		return "", &httpErr{code: http.StatusBadRequest, msg: name + " is required"}
	}
	if hasControl(s) || (ok != nil && !ok(s)) {
		return "", &httpErr{code: http.StatusBadRequest, msg: name + " is not valid"}
	}
	return s, nil
}

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == ' ' || r == ' ' {
			return true
		}
	}
	return false
}

var codeRE = regexp.MustCompile(`^[0-9]{6,8}$`)

func validCode(s string) bool    { return codeRE.MatchString(s) }
func validSecret(s string) bool  { return len(s) <= 1024 }
func validAddress(s string) bool { return len(s) <= 320 && !strings.ContainsAny(s, " \t") }

// --- actions ----------------------------------------------------------------

func (b *broker) login(body map[string]any) error {
	user, err := field(body, "username", validAddress)
	if err != nil {
		return err
	}
	pass, err := field(body, "password", validSecret)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.busy {
		return &httpErr{code: http.StatusConflict, msg: "a sign-in is already running"}
	}
	now := time.Now()
	kept := b.logins[:0]
	for _, t := range b.logins {
		if now.Sub(t) < loginWindow {
			kept = append(kept, t)
		}
	}
	b.logins = kept
	if len(b.logins) >= loginsPerWindow {
		return &httpErr{code: http.StatusTooManyRequests, msg: "too many sign-in attempts", wait: loginWindow - now.Sub(b.logins[0])}
	}
	b.logins = append(b.logins, now)
	b.busy, b.codes = true, 0
	b.before = b.restingStatus()
	b.answers = make(chan answer, 1)
	b.st = Status{State: SigningIn}
	go b.runSignIn(user, pass, b.answers)
	return nil
}

func (b *broker) step(want, name string, ok func(string) bool) action {
	return func(body map[string]any) error {
		val := ""
		if name != "" {
			v, err := field(body, name, ok)
			if err != nil {
				return err
			}
			val = v
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.st.State != want {
			return &httpErr{code: http.StatusConflict, msg: "not waiting for that"}
		}
		if want == Waiting2FA {
			if b.codes >= codesPerSignIn {
				return &httpErr{code: http.StatusTooManyRequests, msg: "too many codes", wait: stepTimeout}
			}
			b.codes++
		}
		b.st = Status{State: SigningIn, Account: b.st.Account}
		b.answers <- answer{text: val}
		return nil
	}
}

func (b *broker) cancel(map[string]any) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.st.State {
	case Waiting2FA, WaitingMailbox, WaitingHuman:
		b.answers <- answer{cancel: true}
		b.st = Status{State: SigningIn}
		return nil
	case StateError:
		b.st = b.restingStatus()
		return nil
	}
	return &httpErr{code: http.StatusConflict, msg: "nothing to cancel"}
}

func (b *broker) logout(map[string]any) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.busy {
		return &httpErr{code: http.StatusConflict, msg: "a sign-in is running"}
	}
	if b.st.State != SignedIn {
		return &httpErr{code: http.StatusConflict, msg: "not signed in"}
	}
	b.busy = true
	b.before = b.st
	b.st = Status{State: SigningIn, Account: b.st.Account}
	go b.runSignOut()
	return nil
}

// finish ends a sign-in or sign-out: daemon back up, final state set.
func (b *broker) finish(final Status) {
	if err := b.startDaemon(); err != nil {
		log.Printf("cannot start Bridge again: %v", err)
		b.died <- err
	}
	b.mu.Lock()
	b.st, b.busy, b.answers = final, false, nil
	b.mu.Unlock()
}

// wait puts the broker in a waiting state and blocks for the portal's answer.
func (b *broker) wait(state, account, hv string, answers chan answer) (string, bool) {
	exp := time.Now().Add(stepTimeout).Unix()
	b.mu.Lock()
	b.st = Status{State: state, Account: account, HVURL: hv, StepExpires: &exp}
	b.mu.Unlock()
	select {
	case a := <-answers:
		return a.text, !a.cancel
	case <-time.After(stepTimeout):
		return "", false
	}
}

// --- the CLI conversation -----------------------------------------------------

type cli struct {
	cmd   *exec.Cmd
	in    io.WriteCloser
	chunk chan string // output pieces: whole lines (ending "\n") or a pending prompt
}

func (b *broker) openCLI() (*cli, error) {
	b.stopDaemon()
	cmd := exec.Command(b.cfg.bridge, "--cli", "--log-level", b.cfg.logLevel)
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr // Bridge's log lines; the CLI's answers go to stdout only
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	c := &cli{cmd: cmd, in: in, chunk: make(chan string, 64)}
	go c.read(out)
	return c, nil
}

// read splits stdout into lines, and also reports text that has sat without a
// newline for a moment: that's a prompt waiting for an answer.
func (c *cli) read(r io.Reader) {
	br := bufio.NewReader(r)
	var buf strings.Builder
	bytes := make(chan byte)
	go func() {
		for {
			ch, err := br.ReadByte()
			if err != nil {
				close(bytes)
				return
			}
			bytes <- ch
		}
	}()
	for {
		select {
		case ch, ok := <-bytes:
			if !ok {
				if buf.Len() > 0 {
					c.chunk <- buf.String() + "\n"
				}
				close(c.chunk)
				return
			}
			buf.WriteByte(ch)
			if ch == '\n' {
				c.chunk <- buf.String()
				buf.Reset()
			} else if buf.Len() > 4096 {
				buf.Reset()
			}
		case <-time.After(150 * time.Millisecond):
			if buf.Len() > 0 && strings.HasSuffix(buf.String(), ": ") {
				c.chunk <- buf.String()
				buf.Reset()
			}
		}
	}
}

func (c *cli) send(s string) { _, _ = io.WriteString(c.in, s+"\n") }

func (c *cli) close() {
	c.send("exit")
	_ = c.in.Close()
	done := make(chan struct{})
	go func() { _ = c.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = c.cmd.Process.Kill()
		<-done
	}
	for range c.chunk {
	}
}

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func plain(s string) string { return strings.TrimRight(ansi.ReplaceAllString(s, ""), "\r\n") }

// next returns the next output piece, or ok=false on EOF or timeout.
func (c *cli) next(d time.Duration) (string, bool) {
	select {
	case s, ok := <-c.chunk:
		return plain(s), ok
	case <-time.After(d):
		return "", false
	}
}

var loginFail = regexp.MustCompile(`Cannot login|Too many attempts`)

func (b *broker) runSignIn(user, pass string, answers chan answer) {
	fail := func(msg string) { b.finish(Status{State: b.before.State, Account: b.before.Account, Error: msg}) }
	c, err := b.openCLI()
	if err != nil {
		log.Printf("cannot open Bridge's CLI: %v", err)
		fail("Bridge's sign-in could not start. Try again in a minute.")
		return
	}
	c.send("login")
	phase, hvURL, hvPending := "login", "", false
	var gotUser, gotPass string
	started := time.Now()
	result := func() (Status, string) { // final status, error text
		for {
			s, ok := c.next(cliTimeout)
			if !ok {
				return Status{}, "Bridge stopped answering during sign-in. Try again."
			}
			line := strings.TrimSpace(s)
			switch phase {
			case "login":
				switch {
				case strings.HasSuffix(s, "Username: "):
					c.send(user)
				case strings.HasSuffix(s, "Password: "):
					c.send(pass)
					pass = ""
				case strings.HasSuffix(s, "Two factor code: "):
					code, ok := b.wait(Waiting2FA, user, "", answers)
					if !ok {
						return Status{}, "cancelled"
					}
					c.send(code)
				case strings.HasSuffix(s, "Mailbox password: "):
					mb, ok := b.wait(WaitingMailbox, user, "", answers)
					if !ok {
						return Status{}, "cancelled"
					}
					c.send(mb)
				case strings.Contains(s, "security key for Two-factor authentication? yes/"):
					c.send("no")
				case strings.Contains(line, "Human Verification requested"):
					hvPending = true
				case hvPending && (strings.HasPrefix(line, "https://")):
					hvURL, hvPending = line, false
					if _, ok := b.wait(WaitingHuman, user, hvURL, answers); !ok {
						return Status{}, "cancelled"
					}
					c.send("")
				case strings.Contains(line, "was added successfully"):
					phase = "settings"
					c.send("updates autoupdates disable")
				case loginFail.MatchString(line):
					return Status{}, loginError(line)
				}
			case "settings":
				switch {
				case strings.Contains(s, "stop bridge from doing this? yes/"):
					c.send("yes")
					c.send("telemetry disable")
				case strings.Contains(line, "already set to NOT automatically install updates"):
					c.send("telemetry disable")
				case strings.Contains(s, "disable usage diagnostics collection? yes/"):
					c.send("yes")
					phase = "info"
					c.send("info")
				case strings.Contains(line, "Usage diagnostics collection is disabled"):
					phase = "info"
					c.send("info")
				}
			case "info":
				switch {
				case strings.Contains(line, "is currently locked"):
					if time.Since(started) > lockedWait {
						return Status{}, "Bridge is still loading the mailbox. Try again in a few minutes."
					}
					time.Sleep(5 * time.Second)
					c.send("info")
				case strings.Contains(line, "No active accounts"), strings.Contains(line, "Please login to"):
					return Status{}, "Bridge didn't keep the sign-in. Try again."
				case strings.Contains(line, "Please choose"):
					return Status{}, "Bridge has more than one account. Use ./bridgekeep relogin on the host."
				case strings.HasPrefix(line, "Username:") && gotUser == "":
					gotUser = strings.TrimSpace(strings.TrimPrefix(line, "Username:"))
				case strings.HasPrefix(line, "Password:") && gotPass == "":
					gotPass = strings.TrimSpace(strings.TrimPrefix(line, "Password:"))
					return Status{State: SignedIn, Account: clean(gotUser)}, ""
				}
			}
		}
	}
	final, msg := result()
	pass = ""
	c.close()
	if msg != "" {
		gotPass = ""
		if msg == "cancelled" {
			msg = ""
		}
		log.Printf("sign-in did not finish")
		fail(msg)
		return
	}
	if err := b.saveCredential(gotUser, gotPass); err != nil {
		gotPass = ""
		log.Printf("cannot save the credential: %v", err)
		b.finish(Status{State: StateError, Account: final.Account, Error: "Signed in, but the mail password could not be saved. Run ./bridgekeep doctor on the host."})
		return
	}
	gotPass = ""
	log.Printf("signed in")
	b.finish(final)
}

func loginError(line string) string {
	l := strings.ToLower(line)
	switch {
	case strings.Contains(l, "security key"):
		return "This account needs a security key, which can't reach Bridge. Add an authenticator app in Proton's settings and try again."
	case strings.Contains(l, "code"):
		return "Proton didn't accept that 2FA code. Sign in again."
	case strings.Contains(l, "mailbox password"):
		return "Proton didn't accept that mailbox password. Sign in again."
	case strings.Contains(l, "too many"):
		return "Proton says too many attempts. Wait a while, then try again."
	case strings.Contains(l, "credentials"), strings.Contains(l, "422"):
		return "Proton didn't accept that address and password."
	}
	return "Proton refused the sign-in. Try again."
}

func (b *broker) runSignOut() {
	c, err := b.openCLI()
	if err != nil {
		b.finish(Status{State: b.before.State, Account: b.before.Account, Error: "Bridge's sign-out could not start. Try again in a minute."})
		return
	}
	c.send("logout")
	ok := false
	for {
		s, more := c.next(cliTimeout)
		if !more {
			break
		}
		line := strings.TrimSpace(s)
		switch {
		case strings.Contains(s, "logout account") && strings.Contains(s, "yes/"):
			// Bridge asks to confirm and prints nothing after: check with info.
			c.send("yes")
			c.send("info")
			continue
		case strings.Contains(line, "Please login to"), strings.Contains(line, "No active accounts"):
			ok = true // signed out (or already was)
		case strings.Contains(line, "Please choose"), strings.Contains(line, "failed"):
		default:
			continue
		}
		break
	}
	c.close()
	if !ok {
		b.finish(Status{State: b.before.State, Account: b.before.Account, Error: "Bridge didn't confirm the sign-out. Try again."})
		return
	}
	_ = os.Remove(filepath.Join(b.cfg.credDir, "bridge_password"))
	_ = os.Remove(filepath.Join(b.cfg.credDir, "bridge_username"))
	log.Printf("signed out")
	b.finish(Status{State: SignedOut})
}

// saveCredential writes the Bridge password and username for imap-proxy:
// 0440, group BROKER_CRED_GID, each through a temp file and a rename.
func (b *broker) saveCredential(user, pass string) error {
	if user == "" || pass == "" || hasControl(user) || hasControl(pass) {
		return errors.New("Bridge gave an unexpected credential")
	}
	for name, val := range map[string]string{"bridge_password": pass, "bridge_username": user} {
		f, err := os.CreateTemp(b.cfg.credDir, ".tmp-"+name+"-")
		if err != nil {
			return err
		}
		tmp := f.Name()
		err = func() error {
			defer f.Close()
			if err := f.Chmod(0o440); err != nil {
				return err
			}
			if b.cfg.credGID >= 0 {
				if err := f.Chown(-1, b.cfg.credGID); err != nil {
					return err
				}
			}
			_, err := f.WriteString(val)
			return err
		}()
		if err == nil {
			err = os.Rename(tmp, filepath.Join(b.cfg.credDir, name))
		}
		if err != nil {
			_ = os.Remove(tmp)
			return err
		}
	}
	return nil
}

// --- helpers ------------------------------------------------------------------

func clean(s string) string {
	s = strings.TrimSpace(s)
	if hasControl(s) || len(s) > 320 {
		return ""
	}
	return s
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if n, err := strconv.Atoi(os.Getenv(k)); err == nil {
		return n
	}
	return def
}
