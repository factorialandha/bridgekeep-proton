package main

// Stand-in for Bridge 3.27.2's CLI: same ishell/readline versions, and the
// same prompt strings and flow as internal/frontend/cli (login, info,
// updates autoupdates disable, telemetry disable). Behaviour via env:
// MOCK_SIGNEDIN=1, MOCK_2FA=1, MOCK_MBOX=1, MOCK_HV=1, MOCK_FIDOTOTP=1,
// MOCK_LOCKED=N (the first N `info` calls say the account is still loading,
// as Bridge does while it unlocks and syncs a signed-in account).
import (
	"fmt"
	"os"
	"strings"

	"github.com/abiosoft/ishell"
)

func on(k string) bool { return os.Getenv(k) == "1" }

func main() {
	sh := ishell.New()
	sh.Interrupt(func(_ *ishell.Context, _ int, _ string) { os.Exit(1) })
	signedIn := on("MOCK_SIGNEDIN")
	locked := 0
	fmt.Sscan(os.Getenv("MOCK_LOCKED"), &locked)
	autoUpd, telem, loggedOut := true, true, false
	ask := func(c *ishell.Context, title string, f func() string) string {
		c.Printf("%s: ", title)
		v := f()
		for i := 0; v == ""; i++ {
			if i >= 3 { c.Println("Too many attempts"); return "" }
			c.Printf("Please fill %s: ", strings.ToLower(title[:1])+title[1:])
			v = f()
		}
		return v
	}
	yn := func(c *ishell.Context, q string) bool {
		c.Print(q, "? yes/"+"\x1b[1mno\x1b[0m"+": ")
		a := strings.ToLower(c.ReadLine())
		return a != "" && strings.HasPrefix("yes", a)
	}
	sh.AddCmd(&ishell.Cmd{Name: "login", Func: func(c *ishell.Context) {
		c.ShowPrompt(false); defer c.ShowPrompt(true)
		u := ask(c, "Username", c.ReadLine)
		p := ask(c, "Password", c.ReadPassword)
		if p != "pw" { c.Println("Cannot login: 422 Incorrect login credentials. Please try again"); return }
		c.Println("Authenticating ... ")
		if on("MOCK_HV") {
			fmt.Print("\nHuman Verification requested. Please open the URL below in a browser and press ENTER when the challenge has been completed.\n\n", "https://verify.proton.me/?methods=captcha&token=abc\n")
			c.ReadLine(); fmt.Println("Authenticating ...")
		}
		if on("MOCK_FIDOTOTP") && yn(c, "Do you want to use a security key for Two-factor authentication") {
			c.Println("Cannot login: security key not reachable"); return
		}
		if on("MOCK_2FA") || on("MOCK_FIDOTOTP") {
			if code := ask(c, "Two factor code", c.ReadLine); code != "123456" { c.Println("Cannot login: 8002 Incorrect code"); return }
		}
		if on("MOCK_MBOX") {
			if ask(c, "Mailbox password", c.ReadPassword) != "mb" { c.Println("Cannot login: bad mailbox password"); return }
		}
		signedIn = true
		c.Printf("Account %s was added successfully.\n", "\x1b[1m"+u+"\x1b[0m")
	}})
	sh.AddCmd(&ishell.Cmd{Name: "info", Func: func(c *ishell.Context) {
		if loggedOut { c.Println("Please login to " + "\x1b[1m" + "me@proton.me" + "\x1b[0m" + " to get email client configuration."); return }
		if !signedIn { c.Println("No active accounts. Please add account to continue."); return }
		if locked > 0 { locked--; c.Printf("User %s is currently locked. Please wait and try again.\n", "\x1b[1m"+"me@proton.me"+"\x1b[0m"); return }
		c.Printf("IMAP Settings\nAddress:   %s\nIMAP port: %d\nUsername:  %s\nPassword:  %s\nSecurity:  %s\n", "127.0.0.1", 1143, "me@proton.me", "GEN-pw_123", "STARTTLS")
		c.Printf("SMTP Settings\nAddress:   %s\nSMTP port: %d\nUsername:  %s\nPassword:  %s\nSecurity:  %s\n", "127.0.0.1", 1025, "me@proton.me", "GEN-pw_123", "STARTTLS")
	}})
	sh.AddCmd(&ishell.Cmd{Name: "logout", Func: func(c *ishell.Context) {
		if !signedIn { c.Println("No active accounts. Please add account to continue."); return }
		if yn(c, "Are you sure you want to logout account "+"\x1b[1m"+"me@proton.me"+"\x1b[0m") { signedIn = false; loggedOut = true }
	}})
	updates := &ishell.Cmd{Name: "updates"}
	aus := &ishell.Cmd{Name: "autoupdates"}
	aus.AddCmd(&ishell.Cmd{Name: "disable", Func: func(c *ishell.Context) {
		if !autoUpd { c.Println("Bridge is already set to NOT automatically install updates."); return }
		c.Println("Bridge is currently set to automatically install updates.")
		if yn(c, "Are you sure you want to stop bridge from doing this") { autoUpd = false }
	}})
	updates.AddCmd(aus); sh.AddCmd(updates)
	tel := &ishell.Cmd{Name: "telemetry"}
	tel.AddCmd(&ishell.Cmd{Name: "disable", Func: func(c *ishell.Context) {
		if !telem { c.Println("Usage diagnostics collection is disabled."); return }
		c.Println("Usage diagnostics collection is enabled right now.")
		if yn(c, "Do you want to disable usage diagnostics collection") { telem = false }
	}})
	sh.AddCmd(tel)
	fmt.Println("\n            Welcome to Proton Mail Bridge interactive shell\n   (ascii art)")
	sh.Run()
	fmt.Fprintf(os.Stderr, "mock: exit (autoupdate=%v telemetry=%v)\n", autoUpd, telem)
}
