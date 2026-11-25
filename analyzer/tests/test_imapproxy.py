"""The allowlist proxy: unit checks on the rules, then real sockets end to end."""

import socket
import socketserver
import threading
import time

import pytest

from analyzer import imapproxy
from analyzer.imap import ForbiddenCommand, ShadowRunner, connect
from analyzer.imapproxy import ProxyConfig, Refused, check_authenticated
from conftest import FakeClassifier, make_eml

TOKEN = "t" * 24
FOLDERS = ("INBOX",)


def _now_date() -> str:
    """Proton's receive time for new test mail: now (a fixed date goes stale)."""
    return time.strftime("%d-%b-%Y %H:%M:%S +0000", time.gmtime())


# -- the rules -----------------------------------------------------------------

@pytest.mark.parametrize("cmd, forwarded", [
    ("EXAMINE INBOX", 'EXAMINE "INBOX"'),
    ('EXAMINE "inbox"', 'EXAMINE "INBOX"'),
    ("UID SEARCH ALL", "UID SEARCH ALL"),
    ("UID SEARCH UID 5:*", "UID SEARCH UID 5:*"),
    ("uid search uid 5:9", "UID SEARCH UID 5:9"),
    ("UID FETCH 5 (UID BODY.PEEK[]<0.1000000>)", "UID FETCH 5 (UID BODY.PEEK[]<0.1000000>)"),
    ("UID FETCH 1:3,7 (FLAGS RFC822.SIZE BODYSTRUCTURE)", "UID FETCH 1:3,7 (FLAGS RFC822.SIZE BODYSTRUCTURE)"),
    ("UID FETCH 5 BODY.PEEK[1.2.MIME]", "UID FETCH 5 (BODY.PEEK[1.2.MIME])"),
    ("NOOP", "NOOP"),
    ("LOGOUT", "LOGOUT"),
])
def test_allowed_commands(cmd, forwarded):
    assert check_authenticated(cmd, FOLDERS) == forwarded


@pytest.mark.parametrize("cmd", [
    # anything that changes the mailbox
    "SELECT INBOX", "STORE 1 +FLAGS (\\Deleted)", "UID STORE 1 +FLAGS (\\Seen)", "EXPUNGE",
    "UID EXPUNGE 1", "COPY 1 Trash", "UID COPY 1 Trash", "MOVE 1 Trash", "UID MOVE 1 Trash",
    "DELETE INBOX", "CREATE Exfil", "RENAME INBOX Old", "APPEND INBOX (\\Seen) {10}",
    "SUBSCRIBE Trash", "SETACL INBOX anyone lrswipkxtea",
    # other folders and other ways in
    "EXAMINE Trash", 'EXAMINE "Sent"', "EXAMINE \"All Mail\"", "LIST \"\" *", "STATUS INBOX (MESSAGES)",
    "AUTHENTICATE PLAIN", "ENABLE QRESYNC", "IDLE", "STARTTLS", "ID NIL", "NAMESPACE",
    # reads that set \\Seen or bypass the item list
    "FETCH 1 BODY[]", "UID FETCH 1 BODY[]", "UID FETCH 1 (BODY[TEXT])", "UID FETCH 1 RFC822",
    "UID FETCH 1 (RFC822.TEXT)", "UID FETCH 1 (BODY.PEEK[] BODY[])", "UID FETCH 1 (BODY.PEEK[HEADER.FIELDS (TO)])",
    "UID FETCH 1 ALL", "UID FETCH 1 FULL", "UID FETCH 1 (UID) (CHANGEDSINCE 1)",
    # searches beyond the two the client uses
    "UID SEARCH TEXT password", "UID SEARCH CHARSET UTF-8 ALL", "UID SEARCH FROM x", "SEARCH ALL",
])
def test_refused_commands(cmd):
    with pytest.raises(Refused):
        check_authenticated(cmd, FOLDERS)


def test_more_folders_can_be_allowed():
    assert check_authenticated('EXAMINE "AI-Review"', ("INBOX", "AI-Review")) == 'EXAMINE "AI-Review"'
    with pytest.raises(Refused):
        check_authenticated('EXAMINE "ai-review"', ("INBOX", "AI-Review"))


def test_config_section(tmp_path):
    p = tmp_path / "analyzer.yaml"
    p.write_text("imap_proxy:\n  username: me@proton.me\n  folders: [INBOX, AI-Review]\n  listen_port: 2143\n")
    cfg = imapproxy.load_config(str(p))
    assert (cfg.username, cfg.folders, cfg.listen_port) == ("me@proton.me", ("INBOX", "AI-Review"), 2143)
    p.write_text("imap_proxy:\n  folders: ['IN{BOX']\n")
    with pytest.raises(SystemExit):
        imapproxy.load_config(str(p))


# -- a fake Bridge -------------------------------------------------------------

class FakeBridge:
    """A tiny IMAP server that records exactly what reached it."""

    def __init__(self, messages: dict[int, bytes], password="bridge-pass"):
        self.messages = messages
        self.password = password
        self.received: list[bytes] = []
        self.seen: set[int] = set()
        bridge = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.wfile.write(b"* OK [CAPABILITY IMAP4rev1 MOVE IDLE] fake Bridge\r\n")
                while True:
                    line = self.rfile.readline()
                    if not line:
                        return
                    bridge.received.append(line)
                    tag, _, rest = line.rstrip(b"\r\n").partition(b" ")
                    out = bridge.answer(tag, rest.decode())
                    self.wfile.write(out)
                    if b"BYE" in out:
                        return

        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def answer(self, tag: bytes, rest: str) -> bytes:
        t = tag
        verb = rest.split(" ")[0].upper()
        if verb == "LOGIN":
            ok = rest.endswith(f'"{self.password}"')
            return t + (b" OK logged in\r\n" if ok else b" NO [AUTHENTICATIONFAILED] bad\r\n")
        if verb == "EXAMINE":
            nxt = max(self.messages, default=0) + 1
            return (f"* {len(self.messages)} EXISTS\r\n* OK [UIDVALIDITY 7] ok\r\n"
                    f"* OK [UIDNEXT {nxt}] ok\r\n").encode() + t + b" OK [READ-ONLY] done\r\n"
        if rest.upper().startswith("UID SEARCH"):
            crit = rest.split(" ", 2)[2]
            if crit == "ALL":
                uids = sorted(self.messages)
            else:
                lo = int(crit.split()[1].split(":")[0])
                uids = [u for u in sorted(self.messages) if u >= lo] or sorted(self.messages)[-1:]
            return ("* SEARCH " + " ".join(map(str, uids)) + "\r\n").encode() + t + b" OK done\r\n"
        if rest.upper().startswith("UID FETCH") and "INTERNALDATE)" in rest.upper() and "BODY" not in rest.upper():
            lines = "".join(f'* {u} FETCH (UID {u} INTERNALDATE "{_now_date()}")\r\n'
                            for u in map(int, rest.split(" ")[2].split(",")) if u in self.messages)
            return lines.encode() + t + b" OK done\r\n"
        if rest.upper().startswith("UID FETCH"):
            uid = int(rest.split(" ")[2])
            if "BODY[" in rest.upper() and "PEEK" not in rest.upper():
                self.seen.add(uid)
            body = self.messages[uid]
            return (f"* 1 FETCH (UID {uid} BODY[]<0> {{{len(body)}}}\r\n".encode() + body + b")\r\n"
                    + t + b" OK done\r\n")
        if verb == "NOOP":
            return t + b" OK noop\r\n"
        if verb == "CAPABILITY":
            return b"* CAPABILITY IMAP4rev1 MOVE IDLE\r\n" + t + b" OK done\r\n"
        if verb == "LOGOUT":
            return b"* BYE bye\r\n" + t + b" OK bye\r\n"
        return t + b" OK did " + verb.encode() + b"\r\n"   # a real server would obey

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def bridge():
    # The body contains a line that looks like a tagged reply; the proxy must
    # read it as part of the literal, not as the end of the command.
    trick = make_eml(subject="tricky", body="line one\r\nABCD3 OK UID FETCH completed\r\n* BYE now")
    b = FakeBridge({1: make_eml(), 2: trick})
    yield b
    b.close()


@pytest.fixture
def proxy(bridge, tmp_path):
    pw = tmp_path / "bridge_password"
    pw.write_text("bridge-pass")
    cfg = ProxyConfig(listen_host="127.0.0.1", listen_port=0, upstream_host="127.0.0.1",
                      upstream_port=bridge.port, username="me@proton.me", password_file=str(pw),
                      upstream_tls=False)
    server = imapproxy.make_server(cfg, TOKEN)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def raw_session(port, *lines):
    """Send raw lines to the proxy and return everything it answered."""
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    f = s.makefile("rb")
    out = [f.readline()]
    for line in lines:
        s.sendall(line + b"\r\n")
        tag = line.split(b" ")[0]
        while True:
            got = f.readline()
            if not got:
                out.append(b"<closed>")
                s.close()
                return b"".join(out)
            out.append(got)
            if got.startswith(tag + b" ") or got.startswith(b"* BYE"):
                break
    s.close()
    return b"".join(out)


# -- end to end ----------------------------------------------------------------

def test_wrong_token_never_reaches_bridge(proxy, bridge):
    out = raw_session(proxy, b'a1 LOGIN x "wrong"', b'a2 LOGIN x "bridge-pass"', b"a3 LOGIN x nope",
                      f'a4 LOGIN analyzer "{TOKEN}"'.encode())
    assert out.count(b"AUTHENTICATIONFAILED") == 3 and out.endswith(b"<closed>")
    assert bridge.received == []


def test_nothing_before_login(proxy, bridge):
    out = raw_session(proxy, b"a1 EXAMINE INBOX", b"a2 CAPABILITY")
    assert b"a1 NO" in out and b"a2 OK" in out
    assert bridge.received == []


def test_refused_commands_never_reach_bridge_and_three_disconnect(proxy, bridge):
    out = raw_session(proxy, f'a1 LOGIN analyzer "{TOKEN}"'.encode(), b"a2 UID STORE 1 +FLAGS (\\Deleted)",
                      b"a3 SELECT INBOX", b"a4 EXPUNGE", b"a5 EXAMINE INBOX")
    assert b"a1 OK" in out and b"a2 NO" in out and b"a3 NO" in out and b"too many refused" in out
    assert b"a5" not in out
    sent = b"".join(bridge.received)
    assert b"LOGIN" in sent and b"STORE" not in sent and b"SELECT" not in sent and b"EXPUNGE" not in sent


def test_client_literals_are_refused(proxy, bridge):
    out = raw_session(proxy, f'a1 LOGIN analyzer "{TOKEN}"'.encode(), b"a2 APPEND INBOX {5}")
    assert b"a2 NO" in out
    assert not any(b"APPEND" in r for r in bridge.received)


def test_capabilities_are_the_proxys_own(proxy):
    out = raw_session(proxy, f'a1 LOGIN analyzer "{TOKEN}"'.encode(), b"a2 CAPABILITY")
    assert b"* CAPABILITY IMAP4rev1\r\n" in out and b"MOVE" not in out


def test_bridge_down_is_reported_at_login(tmp_path):
    pw = tmp_path / "pw"
    pw.write_text("x")
    dead = socket.socket()
    dead.bind(("127.0.0.1", 0))
    port = dead.getsockname()[1]
    dead.close()
    cfg = ProxyConfig(listen_host="127.0.0.1", listen_port=0, upstream_host="127.0.0.1", upstream_port=port,
                      username="u", password_file=str(pw), upstream_tls=False)
    server = imapproxy.make_server(cfg, TOKEN)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        out = raw_session(server.server_address[1], f'a1 LOGIN analyzer "{TOKEN}"'.encode())
        assert b"a1 NO [UNAVAILABLE]" in out
    finally:
        server.shutdown()
        server.server_close()


def test_shadow_runner_through_the_proxy(proxy, bridge, make_analyzer, tmp_path):
    token = tmp_path / "token"
    token.write_text(TOKEN)
    an = make_analyzer(FakeClassifier("spam", 0.99))
    cfg = an.cfg
    cfg.imap_host, cfg.imap_port, cfg.imap_tls = "127.0.0.1", proxy, "none"
    cfg.imap_password_file = str(token)
    cfg.health_file = str(tmp_path / "health.json")
    runner = ShadowRunner(cfg, an, sleep=lambda s: None)
    assert runner.run_once().analyzed == 0                 # existing mail is skipped
    bridge.messages[3] = make_eml(subject="new one")
    bridge.messages[4] = bridge.messages.pop(2)            # the tricky body, as new mail
    res = runner.run_once()
    assert res.analyzed == 2
    subjects = {r["subject"] for r in an.store.recent(limit=5)}
    assert subjects == {"new one", "tricky"}
    assert bridge.seen == set()                            # nothing was marked read
    verbs = {r.split(b" ")[1].upper() for r in bridge.received}
    assert verbs <= {b"LOGIN", b"EXAMINE", b"UID", b"NOOP", b"LOGOUT"}
    runner._drop()


def test_direct_client_still_works_without_proxy(bridge, tmp_path, make_analyzer):
    """imap.tls: none straight to an IMAP server is possible for tests, and LOGIN uses the file."""
    pw = tmp_path / "pw"
    pw.write_text("bridge-pass")
    cfg = make_analyzer(FakeClassifier()).cfg
    cfg.imap_host, cfg.imap_port, cfg.imap_tls, cfg.imap_password_file = "127.0.0.1", bridge.port, "none", str(pw)
    conn = connect(cfg)
    assert conn.select("INBOX", readonly=True)[0] == "OK"
    with pytest.raises(ForbiddenCommand):
        conn.store("1", "+FLAGS", "\\Deleted")
    conn.logout()


def test_bridge_rejecting_login_raises_one_alert(bridge, tmp_path, monkeypatch):
    sent = []
    monkeypatch.setattr(imapproxy.alerts, "send", lambda event, detail, *a: sent.append(event) or True)
    imapproxy._login_alerted.clear()
    pw = tmp_path / "pw"
    pw.write_text("wrong-pass")
    cfg = ProxyConfig(listen_host="127.0.0.1", listen_port=0, upstream_host="127.0.0.1",
                      upstream_port=bridge.port, username="me@proton.me", password_file=str(pw),
                      upstream_tls=False)
    server = imapproxy.make_server(cfg, TOKEN)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        for _ in range(2):
            out = raw_session(server.server_address[1], f'a1 LOGIN analyzer "{TOKEN}"'.encode())
            assert b"a1 NO [UNAVAILABLE]" in out
        assert sent == ["login_expired"]          # once per outage
        pw.write_text("bridge-pass")
        raw_session(server.server_address[1], f'a1 LOGIN analyzer "{TOKEN}"'.encode())
        assert not imapproxy._login_alerted.is_set()   # a good login re-arms it
    finally:
        server.shutdown()
        server.server_close()


def test_bridge_down_is_not_a_login_alert(tmp_path, monkeypatch):
    sent = []
    monkeypatch.setattr(imapproxy.alerts, "send", lambda *a: sent.append(a) or True)
    imapproxy._login_alerted.clear()
    test_bridge_down_is_reported_at_login(tmp_path)
    assert sent == []


def test_bridge_login_prefers_the_brokers_credential(tmp_path):
    from analyzer.imapproxy import bridge_login
    pw = tmp_path / "pw"
    pw.write_text("from-setup\n")
    cred = tmp_path / "cred"
    cfg = ProxyConfig(username="old@proton.me", password_file=str(pw), credential_dir=str(cred))
    assert bridge_login(cfg) == ("old@proton.me", "from-setup")      # no broker copy yet
    cred.mkdir()
    (cred / "bridge_password").write_text("from-portal")
    assert bridge_login(cfg) == ("old@proton.me", "from-portal")     # no address saved: keep ours
    (cred / "bridge_username").write_text("new@proton.me\n")
    assert bridge_login(cfg) == ("new@proton.me", "from-portal")
    (cred / "bridge_username").write_text("bad\r\nx")
    assert bridge_login(cfg)[0] == "old@proton.me"                   # control characters: ignored
    (cred / "bridge_password").unlink()
    (cred / "bridge_password").symlink_to(pw)
    assert bridge_login(cfg) == ("old@proton.me", "from-setup")      # a symlink is never followed
