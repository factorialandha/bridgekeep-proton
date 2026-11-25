"""Live mode: the switch, the proxy's own checks, and moves through the real proxy.

Covers the security review of live mode: strict grammar (1, 2), the undo
ledger (3), mode.json and PAUSE read fresh and failing closed (4), the
daily cap on a volume (5), alerts on refusals (7), the code rules for
what may move (8, 9), the analyzer's cap (11) and the move log (12).
"""

import json
import os
import socket
import threading
import time

import pytest

from analyzer import imapproxy, mode as modes
from analyzer.config import Config, load
from analyzer.imap import ShadowRunner
from analyzer.imapproxy import LiveState, ProxyConfig
from conftest import FakeClassifier, make_eml
from test_imapproxy import TOKEN, FakeBridge, _now_date, raw_session

REVIEW, QUAR = "Folders/AI-Review", "Folders/AI-Quarantine"


def set_live(portal, since=None):
    portal.mkdir(exist_ok=True)
    (portal / "mode.json").write_text(json.dumps({"mode": "live", "ts": int(since or time.time() - 3600),
                                                  "by": "portal"}))


# -- the switch ------------------------------------------------------------------

def test_mode_file_fails_closed(tmp_path):
    p = tmp_path / "portal"
    p.mkdir()
    assert modes.requested(str(p)).mode == "shadow"                      # no file
    for body in ("", "{", '"live"', '{"mode": "LIVE", "ts": 5}', '{"mode": "live"}',
                 '{"mode": "live", "ts": true}', '{"mode": "live", "ts": "5"}', '{"mode": ["live"], "ts": 5}'):
        (p / "mode.json").write_text(body)
        assert modes.requested(str(p)).mode == "shadow", body
    (p / "mode.json").write_text('{"mode": "live", "ts": 5, "pad": "' + "x" * 5000 + '"}')
    assert modes.requested(str(p)).mode == "shadow"                      # over 4 KB
    (p / "mode.json").unlink()
    (tmp_path / "real.json").write_text('{"mode": "live", "ts": 5}')
    os.symlink(tmp_path / "real.json", p / "mode.json")
    assert modes.requested(str(p)).mode == "shadow"                      # a link is never followed
    os.unlink(p / "mode.json")
    os.mkdir(p / "mode.json")
    assert modes.requested(str(p)).mode == "shadow"                      # not a regular file
    os.rmdir(p / "mode.json")
    set_live(p, 1000)
    assert modes.requested(str(p)) == modes.Requested("live", 1000, None)
    (p / "PAUSE").write_text("")
    assert modes.live_allowed(str(p)).mode == "shadow"                   # PAUSE wins


def test_config_goes_live_only_from_the_portal(tmp_path):
    portal = tmp_path / "portal"
    cfg = Config(portal_dir=str(portal), pause_file=str(tmp_path / "PAUSE"))
    assert cfg.effective_mode() == "shadow"
    set_live(portal, 1234)
    assert cfg.effective_mode() == "live" and cfg.live_since() == 1234
    cfg.problems.append("x")
    assert cfg.effective_mode() == "shadow" and "configuration" in cfg.mode_problem()
    cfg.problems.clear()
    cfg.imap_folder = "Archive"
    assert cfg.effective_mode() == "shadow" and "INBOX" in cfg.mode_problem()
    y = tmp_path / "a.yaml"
    y.write_text("mode: live\n")
    assert any("portal" in p for p in load(str(y)).problems)             # never from analyzer.yaml


@pytest.mark.parametrize("name", ["Trash", "inbox", "Spam", "All Mail", "Sent", "Drafts", "Folders/Trash",
                                  "a/b", "&AOk-x", "", "Labels/AI"])
def test_ai_folders_must_be_their_own(tmp_path, name):
    y = tmp_path / "a.yaml"
    y.write_text(json.dumps({"folders": {"quarantine": name}}))
    cfg = load(str(y))
    assert cfg.quarantine_folder == "AI-Quarantine" and cfg.problems


# -- a Bridge with folders --------------------------------------------------------

class FolderBridge(FakeBridge):
    """FakeBridge plus SELECT, CREATE and UID MOVE (with COPYUID), per folder."""

    def __init__(self, messages):
        super().__init__(messages)
        self.folders = {"INBOX": self.messages}
        self.validity = {"INBOX": 7}
        self.next_uid = {"INBOX": 1}
        self.current = "INBOX"
        self.copyuid = True

    def answer(self, tag, rest):
        t = tag
        verb = rest.split(" ")[0].upper()
        if verb in ("SELECT", "EXAMINE"):
            name = rest.split(" ", 1)[1].strip('"')
            if name not in self.folders:
                return t + b" NO no such folder\r\n"
            self.current = name
            self.messages = self.folders[name]
            nxt = max(max(self.messages, default=0) + 1, self.next_uid[name])
            return (f"* {len(self.messages)} EXISTS\r\n* OK [UIDVALIDITY {self.validity[name]}] ok\r\n"
                    f"* OK [UIDNEXT {nxt}] ok\r\n").encode() + t + b" OK done\r\n"
        if verb == "CREATE":
            name = rest.split(" ", 1)[1].strip('"')
            if name in self.folders:
                return t + b" NO [ALREADYEXISTS] exists\r\n"
            self.folders[name], self.validity[name], self.next_uid[name] = {}, 50 + len(self.folders), 1
            return t + b" OK created\r\n"
        if rest.upper().startswith("UID MOVE"):
            _, _, uid, dest = rest.split(" ", 3)
            uid, dest = int(uid), dest.strip('"')
            src = self.folders[self.current]
            if uid not in src or dest not in self.folders:
                return t + b" NO no such message\r\n"
            new = max(max(self.folders[dest], default=0) + 1, self.next_uid[dest])
            self.next_uid[dest] = new + 1
            self.folders[dest][new] = src.pop(uid)
            cu = f"* OK [COPYUID {self.validity[dest]} {uid} {new}] moved\r\n" if self.copyuid else ""
            return (cu + "* 1 EXPUNGE\r\n").encode() + t + b" OK done\r\n"
        return super().answer(tag, rest)


@pytest.fixture
def fbridge():
    b = FolderBridge({1: make_eml()})
    yield b
    b.close()


@pytest.fixture
def live_proxy(fbridge, tmp_path):
    pw = tmp_path / "bridge_password"
    pw.write_text("bridge-pass")
    state = tmp_path / "proxy-state"
    state.mkdir()
    portal = tmp_path / "portal"
    portal.mkdir()
    alerts = tmp_path / "alerts"
    alerts.mkdir()
    cfg = ProxyConfig(listen_host="127.0.0.1", listen_port=0, upstream_host="127.0.0.1",
                      upstream_port=fbridge.port, username="me@proton.me", password_file=str(pw),
                      upstream_tls=False, portal_dir=str(portal), pause_file=str(tmp_path / "PAUSE"),
                      state_dir=str(state), alert_dir=str(alerts), max_moves_per_day=3)
    live = LiveState(cfg)
    server = imapproxy.make_server(cfg, TOKEN, live_state=live)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    server.cfg, server.live, server.portal, server.alerts = cfg, live, portal, alerts
    yield server
    server.shutdown()
    server.server_close()


LOGIN = f'a0 LOGIN analyzer "{TOKEN}"'.encode()


def sent_to_bridge(bridge, word: bytes) -> bool:
    return any(word in r.upper() for r in bridge.received)


# -- the proxy: off unless live ---------------------------------------------------

def test_proxy_refuses_every_move_command_in_shadow(live_proxy, fbridge):
    out = raw_session(live_proxy.server_address[1], LOGIN, b"a1 SELECT INBOX", b'a2 CREATE "Folders/AI-Review"')
    assert b"a1 NO" in out and b"a2 NO" in out
    assert not sent_to_bridge(fbridge, b"SELECT") and not sent_to_bridge(fbridge, b"CREATE")


def test_proxy_reads_the_switch_for_every_command(live_proxy, fbridge, tmp_path):
    set_live(live_proxy.portal)
    port = live_proxy.server_address[1]
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    f = s.makefile("rb")
    f.readline()

    def cmd(line):
        s.sendall(line + b"\r\n")
        tag = line.split(b" ")[0]
        out = b""
        while True:
            got = f.readline()
            out += got
            if got.startswith(tag + b" ") or not got:
                return out

    assert b"a0 OK" in cmd(LOGIN)
    assert b"a1 OK" in cmd(b"a1 SELECT INBOX")
    (tmp_path / "PAUSE").write_text("")                     # paused mid-session
    assert b"a2 NO" in cmd(b'a2 UID MOVE 1 "Folders/AI-Review"')
    os.unlink(tmp_path / "PAUSE")
    (live_proxy.portal / "mode.json").write_text('{"mode": "shadow", "ts": 1}')
    assert b"a3 NO" in cmd(b'a3 UID MOVE 1 "Folders/AI-Review"')
    s.close()
    assert 1 in fbridge.folders["INBOX"] and not sent_to_bridge(fbridge, b"MOVE")


@pytest.mark.parametrize("line", [
    b'a2 UID MOVE 1:3 "Folders/AI-Review"', b'a2 UID MOVE * "Folders/AI-Review"', b'a2 UID MOVE 1,2 "Folders/AI-Review"',
    b'a2 UID MOVE 0 "Folders/AI-Review"', b'a2 UID MOVE 01 "Folders/AI-Review"', b'a2 UID MOVE 1 {17}',
    b'a2 UID MOVE 1 "Folders/ai-review"', b'a2 UID MOVE 1 "Folders/AI-Review "', b'a2 UID MOVE 1 Trash',
    b'a2 UID MOVE 1 "Folders/AI-&AOk-Review"', b'a2 UID MOVE 1 INBOX', b'a2 MOVE 1 "Folders/AI-Review"',
    b'a2 UID MOVE 1 "Folders/AI-Review" extra', b'a2 UID MOVE 1  "Folders/AI-Review"', b'a2 UID MOVE -1 "Folders/AI-Review"',
    b'a2 UID COPY 1 "Folders/AI-Review"', b'a2 UID STORE 1 +FLAGS (\\Deleted)', b"a2 EXPUNGE", b'a2 CREATE "Folders/Exfil"',
    b'a2 CREATE Trash', b'a2 SELECT Trash', b'a2 SELECT "All Mail"', b'a2 UID FETCH 1 BODY[]',
])
def test_live_grammar_is_strict(live_proxy, fbridge, line):
    set_live(live_proxy.portal)
    out = raw_session(live_proxy.server_address[1], LOGIN, b"a1 SELECT INBOX", line)
    assert b"a1 OK" in out and b"a2 NO" in out or b"a2 BAD" in out, out
    assert 1 in fbridge.folders["INBOX"]
    assert not sent_to_bridge(fbridge, b"MOVE") and not sent_to_bridge(fbridge, b"STORE")


def test_move_needs_inbox_selected_read_write(live_proxy, fbridge):
    set_live(live_proxy.portal)
    port = live_proxy.server_address[1]
    out = raw_session(port, LOGIN, b'a1 UID MOVE 1 "Folders/AI-Review"', b"a2 SELECT INBOX", b"a3 EXAMINE INBOX",
                      b'a4 UID MOVE 1 "Folders/AI-Review"')
    assert b"a1 NO" in out and b"a2 OK" in out and b"a3 OK" in out and b"a4 NO" in out


def test_moves_are_counted_on_disk_and_capped(live_proxy, fbridge, tmp_path):
    set_live(live_proxy.portal)
    for u in range(2, 6):
        fbridge.folders["INBOX"][u] = make_eml(subject=f"m{u}")
    port = live_proxy.server_address[1]
    out = raw_session(port, LOGIN, b'a1 CREATE "Folders/AI-Review"', b"a2 SELECT INBOX",
                      *[f'b{u} UID MOVE {u} "Folders/AI-Review"'.encode() for u in (1, 2)])
    assert b"b1 OK" in out and b"b2 OK" in out
    # A restarted proxy keeps the day's count.
    again = LiveState(live_proxy.cfg)
    assert again.take_move() is None                       # the third of 3
    assert again.take_move() == "daily move cap reached"
    assert any(n.startswith("move_cap") for n in os.listdir(live_proxy.alerts))
    out = raw_session(port, LOGIN, b"a1 SELECT INBOX", b'a2 UID MOVE 3 "Folders/AI-Review"')
    assert b"a2 NO" in out and 3 in fbridge.folders["INBOX"]


def test_an_unwritable_count_refuses_the_move(live_proxy, fbridge):
    set_live(live_proxy.portal)
    with open(os.path.join(live_proxy.cfg.state_dir, "moves.json"), "w") as f:
        f.write("not json")
    out = raw_session(live_proxy.server_address[1], LOGIN, b"a1 SELECT INBOX", b'a2 UID MOVE 1 "Folders/AI-Review"')
    assert b"a2 NO" in out and 1 in fbridge.folders["INBOX"]
    os.unlink(os.path.join(live_proxy.cfg.state_dir, "moves.json"))
    os.chmod(live_proxy.cfg.state_dir, 0o500)
    try:
        if os.access(live_proxy.cfg.state_dir, os.W_OK):
            pytest.skip("running as root: permissions don't bind")
        out = raw_session(live_proxy.server_address[1], LOGIN, b"a1 SELECT INBOX", b'a2 UID MOVE 1 "Folders/AI-Review"')
        assert b"a2 NO" in out and 1 in fbridge.folders["INBOX"]
    finally:
        os.chmod(live_proxy.cfg.state_dir, 0o700)


def test_undo_only_for_what_the_proxy_moved(live_proxy, fbridge):
    set_live(live_proxy.portal)
    fbridge.folders["Folders/AI-Review"], fbridge.validity["Folders/AI-Review"] = {}, 60
    fbridge.next_uid["Folders/AI-Review"] = 1
    fbridge.folders["Folders/AI-Review"][9] = make_eml(subject="was already there")
    fbridge.next_uid["Folders/AI-Review"] = 10
    port = live_proxy.server_address[1]
    out = raw_session(port, LOGIN, b"a1 SELECT INBOX", b'a2 UID MOVE 1 "Folders/AI-Review"')
    assert b"a2 OK" in out and live_proxy.live.knows(REVIEW, 60, 10)
    assert json.loads(open(os.path.join(live_proxy.cfg.state_dir, "ledger.json")).read()) == [[REVIEW, 60, 10]]
    out = raw_session(port, LOGIN, b'a1 SELECT "Folders/AI-Review"', b"a2 UID MOVE 9 INBOX",
                      b'a3 UID MOVE 10 "Folders/AI-Quarantine"', b"a4 UID MOVE 10 INBOX")
    assert b"a2 NO" in out and b"a3 NO" in out and b"a4 OK" in out
    assert 9 in fbridge.folders[REVIEW] and not live_proxy.live.knows(REVIEW, 60, 10)
    # The ledger survives a restart, and a recreated folder (new UIDVALIDITY) matches nothing.
    assert LiveState(live_proxy.cfg).ledger == set()


def test_undo_works_in_shadow_but_not_paused(live_proxy, fbridge, tmp_path):
    set_live(live_proxy.portal)
    port = live_proxy.server_address[1]
    raw_session(port, LOGIN, b'a1 CREATE "Folders/AI-Quarantine"', b"a2 SELECT INBOX",
                b'a3 UID MOVE 1 "Folders/AI-Quarantine"')
    (live_proxy.portal / "mode.json").unlink()                 # back to shadow
    (tmp_path / "PAUSE").write_text("")
    out = raw_session(port, LOGIN, b'a1 SELECT "Folders/AI-Quarantine"')
    assert b"a1 NO" in out
    os.unlink(tmp_path / "PAUSE")
    out = raw_session(port, LOGIN, b'a1 SELECT "Folders/AI-Quarantine"', b"a2 UID MOVE 1 INBOX")
    assert b"a2 OK" in out and len(fbridge.folders["INBOX"]) == 1


def test_a_refusal_in_live_mode_alerts_once_an_hour(live_proxy, fbridge, monkeypatch):
    monkeypatch.setattr(imapproxy, "_refused_alert_at", [0.0])
    set_live(live_proxy.portal)
    raw_session(live_proxy.server_address[1], LOGIN, b"a1 UID STORE 1 +FLAGS (\\Seen)", b"a2 EXPUNGE")
    names = [n for n in os.listdir(live_proxy.alerts) if n.startswith("imap_refused")]
    assert len(names) == 1


# -- the analyzer through the proxy ------------------------------------------------

@pytest.fixture
def live_runner(live_proxy, fbridge, make_analyzer, tmp_path):
    token = tmp_path / "token"
    token.write_text(TOKEN)

    def _make(classifier, **kw):
        an = make_analyzer(classifier, portal_dir=str(live_proxy.portal), alert_dir=str(live_proxy.alerts), **kw)
        cfg = an.cfg
        cfg.imap_host, cfg.imap_port, cfg.imap_tls = "127.0.0.1", live_proxy.server_address[1], "none"
        cfg.imap_password_file = str(token)
        cfg.health_file = str(tmp_path / "health.json")
        runner = ShadowRunner(cfg, an, sleep=lambda s: None)
        assert runner.run_once().analyzed == 0             # existing mail is left alone
        return runner
    return _make


def _alerts(live_proxy, prefix):
    return [n for n in os.listdir(live_proxy.alerts) if n.startswith(prefix)]


def test_live_moves_and_the_not_spam_undo(live_runner, live_proxy, fbridge):
    set_live(live_proxy.portal)
    runner = live_runner(FakeClassifier("spam", 0.99))
    fbridge.folders["INBOX"][2] = make_eml(subject="buy now")
    res = runner.run_once()
    assert (res.analyzed, res.moved) == (1, 1)
    assert list(fbridge.folders[QUAR].values()) and 2 not in fbridge.folders["INBOX"]
    assert _alerts(live_proxy, "analyzer_mode_changed")
    row = runner.store.db.execute("SELECT * FROM moves").fetchone()
    assert (row["kind"], row["from_mailbox"], row["to_mailbox"], row["ok"]) == ("move", "INBOX", QUAR, 1)
    assert row["uid"] is not None and runner.store.db.execute("SELECT applied FROM decisions").fetchone()[0] == 1
    assert all(b"FLAGS" not in r.upper() or b"FETCH" in r.upper() for r in fbridge.received)
    assert fbridge.seen == set()                            # nothing was marked read

    # "Not spam" on the portal moves it back, and it is not analyzed again.
    key = runner.store.db.execute("SELECT message_key FROM decisions").fetchone()[0]
    (live_proxy.portal / "feedback.jsonl").write_text(json.dumps(
        {"message_key": key, "label": "legitimate", "scope": "message", "ts": 1, "by": "portal"}) + "\n")
    res = runner.run_once()
    assert res.moved_back == 1 and res.analyzed == 0 and not fbridge.folders[QUAR]
    assert len(fbridge.folders["INBOX"]) == 2
    res = runner.run_once()
    assert (res.analyzed, res.moved, res.moved_back) == (0, 0, 0)
    health = json.loads(open(runner.cfg.health_file).read())
    assert health["mode"] == "live" and health["moved_today"] == 1 and health["moved_back_today"] == 1
    runner._drop()


def test_what_never_moves(live_runner, live_proxy, fbridge):
    set_live(live_proxy.portal)
    runner = live_runner(FakeClassifier("phishing", 0.99))
    fbridge.folders["INBOX"][2] = make_eml(frm="Bank <billing@mybank.com>", subject="statement", auth="")
    fbridge.folders["INBOX"][3] = make_eml(frm="Shop <x@shop.example>", subject="Your verification code 1234")
    res = runner.run_once()
    assert res.analyzed == 2 and res.moved == 0              # protected sender; protected keyword
    rules = {r["rule"] for r in runner.store.db.execute("SELECT rule FROM decisions")}
    assert "protected_keyword" in rules
    assert set(fbridge.folders["INBOX"]) == {1, 2, 3}
    runner._drop()


def test_mail_from_before_the_switch_never_moves(live_runner, live_proxy, fbridge):
    set_live(live_proxy.portal, since=time.time() + 3600)    # switched on "after" the mail arrived
    runner = live_runner(FakeClassifier("spam", 0.99))
    fbridge.folders["INBOX"][2] = make_eml(subject="spam")
    res = runner.run_once()
    assert res.analyzed == 1 and res.moved == 0 and 2 in fbridge.folders["INBOX"]
    runner._drop()


def test_shadow_mode_never_selects(live_runner, live_proxy, fbridge):
    runner = live_runner(FakeClassifier("spam", 0.99))
    fbridge.folders["INBOX"][2] = make_eml(subject="spam")
    res = runner.run_once()
    assert res.analyzed == 1 and res.moved == 0
    assert not sent_to_bridge(fbridge, b"SELECT") and not sent_to_bridge(fbridge, b"MOVE")
    assert runner.store.db.execute("SELECT mode FROM decisions").fetchone()[0] == "shadow"
    runner._drop()


def test_the_analyzers_daily_cap(live_runner, live_proxy, fbridge):
    set_live(live_proxy.portal)
    runner = live_runner(FakeClassifier("spam", 0.8), max_moves_per_day=1)   # review band
    fbridge.folders["INBOX"][2] = make_eml(subject="one")
    fbridge.folders["INBOX"][3] = make_eml(subject="two")
    res = runner.run_once()
    assert res.analyzed == 2 and res.moved == 1 and len(fbridge.folders[REVIEW]) == 1
    assert len(_alerts(live_proxy, "move_cap")) == 1
    runner._drop()


def test_no_copyuid_still_never_moves_it_twice(live_runner, live_proxy, fbridge):
    set_live(live_proxy.portal)
    fbridge.copyuid = False
    runner = live_runner(FakeClassifier("spam", 0.99))
    fbridge.folders["INBOX"][2] = make_eml(subject="buy now")
    assert runner.run_once().moved == 1
    row = runner.store.db.execute("SELECT uid FROM moves").fetchone()
    assert row["uid"] is None                                 # nothing to move back by
    assert runner.store.pending_undos() == []
    runner._drop()
