import json
import imaplib

import pytest

from analyzer.imap import ForbiddenCommand, ReadOnlyIMAP, ShadowRunner, _fetch_raw
from conftest import FakeClassifier, make_eml


class FakeIMAP:
    """Just enough of imaplib.IMAP4 for the runner, recording every call."""

    def __init__(self, messages: dict[int, bytes], uidvalidity=7, fail=None):
        self.messages = dict(messages)
        self.uidvalidity = uidvalidity
        self.calls: list[tuple] = []
        self.fail = fail
        self.dates: dict[int, str] = {}
        self.dates_fail = 0          # answer NO to this many INTERNALDATE fetches
        self._resp = {}

    def select(self, mailbox, readonly=False):
        self.calls.append(("select", mailbox, readonly))
        if self.fail:
            raise self.fail
        uidnext = max(self.messages, default=0) + 1
        self._resp = {"UIDVALIDITY": [str(self.uidvalidity).encode()], "UIDNEXT": [str(uidnext).encode()]}
        return "OK", [str(len(self.messages)).encode()]

    def response(self, code):
        return code, self._resp.get(code, [None])

    def uid(self, command, *args):
        self.calls.append(("uid", command) + args)
        if command == "SEARCH":
            crit = args[-1]
            if crit == "ALL":
                uids = sorted(self.messages)
            else:
                lo = int(crit.split()[1].split(":")[0])
                uids = [u for u in sorted(self.messages) if u >= lo] or sorted(self.messages)[-1:]
            return "OK", [" ".join(map(str, uids)).encode()]
        if command == "FETCH" and args[1] == "(UID INTERNALDATE)":
            if self.dates_fail:
                self.dates_fail -= 1
                return "NO", [b"try later"]
            out = []
            for u in map(int, args[0].split(",")):
                if u in self.messages:
                    day = self.dates.get(u, "24-Nov-2026 10:00:00 +0000")
                    out.append(f'{u} (UID {u} INTERNALDATE "{day}")'.encode())
            return "OK", out
        if command == "FETCH":
            uid = int(args[0])
            assert "BODY.PEEK[]" in args[1]
            return "OK", [(f"1 (UID {uid} BODY[]<0> {{10}}".encode(), self.messages[uid]), b")"]
        raise AssertionError(f"unexpected UID {command}")

    def logout(self):
        self.calls.append(("logout",))


@pytest.fixture
def runner_for(make_analyzer, tmp_path):
    def _make(conn, classifier=None):
        an = make_analyzer(classifier or FakeClassifier("spam", 0.99))
        an.cfg.health_file = str(tmp_path / "health.json")
        return ShadowRunner(an.cfg, an, connect_fn=lambda cfg: conn, sleep=lambda s: None,
                            clock=lambda: 1_000_000.0), an
    return _make


def test_first_run_starts_at_new_mail_only(runner_for):
    conn = FakeIMAP({1: make_eml(), 2: make_eml()})
    runner, an = runner_for(conn)
    assert runner.run_once().analyzed == 0          # existing mail is never analyzed
    conn.messages[3] = make_eml(subject="new")
    assert runner.run_once().analyzed == 1
    assert an.store.recent(limit=5)[0]["message_key"] == "INBOX:7:3"
    assert runner.run_once().analyzed == 0          # "3:*" returning 3 again is ignored


def test_always_examine_and_peek(runner_for):
    conn = FakeIMAP({1: make_eml()})
    runner, _ = runner_for(conn)
    runner.run_once()
    conn.messages[2] = make_eml()
    runner.run_once()
    selects = [c for c in conn.calls if c[0] == "select"]
    assert selects and all(c[2] is True for c in selects)
    assert {c[1] for c in conn.calls if c[0] == "uid"} <= {"SEARCH", "FETCH"}


def test_uidvalidity_change_resets_without_replay(runner_for):
    conn = FakeIMAP({1: make_eml()})
    runner, _ = runner_for(conn)
    runner.run_once()
    conn.messages[2] = make_eml()
    conn.uidvalidity = 8
    res = runner.run_once()
    assert res.reset and res.analyzed == 0
    conn.messages[3] = make_eml()
    assert runner.run_once().analyzed == 1


def test_kill_switch_stops_reading(runner_for, tmp_path):
    conn = FakeIMAP({1: make_eml()})
    runner, _ = runner_for(conn)
    runner.run_once()
    conn.messages[2] = make_eml()
    (tmp_path / "PAUSE").write_text("")
    assert runner.run_once().analyzed == 0


def test_errors_are_retried_then_reported(runner_for):
    conn = FakeIMAP({}, fail=imaplib.IMAP4.abort("bye"))
    runner, an = runner_for(conn)
    t = [1_000_000.0]
    runner.clock = lambda: t[0]
    assert runner.run_once() is None
    assert '"retrying"' in an.store.get_state("health")
    t[0] += 16 * 60
    runner.run_once()
    assert "bridge_unreachable" in an.store.get_state("health")
    conn.fail = None
    assert runner.run_once() is not None
    assert '"ok"' in an.store.get_state("health")


def test_client_refuses_every_write_command():
    c = object.__new__(ReadOnlyIMAP)
    for verb in ("STORE", "COPY", "MOVE", "EXPUNGE", "DELETE", "APPEND", "SELECT", "CREATE", "RENAME",
                 "SUBSCRIBE", "SETACL", "AUTHENTICATE", "ENABLE", "IDLE"):
        with pytest.raises(ForbiddenCommand):
            c._command(verb, "x")
    for sub in ("STORE", "COPY", "MOVE", "EXPUNGE"):
        with pytest.raises(ForbiddenCommand):
            c._command("UID", sub, "1", "+FLAGS", "(\\Deleted)")


def test_fetch_ignores_other_uids():
    conn = FakeIMAP({5: b"five"})
    assert _fetch_raw(conn, 5, 100) == b"five"
    conn.uid = lambda *a: ("OK", [(b"1 (UID 6 BODY[]<0> {3}", b"six"), b")"])
    assert _fetch_raw(conn, 5, 100) is None


def test_db_declares_its_schema_version_for_readers(tmp_path):
    import sqlite3
    from analyzer.store import SCHEMA_VERSION, Store
    db = tmp_path / "a.db"
    Store(str(db))
    ro = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    assert ro.execute("SELECT value FROM state WHERE key='schema_version'").fetchone()[0] == str(SCHEMA_VERSION)
    assert ro.execute("PRAGMA journal_mode").fetchone()[0] == "delete"   # no WAL: read-only readers work


def test_health_reports_model_state(runner_for, tmp_path):
    import json
    runner, an = runner_for(None)
    runner.health("ok", "x")
    h = json.loads((tmp_path / "health.json").read_text())
    assert h["model"] == "on" and h["budget_usd"] == an.cfg.monthly_budget_usd and "spend_month_usd" in h


def test_old_mail_synced_after_go_live_is_left_alone(runner_for):
    """Bridge keeps importing old mail with new UIDs after setup (the owner's
    Amazon email). Only mail received after go-live is analyzed."""
    import calendar
    fc = FakeClassifier("spam", 0.99)
    conn = FakeIMAP({1: make_eml(subject="first")})
    runner, an = runner_for(conn, fc)
    runner.clock = lambda: calendar.timegm((2026, 11, 24, 12, 0, 0))
    runner.run_once()                                   # go-live
    conn.messages[2] = make_eml(subject="old, synced late")
    conn.dates[2] = "03-Feb-2025 09:00:00 +0000"
    conn.messages[3] = make_eml(subject="new")
    conn.dates[3] = "24-Nov-2026 12:30:00 +0000"
    res = runner.run_once()
    assert res.analyzed == 1 and res.skipped_old == 1 and len(fc.calls) == 1
    assert an.store.has_decision("INBOX:7:3") and not an.store.has_decision("INBOX:7:2")
    assert runner.run_once().analyzed == 0              # and they are not retried
    health = json.loads(an.store.get_state("health"))
    assert health["skipped_pre_go_live"] == 1


def test_missing_dates_are_never_skipped(runner_for):
    """A failed INTERNALDATE fetch, or a message with no date, must not let
    mail slip past analysis: the poll stops there and tries again."""
    import calendar
    fc = FakeClassifier("spam", 0.99)
    conn = FakeIMAP({1: make_eml(subject="first")})
    runner, an = runner_for(conn, fc)
    runner.clock = lambda: calendar.timegm((2026, 11, 24, 12, 0, 0))
    runner.run_once()                                   # go-live
    conn.messages[2] = make_eml(subject="new")
    conn.dates[2] = "24-Nov-2026 12:30:00 +0000"
    conn.dates_fail = 1
    res = runner.run_once()                             # FETCH answers NO
    assert res.analyzed == 0 and res.skipped_old == 0 and res.waiting_on_date
    assert runner.run_once().analyzed == 1              # retried, then analyzed
    assert an.store.has_decision("INBOX:7:2")

    conn.messages[3] = make_eml(subject="undated")
    conn.dates[3] = "garbage"
    assert runner.run_once().analyzed == 0              # held back, not skipped
    assert runner.run_once().analyzed == 0
    assert runner.run_once().analyzed == 1              # then analyzed rather than dropped
    assert an.store.has_decision("INBOX:7:3")
