import json
import time

import pytest

from analyzer import backfill as bf
from analyzer.imap import ShadowRunner
from conftest import FakeClassifier, make_eml

import calendar
NOW = calendar.timegm((2026, 11, 24, 12, 0, 0))   # go-live
DATES = {1: "01-Jan-2026", 2: "15-Mar-2026", 3: "01-Jun-2026", 4: "20-Oct-2026", 5: "10-Nov-2026"}


def _now_date() -> str:
    """Proton's receive time for new test mail: an hour after the test's go-live."""
    return time.strftime("%d-%b-%Y %H:%M:%S +0000", time.gmtime(NOW + 3600))


class OldMailIMAP:
    """A folder with five old messages; records what was fetched."""

    def __init__(self, messages, uidvalidity=7):
        self.messages = dict(messages)
        self.uidvalidity = uidvalidity
        self.fetched_full: list[int] = []
        self.header_fetches = 0
        self._resp = {}

    def select(self, mailbox, readonly=False):
        assert readonly
        self._resp = {"UIDVALIDITY": [str(self.uidvalidity).encode()],
                      "UIDNEXT": [str(max(self.messages, default=0) + 1).encode()]}
        return "OK", [b"5"]

    def response(self, code):
        return code, self._resp.get(code, [None])

    def uid(self, command, *args):
        if command == "SEARCH":
            crit = args[-1]
            uids = sorted(self.messages)
            if crit != "ALL":
                lo = int(crit.split()[1].split(":")[0])
                uids = [u for u in uids if u >= lo] or uids[-1:]
            return "OK", [" ".join(map(str, uids)).encode()]
        if command == "FETCH" and args[1] == "(UID INTERNALDATE)":
            return "OK", [f'{u} (UID {u} INTERNALDATE "{DATES.get(u, _now_date())}"'.encode()
                          if " " in DATES.get(u, " ") else
                          f'{u} (UID {u} INTERNALDATE "{DATES[u]} 10:00:00 +0000")'.encode()
                          for u in map(int, args[0].split(",")) if u in self.messages]
        if command == "FETCH":
            items = args[1]
            if "BODY.PEEK[HEADER]" in items:
                self.header_fetches += 1
                out = []
                for u in map(int, args[0].split(",")):
                    if u in self.messages:
                        head = self.messages[u].split(b"\n\n")[0] + b"\n\n"
                        meta = f'{u} (UID {u} INTERNALDATE "{DATES.get(u, "01-Jan-2026")} 10:00:00 +0000" BODY[HEADER]<0> {{{len(head)}}}'
                        out += [(meta.encode(), head), b")"]
                return "OK", out
            assert "BODY.PEEK[]" in items
            u = int(args[0])
            self.fetched_full.append(u)
            return "OK", [(f"1 (UID {u} BODY[]<0> {{10}}".encode(), self.messages[u]), b")"]
        raise AssertionError(command)

    def logout(self):
        pass


@pytest.fixture
def setup(make_analyzer, tmp_path):
    def _make(**cfg):
        msgs = {u: make_eml(subject=f"old {u}") for u in range(1, 6)}
        msgs[2] = make_eml(frm="Bank <billing@mybank.com>")      # settled by the never-trash list
        conn = OldMailIMAP(msgs)
        fc = FakeClassifier("spam", 0.99)
        an = make_analyzer(fc, **cfg)
        an.cfg.db_path = str(tmp_path / "data" / "analyzer.db")
        (tmp_path / "data").mkdir(exist_ok=True)
        an.cfg.health_file = str(tmp_path / "data" / "health.json")
        an.cfg.portal_dir = str(tmp_path / "portal")
        runner = ShadowRunner(an.cfg, an, connect_fn=lambda c: conn, sleep=lambda s: None, clock=lambda: NOW)
        runner.run_once()            # first poll: go-live at UID 5, nothing analyzed
        return runner, an, conn, fc, tmp_path / "data"
    return _make


def ask(data_dir, **req):
    req.setdefault("id", bf.new_id())
    bf.write_request(str(data_dir), req)
    return req["id"]


def status(data_dir):
    return json.loads((data_dir / bf.STATUS_FILE).read_text())


def test_nothing_old_is_touched_without_a_request(setup):
    runner, an, conn, fc, data = setup()
    for _ in range(3):
        runner.run_once()
    assert conn.header_fetches == 0 and not conn.fetched_full and not fc.calls


def test_estimate_then_confirmed_run(setup):
    runner, an, conn, fc, data = setup()
    eid = ask(data, action="estimate", since="2026-03-01")
    runner.run_once()
    job = status(data)
    assert job["status"] == "estimated" and job["id"] == eid
    assert job["selected"] == 4 and job["settled_by_lists"] == 1 and job["est_calls"] == 3
    assert job["fits_budget"] and job["est_usd"] > 0 and not fc.calls
    assert not conn.fetched_full              # estimating reads headers only

    ask(data, action="start", estimate_id="wrong")
    runner.run_once()
    assert status(data)["status"] == "estimated" and "does not match" in status(data)["reason"]

    ask(data, action="start", estimate_id=eid)
    runner.run_once()
    job = status(data)
    assert job["status"] == "done" and job["processed"] == 4
    assert conn.fetched_full == [5, 4, 3, 2]  # newest first, UID 1 is before --since
    assert job["model_calls"] == len(fc.calls) == 3
    keys = [r["message_key"] for r in an.store.db.execute("SELECT message_key FROM decisions")]
    assert sorted(keys) == ["INBOX:7:2", "INBOX:7:3", "INBOX:7:4", "INBOX:7:5"]


def test_limit_and_nothing_analyzed_twice(setup):
    runner, an, conn, fc, data = setup()
    eid = ask(data, action="estimate", limit=2)
    runner.run_once()
    assert status(data)["selected"] == 2
    ask(data, action="start", estimate_id=eid)
    runner.run_once()
    eid = ask(data, action="estimate")
    runner.run_once()
    assert status(data)["selected"] == 3      # 5 and 4 are already in the log


def test_over_budget_needs_allow_partial_and_keeps_a_reserve(setup):
    runner, an, conn, fc, data = setup(monthly_budget_usd=0.00005)
    eid = ask(data, action="estimate")
    runner.run_once()
    assert not status(data)["fits_budget"]
    ask(data, action="start", estimate_id=eid)
    runner.run_once()
    assert status(data)["status"] == "estimated" and "allow_partial" in status(data)["reason"]
    ask(data, action="start", estimate_id=eid, allow_partial=True)
    runner.run_once()
    job = status(data)
    assert job["status"] == "running" and "carries on from" in job["reason"]
    assert an.store.spend_this_month() <= 0.00005 * 0.9 + 2e-5   # stops at the reserve


def test_rate_limit_keeps_room_for_new_mail(setup):
    runner, an, conn, fc, data = setup(max_per_hour=4)
    eid = ask(data, action="estimate")
    runner.run_once()
    ask(data, action="start", estimate_id=eid)
    runner.run_once()
    job = status(data)
    assert job["status"] == "running" and job["model_calls"] == 3 and "hourly" in job["reason"]


def test_pause_resume_cancel_and_kill_switch(setup, tmp_path):
    runner, an, conn, fc, data = setup()
    eid = ask(data, action="estimate")
    runner.run_once()
    ask(data, action="start", estimate_id=eid)
    ask(data, action="pause")
    runner.run_once()                         # both handled before any work
    assert status(data)["status"] == "paused" and not conn.fetched_full
    (tmp_path / "PAUSE").touch()
    ask(data, action="resume")
    runner.run_once()
    assert status(data)["status"] == "running" and not conn.fetched_full
    (tmp_path / "PAUSE").unlink()
    ask(data, action="cancel")
    runner.run_once()
    assert status(data)["status"] == "cancelled" and not conn.fetched_full


def test_portal_request_file_is_read_once(setup, tmp_path):
    runner, an, conn, fc, data = setup()
    portal = tmp_path / "portal"
    portal.mkdir()
    (portal / bf.PORTAL_REQUEST).write_text(json.dumps({"id": "p1", "action": "estimate", "limit": 1}))
    runner.run_once()
    assert status(data)["id"] == "p1" and status(data)["status"] == "estimated"
    first = status(data)["estimated_at"]
    runner.run_once()
    assert status(data)["estimated_at"] == first   # the same id is not handled again
    an.store.set_state(bf.HANDLED_KEY, "[]")       # even once it has aged out of the recent list
    runner.run_once()
    assert status(data)["estimated_at"] == first


@pytest.mark.parametrize("req", [
    {"id": "x", "action": "delete"},
    {"id": "../x", "action": "estimate"},
    {"id": "x", "action": "estimate", "since": "yesterday"},
    {"id": "x", "action": "estimate", "limit": 0},
    {"id": "x", "action": "estimate", "folder": "Sent"},
    {"id": "x", "action": "start"},
    {"id": "x", "action": "estimate", "since": "2026-05-01", "until": "2026-01-01"},
])
def test_bad_requests_are_refused(req):
    with pytest.raises(bf.BadRequest):
        bf.validate(req)


def test_symlinked_request_is_ignored(tmp_path):
    target = tmp_path / "secret"
    target.write_text('{"id": "x", "action": "estimate"}')
    (tmp_path / "req.json").symlink_to(target)
    assert bf.read_request_file(tmp_path / "req.json") is None


def test_status_text(setup):
    runner, an, conn, fc, data = setup()
    eid = ask(data, action="estimate")
    runner.run_once()
    text = "\n".join(bf.status_lines(status(data)))
    assert "Estimated 4 model calls" in text and f"analyzer backfill start {eid}" in text
    assert len(eid) == 6


def test_hints_use_the_host_command(setup, monkeypatch):
    monkeypatch.setenv("BRIDGEKEEP_CLI", "./bridgekeep")
    runner, an, conn, fc, data = setup(monthly_budget_usd=0.0003)
    eid = ask(data, action="estimate")
    runner.run_once()
    text = "\n".join(bf.status_lines(status(data)))
    assert f"./bridgekeep backfill start {eid} --allow-partial" in text
    assert "About 1 of the 4 calls fit" in text and "carries on from" in text
    assert bf._duration(125) == "5 days (125 hours)" and bf._duration(3) == "3 hours"


def test_a_vendor_change_stops_the_backfill(setup):
    """Older mail goes only to the vendor the estimate named (security review)."""
    runner, an, conn, fc, data = setup(max_per_hour=4)
    eid = ask(data, action="estimate")
    runner.run_once()
    assert status(data)["provider"] == "anthropic"
    ask(data, action="start", estimate_id=eid)
    runner.run_once()
    assert status(data)["status"] == "running"          # waiting on the hourly cap
    calls = len(fc.calls)
    an.cfg.provider = "openai"                           # switched on the host meanwhile
    runner.run_once()
    job = status(data)
    assert job["status"] == "paused" and job["reason"] == bf.VENDOR_CHANGED
    assert len(fc.calls) == calls
    ask(data, action="resume")
    runner.run_once()
    assert status(data)["status"] == "paused" and status(data)["reason"] == bf.VENDOR_CHANGED
    assert len(fc.calls) == calls
    # A new estimate names the new vendor and can run.
    eid = ask(data, action="estimate")
    runner.run_once()
    assert status(data)["provider"] == "openai"


def test_an_estimate_for_another_vendor_cannot_start(setup):
    runner, an, conn, fc, data = setup()
    eid = ask(data, action="estimate")
    runner.run_once()
    an.cfg.provider = "gemini"
    ask(data, action="start", estimate_id=eid)
    runner.run_once()
    assert status(data)["status"] == "estimated" and status(data)["reason"] == bf.VENDOR_CHANGED
    assert not fc.calls
