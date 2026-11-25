"""The Status page: what the host reports, the analyzer, storage."""

import json
import time

from portal import hoststatus


def _write(d, name, **kv):
    d.mkdir(exist_ok=True)
    (d / name).write_text("".join(f"{k}={v}\n" for k, v in kv.items()))


def test_read_env_is_strict(tmp_path):
    p = tmp_path / "x.env"
    p.write_text("good=1\nBad=2\n=3\nnoequals\nlong=" + "a" * 500 + "\nctl=a\x1bb\n")
    d = hoststatus.read_env(p)
    assert d["good"] == "1" and "Bad" not in d and len(d["long"]) == 200 and d["ctl"] == "ab"
    (tmp_path / "link.env").symlink_to(p)
    assert hoststatus.read_env(tmp_path / "link.env") is None
    p.write_text("a=" + "x" * 9000)
    assert hoststatus.read_env(p) is None
    assert hoststatus.read_env(tmp_path / "missing.env") is None


def test_sizes_are_decimal_one_place():
    assert hoststatus.size(1_234_567_890) == "1.2 GB"
    assert hoststatus.size(999) == "999 B"
    assert hoststatus.size(None) == "unknown"


def test_load(tmp_path):
    now = time.time()
    _write(tmp_path, "storage.env", bridge_bytes=2_500_000_000, analyzer_bytes=4_000_000, portal_bytes=0,
           images_bytes=900_000_000, disk_path="/", disk_free_bytes=3_000_000_000,
           disk_total_bytes=64_000_000_000, low="no", ts=int(now))
    _write(tmp_path, "host.env", docker_version="26.1.5", ts=int(now))
    h = hoststatus.load(str(tmp_path), now)
    labels = [r[0] for r in h["storage"]["rows"]]
    assert labels == ["Mail (Bridge)", "Analyzer", "Images"]       # Portal hidden at 0
    assert h["storage"]["low"]                                       # under 5 GB free
    assert h["docker"]["old"] and "bridge" not in h


def _claimed_page(claimed, **files):
    portal, c = claimed
    d = portal.tmp / "status"
    portal.settings.host_status = str(d)
    for name, kv in files.items():
        _write(d, name.replace("_", ".", 1) if name.endswith("_env") else name, **kv)
    return portal, c


def test_status_page_shows_host_report(claimed):
    now = int(time.time())
    portal, c = _claimed_page(claimed)
    d = portal.tmp / "status"
    _write(d, "bridge.env", bridge_health="healthy", signed_in="yes", account="me@proton.example",
           messages=12345, update_scheduled="yes", update_when="nightly at 03:41",
           update_waiting_version="3.21.2", last_update_line="<b>built</b> 3.21.2", ts=now)
    _write(d, "storage.env", bridge_bytes=2_500_000_000, analyzer_bytes=1, images_bytes=1, disk_path="/",
           disk_free_bytes=50_000_000_000, disk_total_bytes=64_000_000_000, low="no", ts=now)
    body = c.get("/").body
    assert "✓ Running" in body and "me@proton.example" in body and "12,345 messages" in body
    assert "Update ready" in body and "./bridgekeep deploy-update" in body
    assert "&lt;b&gt;built&lt;/b&gt;" in body and "<b>built" not in body
    assert "2.5 GB" in body and "50.0 GB free of 64.0 GB" in body and "✗ Low" not in body


def test_status_page_before_the_host_reports(claimed):
    portal, c = _claimed_page(claimed)
    body = c.get("/").body
    assert body.count("Not reported yet") == 2


def test_status_page_shows_mail_summary_and_spend(claimed):
    portal, c = claimed
    a = portal.tmp / "analyzer"
    (a / "health.json").write_text(json.dumps({"status": "ok", "ts": time.time(), "mode": "shadow",
                                                "model": "on", "spend_month_usd": 1.234, "budget_usd": 20}))
    body = c.get("/").body
    assert "$1.23 of $20 this month" in body


def test_status_page_bridge_paused(claimed):
    portal, c = _claimed_page(claimed)
    _write(portal.tmp / "status", "bridge.env", bridge_health="paused", signed_in="no",
           paused="bridge analyzer <x>", ts=int(time.time()))
    body = c.get("/").body
    assert "Stopped on purpose: bridge, analyzer." in body and "&lt;x" not in body
    assert "Paused" in body and "./bridgekeep start" in body and "✗ Paused" not in body
