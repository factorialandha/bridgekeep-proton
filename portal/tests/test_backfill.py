"""Older mail: estimate first, confirm with security's wording, then start."""
import json
import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def req_file(portal):
    p = portal.tmp / "pc" / "backfill-request.json"
    return json.loads(p.read_text()) if p.exists() else None


def job(portal, **kw):
    """Write the analyzer's backfill.json, newer than any request."""
    data = {"id": "e1e1e1", "status": "estimated", "selected": 1200, "settled_by_lists": 200, "est_calls": 1000,
            "est_usd": 0.37, "budget_left_usd": 15.5, "budget_usd": 20, "est_hours": 12, "fits_budget": True,
            "calls_that_fit": 1000, "estimated_at": int(time.time()), "since": "2026-01-01", "until": None,
            "limit": None, "processed": 0, "model_calls": 0, "spend_usd": 0.0, "reason": "", "scanned": 1200}
    data.update(kw)
    p = portal.tmp / "analyzer" / "backfill.json"
    p.write_text(json.dumps(data))
    later = time.time() + 5
    os.utime(p, (later, later))


def test_estimate_is_requested_without_step_up_and_nothing_sent(claimed):
    portal, c = claimed
    body = c.get("/backfill").body
    assert "Estimate the cost" in body and 'action="/backfill/start"' not in body
    r = c.post("/backfill/estimate", {"since": "2026-13-01"})
    assert r.status == 400 and req_file(portal) is None
    r = c.post("/backfill/estimate", {"since": "2026-03-01", "until": "2026-02-01"})
    assert r.status == 400 and req_file(portal) is None
    portal.db.execute("UPDATE sessions SET reauth_at = 0")      # estimating needs no step-up
    c.get("/backfill")
    r = c.post("/backfill/estimate", {"since": "2026-01-01", "limit": "5,000"})
    assert r.status == 303
    rq = req_file(portal)
    assert rq["action"] == "estimate" and rq["since"] == "2026-01-01" and rq["limit"] == 5000 and "until" not in rq
    assert "Waiting for the analyzer" in c.get("/backfill").body
    r = c.post("/backfill/estimate", {})
    assert r.status == 409 and req_file(portal)["id"] == rq["id"]
    assert ("older mail: estimate requested", rq["id"]) in [
        tuple(a) for a in portal.db.all("SELECT action, target FROM audit")]


def test_confirm_shows_securitys_wording_and_start_needs_step_up(claimed):
    portal, c = claimed
    job(portal)
    body = c.get("/backfill").body
    assert ("This sends 1,000 older messages to Anthropic&#39;s API (Claude), one at a time: sender name and address, "
            "subject, link domains, attachment types and the first 3,000 characters of each body. Of the 1,200 in "
            "range, 200 are settled by your lists and not sent. Nothing is moved or deleted (log-only).") in body
    assert "2026-01-01 to setup" in body and "$0.37" in body
    # Not without step-up, and not for another estimate.
    assert c.post("/backfill/start", {"estimate_id": "other"}).status == 409 and req_file(portal) is None
    portal.db.execute("UPDATE sessions SET reauth_at = 0")
    c.get("/backfill")
    assert c.post("/backfill/start", {"estimate_id": "e1e1e1"}).status == 401 and req_file(portal) is None


def test_start_writes_a_request_the_analyzer_accepts(claimed):
    portal, c = claimed
    job(portal)
    c.get("/backfill")
    assert c.post("/backfill/start", {"estimate_id": "e1e1e1", "provider": "anthropic"}).status == 303
    rq = req_file(portal)
    assert rq["action"] == "start" and rq["estimate_id"] == "e1e1e1" and rq["allow_partial"] is False
    assert rq["id"] != "e1e1e1"
    sys.path.insert(0, str(ROOT / "analyzer" / "src"))
    try:
        bf = pytest.importorskip("analyzer.backfill")
        assert bf.validate(rq) == rq
    finally:
        sys.path.remove(str(ROOT / "analyzer" / "src"))


def test_over_budget_needs_the_partial_checkbox(claimed):
    portal, c = claimed
    job(portal, est_usd=40.0, fits_budget=False, calls_that_fit=380)
    body = c.get("/backfill").body
    assert "About 380 of the 1,000 messages fit" in body
    assert c.post("/backfill/start", {"estimate_id": "e1e1e1", "provider": "anthropic"}).status == 400 and req_file(portal) is None
    c.get("/backfill")
    assert c.post("/backfill/start", {"estimate_id": "e1e1e1", "allow_partial": "yes", "provider": "anthropic"}).status == 303
    assert req_file(portal)["allow_partial"] is True


def test_stale_estimate_cannot_start(claimed):
    portal, c = claimed
    job(portal, estimated_at=int(time.time()) - 2 * 86400)
    body = c.get("/backfill").body
    assert "more than a day old" in body and 'action="/backfill/start"' not in body
    assert c.post("/backfill/start", {"estimate_id": "e1e1e1"}).status == 409 and req_file(portal) is None


def test_running_pause_resume_cancel(claimed):
    portal, c = claimed
    job(portal, status="running", processed=300, model_calls=250, spend_usd=0.09,
        reason="waiting: hourly limit (keeping room for new mail)")
    body = c.get("/backfill").body
    assert "300 of 1,200 messages" in body and "Waiting: hourly limit" in body and "Pause" in body
    assert c.post("/backfill/pause").status == 303 and req_file(portal)["action"] == "pause"
    job(portal, status="paused")
    portal.db.execute("UPDATE sessions SET reauth_at = 0")
    c.get("/backfill")
    assert c.post("/backfill/resume").status == 401 and req_file(portal)["action"] == "pause"
    assert c.post("/backfill/cancel").status == 303 and req_file(portal)["action"] == "cancel"


def test_other_vendor_is_named_and_junk_status_is_ignored(claimed):
    portal, c = claimed
    (portal.tmp / "analyzer" / "health.json").write_text(
        '{"status": "ok", "ts": 9999999999, "provider": "local", "model_name": "llama3"}')
    job(portal)
    assert "1,000 older messages to your own server" in c.get("/backfill").body
    (portal.tmp / "analyzer" / "backfill.json").write_text('{"status": "<script>", "id": "x"}')
    assert "Estimate the cost" in c.get("/backfill").body


def test_start_refused_when_the_vendor_changed_after_the_disclosure(claimed):
    portal, c = claimed
    job(portal)
    assert 'name="provider" value="anthropic"' in c.get("/backfill").body
    (portal.tmp / "analyzer" / "health.json").write_text(
        '{"status": "ok", "ts": 9999999999, "provider": "openai", "model_name": "gpt-5-mini"}')
    r = c.post("/backfill/start", {"estimate_id": "e1e1e1", "provider": "anthropic"})
    assert r.status == 409 and "AI vendor changed" in r.body and req_file(portal) is None


def test_backfill_json_link_or_oversize_is_ignored(claimed, tmp_path):
    portal, c = claimed
    p = portal.tmp / "analyzer" / "backfill.json"
    big = tmp_path / "big.json"
    big.write_text('{"status": "running", "id": "x", "pad": "' + "a" * 70000 + '"}')
    p.symlink_to(big)
    assert "Estimate the cost" in c.get("/backfill").body
    p.unlink()
    p.write_bytes(big.read_bytes())
    assert "Estimate the cost" in c.get("/backfill").body and "Running" not in c.get("/backfill").body


def test_small_jobs_refresh_and_rules_only_notes(claimed):
    portal, c = claimed
    job(portal, est_hours=0)
    body = c.get("/backfill").body
    assert "Under an hour" in body and 'http-equiv="refresh"' not in body
    job(portal, status="estimating")
    assert 'http-equiv="refresh" content="30"' in c.get("/backfill").body
    (portal.tmp / "analyzer" / "backfill.json").unlink()
    (portal.tmp / "analyzer" / "health.json").write_text(
        '{"status": "ok", "ts": 9999999999, "provider": "gemini", "model": "no_price"}')
    assert 'href="/analyzer/vendor">Add prices' in c.get("/backfill").body
