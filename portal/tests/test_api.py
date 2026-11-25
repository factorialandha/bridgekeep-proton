"""The JSON API for the React pages: same rules as the HTML pages."""
import http.client
import json
import os

import pytest
import yaml
from conftest import PASSWORD, next_code


def call(portal, c, method, path, body=None, csrf=None, origin=True, ctype="application/json"):
    conn = http.client.HTTPConnection("127.0.0.1", portal.port, timeout=10)
    h = {"Host": f"localhost:{portal.port}", "Accept": "application/json"}
    if c.cookie:
        h["Cookie"] = c.cookie
    data = None
    if method == "POST":
        if csrf is None:
            csrf = session(portal, c).get("csrf", "")
        h["X-CSRF-Token"] = csrf
        h["Content-Type"] = ctype
        if origin:
            h["Origin"] = f"http://localhost:{portal.port}"
        data = body if isinstance(body, (str, bytes)) else json.dumps(body or {})
    conn.request(method, path, body=data, headers=h)
    r = conn.getresponse()
    raw = r.read().decode()
    assert r.getheader("Content-Type", "").startswith("application/json"), (path, raw[:200])
    r.data = json.loads(raw)
    return r


def session(portal, c):
    return call(portal, c, "GET", "/api/session").data


def get(portal, c, path):
    return call(portal, c, "GET", path)


def post(portal, c, path, body=None, **kw):
    return call(portal, c, "POST", path, body, **kw)


def expire_step_up(portal):
    portal.db.execute("UPDATE sessions SET reauth_at = 0")


def test_session_and_signed_out(portal, claimed):
    _, c = claimed
    s = session(portal, c)
    assert s["signed_in"] is True and len(s["csrf"]) > 10 and s["mode"] == "shadow" and s["totp_on"] is True
    assert set(s["versions"]) == {"bridgekeep", "commit", "portal", "portal_commit", "portal_stale", "bridge"} \
        and s["versions"]["portal"]
    from conftest import Client
    stranger = Client(portal.port)
    assert session(portal, stranger) == {"signed_in": False, "csrf": "", "product": s["product"]}
    for path in ("/api/status", "/api/review", "/api/analyzer", "/api/log", "/api/lists"):
        r = get(portal, stranger, path)
        assert r.status == 401 and r.data["signed_out"] is True, path
    assert get(portal, c, "/api/nope").status == 404


def test_posts_need_json_csrf_header_and_origin(portal, claimed):
    _, c = claimed
    assert post(portal, c, "/api/analyzer/pause", {}, csrf="wrong").status == 403
    assert post(portal, c, "/api/analyzer/pause", {}, origin=False).status == 403
    assert post(portal, c, "/api/analyzer/pause", {}).status == 200
    assert os.path.exists(portal.tmp / "pc" / "PAUSE")
    # A form post can't reach the API, and JSON can't reach a page.
    conn = http.client.HTTPConnection("127.0.0.1", portal.port, timeout=10)
    conn.request("POST", "/api/analyzer/pause", body="csrf=x", headers={
        "Host": f"localhost:{portal.port}", "Cookie": c.cookie, "Origin": f"http://localhost:{portal.port}",
        "Content-Type": "application/x-www-form-urlencoded"})
    assert conn.getresponse().status == 415
    for bad in ("[1]", "{", '{"x": NaN}', '{"x": ' + "[" * 30000 + "]" * 30000 + "}"):
        assert post(portal, c, "/api/analyzer/pause", bad).status == 400, bad


def test_step_up_and_reauth(portal, claimed):
    _, c = claimed
    expire_step_up(portal)
    r = post(portal, c, "/api/analyzer/resume")
    assert r.status == 401 and r.data["step_up"] is True
    r = post(portal, c, "/api/reauth", {"password": "wrong", "code": "000000"})
    assert r.status == 401 and r.data["error"] == "The password or the code is wrong."
    code, c.step = next_code(c.secret, c.step)
    assert post(portal, c, "/api/reauth", {"password": PASSWORD, "code": code}).data == {"ok": True}
    assert post(portal, c, "/api/analyzer/resume").status == 200
    actions = [a[0] for a in portal.db.all("SELECT action FROM audit")]
    assert "re-authentication failed" in actions and "re-authenticated" in actions and "analyzer resumed" in actions
    for _ in range(12):
        r = post(portal, c, "/api/reauth", {"password": "wrong", "code": "1"})
    assert r.status == 429 and "Wait" in r.data["error"]


def test_status(portal, claimed):
    _, c = claimed
    (portal.tmp / "pc" / "PAUSE").write_text("x")
    d = get(portal, c, "/api/status").data
    assert d["summary"] == {"ok": False, "headline": "Bridge hasn't reported yet"}
    assert {"level": "todo", "text": "The analyzer is paused", "action": "resume"} in d["needs"]
    assert set(d["glance"]) == {"bridge", "bridge_ok", "messages", "spend", "budget", "disk_free", "disk_used_pct"}
    assert [x["label"] for x in d["details"]] == ["Bridge", "Mail analyzer", "Storage", "This portal"]
    (portal.tmp / "status").mkdir(exist_ok=True)
    (portal.tmp / "status" / "bridge.env").write_text(
        "ts=9999999999\nbridge_health=healthy\nsigned_in=yes\naccount=me@proton.example\nmessages=48211\n"
        "update_scheduled=yes\nupdate_when=nightly at 03:41\n")
    d = get(portal, c, "/api/status").data
    assert d["summary"]["ok"] is True and d["glance"]["bridge"] == "Running" and d["glance"]["messages"] == 48211
    bridge = d["details"][0]["rows"]
    assert {"label": "Proton sign-in", "value": "Signed in as me@proton.example", "tone": "ok"} in bridge


@pytest.fixture
def logged(claimed, portal):
    import importlib.util
    import sys
    from pathlib import Path
    store = Path(__file__).resolve().parents[2] / "analyzer" / "src" / "analyzer" / "store.py"
    spec = importlib.util.spec_from_file_location("analyzer_store", store)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    st = mod.Store(str(portal.tmp / "analyzer" / "analyzer.db"))
    R = mod.Record
    ids = [st.add(R("k1", "shadow", "review", "review_band", "x", "news@shop.example", "shop.example",
                    "Sale <b>now</b>", "spam", 0.82, "Marketing")),
           st.add(R("k2", "shadow", "quarantine", "threshold", "y", "a@spam.example", "spam.example",
                    "WIN", "spam", 0.99, "Spam"))]
    return claimed[1], ids


def test_review_and_verdict(portal, logged):
    c, ids = logged
    items = get(portal, c, "/api/review").data["items"]
    assert len(items) == 1 and items[0]["id"] == ids[0] and items[0]["subject"] == "Sale <b>now</b>"
    assert items[0]["confidence"] == 0.82 and items[0]["when"] and isinstance(items[0]["ts"], int)
    assert post(portal, c, "/api/review/verdict", {"id": "1", "verdict": "keep"}).status == 400
    assert post(portal, c, "/api/review/verdict", {"id": 99999, "verdict": "keep"}).status == 404
    assert post(portal, c, "/api/review/verdict", {"id": ids[0], "verdict": "keep"}).data == {"ok": True}
    assert get(portal, c, "/api/review").data["items"] == []
    fb = (portal.tmp / "pc" / "feedback.jsonl").read_text()
    assert '"label": "legitimate"' in fb
    assert session(portal, c)["review_waiting"] == 0


def test_log(portal, logged):
    c, ids = logged
    d = get(portal, c, "/api/log").data
    assert [r["id"] for r in d["rows"]] == [ids[1], ids[0]]
    r = d["rows"][1]
    assert r["action"] == "review" and r["applied"] is False and r["moved_to"] is None and r["why"].startswith("AI: 82%")
    assert d["card"]["seen"] == 2 and d["older"] is None and {"key": "protected", "label": "Protected saves"} in d["filters"]
    assert [r["id"] for r in get(portal, c, "/api/log?action=quarantine").data["rows"]] == [ids[1]]


def test_analyzer_get_and_settings(portal, claimed):
    _, c = claimed
    d = get(portal, c, "/api/analyzer").data
    assert d["settings"]["thresholds.quarantine"] == 97 and d["settings"]["limits.max_moves_per_day"] == 200
    assert d["key"] == {"on": False, "last4": "", "pending": False, "when": None} and d["live_available"] is False
    new = {**d["settings"], "thresholds.quarantine": 95, "limits.max_per_day": 400}
    r = post(portal, c, "/api/analyzer/settings", {"settings": new})
    assert r.status == 200 and set(r.data["changed"]) == {"thresholds.quarantine", "limits.max_per_day"}
    saved = yaml.safe_load((portal.tmp / "pc" / "settings.yaml").read_text())
    assert saved["thresholds"]["quarantine"] == 0.95 and saved["limits"]["max_per_day"] == 400
    r = post(portal, c, "/api/analyzer/settings", {"settings": {**new, "thresholds.review": 99}})
    assert r.status == 400 and r.data["error"] == "Review has to be lower than Trash."
    for bad in ({**new, "limits.max_per_day": "400"}, {**new, "model.enabled": "yes"}, {**new, "imap.poll_seconds": 5}):
        assert post(portal, c, "/api/analyzer/settings", {"settings": bad}).status == 400
    expire_step_up(portal)
    assert post(portal, c, "/api/analyzer/settings", {"settings": new}).data["step_up"] is True


def test_mode_and_secret_is_never_echoed(portal, claimed):
    _, c = claimed
    assert post(portal, c, "/api/analyzer/mode", {"mode": "live", "confirm": True}).status == 409
    assert post(portal, c, "/api/analyzer/mode", {"mode": "LIVE"}).status == 400
    assert not (portal.tmp / "pc" / "mode.json").exists()
    assert post(portal, c, "/api/analyzer/mode", {"mode": "shadow"}).status == 200
    assert json.loads((portal.tmp / "pc" / "mode.json").read_text())["mode"] == "shadow"
    r = post(portal, c, "/api/secrets/set", {"name": "anthropic_api_key", "value": "sk-wrong-thing"})
    assert r.status == 400 and "sk-wrong" not in json.dumps(r.data)
    key = "sk-ant-" + "A" * 40
    assert post(portal, c, "/api/secrets/set", {"name": "anthropic_api_key", "value": key}).status == 200
    assert get(portal, c, "/api/analyzer").data["key"]["pending"] is True
    assert all(key not in str(row) for row in portal.db.all("SELECT * FROM audit"))
    assert post(portal, c, "/api/secrets/set", {"name": "nope", "value": "x"}).status == 400
    assert post(portal, c, "/api/secrets/remove", {"name": "nope"}).status == 400
    expire_step_up(portal)
    assert post(portal, c, "/api/secrets/remove", {"name": "discord_webhook"}).data["step_up"] is True


def test_lists(portal, claimed):
    _, c = claimed
    (portal.tmp / "lists").mkdir(exist_ok=True)
    (portal.tmp / "lists" / "curated.yaml").write_text("block:\n  - address: offers@spam.example\n    reason: Junk\n")
    d = get(portal, c, "/api/lists").data
    assert [x["key"] for x in d["lists"]] == ["protect", "block", "keywords"]
    block = d["lists"][1]
    assert block["label"] == "Always trash" and block["entries"][0]["source"] == "file"
    assert post(portal, c, "/api/lists/add", {"list": "protect", "value": "amazon.com", "reason": "Orders",
                                              "subdomains": True}).data["ok"] is True
    entry = get(portal, c, "/api/lists").data["lists"][0]["entries"][0]
    assert entry["kind"] == "domain" and entry["subdomains"] is True and entry["index"] == 0
    r = post(portal, c, "/api/lists/add", {"list": "block", "value": "spam.example"})
    assert r.status == 400 and "exact address" in r.data["error"]
    assert post(portal, c, "/api/lists/remove", {"list": "protect", "index": 0, "value": "wrong.com"}).status == 409
    assert post(portal, c, "/api/lists/remove", {"list": "protect", "index": 0, "value": "amazon.com"}).status == 200
    assert post(portal, c, "/api/lists/remove", {"list": "block", "value": "offers@spam.example",
                                                 "source": "file"}).status == 200
    d = get(portal, c, "/api/lists").data
    assert d["removed"] == [{"list": "block", "label": "Always trash", "value": "offers@spam.example"}]
    expire_step_up(portal)
    assert post(portal, c, "/api/lists/restore", {"list": "block", "value": "offers@spam.example"}).data["step_up"]
    assert post(portal, c, "/api/lists/add", {"list": "protect", "value": "x.com"}).data["step_up"]


def test_settings_password_totp_and_audit(portal, claimed):
    _, c = claimed
    d = get(portal, c, "/api/settings").data
    assert d["totp_on"] is True and "totp_secret" not in d and d["min_password"] == 12
    assert d["alerts"]["on"] is False and d["test_alert"] == {"pending": False, "result": ""}
    conn = http.client.HTTPConnection("127.0.0.1", portal.port, timeout=10)
    conn.request("GET", "/api/settings/totp.svg", headers={"Host": f"localhost:{portal.port}", "Cookie": c.cookie})
    assert conn.getresponse().status == 404             # already on
    assert post(portal, c, "/api/settings/password", {"password": "short", "confirm": "short"}).status == 400
    new = "another long passphrase here"
    assert post(portal, c, "/api/settings/password", {"password": new, "confirm": new}).data == {"ok": True}
    # Turning the authenticator off always asks for password and code.
    code, c.step = next_code(c.secret, c.step)
    r = post(portal, c, "/api/settings/totp/off", {"password": "nope", "code": code})
    assert r.status == 401
    code, c.step = next_code(c.secret, c.step)
    assert post(portal, c, "/api/settings/totp/off", {"password": new, "code": code}).data == {"ok": True}
    d = get(portal, c, "/api/settings").data
    assert d["totp_on"] is False and len(d["totp_secret"].replace(" ", "")) >= 16 and d["min_password"] == 15
    conn = http.client.HTTPConnection("127.0.0.1", portal.port, timeout=10)
    conn.request("GET", "/api/settings/totp.svg", headers={"Host": f"localhost:{portal.port}", "Cookie": c.cookie})
    r = conn.getresponse()
    assert r.status == 200 and r.getheader("Content-Type") == "image/svg+xml" and r.read().startswith(b"<svg")
    assert r.getheader("Cache-Control") == "no-store"
    assert post(portal, c, "/api/settings/totp/on", {"code": "000000"}).status == 400
    assert post(portal, c, "/api/alerts/test").status in (200, 400)
    rows = get(portal, c, "/api/audit").data["rows"]
    actions = [r["action"] for r in rows]
    assert "admin password changed" in actions and "authenticator turned off" in actions
    assert all(new not in json.dumps(r) for r in rows) and rows[0]["when"]


def test_log_entry_and_undo(portal, logged):
    c, ids = logged
    import sqlite3
    conn = sqlite3.connect(portal.tmp / "analyzer" / "analyzer.db")
    conn.execute("INSERT INTO unsubscribe VALUES (?,?,?,?,?,?)",
                 (ids[0], "one_click", "https://unsub.shop.example/u?t=secret", None, "unsub.shop.example", "shop.example"))
    conn.commit()
    conn.close()
    d = get(portal, c, f"/api/log/entry?id={ids[0]}").data
    row = d["row"]
    assert row["id"] == ids[0] and row["subject"] == "Sale <b>now</b>" and row["rule"] == "review_band"
    assert row["moved_to"] is None and row["injections"] == [] and row["full_when"] and d["verdict"] == ""
    assert d["unsub"] == {"method": "one_click", "host": "unsub.shop.example"}      # never the URL
    assert get(portal, c, "/api/log/entry?id=x").status == 400
    assert get(portal, c, "/api/log/entry?id=%C2%B2").status == 400
    assert get(portal, c, "/api/log/entry?id=99999").status == 404
    post(portal, c, "/api/review/verdict", {"id": ids[0], "verdict": "trash"})
    assert get(portal, c, f"/api/log/entry?id={ids[0]}").data["verdict"] == "trash"
    assert post(portal, c, "/api/review/verdict", {"id": ids[0], "verdict": "undo"}).data == {"ok": True}
    assert get(portal, c, f"/api/log/entry?id={ids[0]}").data["verdict"] == ""
    assert '"label": "withdrawn"' in (portal.tmp / "pc" / "feedback.jsonl").read_text()


def bf_job(portal, **kw):
    import time as _t
    data = {"id": "e1e1e1", "status": "estimated", "selected": 1200, "settled_by_lists": 200, "est_calls": 1000,
            "est_usd": 0.37, "budget_left_usd": 15.5, "budget_usd": 20, "est_hours": 12, "fits_budget": True,
            "calls_that_fit": 1000, "estimated_at": int(_t.time()), "since": "2026-01-01", "until": None,
            "provider": "anthropic"}
    data.update(kw)
    p = portal.tmp / "analyzer" / "backfill.json"
    p.write_text(json.dumps(data))
    later = _t.time() + 5
    os.utime(p, (later, later))


def bf_req(portal):
    p = portal.tmp / "pc" / "backfill-request.json"
    return json.loads(p.read_text()) if p.exists() else None


def test_backfill_api(portal, claimed):
    _, c = claimed
    d = get(portal, c, "/api/backfill").data
    assert d["job"] is None and d["disclosure"] == "" and d["provider"] == "anthropic"
    r = post(portal, c, "/api/backfill/estimate", {"since": "2026-13-01", "until": "", "limit": ""})
    assert r.status == 400 and bf_req(portal) is None
    assert post(portal, c, "/api/backfill/estimate", {"since": 5}).status == 400
    expire_step_up(portal)                              # estimating needs no step-up
    assert post(portal, c, "/api/backfill/estimate", {"since": "2026-01-01", "limit": "5,000"}).data == {"ok": True}
    rq = bf_req(portal)
    assert rq["action"] == "estimate" and rq["limit"] == 5000
    assert get(portal, c, "/api/backfill").data["pending"] is True
    assert post(portal, c, "/api/backfill/estimate", {}).status == 409
    bf_job(portal)
    d = get(portal, c, "/api/backfill").data
    assert d["job"]["id"] == "e1e1e1" and d["disclosure"].startswith("This sends 1,000 older messages to Anthropic's API")
    start = {"estimate_id": "e1e1e1", "provider": "anthropic", "allow_partial": False}
    assert post(portal, c, "/api/backfill/start", start).data["step_up"] is True and bf_req(portal)["id"] == rq["id"]
    code, c.step = next_code(c.secret, c.step)
    post(portal, c, "/api/reauth", {"password": PASSWORD, "code": code})
    assert post(portal, c, "/api/backfill/start", {**start, "estimate_id": "other"}).status == 409
    assert post(portal, c, "/api/backfill/start", {**start, "provider": "openai"}).status == 409
    assert post(portal, c, "/api/backfill/start", {**start, "allow_partial": "yes"}).status == 400
    assert post(portal, c, "/api/backfill/start", start).data == {"ok": True}
    assert bf_req(portal)["action"] == "start" and bf_req(portal)["estimate_id"] == "e1e1e1"
    bf_job(portal, status="running")
    assert post(portal, c, "/api/backfill/pause").data == {"ok": True} and bf_req(portal)["action"] == "pause"
    bf_job(portal, status="paused")
    assert post(portal, c, "/api/backfill/resume").data == {"ok": True}
    bf_job(portal, status="running")
    assert post(portal, c, "/api/backfill/cancel").data == {"ok": True} and bf_req(portal)["action"] == "cancel"
    actions = [a[0] for a in portal.db.all("SELECT action FROM audit")]
    for a in ("estimate requested", "backfill started", "backfill paused", "backfill resumed", "backfill cancelled"):
        assert f"older mail: {a}" in actions


def test_backfill_over_budget_needs_allow_partial(portal, claimed):
    _, c = claimed
    bf_job(portal, est_usd=40.0, fits_budget=False, calls_that_fit=380)
    start = {"estimate_id": "e1e1e1", "provider": "anthropic"}
    assert post(portal, c, "/api/backfill/start", start).status == 400
    assert post(portal, c, "/api/backfill/start", {**start, "allow_partial": True}).data == {"ok": True}
    assert bf_req(portal)["allow_partial"] is True


def test_backfill_resume_refused_after_a_vendor_change(portal, claimed):
    _, c = claimed
    bf_job(portal, status="paused", provider="openai")
    r = post(portal, c, "/api/backfill/resume")
    assert r.status == 409 and "start a new estimate" in r.data["error"] and bf_req(portal) is None
    bf_job(portal, status="paused", provider=None)      # not recorded: refused too
    assert post(portal, c, "/api/backfill/resume").status == 409
    bf_job(portal, status="paused")
    assert post(portal, c, "/api/backfill/resume").data == {"ok": True}
    # The HTML page refuses the same way.
    bf_job(portal, status="paused", provider="openai")
    c.get("/backfill")
    r = c.post("/backfill/resume")
    assert r.status == 409 and "start a new estimate" in r.body


def test_build_commit(tmp_path, monkeypatch):
    from portal import hoststatus
    pkg = tmp_path / "portal"
    pkg.mkdir()
    monkeypatch.setattr(hoststatus.resources, "files", lambda _name: pkg)
    assert hoststatus.build_commit() == ""                        # plain docker build: no file
    (pkg / "BUILD_COMMIT").write_text("")
    assert hoststatus.build_commit() == ""
    (pkg / "BUILD_COMMIT").write_text("c699e32c2d5f134d8aba29f6235159e6b0ba1979")
    assert hoststatus.build_commit() == "c699e32"
    (pkg / "BUILD_COMMIT").write_text("<b>nope</b>")
    assert hoststatus.build_commit() == ""


def write_health(portal, **kw):
    data = {"status": "ok", "ts": 9999999999, "mode": "shadow"}
    data.update(kw)
    (portal.tmp / "analyzer" / "health.json").write_text(json.dumps(data))


def test_going_live_needs_confirm_and_step_up(portal, claimed):
    _, c = claimed
    write_health(portal, mode_requested="shadow", move_cap=200, would_review=12, would_quarantine=30)
    d = get(portal, c, "/api/analyzer/live").data
    assert d["available"] is True and d["paused"] is False
    assert d["live"]["move_cap"] == 200 and d["live"]["would_quarantine"] == 30
    mode_json = portal.tmp / "pc" / "mode.json"
    for bad in ({"mode": "live"}, {"mode": "live", "confirm": "yes"}, {"mode": "live", "confirm": 1}):
        assert post(portal, c, "/api/analyzer/mode", bad).status == 400 and not mode_json.exists()
    assert post(portal, c, "/api/analyzer/mode", {"mode": "live", "confirm": True}).data == {"ok": True}
    assert json.loads(mode_json.read_text())["mode"] == "live"
    assert ("analyzer: live mode",) in [tuple(a) for a in portal.db.all("SELECT action FROM audit")]
    expire_step_up(portal)
    r = post(portal, c, "/api/analyzer/mode", {"mode": "live", "confirm": True})
    assert r.status == 401 and r.data["step_up"] is True
    assert post(portal, c, "/api/analyzer/mode", {"mode": "shadow"}).status == 200      # no step-up
    assert json.loads(mode_json.read_text())["mode"] == "shadow"


def drop_files(portal):
    d = portal.tmp / "req"
    return sorted(p.name for p in d.iterdir()) if d.exists() else []


def test_vendor_api_reviews_switches_and_never_echoes_the_key(portal, claimed):
    from portal import vendors
    _, c = claimed
    write_health(portal, provider="anthropic", model_name="claude-haiku-5-5")
    d = get(portal, c, "/api/analyzer/vendor").data
    assert d["current"] == {"provider": "anthropic", "label": "Anthropic (Claude)", "model": "claude-haiku-5-5"}
    assert set(d["vendors"]) == set(vendors.VENDORS) and d["vendors"]["openai"]["key_placeholder"] == "sk-…"
    assert d["vendors"]["openai"]["needs_price"] is True and d["vendors"]["anthropic"]["needs_price"] is False
    assert d["state"]["pending"] is False and d["no_price"] is False and "drop_writable" in d
    r = post(portal, c, "/api/analyzer/vendor/review", {"provider": "openai", "model": "gpt-5-mini"})
    assert r.status == 400 and "prices" in r.data["error"]
    r = post(portal, c, "/api/analyzer/vendor/review", {"provider": "openai", "model": ["x"], "price_in": 1})
    assert r.status == 400
    fields = {"provider": "openai", "model": "gpt-5-mini", "price_in": "0.25", "price_out": "2"}
    r = post(portal, c, "/api/analyzer/vendor/review", fields)
    assert r.status == 200 and r.data["disclosure"] == vendors.DISCLOSURE["openai"]
    assert r.data["fields"] == {**fields, "endpoint": ""} and r.data["current_provider"] == "anthropic"
    assert r.data["label"] == "OpenAI" and drop_files(portal) == []
    r = post(portal, c, "/api/analyzer/vendor", {**fields, "key": "AIzaWrongVendor"})
    assert r.status == 400 and "OpenAI API key" in r.data["error"] and "AIzaWrong" not in json.dumps(r.data)
    assert post(portal, c, "/api/analyzer/vendor", {**fields, "key": 12345}).status == 400 and drop_files(portal) == []
    key = "sk-" + "B" * 40
    assert post(portal, c, "/api/analyzer/vendor", {**fields, "key": key}).data == {"ok": True}
    files = drop_files(portal)
    assert len(files) == 1 and files[0].startswith("ai_vendor.")
    assert f"value={key}" in (portal.tmp / "req" / files[0]).read_text().splitlines()
    d = get(portal, c, "/api/analyzer/vendor").data
    assert d["state"]["pending"] is True and key not in json.dumps(d)
    assert all(key not in str(row) for row in portal.db.all("SELECT * FROM audit"))
    assert ("AI vendor: change requested", "openai gpt-5-mini") in [
        tuple(a) for a in portal.db.all("SELECT action, target FROM audit")]
    expire_step_up(portal)
    for path in ("/api/analyzer/vendor/review", "/api/analyzer/vendor"):
        assert post(portal, c, path, fields).data["step_up"] is True


def test_vendor_refusal_is_shown_without_its_prefix(portal, claimed):
    _, c = claimed
    status = portal.tmp / "status"
    status.mkdir(exist_ok=True)
    st = status / "secrets.env"
    st.write_text("ai_vendor_provider=openai\nai_vendor_result=refused: no price for that model\nai_vendor_when=5\n")
    d = get(portal, c, "/api/analyzer/vendor").data
    assert d["state"]["result"] == "no price for that model" and d["state"]["when"] == 5


def test_unsaved_settings_show_what_the_analyzer_enforces(portal, claimed):
    _, c = claimed
    write_health(portal, budget_usd=5.0, spend_month_usd=1.25)
    d = get(portal, c, "/api/analyzer").data
    # Nothing saved yet: the analyzer uses analyzer.yaml's $5, not the portal's $20 default.
    assert d["settings"]["model.monthly_budget_usd"] == 5 and "model.monthly_budget_usd" in d["unsaved"]
    assert set(d["unsaved"]) == set(d["defaults"])
    new = {**d["settings"], "model.monthly_budget_usd": 25}
    assert post(portal, c, "/api/analyzer/settings", {"settings": new}).status == 200
    d = get(portal, c, "/api/analyzer").data
    assert d["unsaved"] == [] and d["settings"]["model.monthly_budget_usd"] == 25   # saved wins over health
    write_health(portal, budget_usd=99999)
    (portal.tmp / "pc" / "settings.yaml").unlink()
    assert get(portal, c, "/api/analyzer").data["settings"]["model.monthly_budget_usd"] == 20   # out of range: default
