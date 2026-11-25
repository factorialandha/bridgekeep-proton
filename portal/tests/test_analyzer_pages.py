"""Review and Log pages against a decision log written by the analyzer's own Store."""
import json
import importlib.util
import sqlite3
from pathlib import Path

import pytest

from conftest import Client

STORE = Path(__file__).resolve().parents[2] / "analyzer" / "src" / "analyzer" / "store.py"


@pytest.fixture
def store_mod():
    if not STORE.exists():
        pytest.skip("analyzer source not next to the portal")
    spec = importlib.util.spec_from_file_location("analyzer_store", STORE)
    mod = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[spec.name] = mod   # dataclasses look their module up here
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def log(claimed, store_mod):
    portal, c = claimed
    st = store_mod.Store(str(portal.tmp / "analyzer" / "analyzer.db"))
    R = store_mod.Record
    ids = {
        "spam": st.add(R("k1", "shadow", "quarantine", "threshold", "Model: spam 0.99, at or above 0.97.",
                         "offers@spam.example", "spam.example", "WIN NOW", "spam", 0.99, "Obvious spam")),
        "review": st.add(R("k2", "shadow", "review", "review_band", "Model: spam 0.82, in the review band.",
                           "news@shop.example", "shop.example", "<script>alert('x')</script> sale", "spam", 0.82,
                           "<img src=x onerror=alert(1)>", injections=["ignore previous instructions"])),
        "keep": st.add(R("k3", "shadow", "keep", "protected_verified", "Protected sender (Bank), DMARC verified.",
                         "billing@bank.example", "bank.example", "Your statement", verified=True)),
    }
    return portal, c, ids


def test_log_lists_and_filters(log):
    portal, c, ids = log
    r = c.get("/log")
    assert r.status == 200
    assert "offers@spam.example" in r.body and "billing@bank.example" in r.body
    assert "Would trash" in r.body
    assert "<script>alert" not in r.body and "&lt;script&gt;" in r.body
    r = c.get("/log?action=keep")
    assert "billing@bank.example" in r.body and "offers@spam.example" not in r.body
    r = c.get("/log?q=SHOP")
    assert "news@shop.example" in r.body and "offers@spam.example" not in r.body
    r = c.get("/log?flag=protected")
    assert "billing@bank.example" in r.body and "news@shop.example" not in r.body
    r = c.get("/log?flag=injection")
    assert "news@shop.example" in r.body and "billing@bank.example" not in r.body
    r = c.get("/log?q=%25")  # a literal % matches nothing, not everything
    assert "Nothing matches" in r.body


def test_log_entry_escapes_model_reason(log):
    portal, c, ids = log
    r = c.get(f"/log/entry?id={ids['review']}")
    assert r.status == 200
    assert "<img src=x" not in r.body and "&lt;img src=x onerror=alert(1)&gt;" in r.body
    assert "ignore previous instructions" in r.body
    assert c.get("/log/entry?id=999").status == 404
    assert c.get("/log/entry?id=abc").status == 303


def test_review_verdict_is_recorded_and_undoable(log):
    portal, c, ids = log
    r = c.get("/review")
    assert "news@shop.example" in r.body and "offers@spam.example" not in r.body
    r = c.post("/review/verdict", {"id": str(ids["review"]), "verdict": "keep"})
    assert r.status == 303
    assert portal.db.one("SELECT verdict FROM feedback WHERE message_key = 'k2'")[0] == "keep"
    r = c.get("/review?done=keep")
    assert "Nothing waiting" in r.body and "You: not spam" in r.body
    c.post("/review/verdict", {"id": str(ids["review"]), "verdict": "undo"})
    assert portal.db.one("SELECT COUNT(*) FROM feedback")[0] == 0
    c.get("/review")   # a page with a form token, as a browser would have
    assert c.post("/review/verdict", {"id": str(ids["review"]), "verdict": "delete-all"}).status == 303
    assert portal.db.one("SELECT COUNT(*) FROM feedback")[0] == 0
    actions = [a[0] for a in portal.db.all("SELECT action FROM audit")]
    assert "review: keep" in actions and "review: undo" in actions


def test_portal_never_writes_the_analyzer_db(log):
    portal, c, ids = log
    db = portal.tmp / "analyzer" / "analyzer.db"
    before = db.read_bytes()
    c.get("/log")
    c.get("/review")
    c.post("/review/verdict", {"id": str(ids["review"]), "verdict": "trash"})
    assert db.read_bytes() == before


def test_unknown_schema_is_refused(log):
    portal, c, ids = log
    conn = sqlite3.connect(portal.tmp / "analyzer" / "analyzer.db")
    conn.execute("UPDATE state SET value = '2' WHERE key = 'schema_version'")
    conn.commit()
    conn.close()
    r = c.get("/log")
    assert "different version" in r.body and "offers@spam.example" not in r.body


def test_missing_log_says_not_set_up(claimed):
    portal, c = claimed
    assert "hasn't written a decision log" in c.get("/log").body
    assert "hasn't written a decision log" in c.get("/review").body


def test_analyzer_pages_need_sign_in(log):
    portal, c, ids = log
    anon = Client(portal.port)
    for p in ("/log", "/review", f"/log/entry?id={ids['spam']}"):
        assert anon.get(p).getheader("Location") == "/login"


def test_status_summarises_the_last_14_days(log):
    portal, c, _ = log
    (portal.tmp / "analyzer" / "health.json").write_text('{"status": "ok", "ts": 9999999999, "mode": "shadow"}')
    body = c.get("/").body
    assert "3 messages checked: 1 would go to trash, 1 for you to review, 1 protected senders kept" in body


def test_verdict_id_cannot_split_the_response(log):
    portal, c, ids = log
    c.get("/review")
    r = c.post("/review/verdict", {"id": "1\r\nSet-Cookie: evil=1", "verdict": "keep", "from": "entry"})
    assert r.status == 303 and r.getheader("Location") == "/review"
    assert "evil" not in (r.getheader("Set-Cookie") or "")


def test_redirect_refuses_control_characters():
    from portal.web import redirect
    assert redirect("/log\r\nX: y").headers["Location"] == "/"
    assert redirect("/\\evil.example").headers["Location"] == "/"
    assert redirect("/log/entry?id=3").headers["Location"] == "/log/entry?id=3"


@pytest.fixture
def unsub_service(log):
    """A stand-in for the analyzer's unsubscribe service."""
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    calls = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            calls.append(body)
            out = json.dumps({"result": "done", "detail": "ok\x07", "host": "unsub.shop.example"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    portal, c, ids = log
    portal.settings.unsubscribe_url = f"http://127.0.0.1:{srv.server_address[1]}/unsubscribe"
    yield portal, c, ids, calls
    srv.shutdown()


def _add_unsub(portal, rid, method, mailto=None):
    conn = sqlite3.connect(portal.tmp / "analyzer" / "analyzer.db")
    conn.execute("INSERT INTO unsubscribe VALUES (?,?,?,?,?,?)",
                 (rid, method, "https://unsub.shop.example/u" if method == "one_click" else None, mailto,
                  "unsub.shop.example", "shop.example"))
    conn.commit()
    conn.close()


def test_one_click_unsubscribe_asks_first_needs_step_up_and_is_audited(unsub_service):
    portal, c, ids, calls = unsub_service
    rid = ids["review"]
    assert "Unsubscribe…" not in c.get(f"/log/entry?id={rid}").body
    _add_unsub(portal, rid, "one_click")
    assert "Unsubscribe…" in c.get(f"/log/entry?id={rid}").body
    r = c.post("/unsubscribe", {"id": str(rid)})
    assert r.status == 200 and "Unsubscribe from this sender?" in r.body and calls == []
    r = c.post("/unsubscribe", {"id": str(rid), "confirm": "yes"})
    assert r.status == 200 and "Unsubscribed" in r.body and calls == [{"decision_id": rid}]
    assert ("unsubscribe", f"decision {rid}: unsub.shop.example", "done") in [
        tuple(a) for a in portal.db.all("SELECT action, target, result FROM audit")]
    # Not for a message without a one-click row, and not without step-up.
    c.get("/log")
    assert c.post("/unsubscribe", {"id": str(ids["spam"]), "confirm": "yes"}).status == 303 and len(calls) == 1
    portal.db.execute("UPDATE sessions SET reauth_at = 0")
    c.get("/log")
    assert c.post("/unsubscribe", {"id": str(rid), "confirm": "yes"}).status == 401 and len(calls) == 1


def test_mailto_is_shown_never_sent(unsub_service):
    portal, c, ids, calls = unsub_service
    _add_unsub(portal, ids["spam"], "mailto", "leave@spam.example")
    body = c.get(f"/log/entry?id={ids['spam']}").body
    assert "leave@spam.example" in body and "from your mail app" in body and "Unsubscribe…" not in body
    c.get("/log")
    assert c.post("/unsubscribe", {"id": str(ids["spam"]), "confirm": "yes"}).status == 303 and calls == []


def test_unsubscribe_service_down_fails_cleanly(log):
    portal, c, ids = log
    _add_unsub(portal, ids["review"], "one_click")
    portal.settings.unsubscribe_url = "http://127.0.0.1:9/unsubscribe"
    c.get("/log")
    r = c.post("/unsubscribe", {"id": str(ids["review"]), "confirm": "yes"})
    assert r.status == 200 and "isn&#39;t reachable" in r.body and "Check the Status page" in r.body


def test_a_redirect_from_the_service_is_not_followed(log):
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    hits = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            hits.append(self.path)
            out = b'{"result": "done", "detail": "", "host": "x.example"}'   # a 3xx is never "done"
            self.send_response(307)
            self.send_header("Location", "/elsewhere")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    portal, c, ids = log
    _add_unsub(portal, ids["review"], "one_click")
    portal.settings.unsubscribe_url = f"http://127.0.0.1:{srv.server_address[1]}/unsubscribe"
    c.get("/log")
    r = c.post("/unsubscribe", {"id": str(ids["review"]), "confirm": "yes"})
    srv.shutdown()
    assert "That didn't work" in r.body and "redirect" in r.body and hits == ["/unsubscribe"]
    actions = [a[0] for a in portal.db.all("SELECT action FROM audit ORDER BY id")]
    assert actions[-2:] == ["unsubscribe requested", "unsubscribe"]


def _feedback(portal, name="feedback.jsonl"):
    p = portal.tmp / "pc" / name
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


def test_corrections_reach_the_analyzer_as_feedback_lines(log):
    import sys
    portal, c, ids = log
    body = c.get(f"/log/entry?id={ids['spam']}").body
    assert "Was this right?" in body and "Not spam (keep)" in body
    assert c.post("/review/verdict", {"id": str(ids["spam"]), "verdict": "keep", "from": "entry"}).status == 303
    c.get("/review")
    c.post("/review/verdict", {"id": str(ids["review"]), "verdict": "trash"})
    c.get("/review")
    c.post("/review/verdict", {"id": str(ids["review"]), "verdict": "undo"})    # withdrawn at the analyzer too
    lines = _feedback(portal)
    assert [(x["message_key"], x["label"], x["scope"], x["by"]) for x in lines] == [
        ("k1", "legitimate", "message", "portal"), ("k2", "spam", "message", "portal"),
        ("k2", "withdrawn", "message", "portal")]
    raw = (portal.tmp / "pc" / "feedback.jsonl").read_bytes().splitlines()
    src = str(STORE.parent.parent)
    sys.path.insert(0, src)
    try:
        fb = pytest.importorskip("analyzer.feedback")
        assert [fb.parse_line(x)[2] for x in raw] == ["legitimate", "spam", "withdrawn"]
    finally:
        sys.path.remove(src)
    assert oct((portal.tmp / "pc" / "feedback.jsonl").stat().st_mode & 0o777) == "0o640"


def test_feedback_rotates_and_never_follows_a_link(portal, tmp_path):
    from portal.portal_config import PortalConfig
    cfg = PortalConfig(str(portal.tmp / "pc"))
    p = portal.tmp / "pc" / "feedback.jsonl"
    p.write_bytes(b"x" * (1024 * 1024))
    cfg.append_feedback("INBOX:1:2", "spam", ts=5)
    assert (portal.tmp / "pc" / "feedback.jsonl.1").stat().st_size == 1024 * 1024
    assert _feedback(portal) == [{"message_key": "INBOX:1:2", "label": "spam", "scope": "message", "ts": 5, "by": "portal"}]
    target = tmp_path / "elsewhere"
    target.write_text("keep\n")
    p.unlink()
    p.symlink_to(target)
    cfg.append_feedback("INBOX:1:3", "legitimate", ts=6)
    assert target.read_text() == "keep\n" and not p.is_symlink() and len(_feedback(portal)) == 1


def test_review_cards_count_and_sender_shortcut(log):
    portal, c, ids = log
    r = c.get("/review")
    assert "1 waiting" in r.body and "82% spam" in r.body
    assert ">Not spam</button>" in r.body and ">Spam</button>" in r.body
    assert "/lists?add=protect:address&amp;value=news%40shop.example#add" in r.body
    # The Review tab shows the count on every page, and drops it once answered.
    assert '<span class="count">' in c.get("/log").body
    c.get("/review")
    c.post("/review/verdict", {"id": str(ids["review"]), "verdict": "keep"})
    assert '<span class="count">' not in c.get("/log").body


def test_sender_shortcut_fills_the_lists_form(log):
    portal, c, ids = log
    body = c.get(f"/log/entry?id={ids['spam']}").body
    assert "add=block:address&amp;value=offers%40spam.example" in body
    body = c.get("/lists?add=protect:address&value=news%40shop.example").body
    assert 'value="news@shop.example"' in body
    body = c.get("/lists?add=protect:address&value=%1b[31m").body
    assert "\x1b" not in body


def test_more_page_lists_what_the_phone_tab_bar_leaves_out(claimed):
    portal, c = claimed
    body = c.get("/more").body
    for href in ("/analyzer", "/backfill", "/settings", "/audit"):
        assert f'href="{href}"' in body
    assert 'class="narrow" href="/more" aria-current="page"' in body


def test_live_moves_and_moves_back_show_in_the_log(log):
    portal, c, ids = log
    assert "Moved back" not in c.get("/log").body          # no moves table yet: still works
    conn = sqlite3.connect(portal.tmp / "analyzer" / "analyzer.db")
    conn.execute("CREATE TABLE IF NOT EXISTS moves (id INTEGER PRIMARY KEY, ts TEXT NOT NULL, decision_id INTEGER "
                 "NOT NULL, kind TEXT NOT NULL, from_mailbox TEXT NOT NULL, to_mailbox TEXT NOT NULL, uidvalidity "
                 "INTEGER, uid INTEGER, ok INTEGER NOT NULL, error TEXT)")
    for rid, kind, to, ok in ((ids["spam"], "move", "Folders/AI-Quarantine", 1),
                              (ids["review"], "move", "Folders/AI-Review", 1),
                              (ids["review"], "undo", "INBOX", 1),
                              (ids["keep"], "move", "Folders/AI-Review", 0)):
        conn.execute("INSERT INTO moves (ts, decision_id, kind, from_mailbox, to_mailbox, ok) VALUES "
                     "('2026-11-24T12:00:00Z', ?, ?, 'INBOX', ?, ?)", (rid, kind, to, ok))
    conn.execute("UPDATE decisions SET applied = 1 WHERE id IN (?, ?)", (ids["spam"], ids["review"]))
    conn.commit()
    conn.close()
    body = c.get("/log").body
    assert "✗ Moved to AI-Quarantine" in body and "↩ Moved back" in body and "Trashed" not in body
    assert "Would review" not in body and "Moved to AI-Review" not in body      # the failed move isn't shown
    assert "↩ Moved back" in c.get(f"/log/entry?id={ids['review']}").body

def test_log_says_why_in_plain_words(log):
    portal, c, ids = log
    body = c.get("/log").body
    assert "AI: 99% spam, sure enough to trash" in body
    assert "AI: 82% spam, not sure enough" in body
    assert "Your Never trash list, sender verified" in body
    for code in ("review_band", "protected_verified", "threshold"):
        assert f">{code}<" not in body
    from portal.app import why
    assert why({"rule": "model_keep", "label": "ham", "confidence": 0.95}) == "AI: 95% not spam"
    assert why({"rule": "something_new", "explain": "Its own words."}) == "Its own words."


def test_analyzer_page_preview_counts_the_last_14_days(log):
    portal, c, ids = log
    body = c.get("/analyzer").body
    # Spam scores 0.99 and 0.82 at the defaults 97 / 70: one trashed, one to Review.
    assert 'data-scores="0.990,0.820"' in body or 'data-scores="0.820,0.990"' in body
    assert 'data-would="trash">1<' in body and 'data-would="review">1<' in body
    assert 'type="range"' in body and "limits_max_moves_per_day" in body
    assert '<details class="advanced">' in body


def test_status_puts_the_answer_first(log):
    portal, c, ids = log
    body = c.get("/").body
    assert 'class="summary' in body
    assert "1 message waiting in Review" in body
    assert body.index('class="summary') < body.index("<h2 class=\"section\">Bridge</h2>")
    assert '<details class="status-details">' in body


def test_stylesheet_url_changes_with_its_content(claimed):
    # A cached old stylesheet with new pages made the portal look broken after an update.
    portal, c = claimed
    import re
    body = c.get("/").body
    m = re.search(r'href="/static/portal\.css\?v=([0-9a-f]{12})"', body)
    assert m and re.search(r'src="/static/portal\.js\?v=[0-9a-f]{12}"', body)
    assert c.get(f"/static/portal.css?v={m.group(1)}").status == 200


def test_unsubscribe_api_needs_confirm_step_up_and_a_one_click_row(unsub_service):
    from test_api import expire_step_up, post
    portal, c, ids, calls = unsub_service
    rid = ids["review"]
    _add_unsub(portal, rid, "one_click")
    _add_unsub(portal, ids["spam"], "mailto", "mailto:off@shop.example")
    for bad in ({"id": str(rid), "confirm": True}, {"id": True, "confirm": True}, {"id": 999999, "confirm": True},
                {"id": ids["spam"], "confirm": True}):
        r = post(portal, c, "/api/unsubscribe", bad)
        assert r.status == 400 and r.data["error"] == "This message has no one-click unsubscribe.", bad
    assert post(portal, c, "/api/unsubscribe", {"id": rid}).status == 400 and calls == []
    assert post(portal, c, "/api/unsubscribe", {"id": rid, "confirm": "yes"}).status == 400 and calls == []
    r = post(portal, c, "/api/unsubscribe", {"id": rid, "confirm": True})
    assert r.status == 200 and r.data == {"result": "done", "detail": "ok", "host": "unsub.shop.example"}
    assert calls == [{"decision_id": rid}]
    actions = [tuple(a) for a in portal.db.all("SELECT action, target FROM audit")]
    assert ("unsubscribe requested", f"decision {rid}: unsub.shop.example") in actions
    assert ("unsubscribe", f"decision {rid}: unsub.shop.example") in actions
    expire_step_up(portal)
    r = post(portal, c, "/api/unsubscribe", {"id": rid, "confirm": True})
    assert r.status == 401 and r.data["step_up"] is True and len(calls) == 1
