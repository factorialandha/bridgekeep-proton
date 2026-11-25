"""Settings > AI vendor: choose, confirm with the vendor's disclosure, drop box."""
import ast
import os
from pathlib import Path

from portal import vendors

ROOT = Path(__file__).resolve().parents[2]
OPENAI_KEY = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz012345"


def reqs(portal):
    return sorted(os.listdir(portal.tmp / "req"))


def health(portal, provider="anthropic", model="claude-haiku-5-5", state="on"):
    (portal.tmp / "analyzer" / "health.json").write_text(
        f'{{"status": "ok", "ts": 9999999999, "mode": "shadow", "model": "{state}", '
        f'"provider": "{provider}", "model_name": "{model}"}}')


def test_disclosure_matches_the_analyzer_word_for_word():
    tree = ast.parse((ROOT / "analyzer" / "src" / "analyzer" / "providers.py").read_text())
    theirs = next(ast.literal_eval(n.value) for n in tree.body
                  if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "DISCLOSURE")
    assert theirs == vendors.DISCLOSURE
    providers = next(ast.literal_eval(n.value) for n in tree.body
                     if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "PROVIDERS")
    assert tuple(vendors.VENDORS) == providers


def test_switch_asks_first_shows_the_disclosure_and_never_echoes_the_key(claimed):
    portal, c = claimed
    health(portal)
    body = c.get("/analyzer/vendor").body
    assert "Anthropic (Claude)" in body and "claude-haiku-5-5" in body
    # OpenAI without prices: refused, with what to type.
    r = c.post("/analyzer/vendor/review", {"provider": "openai", "model": "gpt-5-mini"})
    assert r.status == 400 and "prices" in r.body and reqs(portal) == []
    r = c.post("/analyzer/vendor/review", {"provider": "openai", "model": "gpt-5-mini",
                                           "price_in": "0.25", "price_out": "2"})
    assert r.status == 200 and vendors.DISCLOSURE["openai"].replace("'", "&#39;") in r.body
    assert "instead of Anthropic (Claude)" in r.body and reqs(portal) == []
    # A bad key: refused, not echoed.
    r = c.post("/analyzer/vendor", {"provider": "openai", "model": "gpt-5-mini", "price_in": "0.25",
                                    "price_out": "2", "value": "AIzaWrongVendor"})
    assert r.status == 400 and "OpenAI API key" in r.body and "AIzaWrongVendor" not in r.body and reqs(portal) == []
    r = c.post("/analyzer/vendor", {"provider": "openai", "model": "gpt-5-mini", "price_in": "0.25",
                                    "price_out": "2", "value": OPENAI_KEY})
    assert r.status == 303 and r.getheader("Location") == "/analyzer/vendor?done=sent"
    files = reqs(portal)
    assert len(files) == 1 and files[0].startswith("ai_vendor.")
    lines = (portal.tmp / "req" / files[0]).read_text().splitlines()
    assert lines[0] == "secret=ai_vendor" and lines[1] == "action=set"
    assert lines[3:] == ["provider=openai", "model=gpt-5-mini", "endpoint=", "price_in=0.25", "price_out=2",
                         f"value={OPENAI_KEY}"]
    body = c.get("/analyzer/vendor").body
    assert "waiting for the host" in body and OPENAI_KEY not in body
    assert all(OPENAI_KEY not in str(row) for row in portal.db.all("SELECT * FROM audit"))
    assert ("AI vendor: change requested", "openai gpt-5-mini") in [
        tuple(a) for a in portal.db.all("SELECT action, target FROM audit")]


def test_empty_key_keeps_the_saved_one_and_local_needs_an_address(claimed):
    portal, c = claimed
    c.get("/analyzer/vendor")
    r = c.post("/analyzer/vendor/review", {"provider": "local", "model": "llama3.1:8b"})
    assert r.status == 400 and "server&#39;s address" in r.body
    r = c.post("/analyzer/vendor/review", {"provider": "local", "model": "llama3.1:8b",
                                           "endpoint": "http://192.168.1.20:11434/v1 --yes"})
    assert r.status == 400 and reqs(portal) == []
    r = c.post("/analyzer/vendor", {"provider": "local", "model": "llama3.1:8b", "endpoint": "http://192.168.1.20:11434/v1"})
    assert r.status == 303
    lines = (portal.tmp / "req" / reqs(portal)[0]).read_text().splitlines()
    assert "endpoint=http://192.168.1.20:11434/v1" in lines and not any(x.startswith("value=") for x in lines)


def test_fields_cannot_smuggle_options_or_lines():
    for model in ("--endpoint", "-x", "a b", "a\nprovider=local", "x" * 101):
        try:
            vendors.check({"provider": "anthropic", "model": model})
        except vendors.VendorError:
            continue
        raise AssertionError(model)
    assert vendors.check({"provider": "anthropic"})["model"] == "claude-haiku-5-5"
    assert vendors.check({"provider": "anthropic", "endpoint": "http://x"})["endpoint"] == ""


def test_vendor_change_needs_step_up(claimed):
    portal, c = claimed
    portal.db.execute("UPDATE sessions SET reauth_at = 0")
    c.get("/analyzer/vendor")
    assert c.post("/analyzer/vendor/review", {"provider": "anthropic"}).status == 401
    assert c.post("/analyzer/vendor", {"provider": "anthropic"}).status == 401 and reqs(portal) == []


def test_analyzer_and_status_pages_name_the_vendor(claimed):
    portal, c = claimed
    health(portal, "gemini", "gemini-2.5-flash", "no_price")
    body = c.get("/analyzer").body
    assert "Google Gemini" in body and "gemini-2.5-flash" in body and "Claude API key" not in body
    assert "No price" in c.get("/").body and "Google Gemini, gemini-2.5-flash" in c.get("/").body
    assert "isn't using this model yet" in c.get("/analyzer/vendor").body
    (portal.tmp / "status" ).mkdir(exist_ok=True)
    (portal.tmp / "status" / "secrets.env").write_text("ai_vendor_result=refused: no API key for Google Gemini\n")
    assert "no API key for Google Gemini" in c.get("/analyzer/vendor").body


def test_refusal_reads_plainly_and_status_links_to_the_vendor_page(claimed):
    portal, c = claimed
    health(portal, "openai", "gpt-5-mini", "no_key")
    assert 'href="/analyzer/vendor">Add a key' in c.get("/").body
    (portal.tmp / "status").mkdir(exist_ok=True)
    (portal.tmp / "status" / "secrets.env").write_text("ai_vendor_result=refused: no API key for OpenAI\n")
    body = c.get("/analyzer/vendor").body
    assert "last change: no API key for OpenAI. Change it below" in body and "refused:" not in body
