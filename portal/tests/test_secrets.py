"""The portal's write-only drop box for the API key and the Discord webhook."""
import os
import stat

KEY = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz012345"
HOOK = ("https://discord.com/api/webhooks/123456789012345678/"
        "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdEfGhIjKlMnOpQrStUvWx")


def reqs(portal):
    return sorted(os.listdir(portal.tmp / "req"))


def test_key_is_written_once_never_echoed_and_audited_without_the_value(claimed):
    portal, c = claimed
    body = c.get("/analyzer").body
    assert "Not set" in body and 'type="password"' in body
    r = c.post("/secrets/set", {"name": "anthropic_api_key", "value": KEY})
    assert r.status == 303
    files = reqs(portal)
    assert len(files) == 1 and files[0].startswith("anthropic_api_key.") and files[0].endswith(".req")
    f = portal.tmp / "req" / files[0]
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    lines = f.read_text().splitlines()
    assert lines[0] == "secret=anthropic_api_key" and lines[1] == "action=set" and lines[3] == f"value={KEY}"
    body = c.get("/analyzer").body
    assert "Waiting for the host" in body and KEY not in body
    assert all(KEY not in str(row) for row in portal.db.all("SELECT * FROM audit"))
    assert ("Claude API key: change requested",) in [tuple(a) for a in portal.db.all("SELECT action FROM audit")]
    # A second change while one waits is refused.
    c.get("/analyzer")
    r = c.post("/secrets/set", {"name": "anthropic_api_key", "value": KEY})
    assert r.status == 400 and "already waiting" in r.body and KEY not in r.body


def test_bad_values_are_refused_and_not_echoed(claimed):
    portal, c = claimed
    c.get("/analyzer")
    r = c.post("/secrets/set", {"name": "anthropic_api_key", "value": "sk-live-notakey-123456789012345"})
    assert r.status == 400 and "starts with sk-ant-" in r.body and "notakey" not in r.body
    c.get("/settings")
    r = c.post("/secrets/set", {"name": "discord_webhook", "value": "https://evil.example/api/webhooks/1/x"})
    assert r.status == 400 and "a Discord webhook URL" in r.body and "evil.example" not in r.body
    c.get("/settings")
    r = c.post("/secrets/set", {"name": "bridge_password", "value": "x"})
    assert r.status == 303 and reqs(portal) == []


def test_host_result_is_shown_last4_only(claimed):
    portal, c = claimed
    (portal.tmp / "status").mkdir(exist_ok=True)
    (portal.tmp / "status" / "secrets.env").write_text(
        "anthropic_api_key=set\nanthropic_api_key_last4=2345\nanthropic_api_key_when=1700000000\n"
        "anthropic_api_key_result=ok\ndiscord_webhook=set\ndiscord_webhook_last4=StUv\n"
        "discord_webhook_result=refused: Discord did not accept a test message with it\n")
    body = c.get("/analyzer").body
    assert "…2345" in body and "Replace the key" in body and "Remove the key" in body
    body = c.get("/settings").body
    assert "…StUv" in body and "Send a test message" in body and "did not accept a test message" in body


def test_remove_and_test_alert_need_the_right_auth(claimed):
    portal, c = claimed
    (portal.tmp / "status").mkdir(exist_ok=True)
    (portal.tmp / "status" / "secrets.env").write_text("discord_webhook=set\ndiscord_webhook_last4=StUv\n")
    c.get("/settings")
    assert c.post("/alerts/test").status == 303
    assert any(n.startswith("test_alert.") for n in reqs(portal))
    portal.db.execute("UPDATE sessions SET reauth_at = 0")
    c.get("/settings")
    assert c.post("/secrets/remove", {"name": "discord_webhook"}).status == 401
    assert not any(n.startswith("discord_webhook.") for n in reqs(portal))
    c.get("/settings")
    assert c.post("/secrets/set", {"name": "discord_webhook", "value": HOOK}).status == 401
    assert not any(n.startswith("discord_webhook.") for n in reqs(portal))


def test_a_planted_symlink_is_not_followed(portal, tmp_path):
    from portal.secret_drop import SecretDrop
    d = tmp_path / "drop"
    d.mkdir()
    target = tmp_path / "elsewhere"
    target.write_text("keep")
    drop = SecretDrop(str(d), str(tmp_path / "status"))
    rid = drop.request("anthropic_api_key", "set", KEY)
    assert (d / f"anthropic_api_key.{rid}.req").is_file() and target.read_text() == "keep"


def test_remove_asks_first(claimed):
    portal, c = claimed
    (portal.tmp / "status").mkdir(exist_ok=True)
    (portal.tmp / "status" / "secrets.env").write_text("anthropic_api_key=set\nanthropic_api_key_last4=2345\n")
    c.get("/analyzer")
    r = c.post("/secrets/remove", {"name": "anthropic_api_key"})
    assert r.status == 200 and "Remove the Claude API key?" in r.body and reqs(portal) == []
    r = c.post("/secrets/remove", {"name": "anthropic_api_key", "confirm": "yes"})
    assert r.status == 303
    f = [n for n in reqs(portal) if n.startswith("anthropic_api_key.")]
    assert len(f) == 1 and "action=remove" in (portal.tmp / "req" / f[0]).read_text()
