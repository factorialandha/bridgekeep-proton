import re
import json
import time

from conftest import PASSWORD, Client
from portal import auth
from portal.web import CSP


def test_unknown_host_is_refused(portal):
    c = Client(portal.port)
    for host in ("evil.example", "evil.example:80", "localhost.evil.example", "127.0.0.1@evil"):
        assert c.get("/login", host=host).status in (400, 421), host
    assert c.get("/healthz", host=f"127.0.0.1:{portal.port}").status == 200
    assert c.get("/healthz", host="[::1]:9000").status == 200
    assert not portal.settings.host_allowed("")
    assert not portal.settings.host_allowed("localhost:abc")


def test_extra_hosts_are_allowed(portal):
    portal.settings.extra_hosts = ("bridgekeep.localhost",)
    assert Client(portal.port).get("/healthz", host="bridgekeep.localhost:8443").status == 200


def test_security_headers_on_every_response(portal):
    r = Client(portal.port).get("/claim")
    assert r.getheader("Content-Security-Policy") == CSP
    assert "script-src 'self'" in CSP and "frame-ancestors 'none'" in CSP
    assert r.getheader("X-Frame-Options") == "DENY"
    assert r.getheader("Cache-Control") == "no-store"
    assert r.getheader("Referrer-Policy") == "same-origin"
    cookie = r.getheader("Set-Cookie")
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie and "Path=/" in cookie


def test_post_needs_same_origin(claimed):
    portal, c = claimed
    c.get("/settings")
    r = c.post("/logout", headers={"Origin": "http://evil.example"})
    assert r.status == 403
    r = c.post("/logout", origin=False)
    assert r.status == 403
    r = c.post("/logout", origin=False, headers={"Sec-Fetch-Site": "same-origin"})
    assert r.status == 303


def test_post_needs_csrf_token(claimed):
    portal, c = claimed
    c.get("/settings")
    assert c.post("/logout", {"csrf": "nope"}).status == 403
    assert c.post("/logout", csrf=False).status == 403
    assert c.get("/").status == 200  # still signed in


def test_get_never_changes_state(claimed):
    portal, c = claimed
    assert c.get("/logout").status == 404
    assert c.get("/").status == 200


def test_other_methods_are_refused(portal):
    c = Client(portal.port)
    for m in ("PUT", "DELETE", "PATCH", "OPTIONS"):
        assert c.request(m, "/").status == 405


def test_body_size_and_encoding_are_checked(portal):
    c = Client(portal.port)
    c.get("/claim")
    r = c.request("POST", "/claim", headers={"Content-Type": "application/json"}, csrf=False)
    assert r.status == 415
    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", portal.port, timeout=5)
    conn.request("POST", "/claim", body=b"x" * 70000, headers={
        "Host": "localhost", "Content-Type": "application/x-www-form-urlencoded"})
    assert conn.getresponse().status == 413


def test_static_files_only_by_safe_name(portal):
    c = Client(portal.port)
    assert c.get("/static/portal.css").status == 200
    assert c.get("/static/../app.py").status == 404
    assert c.get("/static/%2e%2e/app.py").status == 404
    assert c.get("/static/missing.css").status == 404


def test_request_bodies_and_queries_are_not_logged(portal, caplog):
    import logging
    caplog.set_level(logging.DEBUG, logger="portal")
    c = Client(portal.port)
    c.get("/claim?token=SECRETQUERY")
    c.post("/claim", {"code": "SECRETBODY"})
    text = caplog.text
    assert "SECRETQUERY" not in text and "SECRETBODY" not in text
    assert "/claim" in text


def test_status_page_escapes_analyzer_text(claimed):
    portal, c = claimed
    (portal.tmp / "analyzer" / "health.json").write_text(json.dumps(
        {"status": "retrying", "detail": "<script>alert(1)</script>", "ts": time.time(), "mode": "shadow"}))
    r = c.get("/")
    assert "<script>alert(1)" not in r.body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in r.body
    assert "Shadow mode: nothing is being moved" in r.body


def test_status_page_reports_a_stalled_or_missing_analyzer(claimed):
    portal, c = claimed
    assert "Not set up" in c.get("/").body
    (portal.tmp / "analyzer" / "health.json").write_text(json.dumps(
        {"status": "ok", "detail": "", "ts": time.time() - 3600, "mode": "shadow"}))
    assert "Stalled" in c.get("/").body
    (portal.tmp / "analyzer" / "health.json").write_text("not json")
    assert c.get("/").status == 200


def test_secure_cookie_name_is_host_prefixed():
    from portal.web import App
    app = App(None)
    assert app.cookie_name(True) == "__Host-bk_session"
    assert app.cookie_name(False) == "bk_session"


def test_network_mode_settings(monkeypatch):
    from portal import settings
    s = settings.load()
    assert not s.lan and not s.problems and s.idle_timeout == 12 * 3600
    monkeypatch.setenv("PORTAL_ADDRESS", "192.168.1.20")
    s = settings.load()
    assert s.lan and s.problems          # PORTAL_HOSTS is required
    monkeypatch.setenv("PORTAL_HOSTS", "nas.local,192.168.1.20")
    s = settings.load()
    assert s.lan and not s.problems and s.idle_timeout == 3600
    assert s.host_allowed("nas.local:8443") and not s.host_allowed("evil.example")
    for bad in ("0.0.0.0", "::", "nas.local"):
        monkeypatch.setenv("PORTAL_ADDRESS", bad)
        assert settings.load().problems, bad


def test_cli_code_and_reset(tmp_path, monkeypatch, capsys):
    from portal import cli
    monkeypatch.setenv("PORTAL_DATA", str(tmp_path))
    assert cli.main(["code"]) == 0
    assert "Enter" in capsys.readouterr().out
    assert cli.main(["code", "--plain"]) == 0
    assert re.fullmatch(r"[A-Z2-7]{4}(-[A-Z2-7]{4}){5}\n", capsys.readouterr().out)
    assert cli.main(["reset-admin"]) == 0  # nothing to reset: no --yes needed
    from portal.db import DB
    db = DB(str(tmp_path / "portal.db"))
    auth.create_admin(db, PASSWORD, "JBSWY3DPEHPK3PXP", 0)
    assert cli.main(["code"]) == 1
    assert cli.main(["reset-admin"]) == 1
    assert cli.main(["reset-admin", "--yes"]) == 0
    assert not auth.is_claimed(db)


def test_connection_cap(monkeypatch, tmp_path):
    import socket
    import threading
    from portal import web
    monkeypatch.setattr(web, "MAX_CONNECTIONS", 2)
    server = web.serve(web.App(None), "127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    idle = [socket.create_connection(("127.0.0.1", port)) for _ in range(2)]
    try:
        import time
        time.sleep(0.3)
        extra = socket.create_connection(("127.0.0.1", port))
        extra.settimeout(3)
        assert extra.recv(1) == b""          # closed straight away
        extra.close()
    finally:
        for s in idle:
            s.close()
        server.shutdown()
        server.server_close()
