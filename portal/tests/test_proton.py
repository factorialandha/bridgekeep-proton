"""Proton sign-in from the portal, through a stand-in for the Bridge
container's login broker (HTTP + JSON on a Unix socket)."""
import json
import os
import shutil
import socketserver
import tempfile
import threading
from http.server import BaseHTTPRequestHandler

import pytest
from test_api import expire_step_up, get, post

from portal import broker


class FakeBroker:
    def __init__(self):
        self.state = {"state": "signed_out", "account": "", "error": "", "hv_url": "", "step_expires": None}
        self.seen = []           # (path, body) the broker received
        self.reply = None        # (status, body) to force once

    def handle(self, method, path, body):
        self.seen.append((path, body))
        if self.reply:
            out, self.reply = self.reply, None
            return out
        st = self.state
        if method == "GET" and path == "/status":
            return 200, st
        if path == "/login":
            if st["state"] != "signed_out":
                return 409, st
            st.update(state="waiting_2fa", account=body["username"], step_expires=2000000000)
        elif path == "/2fa":
            if st["state"] != "waiting_2fa":
                return 409, {"error": "wrong step"}     # the real broker's error body
            if body["code"] != "123456":
                st["error"] = "That code didn't work. Try the next one."
            else:
                st.update(state="waiting_mailbox_password", error="")
        elif path == "/mailbox-password":
            if st["state"] != "waiting_mailbox_password":
                return 409, st
            st.update(state="signed_in", step_expires=None)
        elif path == "/cancel":
            st.update(state="signed_out", account="", error="", step_expires=None)
        elif path == "/logout":
            st.update(state="signed_out", account="")
        else:
            return 404, {}
        return 200, st


@pytest.fixture
def fake(portal):
    d = tempfile.mkdtemp(prefix="bk", dir="/tmp")
    path = os.path.join(d, "b.sock")
    fb = FakeBroker()

    class H(BaseHTTPRequestHandler):
        def _go(self, method):
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n)) if n else None
            code, out = fb.handle(method, self.path, body)
            raw = out if isinstance(out, bytes) else json.dumps(out).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            self._go("GET")

        def do_POST(self):
            self._go("POST")

        def address_string(self):
            return "local"

        def log_message(self, *a):
            pass

    class S(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True

    srv = S(path, H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    portal.settings.broker_socket = path
    yield fb
    srv.shutdown()
    srv.server_close()
    shutil.rmtree(d, ignore_errors=True)


def audit(portal):
    return [tuple(a) for a in portal.db.all("SELECT action, target, result FROM audit")]


def test_sign_in_walks_the_brokers_steps_and_never_echoes_secrets(portal, claimed, fake):
    _, c = claimed
    d = get(portal, c, "/api/proton").data
    assert d["available"] is True and d["state"] == "signed_out" and d["mail_paused"] is False
    secret = "hunter2-proton-pass"
    r = post(portal, c, "/api/proton/login", {"username": "me@proton.example", "password": secret})
    assert r.status == 200 and r.data["state"] == "waiting_2fa" and r.data["mail_paused"] is True
    assert r.data["step_expires"] == 2000000000 and secret not in json.dumps(r.data)
    assert fake.seen[-1] == ("/login", {"username": "me@proton.example", "password": secret})
    # A wrong code: 200, same step, the broker's sentence shown.
    r = post(portal, c, "/api/proton/2fa", {"code": "000 000"})
    assert r.status == 200 and r.data["state"] == "waiting_2fa" and "didn't work" in r.data["error"]
    assert fake.seen[-1] == ("/2fa", {"code": "000000"})
    for bad in ("12345", "abcdef", "123456789", 123456, "１２３４５６"):
        assert post(portal, c, "/api/proton/2fa", {"code": bad}).status == 400, bad
    assert post(portal, c, "/api/proton/2fa", {"code": "123456"}).data["state"] == "waiting_mailbox_password"
    mbox = "second-mailbox-pass"
    r = post(portal, c, "/api/proton/mailbox-password", {"password": mbox})
    assert r.data["state"] == "signed_in" and r.data["mail_paused"] is False and r.data["account"] == "me@proton.example"
    rows = audit(portal)
    assert ("proton: sign-in started", "me@proton.example", "ok") in rows
    assert ("proton: 2FA code sent", "", "error") in rows and ("proton: signed in", "me@proton.example", "ok") in rows
    assert all(secret not in str(r) and mbox not in str(r) for r in portal.db.all("SELECT * FROM audit"))


def test_fields_are_checked_before_the_broker_sees_them(portal, claimed, fake):
    _, c = claimed
    for bad in ({"username": "me@x", "password": ""}, {"username": "", "password": "x"},
                {"username": "me@x", "password": "a\nb"}, {"username": "me\r@x", "password": "p"},
                {"username": "me@x", "password": 5}, {"username": "me@x", "password": "p" * 1025}):
        assert post(portal, c, "/api/proton/login", bad).status == 400, bad
    assert post(portal, c, "/api/proton/mailbox-password", {"password": "\x00"}).status == 400
    assert [p for p, _ in fake.seen if p != "/status"] == []


def test_step_up_for_starting_and_signing_out(portal, claimed, fake):
    _, c = claimed
    fake.state.update(state="signed_in", account="me@proton.example")
    assert post(portal, c, "/api/proton/logout", {}).status == 400
    expire_step_up(portal)
    assert post(portal, c, "/api/proton/logout", {"confirm": True}).data["step_up"] is True
    assert post(portal, c, "/api/proton/login", {"username": "a@b", "password": "p"}).data["step_up"] is True
    assert post(portal, c, "/api/proton/cancel", {}).status == 200        # the safe direction: no step-up
    assert [p for p, _ in fake.seen if p != "/status"] == ["/cancel"]


def test_logout_with_confirm(portal, claimed, fake):
    _, c = claimed
    fake.state.update(state="signed_in", account="me@proton.example")
    r = post(portal, c, "/api/proton/logout", {"confirm": True})
    assert r.status == 200 and r.data["state"] == "signed_out"
    assert ("proton: signed out", "", "ok") in audit(portal)


def test_broker_errors_are_passed_on_in_plain_words(portal, claimed, fake):
    _, c = claimed
    r = post(portal, c, "/api/proton/2fa", {"code": "123456"})       # not waiting for a code
    assert r.status == 409 and r.data["proton"]["state"] == "signed_out"
    fake.reply = (429, {"error": "too many attempts"})
    r = post(portal, c, "/api/proton/human-verification", {})
    assert r.status == 429 and "Too many" in r.data["error"] and r.data["proton"]["state"] == "signed_out"
    fake.reply = (500, {"state": "weird"})
    assert post(portal, c, "/api/proton/cancel", {}).status == 502
    fake.reply = (200, b"not json")
    d = get(portal, c, "/api/proton").data
    assert d["available"] is False and "doesn't understand" in d["error"]


def test_broker_missing_reads_as_unavailable(portal, claimed):
    _, c = claimed
    portal.settings.broker_socket = str(portal.tmp / "nope.sock")
    d = get(portal, c, "/api/proton").data
    assert d["available"] is False and "isn't running" in d["error"]
    assert post(portal, c, "/api/proton/cancel", {}).status == 503


def test_status_view_trusts_nothing():
    v = broker.status_view({"state": "waiting_human", "hv_url": "https://verify.proton.me/x?y=1", "account": "a\x07b",
                            "step_expires": True, "password": "leak"})
    assert v == {"state": "waiting_human", "account": "ab", "error": "", "hv_url": "https://verify.proton.me/x?y=1",
                 "step_expires": None}
    for url in ("http://verify.proton.me/", "https://proton.me.evil.example/", "https://user@verify.proton.me/",
                "https://verify.proton.me:8443/", "javascript:alert(1)"):
        assert broker.status_view({"state": "waiting_human", "hv_url": url})["hv_url"] == "", url
    assert broker.status_view({"state": "signed_in", "hv_url": "https://proton.me/"})["hv_url"] == ""
    assert broker.status_view({"state": "pwned"})["state"] == "error"
    assert broker.status_view([1, 2])["state"] == "error"
