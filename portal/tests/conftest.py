import http.client
import re
import threading
import time
from urllib.parse import urlencode

import pytest

from portal import auth, totp
from portal import app as app_module
from portal.app import Context, build, make_env
from portal.db import DB
from portal.settings import Settings
from portal.web import serve

CSRF = re.compile(r'name="csrf" value="([^"]+)"')
SECRET = re.compile(r'class="mono secret">([A-Z2-7 ]+)<')


class Client:
    """A tiny browser: keeps the cookie, sends Origin like a real form post."""

    def __init__(self, port: int, host: str = "localhost"):
        self.port, self.host = port, host
        self.cookie = ""
        self.last_body = ""

    def request(self, method, path, form=None, headers=None, origin=True, csrf=True, host=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Host": host or f"{self.host}:{self.port}"}
        if self.cookie:
            h["Cookie"] = self.cookie
        body = None
        if method == "POST":
            form = dict(form or {})
            if csrf and "csrf" not in form:
                m = CSRF.search(self.last_body)
                form["csrf"] = m.group(1) if m else ""
            body = urlencode(form)
            h["Content-Type"] = "application/x-www-form-urlencoded"
            if origin:
                h["Origin"] = f"http://{self.host}:{self.port}"
        h.update(headers or {})
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read().decode("utf-8", "replace")
        sc = r.getheader("Set-Cookie")
        if sc:
            first = sc.split(";")[0]
            self.cookie = "" if first.endswith("=") else first
        if r.getheader("Content-Type", "").startswith("text/html"):
            self.last_body = data
        r.body = data.replace("<wbr>", "")   # as text: soft breaks are invisible
        return r

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, form=None, **kw):
        return self.request("POST", path, form, **kw)


@pytest.fixture(autouse=True)
def classic_pages(monkeypatch):
    """Tests of the server-rendered pages see them even where web_dist is built.
    test_spa_redirect.py turns the redirect to /app back on."""
    monkeypatch.setattr(app_module, "web_built", lambda: False)


@pytest.fixture
def portal(tmp_path):
    s = Settings(data_dir=str(tmp_path / "data"), analyzer_data=str(tmp_path / "analyzer"), listen_host="127.0.0.1",
                 listen_port=0, host_status=str(tmp_path / "status"), portal_config=str(tmp_path / "pc"),
                 curated_lists=str(tmp_path / "lists"), secret_requests=str(tmp_path / "req"))
    (tmp_path / "analyzer").mkdir()
    (tmp_path / "pc").mkdir()
    (tmp_path / "req").mkdir(mode=0o700)
    ctx = Context(s, DB(s.db_path), make_env())
    server = serve(build(ctx), "127.0.0.1", 0)
    port = server.server_address[1]
    s.public_port = port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    ctx.port = port
    ctx.tmp = tmp_path
    yield ctx
    server.shutdown()
    server.server_close()


PASSWORD = "correct horse battery staple"


def next_code(secret: str, after_step: int = -1) -> tuple[str, int]:
    """A valid code for a step newer than after_step (waits out a step if needed)."""
    while True:
        step = int(time.time() // totp.STEP)
        for s in (step, step + 1):
            if s > after_step:
                return totp.code_at(secret, s), s
        time.sleep(1)


@pytest.fixture
def claimed(portal):
    """A portal with an admin, and a signed-in client."""
    code = auth.new_claim_code(portal.db, 3600)
    c = Client(portal.port)
    c.get("/claim")
    r = c.post("/claim", {"code": code})
    assert r.status == 303, r.body
    c.get("/claim/admin")
    secret = SECRET.search(c.last_body).group(1).replace(" ", "")
    otp, step = next_code(secret)
    r = c.post("/claim/admin", {"password": PASSWORD, "confirm": PASSWORD, "code": otp})
    assert r.status == 303 and r.getheader("Location") == "/", r.body
    c.secret, c.step = secret, step
    c.get("/")  # a page with this session's form token
    return portal, c
