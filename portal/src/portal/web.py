"""A small, strict HTTP layer on the standard library.

Every request passes the same gate before any page code runs:

* Host must be on the allowlist (P10, DNS rebinding) or it gets 421.
* Only GET, HEAD and POST. GET never changes state (A8).
* A POST needs a same-origin Origin (or Sec-Fetch-Site: same-origin) and the
  session's synchronizer token (P10). Bodies are capped and never logged (P4).
* Every response carries the CSP from P11 and no-store caching.
"""

from __future__ import annotations

import hmac
import json
import logging
import mimetypes
import dataclasses
import re
import ssl
import threading
from dataclasses import dataclass, field
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import Callable
from urllib.parse import parse_qs, urlsplit

from . import auth

log = logging.getLogger("portal")

MAX_BODY = 64 * 1024
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; object-src 'none'; "
       "base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
# The React frontend (portal/web, built into web_dist/): same as CSP, plus inline
# style *attributes* only, which Radix uses to position menus and dialogs.
# Scripts and style elements stay 'self' only.
CSP_APP = CSP.replace("style-src 'self'", "style-src 'self'; style-src-elem 'self'; style-src-attr 'unsafe-inline'")
WEB_ASSET = re.compile(r"^[A-Za-z0-9_-]{1,80}\.(js|css|svg|woff2)$")
STATIC_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,60}\.(css|js|svg|woff2)$")


@dataclass
class Request:
    method: str
    path: str
    query: dict[str, list[str]]
    form: dict[str, list[str]]
    headers: dict[str, str]
    ip: str
    secure: bool
    host: str
    session: auth.Session | None = None
    json: dict | None = None        # /api/ POST bodies (application/json, an object)

    @property
    def is_api(self) -> bool:
        return self.path.startswith("/api/")

    def arg(self, name: str, default: str = "") -> str:
        v = self.query.get(name)
        return v[0] if v else default

    def field(self, name: str, default: str = "") -> str:
        v = self.form.get(name)
        return v[0] if v else default


@dataclass
class Response:
    status: int = 200
    body: bytes = b""
    content_type: str = "text/html; charset=utf-8"
    headers: dict[str, str] = field(default_factory=dict)
    cache: str = "no-store"


def redirect(location: str, status: int = 303) -> Response:
    # Only local paths: never an open redirect.
    if not location.startswith("/") or location.startswith("//") or location.startswith("/\\") \
            or _has_ctl(location):
        location = "/"
    return Response(status, b"", headers={"Location": location})


def _has_ctl(v: str) -> bool:
    return any(ord(c) < 0x20 or ord(c) == 0x7F for c in v)


def text(status: int, msg: str) -> Response:
    return Response(status, msg.encode(), "text/plain; charset=utf-8")


def _no_constant(name: str):
    raise ValueError(f"{name} is not allowed")


def json_response(status: int, data) -> Response:
    return Response(status, json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")


def api_error(status: int, msg: str, **extra) -> Response:
    return json_response(status, {"error": msg, **extra})


Handler = Callable[[Request], Response]


class App:
    def __init__(self, ctx) -> None:
        self.ctx = ctx              # portal.app.Context: settings, db, templates
        self.routes: dict[tuple[str, str], Handler] = {}

    def route(self, method: str, path: str):
        def deco(fn: Handler) -> Handler:
            self.routes[(method, path)] = fn
            return fn
        return deco

    def cookie_name(self, secure: bool) -> str:
        # __Host- needs Secure, which Safari refuses on plain http://localhost.
        return "__Host-bk_session" if secure else "bk_session"

    def set_cookie(self, resp: Response, req: Request, s: auth.Session | None) -> None:
        name = self.cookie_name(req.secure)
        if s is None:
            resp.headers["Set-Cookie"] = f"{name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict" + (
                "; Secure" if req.secure else "")
            return
        resp.headers["Set-Cookie"] = (f"{name}={s.token}; Path=/; HttpOnly; SameSite=Strict"
                                      + ("; Secure" if req.secure else ""))

    def dispatch(self, req: Request) -> Response:
        s = self.ctx.settings
        if not s.host_allowed(req.host):
            return text(421, "This address isn't allowed. Open the portal at http://localhost:%d" % s.public_port)
        if req.method not in ("GET", "HEAD", "POST"):
            return text(405, "Method not allowed")

        if req.path.startswith("/static/"):
            return self.static(req.path[len("/static/"):])
        if req.path == "/healthz":
            return text(200, "ok")

        cookies = SimpleCookie()
        try:
            cookies.load(req.headers.get("cookie", ""))
        except Exception:  # a malformed cookie header is just no cookie
            cookies = SimpleCookie()
        morsel = cookies.get(self.cookie_name(req.secure))
        req.session = auth.load_session(self.ctx.db, morsel.value if morsel else "",
                                        s.idle_timeout, s.absolute_timeout)

        if req.path.startswith("/app/assets/"):
            return self.web_asset(req.path[len("/app/assets/"):])
        if req.path == "/app" or req.path.startswith("/app/"):
            if req.method == "POST":
                return text(405, "Method not allowed")
            # Every page of the frontend is the same index.html; its own router
            # picks the page. The /app route decides who may load it.
            req = dataclasses.replace(req, path="/app")

        if req.method == "POST":
            problem = self.check_post(req)
            if problem:
                log.warning("refused POST %s from %s: %s", req.path, req.ip, problem)
                if req.is_api:
                    return api_error(403, "This page expired or the request came from another site. Reload and try again.")
                return text(403, "This form expired or came from another site. Go back, reload the page and try again.")

        handler = self.routes.get(("GET" if req.method == "HEAD" else req.method, req.path))
        if handler is None:
            return api_error(404, "Not found.") if req.is_api else text(404, "Not found")
        before = req.session
        resp = handler(req)
        if req.session is not before or (req.session and req.session.is_new):
            self.set_cookie(resp, req, req.session)
        return resp

    def check_post(self, req: Request) -> str | None:
        origin = req.headers.get("origin", "")
        expected = ("https://" if req.secure else "http://") + req.host.lower()
        if origin:
            if origin.lower() != expected:
                return "cross-origin"
        elif req.headers.get("sec-fetch-site", "") != "same-origin":
            return "no origin"
        if req.session is None:
            return "no session"
        # The JSON API sends the token in a header (a form can't set one).
        token = req.headers.get("x-csrf-token", "") if req.is_api else req.field("csrf")
        if not hmac.compare_digest(token, req.session.csrf):
            return "bad csrf token"
        return None

    def web_asset(self, name: str) -> Response:
        """Vite's hashed build files: the name changes with the content, so cache for good."""
        if not WEB_ASSET.match(name):
            return text(404, "Not found")
        try:
            data = resources.files("portal").joinpath("web_dist", "assets", name).read_bytes()
        except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
            return text(404, "Not found")
        ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype.endswith("javascript"):
            ctype += "; charset=utf-8"
        return Response(200, data, ctype, cache="public, max-age=31536000, immutable")

    def static(self, name: str) -> Response:
        if not STATIC_NAME.match(name):
            return text(404, "Not found")
        try:
            data = resources.files("portal").joinpath("static", name).read_bytes()
        except (FileNotFoundError, IsADirectoryError):
            return text(404, "Not found")
        ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype.endswith("javascript"):
            ctype += "; charset=utf-8"
        return Response(200, data, ctype, cache="private, max-age=3600")


def make_handler(app: App, secure: bool = False):
    class H(BaseHTTPRequestHandler):
        server_version = "Bridgekeep"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def handle(self) -> None:
            try:
                super().handle()
            except (ssl.SSLError, ConnectionError, TimeoutError) as e:
                # A browser that hasn't accepted the certificate yet drops the
                # handshake; that's expected, not an error worth a traceback.
                log.debug("connection from %s ended: %s", self.client_address[0], e)

        def _handle(self) -> None:
            url = urlsplit(self.path)
            body = b""
            if self.command == "POST":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    length = -1
                if length < 0 or length > MAX_BODY:
                    big = (api_error(413, "Too large.") if (url.path or "").startswith("/api/")
                           else Response(413, b"Too large", "text/plain"))
                    return self._send(big, head=False, close=True)
                body = self.rfile.read(length)
            api = (url.path or "/").startswith("/api/")
            payload = None
            if self.command == "POST":
                ctype = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
                # /api/ takes JSON only, the pages forms only: a form post can't reach the API.
                if ctype != ("application/json" if api else "application/x-www-form-urlencoded"):
                    return self._send(api_error(415, "Unsupported encoding.") if api
                                      else text(415, "Unsupported form encoding"), head=False)
            try:
                if api and self.command == "POST":
                    payload = json.loads(body.decode("utf-8"), parse_constant=_no_constant) if body else {}
                    if not isinstance(payload, dict):
                        raise ValueError("not an object")
                    form = {}
                else:
                    form = parse_qs(body.decode("utf-8"), keep_blank_values=True, max_num_fields=50) if body else {}
                query = parse_qs(url.query, keep_blank_values=True, max_num_fields=50)
            except (UnicodeDecodeError, ValueError, RecursionError):   # deeply nested JSON too
                return self._send(api_error(400, "Bad request.") if api else text(400, "Bad request"), head=False)
            headers = {k.lower(): v for k, v in self.headers.items()}
            req = Request(self.command, url.path or "/", query, form, headers,
                          self.client_address[0], secure, headers.get("host", ""), json=payload)
            try:
                resp = app.dispatch(req)
            except Exception:
                log.exception("error on %s %s", self.command, req.path)
                msg = "Something went wrong. The portal log has the details."
                resp = api_error(500, msg) if req.is_api else text(500, msg)
            self._send(resp, head=self.command == "HEAD")

        do_GET = do_POST = do_HEAD = _handle

        def do_PUT(self) -> None:  # noqa: N802
            self._send(text(405, "Method not allowed"), head=False)

        do_DELETE = do_PATCH = do_OPTIONS = do_PUT

        def _send(self, resp: Response, head: bool, close: bool = False) -> None:
            self.send_response(resp.status)
            hdrs = {
                "Content-Type": resp.content_type,
                "Content-Length": str(len(resp.body)),
                "Cache-Control": resp.cache,
                "Content-Security-Policy": CSP,
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "same-origin",  # no-referrer makes browsers send Origin: null on POST
                "Cross-Origin-Opener-Policy": "same-origin",
                "Cross-Origin-Resource-Policy": "same-origin",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
                **resp.headers,
            }
            if secure:
                hdrs["Strict-Transport-Security"] = "max-age=31536000"
            if close:
                hdrs["Connection"] = "close"
                self.close_connection = True
            for k, v in hdrs.items():
                # No header splitting, whatever a handler put in a value.
                if _has_ctl(str(k)) or _has_ctl(str(v)):
                    log.warning("dropped a header with a control character: %s", str(k)[:40].encode())
                    continue
                self.send_header(k, v)
            self.end_headers()
            if not head:
                self.wfile.write(resp.body)

        def log_request(self, code="-", size="-") -> None:
            # Path only: no query string (digest links will carry tokens), no body (P4).
            path = urlsplit(self.path).path[:200]
            log.info("%s %s %s %s", self.client_address[0], self.command, path, code)

        def log_message(self, fmt, *args) -> None:
            log.debug(fmt, *args)

    return H


MAX_CONNECTIONS = 32


class _Server(ThreadingHTTPServer):
    """At most MAX_CONNECTIONS at once: one LAN client can't tie up every
    thread. Extra connections are closed straight away."""

    daemon_threads = True

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            log.warning("too many connections; closed one from %s", client_address[0])
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class _TLSServer(_Server):
    """TLS with the handshake in the request's own thread, so one slow
    client can't hold up accept() for everyone else."""

    ssl_context = None

    def get_request(self):
        sock, addr = super().get_request()
        sock.settimeout(30)
        return self.ssl_context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr


def serve(app: App, host: str, port: int, ssl_context=None) -> ThreadingHTTPServer:
    if ssl_context is None:
        server = _Server((host, port), make_handler(app))
    else:
        server = _TLSServer((host, port), make_handler(app, secure=True))
        server.ssl_context = ssl_context
    server.daemon_threads = True
    return server


__all__ = ["App", "Request", "Response", "redirect", "text", "serve", "HTTPStatus"]
