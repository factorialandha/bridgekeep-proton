"""One-click unsubscribe (RFC 8058), only where it is safe and will work.

The owner asked: "make sure we aren't verifying anything" and "only show the
unsubscribe button where it should work". So:

* The analyzer only *records* an offer, never contacts anyone. An offer is
  recorded when all of these hold:
  - DMARC passed for the From domain (Proton's own header) and a passing
    DKIM signature's d= is that domain or a parent of it;
  - the message has ``List-Unsubscribe-Post: List-Unsubscribe=One-Click``
    and an https URL in ``List-Unsubscribe`` whose host is under that d=;
  - the model did not call it spam or phishing, and nothing else looked off
    (no text aimed at AI filters, no lookalike domain).
  A mailto address is recorded only to *show* it; nothing here sends mail
  (security review: sending as the owner stays out of every container).
* The unsubscribe service (``analyzer unsubscribe-service``, its own
  container and network) acts only when the portal asks, by decision id
  alone. It re-reads the offer from the decision log itself, re-checks it,
  and makes exactly one POST with ``List-Unsubscribe=One-Click``: https on
  port 443, no IP literals, the name resolved once and refused if any
  address is not public, the connection made to that exact address (so DNS
  rebinding cannot redirect it), no redirects, no cookies, a 10-second
  timeout, at most 4 KB read and thrown away. One attempt per message and
  at most 20 a day. No images, no other links, no GET, ever.
"""

from __future__ import annotations

import datetime as dt
import http.client
import ipaddress
import json
import logging
import os
import re
import socket
import sqlite3
import ssl
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .lists import PUBLIC_SUFFIXES

log = logging.getLogger(__name__)

ONE_CLICK_BODY = b"List-Unsubscribe=One-Click"
MAX_HEADER = 2048
MAX_URL = 1024
TIMEOUT = 10
MAX_RESPONSE = 4096
PER_DAY = 20
USER_AGENT = "Mozilla/5.0 (compatible; mail-unsubscribe)"
_ANGLE = re.compile(r"<([^<>\s]{1,2048})>")
_HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_MAILTO = re.compile(r"^mailto:([A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253})(\?.*)?$", re.I)


@dataclass
class Offer:
    method: str              # "one_click" or "mailto" (mailto: shown, never sent)
    url: str = ""
    mailto: str = ""
    host: str = ""
    dkim_domain: str = ""


def _under(host: str, domain: str) -> bool:
    return bool(host and domain) and (host == domain or host.endswith("." + domain))


def check_url(url: str) -> str | None:
    """The host of a URL we are willing to POST to, or None."""
    if len(url) > MAX_URL or not url.isascii() or any(c.isspace() for c in url):
        return None
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    if parts.scheme != "https" or parts.username or parts.password or port not in (None, 443):
        return None
    host = (parts.hostname or "").lower().rstrip(".")
    try:
        ipaddress.ip_address(host.strip("[]"))
        return None                         # no IP literals
    except ValueError:
        pass
    return host if _HOST.match(host) else None


def parse(list_unsubscribe: str, list_unsubscribe_post: str) -> tuple[str, str, bool]:
    """(first https URL, first mailto address, one-click header present)."""
    https = mailto = ""
    for target in _ANGLE.findall((list_unsubscribe or "")[:MAX_HEADER]):
        if not https and target.lower().startswith("https:") and check_url(target):
            https = target
        m = _MAILTO.match(target)
        if not mailto and m:
            mailto = m.group(1).lower()
    one_click = " ".join((list_unsubscribe_post or "").split()).lower() == "list-unsubscribe=one-click"
    return https, mailto, one_click


def _aligned_dkim(dkim: list[str], from_domain: str) -> str:
    """The longest passing DKIM d= that is the From domain or a parent of it."""
    best = ""
    for item in dkim:
        result, _, d = item.partition(":")
        d = d.lower().rstrip(".")
        if (result == "pass" and "." in d and d not in PUBLIC_SUFFIXES and _under(from_domain, d)
                and len(d) > len(best)):
            best = d
    return best


def offer(ex, label: str | None, action: str, injections: list, lookalike: bool) -> Offer | None:
    """What the portal may offer for this message, or None (no button)."""
    if not ex.auth.verified or ex.from_count != 1 or injections or lookalike or action != "keep":
        return None
    if label in ("spam", "phishing"):
        return None
    d = _aligned_dkim(ex.auth.dkim, ex.from_domain)
    if not d:
        return None
    https, mailto, one_click = parse(ex.list_unsubscribe, ex.list_unsubscribe_post)
    if https and one_click:
        host = check_url(https)
        if host and _under(host, d):
            return Offer("one_click", url=https, host=host, dkim_domain=d)
    if mailto and _under(mailto.rpartition("@")[2], d):
        return Offer("mailto", mailto=mailto, dkim_domain=d)
    return None


# -- the service ---------------------------------------------------------------

class Refused(Exception):
    """Not sent; the message says why, without echoing sender text."""


def _public_addresses(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        raise Refused("the sender's address could not be looked up") from None
    addrs = []
    for *_, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0].split("%")[0])
        if (not ip.is_global or ip.is_multicast or ip.is_private or ip.is_loopback
                or ip.is_link_local or ip.is_reserved or ip.is_unspecified):
            # Any private answer refuses the whole name: a sender's DNS must
            # not be able to point the request into the owner's home network.
            raise Refused("the sender's address points into a private network")
        addrs.append(str(ip))
    if not addrs:
        raise Refused("the sender's address could not be looked up")
    return addrs


class _PinnedHTTPS(http.client.HTTPSConnection):
    """HTTPS to one already-checked IP, with SNI and certificate checks for the name."""

    def __init__(self, host: str, ip: str, context: ssl.SSLContext) -> None:
        super().__init__(host, 443, timeout=TIMEOUT, context=context)
        self._ip = ip
        self._ctx = context

    def connect(self) -> None:
        sock = socket.create_connection((self._ip, 443), timeout=TIMEOUT)
        self.sock = self._ctx.wrap_socket(sock, server_hostname=self.host)


def post_one_click(url: str, *, resolve=_public_addresses, context: ssl.SSLContext | None = None,
                   connection=_PinnedHTTPS) -> int:
    """Exactly one POST. Returns the HTTP status; raises Refused."""
    host = check_url(url)
    if host is None:
        raise Refused("the unsubscribe link is not a plain https address")
    ip = resolve(host)[0]
    parts = urlsplit(url)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    conn = connection(host, ip, context or ssl.create_default_context())
    try:
        conn.request("POST", path, body=ONE_CLICK_BODY, headers={
            "Host": host, "User-Agent": USER_AGENT, "Accept": "*/*",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(ONE_CLICK_BODY)), "Connection": "close"})
        resp = conn.getresponse()
        resp.read(MAX_RESPONSE)              # read a little, keep nothing
        return resp.status
    except (OSError, http.client.HTTPException, ssl.SSLError) as e:
        raise Refused(f"the sender's server did not answer ({type(e).__name__})") from None
    finally:
        conn.close()


class Service:
    """State: one attempt per decision, PER_DAY a day, in its own small file."""

    def __init__(self, db_path: str, state_file: str, post=post_one_click, now=None) -> None:
        self.db_path = db_path
        self.state_file = Path(state_file)
        self.post = post
        self.now = now or (lambda: dt.datetime.now(dt.timezone.utc))
        self.lock = threading.Lock()

    def _state(self) -> dict:
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self, state: dict) -> None:
        tmp = self.state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(state), encoding="utf-8")
        os.replace(tmp, self.state_file)

    def _offer(self, decision_id: int) -> sqlite3.Row | None:
        db = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            return db.execute(
                "SELECT u.method, u.url, u.host, u.dkim_domain, d.label, d.verified, d.from_domain "
                "FROM unsubscribe u JOIN decisions d ON d.id = u.decision_id WHERE u.decision_id=?",
                (decision_id,)).fetchone()
        finally:
            db.close()

    def handle(self, decision_id: int) -> dict:
        with self.lock:
            state = self._state()
            today = self.now().strftime("%Y-%m-%d")
            done = state.setdefault("done", {})
            if str(decision_id) in done:
                return {"result": "refused", "detail": "already tried for this message"}
            if state.get("day") != today:
                state["day"], state["count"] = today, 0
            if state.get("count", 0) >= PER_DAY:
                return {"result": "refused", "detail": f"at most {PER_DAY} unsubscribes a day"}
            try:
                row = self._offer(decision_id)
            except sqlite3.Error:
                return {"result": "failed", "detail": "the decision log could not be read"}
            # Re-check everything: never trust that the row was written by us.
            if (row is None or row["method"] != "one_click" or not row["verified"]
                    or row["label"] in ("spam", "phishing") or check_url(row["url"] or "") != row["host"]
                    or not _under(row["host"] or "", row["dkim_domain"] or "")
                    or not _under(row["from_domain"] or "", row["dkim_domain"] or "")):
                return {"result": "refused", "detail": "no one-click unsubscribe for this message"}
            done[str(decision_id)] = today          # one attempt, whatever happens next
            state["count"] = state.get("count", 0) + 1
            self._save(state)
        host = row["host"]
        try:
            status = self.post(row["url"])
        except Refused as e:
            result = {"result": "failed", "detail": str(e), "host": host}
        else:
            if 200 <= status < 300:
                result = {"result": "done", "detail": "the sender accepted the unsubscribe", "host": host}
            elif 300 <= status < 400:
                result = {"result": "failed", "detail": "the sender answered with a redirect; not followed",
                          "host": host}
            else:
                result = {"result": "failed", "detail": f"the sender answered {status}", "host": host}
        log.info("unsubscribe decision=%d host=%s result=%s", decision_id, host, result["result"])
        return result


def serve(service: Service, address: str = "0.0.0.0", port: int = 8025) -> None:
    httpd = make_server(service, address, port)
    log.info("unsubscribe service listening on %s:%d", address, port)
    httpd.serve_forever()


def make_server(service: Service, address: str, port: int) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        server_version = "unsubscribe"
        sys_version = ""

        def log_message(self, *args) -> None:   # requests are logged by Service, not here
            pass

        def _send(self, code: int, body: dict) -> None:
            raw = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health":
                self._send(200, {"ok": True})
            else:
                self._send(404, {"result": "refused", "detail": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/unsubscribe":
                return self._send(404, {"result": "refused", "detail": "not found"})
            try:
                n = int(self.headers.get("Content-Length", "0"))
                req = json.loads(self.rfile.read(min(n, 256)) or b"{}") if 0 < n <= 256 else None
                decision_id = req.get("decision_id") if isinstance(req, dict) else None
                if set(req) != {"decision_id"} or isinstance(decision_id, bool) \
                        or not isinstance(decision_id, int) or decision_id <= 0:
                    raise ValueError
            except (ValueError, TypeError, AttributeError):
                return self._send(400, {"result": "refused", "detail": 'send {"decision_id": N} only'})
            self._send(200, service.handle(decision_id))

    return ThreadingHTTPServer((address, port), Handler)
