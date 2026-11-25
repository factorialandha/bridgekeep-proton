"""Client for the Bridge container's login broker: the only way the portal
signs in to Proton. HTTP/1.1 and JSON over a Unix socket in the broker-sock
volume, shared by the bridge and portal containers only.

The broker owns Bridge's CLI and the Bridge password; the portal only ever
sends what the admin typed (address, password, 2FA code, mailbox password)
and reads back a small status object. Nothing the broker says is trusted:
unknown states read as "error", strings are cut to printable text, and the
human-verification link must be an https link on proton.me.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import stat
from urllib.parse import urlsplit

STATES = ("signed_out", "signing_in", "waiting_2fa", "waiting_mailbox_password", "waiting_human",
          "signed_in", "error")
MAX_REPLY = 16 * 1024


class Unavailable(Exception):
    """The broker isn't there or didn't answer; shown as is."""


def _clean(v, n: int) -> str:
    return "".join(ch for ch in str(v or "") if ch.isprintable())[:n]


def _hv_url(v) -> str:
    url = _clean(v, 500)
    try:
        u = urlsplit(url)
    except ValueError:
        return ""
    host = (u.hostname or "").lower()
    if u.scheme != "https" or u.username or u.password or u.port not in (None, 443):
        return ""
    return url if host == "proton.me" or host.endswith(".proton.me") else ""


def status_view(data) -> dict:
    """The broker's reply as the portal shows it: known keys only."""
    if not isinstance(data, dict):
        data = {}
    state = data.get("state") if data.get("state") in STATES else "error"
    out = {"state": state, "account": _clean(data.get("account"), 254), "error": _clean(data.get("error"), 300),
           "hv_url": _hv_url(data.get("hv_url")) if state == "waiting_human" else "",
           "step_expires": None}
    exp = data.get("step_expires")
    if isinstance(exp, int) and not isinstance(exp, bool) and 0 < exp < 2 ** 40 and state.startswith("waiting"):
        out["step_expires"] = exp
    if state == "error" and not out["error"]:
        out["error"] = "The sign-in service answered with something the portal doesn't understand."
    return out


class _Conn(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("broker", timeout=timeout)
        self._path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect(self._path)
        except OSError:
            s.close()
            raise
        self.sock = s


class Broker:
    def __init__(self, path: str, timeout: float = 20):
        self.path = path
        self.timeout = timeout

    def present(self) -> bool:
        try:
            return stat.S_ISSOCK(os.lstat(self.path).st_mode)
        except OSError:
            return False

    def call(self, method: str, endpoint: str, body: dict | None = None) -> tuple[int, dict]:
        """(HTTP status, cleaned status object). Unavailable when the broker
        can't be reached or answers with something that isn't JSON."""
        if not self.present():
            raise Unavailable("The sign-in service isn't running. Check the Status page.")
        data = json.dumps(body).encode() if body is not None else None
        conn = _Conn(self.path, self.timeout)
        try:
            headers = {"Content-Type": "application/json"} if data is not None else {}
            conn.request(method, endpoint, body=data, headers=headers)
            r = conn.getresponse()
            raw = r.read(MAX_REPLY + 1)
        except (OSError, http.client.HTTPException) as e:
            raise Unavailable("The sign-in service didn't answer. Check the Status page, then try again.") from e
        finally:
            data = body = None
            conn.close()
        if len(raw) > MAX_REPLY:
            raise Unavailable("The sign-in service answered with too much data.")
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise Unavailable("The sign-in service answered with something the portal doesn't understand.")
        return r.status, status_view(parsed)

    def status(self) -> dict:
        return self.call("GET", "/status")[1]
