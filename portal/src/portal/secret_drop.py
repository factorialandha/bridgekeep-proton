"""The portal's write-only drop box for the Claude API key and the Discord
webhook (security review, 2026-11-24).

The portal never holds or reads back a secret. It writes one small request
file to its own folder (/secret-requests, the host's
/var/lib/bridgekeep/secret-requests, 10003 0700); root's
scripts/secret-requests.sh checks it within 5 minutes, alerts the current
Discord channel, installs it, and reports the outcome in the host status
folder (secrets.env: set or off, the last 4 characters, when, the result).
"""

from __future__ import annotations

import os
import re
import secrets
from pathlib import Path

from . import hoststatus

SECRETS = {
    "anthropic_api_key": ("Claude API key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,200}"),
                          "That isn't a Claude API key. It starts with sk-ant-."),
    "discord_webhook": ("Discord webhook", re.compile(
        r"https://(discord\.com|discordapp\.com|canary\.discord\.com|ptb\.discord\.com)"
        r"/api/webhooks/[0-9]{15,22}/[A-Za-z0-9_-]{40,100}"),
        "That isn't a Discord webhook URL. It looks like https://discord.com/api/webhooks/<numbers>/<token>."),
}


VENDOR_FIELDS = ("provider", "model", "endpoint", "price_in", "price_out")


class DropError(Exception):
    """Shown to the admin as is: never contains the value."""


class SecretDrop:
    def __init__(self, directory: str, status_dir: str) -> None:
        self.dir = Path(directory)
        self.status_dir = Path(status_dir)

    def writable(self) -> bool:
        try:
            return os.path.isdir(self.dir) and not os.path.islink(self.dir) and os.access(self.dir, os.W_OK)
        except OSError:
            return False

    def state(self) -> dict:
        """What the host last reported, plus requests still waiting."""
        env = hoststatus.read_env(self.status_dir / "secrets.env") or {}
        out = {}
        for name in (*SECRETS, "test_alert"):
            out[name] = {
                "on": env.get(name) == "set",
                "last4": re.sub(r"[^A-Za-z0-9_-]", "", env.get(f"{name}_last4", ""))[:4],
                "when": hoststatus._int(env, f"{name}_when"),
                "result": env.get(f"{name}_result", ""),
                "pending": self.pending(name),
            }
        out["ai_vendor"] = {
            "provider": env.get("ai_vendor_provider", ""), "model": env.get("ai_vendor_model", ""),
            "when": hoststatus._int(env, "ai_vendor_when"), "result": env.get("ai_vendor_result", ""),
            "pending": self.pending("ai_vendor"),
        }
        return out

    def pending(self, name: str) -> bool:
        try:
            return any(n.startswith(name + ".") and n.endswith(".req") for n in os.listdir(self.dir))
        except OSError:
            return False

    def request(self, name: str, action: str, value: str = "") -> str:
        """Leave one request for the host. Returns its id."""
        if name == "test_alert":
            if action != "test":
                raise DropError("Not a request the portal can make.")
        elif name not in SECRETS or action not in ("set", "remove"):
            raise DropError("Not a request the portal can make.")
        if action == "set":
            value = value.strip()
            if not SECRETS[name][1].fullmatch(value):
                raise DropError(SECRETS[name][2])
        body = f"value={value}\n" if action == "set" else ""
        try:
            return self._write(name, action, body)
        finally:
            body = value = ""          # drop the references

    def request_vendor(self, fields: dict, key: str = "") -> str:
        """Switch the AI vendor (fields from vendors.check, key from vendors.check_key)."""
        body = "".join(f"{k}={fields[k]}\n" for k in VENDOR_FIELDS) + (f"value={key}\n" if key else "")
        try:
            return self._write("ai_vendor", "set", body)
        finally:
            body = key = ""

    def _write(self, name: str, action: str, body: str) -> str:
        if "\r" in body or len(body) > 900:
            raise DropError("Not a request the portal can make.")
        if not self.writable():
            raise DropError("The portal can't reach the host's drop box yet. Run ./bridgekeep setup on the host.")
        if self.pending(name):
            raise DropError("A change is already waiting for the host. It's applied within 5 minutes.")
        rid = secrets.token_hex(8)
        body = f"secret={name}\naction={action}\nid={rid}\n" + body
        tmp, final = self.dir / f".{name}.{rid}.tmp", self.dir / f"{name}.{rid}.req"
        old = os.umask(0o077)
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(body.encode("utf-8"))
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, final)
        except OSError as e:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise DropError(f"Couldn't save ({e.strerror}).") from None
        finally:
            os.umask(old)
            body = ""
        return rid
