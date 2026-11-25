"""What the host reports about itself, for the Status page.

The portal has no Docker socket and sees no other container's data, so the
host's health-watch job (root, every 5 minutes) writes small key=value files
to /var/lib/bridgekeep/status, which the portal mounts read-only:

  bridge.env   Bridge health, Proton sign-in, mail sync, updates
  storage.env  sizes and free disk (scripts/storage.sh, same as ./bridgekeep status)
  host.env     Docker version; Bridgekeep version and commit; running Bridge version

Every value is untrusted text: it is length-capped here and escaped by the
templates. A missing file just means "not reported yet".
"""

from __future__ import annotations

import re
import time
from importlib import resources
from pathlib import Path

MAX_FILE = 8192
STALE_AFTER = 15 * 60          # three missed 5-minute runs
KEY = re.compile(r"^[a-z][a-z0-9_]{0,40}$")
LOW_FREE_FRACTION = 0.10
LOW_FREE_BYTES = 5 * 1024 ** 3


def read_env(path: Path) -> dict[str, str] | None:
    """key=value lines; None if the file is missing or unreadable."""
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FILE:
            return None
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    out: dict[str, str] = {}
    for line in text.splitlines():
        k, sep, v = line.partition("=")
        if sep and KEY.match(k):
            out[k] = "".join(ch for ch in v if ch.isprintable())[:200]
    return out


def _int(d: dict, k: str) -> int | None:
    try:
        return int(d.get(k, ""))
    except ValueError:
        return None


def size(n: int | None) -> str:
    """Decimal units with one decimal place, like ./bridgekeep status."""
    if n is None:
        return "unknown"
    for unit, div in (("TB", 10 ** 12), ("GB", 10 ** 9), ("MB", 10 ** 6), ("KB", 10 ** 3)):
        if n >= div:
            return f"{n / div:.1f} {unit}"
    return f"{n} B"


def _age(d: dict | None, now: float) -> tuple[float, bool]:
    ts = float(_int(d, "ts") or 0) if d else 0.0
    return ts, bool(ts) and now - ts > STALE_AFTER


def load(directory: str, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    d = Path(directory)
    bridge, storage, host = (read_env(d / n) for n in ("bridge.env", "storage.env", "host.env"))
    out: dict = {"reported": any(x is not None for x in (bridge, storage, host))}

    if bridge is not None:
        ts, stale = _age(bridge, now)
        out["bridge"] = {
            "health": bridge.get("bridge_health", "") or "unknown",
            "signed_in": bridge.get("signed_in") == "yes",
            "account": bridge.get("account", ""),
            "error": bridge.get("sign_in_error", ""),
            "messages": _int(bridge, "messages"),
            "messages_prev": _int(bridge, "messages_prev"),
            "update_scheduled": bridge.get("update_scheduled") == "yes",
            "update_when": bridge.get("update_when", ""),
            "update_waiting": bridge.get("update_waiting_version", ""),
            "last_update": bridge.get("last_update_line", ""),
            "paused": [x for x in bridge.get("paused", "").split() if x.replace("-", "").isalpha()],
            "ts": ts, "stale": stale,
        }

    if storage is not None:
        ts, stale = _age(storage, now)
        free, total = _int(storage, "disk_free_bytes"), _int(storage, "disk_total_bytes")
        low = storage.get("low") == "yes"
        if free is not None and total:
            low = low or free < total * LOW_FREE_FRACTION or free < LOW_FREE_BYTES
        rows = [("Mail (Bridge)", _int(storage, "bridge_bytes")), ("Analyzer", _int(storage, "analyzer_bytes"))]
        portal = _int(storage, "portal_bytes")
        if portal:
            rows.append(("Portal", portal))
        rows.append(("Images", _int(storage, "images_bytes")))
        out["storage"] = {
            "rows": [(label, size(n)) for label, n in rows],
            "free": size(free), "total": size(total), "path": storage.get("disk_path", ""),
            "used_pct": round(100 * (1 - free / total)) if free is not None and total else None,
            "low": low, "ts": ts, "stale": stale,
        }

    if host is not None:
        out["versions"] = versions_from(host)
        v = host.get("docker_version", "")
        major = _int({"m": v.split(".")[0]}, "m")
        out["docker"] = {"version": v, "old": major is not None and major < 28}
    return out


VERSION_TEXT = re.compile(r"[0-9A-Za-z.+-]{1,40}")
COMMIT_TEXT = re.compile(r"[0-9a-f]{7,40}")
TREE_TEXT = re.compile(r"[0-9a-f]{40}")


def versions_from(host: dict | None) -> dict:
    """Bridgekeep (VERSION file and git commit of the checkout) and the running Bridge."""
    host = host or {}
    def pick(key, pattern):
        v = host.get(key, "")
        return v if pattern.fullmatch(v) else ""
    # Setup records the git tree it built each image from; after a git pull the
    # checkout's tree differs until ./bridgekeep setup rebuilds.
    pending, known = [], False
    for svc in ("portal", "analyzer"):
        built, now = host.get(f"{svc}_built", ""), host.get(f"{svc}_checkout", "")
        if TREE_TEXT.fullmatch(built) and TREE_TEXT.fullmatch(now):
            known = True
            if built != now:
                pending.append(svc)
    return {"bridgekeep": pick("bridgekeep_version", VERSION_TEXT),
            "commit": pick("bridgekeep_commit", COMMIT_TEXT)[:7],
            "bridge": pick("bridge_version", VERSION_TEXT),
            "update_ready": pending, "trees_known": known}


def build_commit() -> str:
    """The Bridgekeep commit this portal image was built from (7 characters), or ""."""
    try:
        text = resources.files("portal").joinpath("BUILD_COMMIT").read_text().strip()
    except (OSError, ValueError):
        return ""
    return text[:7] if COMMIT_TEXT.fullmatch(text) else ""


def versions(directory: str) -> dict:
    return versions_from(read_env(Path(directory) / "host.env"))
