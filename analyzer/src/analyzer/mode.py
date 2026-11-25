"""Shadow or live: the one switch that lets the analyzer move mail.

The portal writes ``<portal_dir>/mode.json`` after step-up and an audit
entry (only for the live direction; going back to shadow, or Pause, never
needs step-up). On the host, ``./bridgekeep analyzer shadow`` writes the
same file, so live mode can be turned off with the portal down:

    {"mode": "live", "ts": 1764000000, "by": "portal"}

Every failure means shadow: a missing file, a link, something that is not a
regular file, more than 4 KB, bad JSON, or any mode other than exactly
"live". PAUSE wins over live. Both the analyzer and the IMAP proxy read this
file, each for itself, before every move: the proxy never takes the
analyzer's word for it (security review of live mode, item 4).
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass

FILE_NAME = "mode.json"
PAUSE_NAME = "PAUSE"
MAX_BYTES = 4096


@dataclass(frozen=True)
class Requested:
    mode: str            # "live" or "shadow"
    since: int | None    # when live was switched on (unix), None for shadow
    problem: str | None  # why the file was not taken as live, for health.json


SHADOW = Requested("shadow", None, None)


def _read_small(path: str) -> bytes | None:
    """The bytes of a small regular file, opened without following links, or None."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return None
    except OSError:
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_BYTES:
            raise OSError("not a small regular file")
        data = os.read(fd, MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise OSError("too large")
        return data
    finally:
        os.close(fd)


def requested(portal_dir: str) -> Requested:
    """What the portal (or the host) asked for. Never raises."""
    if not portal_dir:
        return SHADOW
    try:
        data = _read_small(os.path.join(portal_dir, FILE_NAME))
    except OSError:
        return Requested("shadow", None, "mode.json can't be read safely, so the analyzer stays in shadow mode")
    if data is None:
        return SHADOW
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return Requested("shadow", None, "mode.json is not valid, so the analyzer stays in shadow mode")
    if not isinstance(obj, dict) or obj.get("mode") != "live":
        return SHADOW
    ts = obj.get("ts")
    if isinstance(ts, bool) or not isinstance(ts, int) or ts <= 0:
        return Requested("shadow", None, "mode.json has no valid time, so the analyzer stays in shadow mode")
    return Requested("live", ts, None)


def paused(portal_dir: str, extra_pause_file: str = "") -> bool:
    """The kill switch. Anything odd about it counts as paused."""
    try:
        for p in ([os.path.join(portal_dir, PAUSE_NAME)] if portal_dir else []) + (
                [extra_pause_file] if extra_pause_file else []):
            if os.path.lexists(p):
                return True
    except OSError:
        return True
    return False


def live_allowed(portal_dir: str, extra_pause_file: str = "") -> Requested:
    """Live only when asked for and not paused; read fresh on every call."""
    r = requested(portal_dir)
    if r.mode == "live" and paused(portal_dir, extra_pause_file):
        return Requested("shadow", None, "paused")
    return r


def mailbox(name: str) -> str:
    """The Bridge name of one of the analyzer's own folders: Proton folders
    appear under Folders/ in IMAP."""
    return name if name.startswith("Folders/") else f"Folders/{name}"
