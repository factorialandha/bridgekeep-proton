"""Operational alerts, handed to the host's notifier (docs/alerts.md).

The analyzer never talks to Discord itself: it drops one small file per
alert into /run/bridgekeep/alerts and the host sends it. Alerts carry status
only, never anything from a message. Writing is best effort: a missing
folder (an older host) or any OSError is logged and ignored.
"""

from __future__ import annotations

import logging
import os
import re
import time

log = logging.getLogger("analyzer.alerts")

ALERT_DIR = "/run/bridgekeep/alerts"
EVENTS = frozenset({"budget_cap", "login_expired", "health_failed", "health_recovered",
                    "analyzer_mode_changed", "move_cap", "imap_refused"})
MAX_DETAIL = 200
MAX_FILE = 1024


def _clean(detail: str) -> str:
    one_line = re.sub(r"[^\x21-\x7e]+", " ", detail).strip()
    return one_line[:MAX_DETAIL]


def send(event: str, detail: str, directory: str = ALERT_DIR) -> bool:
    if event not in EVENTS:
        raise ValueError(f"unknown alert event {event!r}")
    body = f"event={event}\ndetail={_clean(detail)}\n".encode("ascii")
    assert len(body) <= MAX_FILE
    name = f"{event}-{time.time_ns()}-{os.getpid()}"
    tmp = os.path.join(directory, name + ".tmp")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
        try:
            os.write(fd, body)
        finally:
            os.close(fd)
        os.replace(tmp, os.path.join(directory, name + ".alert"))
    except OSError as e:
        log.warning("could not queue the %s alert: %s", event, type(e).__name__)
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False
    log.info("queued the %s alert", event)
    return True
