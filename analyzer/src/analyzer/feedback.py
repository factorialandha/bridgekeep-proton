"""Corrections from the admin portal ("this isn't spam", "this is spam").

The portal appends one JSON object per line to ``<portal_dir>/feedback.jsonl``:

    {"message_key": "INBOX:7:123", "label": "legitimate", "scope": "message",
     "ts": 1764000000, "by": "portal"}

and rotates the file to ``feedback.jsonl.1`` at 1 MB. Clearing an answer in
the portal appends the same line with ``"label": "withdrawn"``, which deletes
the stored correction for that message_key (as if it had never been given). The analyzer reads only
what is new since last time (by inode and offset, kept in the state table),
with the same hardened open as the list files. Lines over 1 KB, malformed
lines and unknown labels are counted and skipped, never echoed.

What a correction does:
* It is stored with the sender domain and DMARC result of the decision it
  corrects, so later mail from that domain can use it.
* For DMARC-verified mail only, the model is told how the recipient has
  answered for that domain before (for free-mail and shared senders such as
  gmail.com or sendgrid.net: that exact address) (``classify`` puts this outside the
  untrusted-email markers).
* Code rule: a verified domain with 2 or more "not spam" answers and no
  "spam" answers is never quarantined, only sent to review at most.
Sender- and domain-wide choices (always trust, always junk) are list
entries in portal.yaml, not feedback.
"""

from __future__ import annotations

import json
import logging
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .classify import LABELS
from .lists import shared_domain
from .store import Store

log = logging.getLogger(__name__)

FILE_NAME = "feedback.jsonl"
ROTATED = FILE_NAME + ".1"
MAX_LINE = 1024
MAX_READ = 1024 * 1024
SCOPES = ("message", "sender", "domain")
NOT_SPAM = ("legitimate", "promotional")
SPAM = ("spam", "phishing")
WITHDRAWN = "withdrawn"  # the portal cleared its answer for this message
TRUSTED_AFTER = 2        # "not spam" answers before a verified domain is never quarantined
STATE_KEY = "feedback:pos"


@dataclass
class Hint:
    sender: str          # the domain, or the exact address for free-mail and shared senders
    not_spam: int
    spam: int

    @property
    def trusted(self) -> bool:
        return self.not_spam >= TRUSTED_AFTER and self.spam == 0

    def sentence(self) -> str:
        return (f"The recipient has previously marked mail from {self.sender} (DMARC verified) as not spam "
                f"{times(self.not_spam)} and as spam {times(self.spam)}.")


def plural(n: int, word: str, many: str | None = None) -> str:
    return f"{n:,} {word if n == 1 else (many or word + 's')}"


def times(n: int) -> str:
    return {0: "never", 1: "once", 2: "twice"}.get(n, f"{n:,} times")


def _open(path: Path):
    """A regular file opened without following links, or None."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    f = os.fdopen(fd, "rb")
    if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
        f.close()
        return None
    return f


def parse_line(line: bytes) -> tuple[str, int, str, str] | None:
    if len(line) > MAX_LINE:
        return None
    try:
        obj = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(obj, dict):
        return None
    key, label, scope, ts = obj.get("message_key"), obj.get("label"), obj.get("scope", "message"), obj.get("ts")
    if not isinstance(key, str) or not 0 < len(key) <= 200 or not key.isprintable():
        return None
    if (label not in LABELS and label != WITHDRAWN) or scope not in SCOPES:
        return None
    if isinstance(ts, bool) or not isinstance(ts, int) or ts < 0:
        return None
    return key, ts, label, scope


class Feedback:
    def __init__(self, store: Store, portal_dir: str) -> None:
        self.store = store
        self.dir = Path(portal_dir) if portal_dir else None
        self.bad_lines = 0

    def _pos(self) -> tuple[int, int]:
        raw = self.store.get_state(STATE_KEY) or "0:0"
        ino, off = raw.split(":")
        return int(ino), int(off)

    def step(self) -> int:
        """Read new corrections. Returns how many were stored."""
        if self.dir is None:
            return 0
        ino, off = self._pos()
        f = _open(self.dir / FILE_NAME)
        if f is None:
            return 0
        added = 0
        with f:
            cur = os.fstat(f.fileno()).st_ino
            if cur != ino:
                # Rotated since last time: finish the old file first.
                old = _open(self.dir / ROTATED)
                if old is not None and ino:
                    with old:
                        if os.fstat(old.fileno()).st_ino == ino:
                            added += self._read(old, off)[0]
                ino, off = cur, 0
            n, off = self._read(f, off)
            added += n
        self.store.set_state(STATE_KEY, f"{ino}:{off}")
        if added:
            log.info("%s from the portal", plural(added, "correction"))
        return added

    def _read(self, f, off: int) -> tuple[int, int]:
        size = os.fstat(f.fileno()).st_size
        if off > size:                      # truncated in place: start again
            off = 0
        f.seek(off)
        chunk = f.read(MAX_READ)
        end = chunk.rfind(b"\n")
        if end < 0:
            return 0, off                   # nothing complete yet
        added = 0
        for line in chunk[:end].split(b"\n"):
            if not line.strip():
                continue
            item = parse_line(line)
            if item is None:
                self.bad_lines += 1
                continue
            if item[2] == WITHDRAWN:
                self.store.remove_feedback(item[0])
            else:
                self.store.add_feedback(*item)
            added += 1
        return added, off + end + 1

    def hint(self, domain: str, address: str, verified: bool) -> Hint | None:
        """Past answers for a verified sender, or None. Keyed by domain, except
        for free-mail and shared-sending domains, where anyone can get a
        verified address: there only the exact address counts."""
        if not verified or not domain:
            return None
        by_address = shared_domain(domain)
        sender = address if by_address else domain
        if not sender:
            return None
        not_spam, spam = self.store.sender_feedback(sender, by_address)
        if not (not_spam or spam):
            return None
        return Hint(sender, not_spam, spam)


def agreement(store: Store) -> dict:
    """How often the model agreed with the corrections, for `analyzer feedback`."""
    rows = store.feedback_rows()
    judged = [r for r in rows if r["model_label"]]
    agree = sum(1 for r in judged
                if (r["label"] in SPAM) == (r["model_label"] in SPAM))
    return {"corrections": len(rows), "with_model_answer": len(judged), "model_agreed": agree,
            "said_spam_was_fine": sum(1 for r in judged if r["label"] in NOT_SPAM and r["model_label"] in SPAM),
            "missed_spam": sum(1 for r in judged if r["label"] in SPAM and r["model_label"] not in SPAM)}
