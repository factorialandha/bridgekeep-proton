"""Admin authentication: claim code (P6), argon2id password and TOTP (P7),
sessions with CSRF tokens (P10), step-up (P8) and login backoff (P7)."""

from __future__ import annotations

import base64
import functools
import gzip
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from importlib import resources

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from . import totp
from .db import DB

# argon2id with RFC 9106's second recommended profile (64 MiB, 3 passes):
# well under a second on a Raspberry Pi 4, and inside the 192 MB memory limit.
_hasher = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2)
_DUMMY_HASH = _hasher.hash(secrets.token_hex(16))

MIN_PASSWORD = 12            # with an authenticator
MIN_PASSWORD_ALONE = 15      # password only (security lead, after the owner made TOTP optional)
BANNED_WORDS = ("bridgekeep", "proton")
MAX_PASSWORD = 1024
FREE_ATTEMPTS = 3
FREE_ATTEMPTS_GLOBAL = 20
MAX_LOCK = 15 * 60


def hash_password(pw: str) -> str:
    return _hasher.hash(pw)


def check_password(pw_hash: str | None, pw: str) -> bool:
    """Constant work whether or not an admin exists."""
    try:
        return _hasher.verify(pw_hash or _DUMMY_HASH, pw) and pw_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


@functools.lru_cache(maxsize=1)
def _common() -> frozenset[str]:
    data = resources.files("portal").joinpath("data", "common-passwords.txt.gz").read_bytes()
    return frozenset(gzip.decompress(data).decode("utf-8", "replace").lower().split())


def password_problem(pw: str, confirm: str, with_totp: bool) -> str | None:
    need = MIN_PASSWORD if with_totp else MIN_PASSWORD_ALONE
    if len(pw) < need:
        extra = "" if with_totp else " (or 12 with an authenticator app)"
        return f"Use at least {need} characters{extra}. A few unrelated words work well."
    if len(pw) > MAX_PASSWORD:
        return "That password is too long."
    low = pw.lower()
    if low in _common() or any(w in low for w in BANNED_WORDS):
        return "That password is too easy to guess. Pick a few unrelated words instead."
    if pw != confirm:
        return "The two passwords don't match."
    return None


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


# --- claim code (P6) ---------------------------------------------------------

def new_claim_code(db: DB, ttl: int, now: float | None = None) -> str:
    """Issue a fresh one-time code, replacing any earlier one. Only its hash is stored."""
    raw = base64.b32encode(secrets.token_bytes(15)).decode()  # 24 chars, 120 bits
    code = "-".join(raw[i:i + 4] for i in range(0, 24, 4))
    db.execute("INSERT INTO claim (id, code_hash, expires) VALUES (1, ?, ?) "
               "ON CONFLICT(id) DO UPDATE SET code_hash = excluded.code_hash, expires = excluded.expires",
               (_sha(_norm_code(code)), (now or time.time()) + ttl))
    return code


def _norm_code(code: str) -> str:
    return "".join(ch for ch in code.upper() if ch.isalnum())


def check_claim_code(db: DB, code: str, now: float | None = None) -> bool:
    row = db.one("SELECT code_hash, expires FROM claim WHERE id = 1")
    if row is None or row["expires"] < (now or time.time()):
        return False
    return hmac.compare_digest(row["code_hash"], _sha(_norm_code(code)))


def consume_claim_code(db: DB) -> None:
    db.execute("DELETE FROM claim")


def is_claimed(db: DB) -> bool:
    return db.one("SELECT 1 FROM admin WHERE id = 1") is not None


def has_totp(db: DB) -> bool:
    row = db.one("SELECT totp_secret FROM admin WHERE id = 1")
    return bool(row and row["totp_secret"])


def set_totp(db: DB, secret: str, step: int = -1) -> None:
    db.execute("UPDATE admin SET totp_secret = ?, totp_last_step = ?, updated = ? WHERE id = 1",
               (secret, step, time.time()))


def create_admin(db: DB, pw: str, totp_secret: str, step: int) -> None:
    now = time.time()
    with db.lock:
        db.execute("INSERT INTO admin (id, pw_hash, totp_secret, totp_last_step, created, updated) "
                   "VALUES (1, ?, ?, ?, ?, ?)", (hash_password(pw), totp_secret, step, now, now))
        db.execute("DELETE FROM claim")
        db.execute("DELETE FROM sessions WHERE kind = 'claim'")


def reset_admin(db: DB) -> None:
    """Host CLI only (P7): forget the admin and every session."""
    with db.lock:
        db.execute("DELETE FROM admin")
        db.execute("DELETE FROM sessions")


def verify_admin(db: DB, pw: str, code: str, now: float | None = None) -> bool:
    """The password, and the TOTP code when one is enrolled; the step is
    recorded so a code works once."""
    row = db.one("SELECT pw_hash, totp_secret, totp_last_step FROM admin WHERE id = 1")
    pw_ok = check_password(row["pw_hash"] if row else None, pw)
    if not row or not pw_ok:
        return False
    if not row["totp_secret"]:
        return True
    step = totp.verify(row["totp_secret"], code, row["totp_last_step"], now)
    if step is None:
        return False
    db.execute("UPDATE admin SET totp_last_step = ? WHERE id = 1", (step,))
    return True


# --- backoff (P7) ------------------------------------------------------------

def locked_for(db: DB, key: str, now: float | None = None) -> int:
    row = db.one("SELECT locked_until FROM failures WHERE key = ?", (key,))
    left = (row["locked_until"] if row else 0) - (now or time.time())
    return max(0, int(left + 0.999))


def record_failure(db: DB, key: str, now: float | None = None, free: int = FREE_ATTEMPTS) -> int:
    """Exponential backoff after `free` failures: 1 s, 2 s, 4 s ... up to 15 min."""
    now = now or time.time()
    row = db.one("SELECT count, last FROM failures WHERE key = ?", (key,))
    # A quiet day forgives old failures.
    count = (row["count"] if row and now - row["last"] < 86400 else 0) + 1
    lock = 0 if count <= free else min(MAX_LOCK, 2 ** min(count - free - 1, 20))
    db.execute("INSERT INTO failures (key, count, locked_until, last) VALUES (?,?,?,?) "
               "ON CONFLICT(key) DO UPDATE SET count = excluded.count, locked_until = excluded.locked_until, "
               "last = excluded.last", (key, count, now + lock, now))
    return lock


def clear_failures(db: DB, key: str) -> None:
    db.execute("DELETE FROM failures WHERE key = ?", (key,))


# --- sessions (P10) ----------------------------------------------------------

@dataclass
class Session:
    token: str
    id_hash: str
    kind: str
    csrf: str
    created: float
    last_seen: float
    reauth_at: float
    pending_totp: str | None
    is_new: bool = False


def new_session(db: DB, kind: str, ip: str) -> Session:
    token = secrets.token_urlsafe(32)
    now = time.time()
    s = Session(token, _sha(token), kind, secrets.token_urlsafe(32), now, now, 0.0, None, True)
    db.execute("INSERT INTO sessions (id_hash, kind, csrf, created, last_seen, ip) VALUES (?,?,?,?,?,?)",
               (s.id_hash, kind, s.csrf, now, now, ip[:64]))
    return s


def load_session(db: DB, token: str, idle: int, absolute: int, now: float | None = None) -> Session | None:
    if not token or len(token) > 100:
        return None
    now = now or time.time()
    row = db.one("SELECT * FROM sessions WHERE id_hash = ?", (_sha(token),))
    if row is None:
        return None
    if now - row["last_seen"] > idle or now - row["created"] > absolute:
        db.execute("DELETE FROM sessions WHERE id_hash = ?", (row["id_hash"],))
        return None
    db.execute("UPDATE sessions SET last_seen = ? WHERE id_hash = ?", (now, row["id_hash"]))
    return Session(token, row["id_hash"], row["kind"], row["csrf"], row["created"], now,
                   row["reauth_at"], row["pending_totp"])


def upgrade_session(db: DB, old: Session, kind: str, ip: str) -> Session:
    """A new id at every privilege change, so a planted id is worthless."""
    db.execute("DELETE FROM sessions WHERE id_hash = ?", (old.id_hash,))
    s = new_session(db, kind, ip)
    if kind == "admin":
        mark_reauth(db, s)
    return s


def mark_reauth(db: DB, s: Session) -> None:
    s.reauth_at = time.time()
    db.execute("UPDATE sessions SET reauth_at = ? WHERE id_hash = ?", (s.reauth_at, s.id_hash))


def set_pending_totp(db: DB, s: Session, secret: str) -> None:
    s.pending_totp = secret
    db.execute("UPDATE sessions SET pending_totp = ? WHERE id_hash = ?", (secret, s.id_hash))


def end_other_sessions(db: DB, keep: Session) -> None:
    """After a credential change: every other browser signs in again."""
    db.execute("DELETE FROM sessions WHERE id_hash != ?", (keep.id_hash,))


def end_session(db: DB, s: Session) -> None:
    db.execute("DELETE FROM sessions WHERE id_hash = ?", (s.id_hash,))


def prune(db: DB, idle: int, absolute: int) -> None:
    now = time.time()
    db.execute("DELETE FROM sessions WHERE last_seen < ? OR created < ?", (now - idle, now - absolute))
