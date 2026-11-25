"""The portal's own SQLite database: admin, sessions, claim code, rate limits
and the audit log. Nothing here is a Proton or Bridge secret (P2, P3)."""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA_VERSION = "1"

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS admin (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  pw_hash TEXT NOT NULL,
  totp_secret TEXT NOT NULL DEFAULT '',   -- '' = no authenticator (owner: optional for now)
  totp_last_step INTEGER NOT NULL DEFAULT -1,
  created REAL NOT NULL,
  updated REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS claim (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  code_hash TEXT NOT NULL,
  expires REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id_hash TEXT PRIMARY KEY,
  kind TEXT NOT NULL,              -- anon | claim | admin
  csrf TEXT NOT NULL,
  created REAL NOT NULL,
  last_seen REAL NOT NULL,
  reauth_at REAL NOT NULL DEFAULT 0,
  ip TEXT NOT NULL DEFAULT '',
  pending_totp TEXT               -- claim only: the secret being enrolled
);
CREATE TABLE IF NOT EXISTS failures (
  key TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  locked_until REAL NOT NULL,
  last REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY,
  ts REAL NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '',
  ip TEXT NOT NULL DEFAULT '',
  result TEXT NOT NULL DEFAULT 'ok'
);
-- Your verdicts on review-queue messages (shadow mode moves nothing, so a
-- verdict is labeled feedback for the analyzer's evaluation, not a move).
CREATE TABLE IF NOT EXISTS feedback (
  account TEXT NOT NULL DEFAULT 'default',   -- account id, never an address
  message_key TEXT NOT NULL,
  decision_id INTEGER NOT NULL,
  verdict TEXT NOT NULL CHECK (verdict IN ('keep', 'trash')),
  ts REAL NOT NULL,
  from_addr TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (account, message_key)
);
-- P12: append-only. The portal has no code path that edits or deletes rows,
-- and these triggers refuse it if one ever appears.
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
  BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
  BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
"""


class DB:
    """One connection guarded by a lock: the portal has a single admin and
    a handful of requests a minute, so simplicity beats concurrency."""

    def __init__(self, path: str) -> None:
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            # The db holds password and TOTP hashes: owner-only.
            old = os.umask(0o077)
        try:
            self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        finally:
            if path != ":memory:":
                os.umask(old)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self.conn.execute("PRAGMA foreign_keys = ON")
            self.conn.executescript(SCHEMA)
            self.conn.execute("INSERT OR IGNORE INTO meta VALUES ('schema_version', ?)", (SCHEMA_VERSION,))

    def execute(self, sql: str, args: tuple = ()) -> sqlite3.Cursor:
        with self.lock:
            return self.conn.execute(sql, args)

    def one(self, sql: str, args: tuple = ()) -> sqlite3.Row | None:
        with self.lock:
            return self.conn.execute(sql, args).fetchone()

    def all(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        with self.lock:
            return list(self.conn.execute(sql, args))

    def audit(self, action: str, target: str = "", ip: str = "", result: str = "ok") -> None:
        """Never pass a secret here: action and target are shown in the UI."""
        self.execute("INSERT INTO audit (ts, action, target, ip, result) VALUES (?,?,?,?,?)",
                     (time.time(), action, target[:200], ip[:64], result[:32]))
