"""SQLite decision log and spend tracking.

Stores sender, subject (or its hash), label, confidence, the model's reason
and the rule that acted. Never message bodies (scoping doc 6A.5). The reason
string is inert text: anything that displays it must escape it.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

SCHEMA_VERSION = 1
SCHEMA = """
CREATE TABLE IF NOT EXISTS decisions (
  id INTEGER PRIMARY KEY,
  ts TEXT NOT NULL,
  message_key TEXT NOT NULL,
  mode TEXT NOT NULL,
  action TEXT NOT NULL,
  applied INTEGER NOT NULL DEFAULT 0,
  rule TEXT NOT NULL,
  explain TEXT NOT NULL,
  from_addr TEXT,
  from_domain TEXT,
  subject TEXT,
  subject_hash TEXT,
  label TEXT,
  confidence REAL,
  reason TEXT,
  model TEXT,
  prompt_version TEXT,
  verified INTEGER,
  injections TEXT,
  error TEXT
);
CREATE INDEX IF NOT EXISTS decisions_ts ON decisions(ts);
CREATE INDEX IF NOT EXISTS decisions_from ON decisions(from_addr);
CREATE INDEX IF NOT EXISTS decisions_key ON decisions(message_key);
CREATE TABLE IF NOT EXISTS usage (
  ts TEXT NOT NULL,
  input_tokens INTEGER NOT NULL,
  output_tokens INTEGER NOT NULL,
  cost_usd REAL NOT NULL,
  model TEXT
);
CREATE INDEX IF NOT EXISTS usage_ts ON usage(ts);
CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS feedback (
  message_key TEXT PRIMARY KEY,   -- one answer per message; the latest wins
  ts INTEGER NOT NULL,
  label TEXT NOT NULL,            -- what the owner says it is
  scope TEXT NOT NULL,
  from_addr TEXT,                 -- copied from the decision when it arrived
  from_domain TEXT,
  verified INTEGER,
  model_label TEXT,
  action TEXT
);
CREATE INDEX IF NOT EXISTS feedback_domain ON feedback(from_domain);
CREATE INDEX IF NOT EXISTS feedback_addr ON feedback(from_addr);
-- Where the portal may show an Unsubscribe button (unsubscribe.py). Written
-- by the analyzer only; the unsubscribe service reads it read-only.
CREATE TABLE IF NOT EXISTS unsubscribe (
  decision_id INTEGER PRIMARY KEY,
  method TEXT NOT NULL,           -- one_click | mailto (mailto is shown, never sent)
  url TEXT,
  mailto TEXT,
  host TEXT,
  dkim_domain TEXT NOT NULL
);
-- Live mode: every move and every move back, ok or not (security review of
-- live mode, item 12). uidvalidity and uid are where the message is now,
-- from the server's COPYUID answer; NULL when the server gave none.
CREATE TABLE IF NOT EXISTS moves (
  id INTEGER PRIMARY KEY,
  ts TEXT NOT NULL,
  decision_id INTEGER NOT NULL,
  kind TEXT NOT NULL,             -- move | undo
  from_mailbox TEXT NOT NULL,
  to_mailbox TEXT NOT NULL,
  uidvalidity INTEGER,
  uid INTEGER,
  ok INTEGER NOT NULL,
  error TEXT
);
CREATE INDEX IF NOT EXISTS moves_decision ON moves(decision_id);
CREATE INDEX IF NOT EXISTS moves_ts ON moves(ts);
"""


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _iso(t: dt.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Record:
    message_key: str
    mode: str
    action: str
    rule: str
    explain: str
    from_addr: str = ""
    from_domain: str = ""
    subject: str = ""
    label: str | None = None
    confidence: float | None = None
    reason: str | None = None
    model: str | None = None
    prompt_version: str | None = None
    verified: bool = False
    injections: list[str] | None = None
    error: str | None = None
    applied: bool = False


class Store:
    def __init__(self, path: str, store_subjects: bool = True) -> None:
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        # Additive columns for databases made by older versions (readers ignore them).
        if "model" not in {r[1] for r in self.db.execute("PRAGMA table_info(usage)")}:
            self.db.execute("ALTER TABLE usage ADD COLUMN model TEXT")
            self.db.commit()
        # Readers such as the admin portal refuse a version they don't know.
        # Bump on any incompatible change to the decisions, usage or state tables.
        self.set_state("schema_version", SCHEMA_VERSION)
        self.store_subjects = store_subjects

    def add(self, r: Record, now: dt.datetime | None = None) -> int:
        subject_hash = hashlib.sha256(r.subject.encode()).hexdigest()[:16] if r.subject else None
        cur = self.db.execute(
            """INSERT INTO decisions (ts, message_key, mode, action, applied, rule, explain, from_addr,
               from_domain, subject, subject_hash, label, confidence, reason, model, prompt_version,
               verified, injections, error) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (_iso(now or _now()), r.message_key, r.mode, r.action, int(r.applied), r.rule, r.explain,
             r.from_addr, r.from_domain, r.subject if self.store_subjects else None, subject_hash,
             r.label, r.confidence, r.reason, r.model, r.prompt_version, int(r.verified),
             json.dumps(r.injections or []), r.error),
        )
        self.db.commit()
        return int(cur.lastrowid)

    def add_usage(self, input_tokens: int, output_tokens: int, cost: float,
                  now: dt.datetime | None = None, model: str | None = None) -> None:
        self.db.execute("INSERT INTO usage (ts, input_tokens, output_tokens, cost_usd, model) VALUES (?,?,?,?,?)",
                        (_iso(now or _now()), input_tokens, output_tokens, cost, model))
        self.db.commit()

    def spend_this_month(self, now: dt.datetime | None = None) -> float:
        now = now or _now()
        start = now.strftime("%Y-%m-01T00:00:00Z")
        row = self.db.execute("SELECT COALESCE(SUM(cost_usd),0) FROM usage WHERE ts >= ?", (start,)).fetchone()
        return float(row[0])

    def has_decision(self, message_key: str) -> bool:
        return self.db.execute("SELECT 1 FROM decisions WHERE message_key = ? LIMIT 1",
                               (message_key,)).fetchone() is not None

    def usage_totals(self, model: str | None = None) -> tuple[int, float]:
        """Model calls logged (for one provider/model if given): (count, total cost)."""
        if model is None:
            n, cost = self.db.execute("SELECT COUNT(*), COALESCE(SUM(cost_usd),0) FROM usage").fetchone()
        else:
            n, cost = self.db.execute("SELECT COUNT(*), COALESCE(SUM(cost_usd),0) FROM usage WHERE model=?",
                                      (model,)).fetchone()
        return int(n), float(cost)

    def calls_since(self, seconds: int, now: dt.datetime | None = None) -> int:
        since = _iso((now or _now()) - dt.timedelta(seconds=seconds))
        return int(self.db.execute("SELECT COUNT(*) FROM usage WHERE ts >= ?", (since,)).fetchone()[0])

    def recent(self, since_hours: float = 24, action: str | None = None, limit: int = 200,
               now: dt.datetime | None = None) -> list[sqlite3.Row]:
        since = _iso((now or _now()) - dt.timedelta(hours=since_hours))
        q = "SELECT * FROM decisions WHERE ts >= ?"
        args: list = [since]
        if action:
            q += " AND action = ?"
            args.append(action)
        q += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        return list(self.db.execute(q, args))

    # -- feedback from the portal ("this isn't spam") ------------------
    def decision_for(self, message_key: str) -> sqlite3.Row | None:
        return self.db.execute(
            "SELECT from_addr, from_domain, verified, label, action FROM decisions WHERE message_key=? "
            "ORDER BY id DESC LIMIT 1", (message_key,)).fetchone()

    def add_feedback(self, message_key: str, ts: int, label: str, scope: str) -> None:
        d = self.decision_for(message_key)
        self.db.execute(
            "INSERT OR REPLACE INTO feedback VALUES (?,?,?,?,?,?,?,?,?)",
            (message_key, ts, label, scope,
             d["from_addr"] if d else None, d["from_domain"] if d else None, int(bool(d and d["verified"])),
             d["label"] if d else None, d["action"] if d else None))
        self.db.commit()

    def remove_feedback(self, message_key: str) -> None:
        self.db.execute("DELETE FROM feedback WHERE message_key = ?", (message_key,))
        self.db.commit()

    def sender_feedback(self, value: str, by_address: bool = False) -> tuple[int, int]:
        """(not spam, spam) answers for DMARC-verified mail from this domain,
        or from this exact address (free-mail and shared senders)."""
        column = "from_addr" if by_address else "from_domain"
        row = self.db.execute(
            "SELECT SUM(label IN ('legitimate','promotional')), SUM(label IN ('spam','phishing')) "
            f"FROM feedback WHERE {column}=? AND verified=1", (value,)).fetchone()
        return int(row[0] or 0), int(row[1] or 0)

    def feedback_rows(self) -> list[sqlite3.Row]:
        return self.db.execute("SELECT * FROM feedback ORDER BY ts").fetchall()

    # -- live mode --------------------------------------------------------
    def add_move(self, decision_id: int, kind: str, from_mailbox: str, to_mailbox: str,
                 uidvalidity: int | None, uid: int | None, ok: bool, error: str | None = None,
                 now: dt.datetime | None = None) -> None:
        self.db.execute(
            "INSERT INTO moves (ts, decision_id, kind, from_mailbox, to_mailbox, uidvalidity, uid, ok, error)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (_iso(now or _now()), decision_id, kind, from_mailbox, to_mailbox, uidvalidity, uid, int(ok),
             (error or None) and error[:200]))
        if kind == "move" and ok:
            self.db.execute("UPDATE decisions SET applied=1 WHERE id=?", (decision_id,))
        self.db.commit()

    def moves_today(self, kind: str = "move", now: dt.datetime | None = None) -> int:
        day = (now or _now()).strftime("%Y-%m-%dT00:00:00Z")
        return int(self.db.execute("SELECT COUNT(*) FROM moves WHERE kind=? AND ok=1 AND ts >= ?",
                                   (kind, day)).fetchone()[0])

    def pending_undos(self, max_tries: int = 3) -> list[sqlite3.Row]:
        """Moved messages the recipient has since said are fine, not yet moved back."""
        return self.db.execute(
            """SELECT m.decision_id, m.to_mailbox AS mailbox, m.uidvalidity, m.uid, d.message_key
               FROM moves m JOIN decisions d ON d.id = m.decision_id
               JOIN feedback f ON f.message_key = d.message_key
               WHERE m.kind='move' AND m.ok=1 AND m.uid IS NOT NULL
                 AND f.label IN ('legitimate','promotional')
                 AND NOT EXISTS (SELECT 1 FROM moves u WHERE u.decision_id=m.decision_id AND u.kind='undo' AND u.ok=1)
                 AND (SELECT COUNT(*) FROM moves u WHERE u.decision_id=m.decision_id AND u.kind='undo') < ?
               ORDER BY m.id LIMIT 50""", (max_tries,)).fetchall()

    def moved_back_uid(self, uidvalidity: int, uid: int) -> bool:
        """True for a message that is in INBOX because it was moved back there."""
        return self.db.execute("SELECT 1 FROM moves WHERE kind='undo' AND ok=1 AND uidvalidity=? AND uid=?",
                               (uidvalidity, uid)).fetchone() is not None

    def moved_back_before(self, from_addr: str, subject: str) -> bool:
        """The same sender and subject was moved back after a "not spam" answer:
        never move that message again (also when the server gave no COPYUID)."""
        if not from_addr:
            return False
        h = hashlib.sha256(subject.encode()).hexdigest()[:16] if subject else None
        return self.db.execute(
            """SELECT 1 FROM moves m JOIN decisions d ON d.id = m.decision_id
               WHERE m.kind='undo' AND m.ok=1 AND d.from_addr=? AND d.subject_hash IS ?""",
            (from_addr, h)).fetchone() is not None

    def shadow_counts(self) -> dict:
        row = self.db.execute(
            "SELECT MIN(ts), SUM(action='review'), SUM(action='quarantine') FROM decisions WHERE mode='shadow'"
        ).fetchone()
        return {"would_review": int(row[1] or 0), "would_quarantine": int(row[2] or 0)}

    def add_unsubscribe(self, decision_id: int, o) -> None:
        self.db.execute("INSERT OR REPLACE INTO unsubscribe VALUES (?,?,?,?,?,?)",
                        (decision_id, o.method, o.url or None, o.mailto or None, o.host or None, o.dkim_domain))
        self.db.commit()

    def get_state(self, key: str) -> str | None:
        row = self.db.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
        return None if row is None else str(row[0])

    def set_state(self, key: str, value) -> None:
        self.db.execute("INSERT INTO state VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                        (key, str(value)))
        self.db.commit()

    def get(self, rid: int) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM decisions WHERE id = ?", (rid,)).fetchone()

    def prune(self, retention_days: int, now: dt.datetime | None = None) -> int:
        cutoff = _iso((now or _now()) - dt.timedelta(days=retention_days))
        n = self.db.execute("DELETE FROM decisions WHERE ts < ?", (cutoff,)).rowcount
        # Spend rows are kept at least two months so the monthly cap stays right.
        usage_cutoff = _iso((now or _now()) - dt.timedelta(days=max(retention_days, 62)))
        self.db.execute("DELETE FROM usage WHERE ts < ?", (usage_cutoff,))
        self.db.execute("DELETE FROM unsubscribe WHERE decision_id NOT IN (SELECT id FROM decisions)")
        self.db.execute("DELETE FROM moves WHERE decision_id NOT IN (SELECT id FROM decisions)")
        self.db.commit()
        return n
