"""Read-only access to the analyzer's decision log (/analyzer/analyzer.db).

The database belongs to the analyzer. The portal opens it with mode=ro, so it
can never write to it, and refuses a schema version it doesn't know rather
than misreading it. Every text column holds attacker-written data (senders,
subjects, the model's reason): templates escape it and nothing here turns it
into HTML.
"""

from __future__ import annotations

import datetime as dt
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

KNOWN_SCHEMA = "1"
PAGE = 100
ACTIONS = ("quarantine", "review", "keep")
FILTERS = {
    # name: (label, SQL condition)
    "protected": ("Protected saves", "rule LIKE 'protected%'"),
    "injection": ("Injection attempts", "injections IS NOT NULL AND injections NOT IN ('', '[]')"),
    "disagree": ("Disagreements", "rule LIKE 'disagree%'"),
}


class Unavailable(Exception):
    """The log is missing, locked, or from a version the portal doesn't know."""


@dataclass
class Query:
    q: str = ""
    action: str = ""
    days: int = 14
    flag: str = ""
    before: int = 0

    @classmethod
    def from_args(cls, arg) -> "Query":
        action = arg("action")
        flag = arg("flag")
        try:
            days = int(arg("days", "14"))
        except ValueError:
            days = 14
        try:
            before = max(0, int(arg("before", "0")))
        except ValueError:
            before = 0
        return cls(q=arg("q")[:200], action=action if action in ACTIONS else "",
                   days=days if days in (1, 7, 14, 30, 90) else 14,
                   flag=flag if flag in FILTERS else "", before=before)

    def url(self, **change) -> str:
        """The page URL for this filter with some fields changed (filter state lives in the URL)."""
        d = {"q": self.q, "action": self.action, "days": str(self.days), "flag": self.flag, **change}
        d = {k: str(v) for k, v in d.items() if v not in ("", None, 0) and not (k == "days" and str(v) == "14")}
        return "/log" + ("?" + "&".join(f"{k}={quote(v)}" for k, v in d.items()) if d else "")


class AnalyzerDB:
    def __init__(self, directory: str) -> None:
        self.path = Path(directory) / "analyzer.db"

    def _connect(self) -> sqlite3.Connection:
        if not self.path.exists():
            raise Unavailable("not_set_up")
        uri = f"file:{quote(str(self.path))}?mode=ro"
        last: Exception | None = None
        # A crashed analyzer can leave a hot journal; a read-only reader then
        # gets SQLITE_READONLY or BUSY until the analyzer rolls it back.
        for delay in (0, 0.2, 0.5):
            time.sleep(delay)
            try:
                conn = sqlite3.connect(uri, uri=True, timeout=2)
                conn.row_factory = sqlite3.Row
                # The analyzer's file is parsed, not trusted: no schema-defined
                # functions or virtual tables run, and nothing can be written.
                conn.execute("PRAGMA trusted_schema = OFF")
                conn.execute("PRAGMA query_only = ON")
                row = conn.execute("SELECT value FROM state WHERE key = 'schema_version'").fetchone()
                if row is None or str(row[0]) != KNOWN_SCHEMA:
                    conn.close()
                    raise Unavailable("schema")
                return conn
            except sqlite3.OperationalError as e:
                last = e
        raise Unavailable(f"locked: {last}")

    def search(self, query: Query, now: float | None = None) -> list[sqlite3.Row]:
        since = _iso((now or time.time()) - query.days * 86400)
        sql = ["SELECT * FROM decisions WHERE ts >= ?"]
        args: list = [since]
        if query.action:
            sql.append("AND action = ?")
            args.append(query.action)
        if query.flag:
            sql.append("AND " + FILTERS[query.flag][1])
        if query.q:
            like = "%" + query.q.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            sql.append("AND (lower(from_addr) LIKE ? ESCAPE '\\' OR lower(from_domain) LIKE ? ESCAPE '\\' "
                       "OR lower(COALESCE(subject, '')) LIKE ? ESCAPE '\\')")
            args += [like, like, like]
        if query.before:
            sql.append("AND id < ?")
            args.append(query.before)
        sql.append("ORDER BY id DESC LIMIT ?")
        args.append(PAGE + 1)
        with self._connect() as conn:
            return list(conn.execute(" ".join(sql), args))

    def get(self, rid: int) -> sqlite3.Row | None:
        with self._connect() as conn:
            return conn.execute("SELECT * FROM decisions WHERE id = ?", (rid,)).fetchone()

    def unsubscribe(self, rid: int) -> dict | None:
        """Where the analyzer says this message can be unsubscribed from, if
        anywhere (analyzer PR #49). None when there's no row or no table yet."""
        with self._connect() as conn:
            try:
                r = conn.execute("SELECT method, mailto, host FROM unsubscribe WHERE decision_id = ?",
                                 (rid,)).fetchone()
            except sqlite3.OperationalError:
                return None
        if r is None or r["method"] not in ("one_click", "mailto"):
            return None
        return {"method": r["method"], "mailto": str(r["mailto"] or "")[:254], "host": str(r["host"] or "")[:253]}

    def moves(self, ids: list[int]) -> dict[int, dict]:
        """Live-mode moves (analyzer PR #66) of these decisions: {id: {"moved_to",
        "moved_back"}}. Empty when there's no moves table yet."""
        ids = [int(i) for i in ids][:500]
        if not ids:
            return {}
        out: dict[int, dict] = {}
        with self._connect() as conn:
            try:
                rows = conn.execute(
                    f"SELECT decision_id, kind, to_mailbox FROM moves WHERE ok = 1 AND decision_id IN "
                    f"({','.join('?' * len(ids))}) ORDER BY id", ids).fetchall()
            except sqlite3.OperationalError:
                return {}
        for r in rows:
            d = out.setdefault(int(r["decision_id"]), {"moved_to": "", "moved_back": False})
            if r["kind"] == "move":
                d["moved_to"] = str(r["to_mailbox"] or "").rsplit("/", 1)[-1][:60]
            elif r["kind"] == "undo":
                d["moved_back"] = True
        return out

    def review_queue(self, days: int = 14, now: float | None = None) -> list[sqlite3.Row]:
        since = _iso((now or time.time()) - days * 86400)
        with self._connect() as conn:
            return list(conn.execute(
                "SELECT * FROM decisions WHERE action = 'review' AND ts >= ? ORDER BY id DESC LIMIT 500", (since,)))

    def spam_scores(self, days: int = 14, now: float | None = None) -> tuple[int, list[float]]:
        """For the Analyzer page preview: how many messages the AI's score alone decided,
        and the spam scores among them (newest 2,000)."""
        since = _iso((now or time.time()) - days * 86400)
        with self._connect() as conn:
            rows = list(conn.execute(
                "SELECT label, confidence FROM decisions WHERE ts >= ? AND confidence IS NOT NULL "
                "AND rule IN ('threshold', 'review_band', 'model_keep') ORDER BY id DESC LIMIT 2000", (since,)))
        scores = []
        for r in rows:
            try:
                if r["label"] in ("spam", "phishing"):
                    scores.append(min(1.0, max(0.0, float(r["confidence"]))))
            except (TypeError, ValueError):
                continue          # a malformed row is left out, never a 500
        return len(rows), scores

    def scorecard(self, days: int = 14, now: float | None = None) -> dict:
        since = _iso((now or time.time()) - days * 86400)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS seen, "
                "SUM(action = 'quarantine') AS quarantine, SUM(action = 'review') AS review, "
                "SUM(rule LIKE 'protected%') AS protected, "
                "SUM(error IS NOT NULL AND error != '') AS errors "
                "FROM decisions WHERE ts >= ?", (since,)).fetchone()
        return {k: int(row[k] or 0) for k in row.keys()}


def _iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(s: str | None) -> float:
    try:
        return dt.datetime.strptime(str(s), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc).timestamp()
    except (TypeError, ValueError):
        return 0.0
