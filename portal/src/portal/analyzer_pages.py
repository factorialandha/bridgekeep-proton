"""Review and Log pages over the analyzer's decision log (read-only)."""

from __future__ import annotations

import json
import time

from . import analyzer_db, sources
from .analyzer_db import AnalyzerDB, Query, Unavailable
from .portal_config import ConfigError, PortalConfig
from .web import Request, Response, redirect

REVIEW_DAYS = 14


def _row(r) -> dict:
    """A decision row as plain data for the templates (still unescaped text)."""
    try:
        injections = json.loads(r["injections"] or "[]")
        if not isinstance(injections, list):
            injections = []
    except ValueError:
        injections = []
    return {
        "id": r["id"], "ts": analyzer_db.parse_ts(r["ts"]), "key": r["message_key"], "mode": r["mode"],
        "action": r["action"], "applied": bool(r["applied"]), "rule": r["rule"], "explain": r["explain"],
        "from_addr": r["from_addr"] or "", "from_domain": r["from_domain"] or "",
        "subject": r["subject"], "label": r["label"] or "", "confidence": r["confidence"],
        "reason": r["reason"] or "", "model": r["model"] or "", "prompt_version": r["prompt_version"] or "",
        "verified": bool(r["verified"]), "injections": [str(i)[:200] for i in injections][:20],
        "error": r["error"] or "", "moved_to": "", "moved_back": False,
    }


def _with_moves(adb, rows: list[dict]) -> list[dict]:
    try:
        moves = adb.moves([r["id"] for r in rows])
    except Unavailable:
        return rows
    for r in rows:
        r.update(moves.get(r["id"], {}))
    return rows


def register(app, ctx, render, admin_only) -> None:
    db = ctx.db
    account = sources.get(ctx.settings)   # one account for now; a picker comes with multi-Bridge
    acct = account.id
    adb = AnalyzerDB(account.analyzer_dir)
    cfg = PortalConfig(ctx.settings.portal_config)

    def unavailable(req: Request, e: Unavailable, title: str) -> Response:
        return render(req, "analyzer_unavailable.html", 200, title=title, why=str(e))

    def verdicts() -> dict[str, str]:
        rows = db.all("SELECT message_key, verdict FROM feedback WHERE account = ?", (acct,))
        return {r["message_key"]: r["verdict"] for r in rows}

    def review_waiting() -> int:
        """How many Review messages have no answer yet (the count on the Review tab)."""
        try:
            keys = [r["message_key"] for r in adb.review_queue(REVIEW_DAYS)]
        except Unavailable:
            return 0
        return len(set(keys) - set(verdicts()))
    ctx.review_waiting = review_waiting

    def spam_scores() -> tuple[int, list[float]]:
        try:
            return adb.spam_scores(REVIEW_DAYS)
        except Unavailable:
            return 0, []
    ctx.spam_scores = spam_scores

    def log_data(query: Query) -> tuple[list[dict], dict, dict, int | None]:
        """(rows, 14-day card, verdicts, the "before" id for older rows). Raises Unavailable."""
        rows = [_row(r) for r in adb.search(query)]
        card = adb.scorecard(REVIEW_DAYS)
        more = len(rows) > analyzer_db.PAGE
        rows = _with_moves(adb, rows[:analyzer_db.PAGE])
        v = verdicts()
        card["answered"] = len(v)
        return rows, card, v, (rows[-1]["id"] if more and rows else None)
    ctx.log_data = log_data
    ctx.log_query = Query.from_args

    @app.route("GET", "/log")
    @admin_only
    def log_page(req: Request) -> Response:
        query = Query.from_args(req.arg)
        try:
            rows, card, v, before = log_data(query)
        except Unavailable as e:
            return unavailable(req, e, "Log")
        older = query.url(before=before) if before else ""
        return render(req, "log.html", rows=rows, query=query, filters=analyzer_db.FILTERS, card=card,
                      older=older, verdicts=v, days_options=(1, 7, 14, 30, 90))

    def entry_data(rid: int) -> tuple[dict, str, dict | None] | None:
        """(row, the admin's verdict, unsubscribe offer) for one decision, or
        None when there's no such row. Raises Unavailable."""
        r = adb.get(rid)
        if r is None:
            return None
        row = _with_moves(adb, [_row(r)])[0]
        fb = db.one("SELECT verdict FROM feedback WHERE account = ? AND message_key = ?", (acct, row["key"]))
        try:
            unsub = adb.unsubscribe(rid)
        except Unavailable:
            unsub = None
        return row, (fb["verdict"] if fb else ""), unsub
    ctx.log_entry = entry_data

    @app.route("GET", "/log/entry")
    @admin_only
    def log_entry(req: Request) -> Response:
        try:
            rid = int(req.arg("id"))
        except ValueError:
            return redirect("/log")
        try:
            got = entry_data(rid)
        except Unavailable as e:
            return unavailable(req, e, "Log")
        if got is None:
            return render(req, "log_entry.html", 404, row=None, verdict="", unsub=None)
        row, verdict, unsub = got
        return render(req, "log_entry.html", row=row, verdict=verdict, unsub=unsub)

    @app.route("GET", "/review")
    @admin_only
    def review_page(req: Request) -> Response:
        try:
            rows = _with_moves(adb, [_row(r) for r in adb.review_queue(REVIEW_DAYS)])
        except Unavailable as e:
            return unavailable(req, e, "Review")
        v = verdicts()
        waiting = [r for r in rows if r["key"] not in v]
        answered = [r for r in rows if r["key"] in v][:20]
        return render(req, "review.html", waiting=waiting, answered=answered, verdicts=v,
                      done=req.arg("done"))

    def record_verdict(rid: int, verdict: str, ip: str) -> bool:
        """keep / trash / undo on decision `rid`: the portal's record, the
        analyzer's feedback.jsonl, and the audit. False if there's no such row."""
        try:
            r = adb.get(rid)
        except Unavailable:
            return False
        if r is None:
            return False
        key = r["message_key"]
        taught = "ok"
        # Teaches the analyzer too (feedback.jsonl); Clear withdraws the answer there as well.
        try:
            cfg.append_feedback(key, {"keep": "legitimate", "trash": "spam", "undo": "withdrawn"}[verdict])
        except ConfigError:
            taught = "not sent to analyzer"   # the portal's own record still counts
        if verdict == "undo":
            db.execute("DELETE FROM feedback WHERE account = ? AND message_key = ?", (acct, key))
        else:
            db.execute("INSERT INTO feedback (account, message_key, decision_id, verdict, ts, from_addr) "
                       "VALUES (?,?,?,?,?,?) ON CONFLICT(account, message_key) "
                       "DO UPDATE SET verdict = excluded.verdict, ts = excluded.ts",
                       (acct, key, r["id"], verdict, time.time(), r["from_addr"] or ""))
        db.audit(f"review: {verdict}", target=f"decision {r['id']}", ip=ip, result=taught)
        return True
    ctx.record_verdict = record_verdict

    def review_items() -> list[dict]:
        """Unanswered Review messages, newest first (raises Unavailable)."""
        v = verdicts()
        return [r for r in _with_moves(adb, [_row(x) for x in adb.review_queue(REVIEW_DAYS)]) if r["key"] not in v]
    ctx.review_items = review_items

    @app.route("POST", "/review/verdict")
    @admin_only
    def review_verdict(req: Request) -> Response:
        verdict = req.field("verdict")
        try:
            rid = int(req.field("id"))
        except ValueError:
            return redirect("/review")
        back = f"/log/entry?id={rid}" if req.field("from") == "entry" else "/review"
        if verdict not in ("keep", "trash", "undo"):
            return redirect(back)
        record_verdict(rid, verdict, req.ip)
        return redirect(back + ("?done=" + verdict if back == "/review" else ""))
