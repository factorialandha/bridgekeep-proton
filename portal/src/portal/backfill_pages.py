"""Older mail: the analyzer's backfill (analyzer/backfill.py), from the portal.

Mail from before setup is only analyzed after a cost estimate that the admin
has seen and confirmed. The portal writes one request file
(/portal-config/backfill-request.json, read-only for the analyzer) and reads
progress from the analyzer's /data/backfill.json. It never talks to the
container.

The confirm page carries security's wording (2026-11-24), the same as the CLI.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import secrets
import stat
import time
from pathlib import Path

from . import sources, vendors
from .portal_config import ConfigError, PortalConfig
from .web import Request, Response, redirect

MAX_LIMIT = 200_000
MAX_JOB_BYTES = 64 * 1024
ESTIMATE_TTL = 24 * 3600
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
STATUSES = {"estimating", "estimated", "running", "paused", "done", "cancelled"}
# Who receives the fields, in the disclosure ("This sends N older messages to ...").
DEST = {"anthropic": "Anthropic's API (Claude)", "openai": "OpenAI's API", "gemini": "Google's Gemini API",
        "local": "your own server"}


def disclosure(job: dict, provider: str) -> str:
    return (f"This sends {job['est_calls']:,} older messages to {DEST.get(provider, DEST['anthropic'])}, one at a time: "
            "sender name and address, subject, link domains, attachment types and the first 3,000 characters "
            f"of each body. Of the {job['selected']:,} in range, {job['settled_by_lists']:,} are settled by your "
            "lists and not sent. Nothing is moved or deleted (log-only).")


def read_job(analyzer_dir: str) -> tuple[dict | None, float]:
    """The analyzer's backfill.json (or None) and when it was written."""
    p = Path(analyzer_dir) / "backfill.json"
    try:
        fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None, 0.0
    try:
        with os.fdopen(fd, "rb") as f:
            st = os.fstat(f.fileno())
            if not stat.S_ISREG(st.st_mode):
                return None, 0.0
            raw = f.read(MAX_JOB_BYTES + 1)
        if len(raw) > MAX_JOB_BYTES:
            return None, 0.0
        data = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None, 0.0
    if not isinstance(data, dict) or data.get("status") not in STATUSES:
        return None, st.st_mtime
    num = lambda k: data.get(k) if isinstance(data.get(k), (int, float)) and not isinstance(data.get(k), bool) else 0  # noqa: E731
    job = {k: num(k) for k in ("scanned", "candidates", "selected", "settled_by_lists", "est_calls", "est_usd",
                               "budget_left_usd", "budget_usd", "est_hours", "processed", "model_calls",
                               "spend_usd", "calls_that_fit", "estimated_at", "created", "finished")}
    job.update({
        "id": re.sub(r"[^A-Za-z0-9_-]", "", str(data.get("id", "")))[:64],
        "status": data["status"],
        "since": data.get("since") if isinstance(data.get("since"), str) and DATE.fullmatch(data["since"]) else "",
        "until": data.get("until") if isinstance(data.get("until"), str) and DATE.fullmatch(data["until"]) else "",
        "limit": num("limit"),
        "fits_budget": data.get("fits_budget") is True,
        "estimated": "est_calls" in data,
        "reason": "".join(ch for ch in str(data.get("reason", "")) if ch.isprintable())[:200],
        # The vendor the job was started for (analyzer records it at start).
        "provider": data.get("provider") if isinstance(data.get("provider"), str)
        and re.fullmatch(r"[a-z0-9_-]{1,20}", data["provider"]) else "",
    })
    return job, st.st_mtime


def _date(v: str, what: str) -> str:
    v = v.strip()
    if not v:
        return ""
    if not DATE.fullmatch(v):
        raise ValueError(f"{what}: a date like 2026-01-31.")
    try:
        dt.date.fromisoformat(v)
    except ValueError:
        raise ValueError(f"{what}: not a real date.") from None
    return v


def estimate_request(form: dict) -> dict:
    since, until = _date(form.get("since", ""), "From"), _date(form.get("until", ""), "To")
    if since and until and since > until:
        raise ValueError("“From” is after “To”.")
    req = {"id": secrets.token_hex(3), "action": "estimate"}
    if since:
        req["since"] = since
    if until:
        req["until"] = until
    lim = form.get("limit", "").strip().replace(",", "")
    if lim:
        if not lim.isdigit() or not 1 <= int(lim) <= MAX_LIMIT:
            raise ValueError(f"At most: a whole number from 1 to {MAX_LIMIT:,}.")
        req["limit"] = int(lim)
    return req


def register(app, ctx, render, admin_only, step_up, analyzer_health=None) -> None:
    db = ctx.db
    account = sources.get(ctx.settings)
    cfg = PortalConfig(ctx.settings.portal_config)

    def state() -> dict:
        job, written = read_job(account.analyzer_dir)
        requested = cfg.backfill_requested_at()
        health = analyzer_health() if analyzer_health else {}
        provider = health.get("provider") or "anthropic"
        stale = bool(job and job["status"] == "estimated" and time.time() - job["estimated_at"] > ESTIMATE_TTL)
        return {"job": job, "pending": requested > written, "provider": provider,
                "vendor": vendors.label(provider) or provider, "stale": stale,
                "model_state": health.get("model", ""), "writable": cfg.writable()}

    def checks(action: str, form: dict, provider_field: str = "", allow_partial: bool = False,
               estimate_id: str = "") -> tuple[int, str, dict | None]:
        """The same checks for the HTML pages and /api/backfill: (status, error, request body)."""
        st = state()
        job = st["job"]
        if action == "estimate":
            if st["pending"]:
                return 409, "The analyzer hasn't picked up the last request yet. It does within a minute or two.", None
            if job and job["status"] in ("estimating", "running"):
                return 409, "A backfill is already under way. Cancel it first to estimate a new one.", None
            try:
                return 200, "", estimate_request(form)
            except ValueError as e:
                return 400, str(e), None
        if action == "start":
            if (st["pending"] or not job or job["status"] != "estimated" or st["stale"]
                    or estimate_id != job["id"]):
                return 409, "That estimate has changed or is out of date. Check the numbers below and start again.", None
            if provider_field != st["provider"]:
                # The disclosure named another vendor than the one that would get the mail.
                return 409, "The AI vendor changed; start a new estimate.", None
            partial = not job["fits_budget"]
            if partial and not allow_partial:
                return 400, "This is more than the budget left this month. Confirm that it may stop there.", None
            return 200, "", {"id": secrets.token_hex(3), "action": "start", "estimate_id": job["id"],
                             "allow_partial": partial}
        if action == "resume" and job and job["provider"] != st["provider"]:
            # Resuming would send the rest to a vendor the disclosure never named
            # (or one the job doesn't record): a new estimate replaces it.
            return 409, "The AI vendor changed; start a new estimate.", None
        return 200, "", {"id": secrets.token_hex(3), "action": action}

    def write(body: dict, what: str, ip: str) -> str:
        """Write the request and audit it; returns an error sentence, or ""."""
        try:
            cfg.request_backfill(body)
        except ConfigError as e:
            return str(e)
        db.audit(f"older mail: {what}", target=body.get("estimate_id", body["id"]), ip=ip)
        return ""

    ctx.backfill_state, ctx.backfill_checks, ctx.backfill_write = state, checks, write
    ctx.backfill_disclosure = disclosure

    def page(req: Request, status: int = 200, error: str = "", form: dict | None = None) -> Response:
        st = state()
        job = st["job"]
        text = disclosure(job, st["provider"]) if job and job["status"] == "estimated" and job["estimated"] else ""
        return render(req, "backfill.html", status, error=error or None, form=form or {}, done=req.arg("done"),
                      disclosure=text, **st)

    def send(req: Request, body: dict, what: str, done: str) -> Response:
        err = write(body, what, req.ip)
        if err:
            return page(req, 500, err)
        return redirect(f"/backfill?done={done}")

    @app.route("GET", "/backfill")
    @admin_only
    def backfill_get(req: Request) -> Response:
        return page(req)

    # Estimating reads headers only and sends nothing anywhere: no step-up.
    @app.route("POST", "/backfill/estimate")
    @admin_only
    def backfill_estimate(req: Request) -> Response:
        form = {k: req.field(k)[:20] for k in ("since", "until", "limit")}
        status, err, body = checks("estimate", form)
        if body is None:
            return page(req, status, err, form)
        return send(req, body, "estimate requested", "estimate")

    @app.route("POST", "/backfill/start")
    @step_up
    def backfill_start(req: Request) -> Response:
        status, err, body = checks("start", {}, req.field("provider"), req.field("allow_partial") == "yes",
                                   req.field("estimate_id"))
        if body is None:
            return page(req, status, err)
        return send(req, body, "backfill started", "started")

    @app.route("POST", "/backfill/pause")
    @admin_only
    def backfill_pause(req: Request) -> Response:
        return send(req, {"id": secrets.token_hex(3), "action": "pause"}, "backfill paused", "paused")

    @app.route("POST", "/backfill/resume")
    @step_up
    def backfill_resume(req: Request) -> Response:
        status, err, body = checks("resume", {})
        if body is None:
            return page(req, status, err)
        return send(req, body, "backfill resumed", "resumed")

    @app.route("POST", "/backfill/cancel")
    @admin_only
    def backfill_cancel(req: Request) -> Response:
        return send(req, {"id": secrets.token_hex(3), "action": "cancel"}, "backfill cancelled", "cancelled")
