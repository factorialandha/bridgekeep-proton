"""Analyze mail that was already in the folder before go-live, on request.

The live runner only ever looks at new mail. A backfill is the one way to
look further back, and it only starts from an estimate that a person has
seen and confirmed:

1. ``estimate``: list the folder's older messages (optionally a date range
   and a limit), read only their headers, count the ones the never-trash
   list or blocklist settles without the model, and price the rest at the
   average cost per call so far (or a conservative default). The result says
   how this compares with what is left of the monthly budget, and how long
   the rate limits make it take.
2. ``start`` with that estimate's id (and ``allow_partial`` when the estimate
   is more than the budget left). Anything else is refused.
3. Each poll, after new mail, the runner analyzes a few backfill messages,
   newest first. It keeps a quarter of the hourly and daily call limits and
   10% of the monthly budget free for new mail, waits when it gets there and
   stops for the month at the budget reserve. ``pause``, ``resume`` and
   ``cancel`` work at any time, and so does the kill switch.

It is log-only like everything else: decisions are written to the log,
nothing is moved. Requests come from files (the CLI writes them to
``/data/backfill-requests/``, the admin portal to
``<portal_dir>/backfill-request.json``) and progress goes to
``/data/backfill.json``, so the portal needs no access to the container.
"""

from __future__ import annotations

import datetime as dt
import imaplib
import json
import logging
import os
import re
import secrets
import stat
import time
from pathlib import Path

from . import decide, lists
from . import providers
from .extract import Limits, extract
from .imap import GOLIVE_GRACE

log = logging.getLogger("analyzer.backfill")

STATE_KEY = "backfill"
UIDS_KEY = "backfill:uids"
HANDLED_KEY = "backfill:handled"
STATUS_FILE = "backfill.json"
VENDOR_CHANGED = "AI vendor changed; start a new estimate"
REQUEST_DIR = "backfill-requests"
PORTAL_REQUEST = "backfill-request.json"

ESTIMATE_PER_POLL = 2000      # headers read per poll while estimating
FETCH_CHUNK = 200
HEADER_BYTES = 8192
RUN_PER_POLL = 30             # most backfill messages analyzed per poll
RESERVE_CALLS = 0.25          # share of the hourly/daily limits kept for new mail
RESERVE_BUDGET = 0.10         # share of the monthly budget kept for new mail
ESTIMATE_TTL = 24 * 3600      # an estimate older than this must be redone
DEFAULT_IN_TOKENS = 1800      # per call, until there is real usage to average
DEFAULT_OUT_TOKENS = 90
MAX_REQUEST_BYTES = 4096
MAX_LIMIT = 200_000
ACTIONS = {"estimate", "start", "pause", "resume", "cancel"}
_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


class BadRequest(ValueError):
    pass


def new_id() -> str:
    """Short enough to read and type; there is only ever one job."""
    return secrets.token_hex(3)


def cli() -> str:
    """How the person runs this CLI on their host, for the hints we print."""
    return os.environ.get("BRIDGEKEEP_CLI", "analyzer")


def _next_month() -> str:
    today = dt.datetime.now(dt.timezone.utc).date()
    first = (today.replace(day=1) + dt.timedelta(days=32)).replace(day=1)
    return first.strftime("%b %-d")


def validate(req: object) -> dict:
    """A request as the runner accepts it, or BadRequest. Unknown keys are refused."""
    if not isinstance(req, dict):
        raise BadRequest("a request is a JSON object")
    allowed = {"id", "action", "since", "until", "limit", "estimate_id", "allow_partial"}
    extra = set(req) - allowed
    if extra:
        raise BadRequest(f"unknown field(s): {', '.join(sorted(extra))}")
    rid, action = req.get("id"), req.get("action")
    if not isinstance(rid, str) or not _ID_RE.fullmatch(rid):
        raise BadRequest("id: 1-64 letters, digits, - or _")
    if action not in ACTIONS:
        raise BadRequest(f"action: one of {', '.join(sorted(ACTIONS))}")
    out = {"id": rid, "action": action}
    for k in ("since", "until"):
        v = req.get(k)
        if v is None:
            continue
        if not isinstance(v, str) or not _DATE_RE.fullmatch(v):
            raise BadRequest(f"{k}: a date like 2026-01-31")
        try:
            dt.date.fromisoformat(v)
        except ValueError:
            raise BadRequest(f"{k}: not a real date") from None
        out[k] = v
    if out.get("since") and out.get("until") and out["since"] > out["until"]:
        raise BadRequest("since is after until")
    if req.get("limit") is not None:
        lim = req["limit"]
        if not isinstance(lim, int) or isinstance(lim, bool) or not 1 <= lim <= MAX_LIMIT:
            raise BadRequest(f"limit: a whole number from 1 to {MAX_LIMIT}")
        out["limit"] = lim
    if action == "start":
        eid = req.get("estimate_id")
        if not isinstance(eid, str) or not _ID_RE.fullmatch(eid):
            raise BadRequest("start needs the estimate_id it confirms")
        out["estimate_id"] = eid
        out["allow_partial"] = req.get("allow_partial") is True
    return out


def read_request_file(path: Path) -> dict | None:
    """Parse one request file without following links, or None if unusable."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            return None
        raw = f.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        log.warning("backfill request %s is too large; ignored", path.name)
        return None
    try:
        return validate(json.loads(raw.decode("utf-8")))
    except (ValueError, UnicodeDecodeError) as e:
        log.warning("backfill request %s refused: %s", path.name, str(e)[:120])
        return None


def write_request(data_dir: str, req: dict) -> Path:
    """For the CLI: queue a request for the running analyzer."""
    validate(req)
    d = Path(data_dir) / REQUEST_DIR
    d.mkdir(parents=True, exist_ok=True)
    name = f"{time.time_ns()}-{req['id']}"     # files sort in the order they were asked
    tmp = d / f".{name}.tmp"
    tmp.write_text(json.dumps(req), encoding="utf-8")
    final = d / f"{name}.json"
    os.replace(tmp, final)
    return final


class Backfill:
    """The backfill job, driven one slice per poll by the live runner."""

    def __init__(self, runner) -> None:
        self.runner = runner
        self.cfg = runner.cfg
        self.an = runner.an
        self.store = runner.store
        self.data_dir = str(Path(self.cfg.db_path).parent) if self.cfg.db_path != ":memory:" else ""

    # -- state ----------------------------------------------------------------
    def job(self) -> dict | None:
        raw = self.store.get_state(STATE_KEY)
        return json.loads(raw) if raw else None

    def _save(self, job: dict | None) -> None:
        if job is not None:
            job["updated"] = int(self.runner.clock())
        self.store.set_state(STATE_KEY, json.dumps(job) if job else "")
        if not self.data_dir:
            return
        try:
            tmp = Path(self.data_dir) / f".{STATUS_FILE}.tmp"
            tmp.write_text(json.dumps(job or {"status": "none"}), encoding="utf-8")
            os.replace(tmp, Path(self.data_dir) / STATUS_FILE)
        except OSError:
            pass

    def _uids(self) -> list[int]:
        raw = self.store.get_state(UIDS_KEY)
        return json.loads(raw) if raw else []

    def _set_uids(self, uids: list[int]) -> None:
        self.store.set_state(UIDS_KEY, json.dumps(uids))

    # -- requests -------------------------------------------------------------
    def _pending_requests(self) -> list[dict]:
        paths = []
        if self.data_dir:
            d = Path(self.data_dir) / REQUEST_DIR
            try:
                paths += sorted(p for p in d.iterdir() if p.suffix == ".json")
            except OSError:
                pass
        if self.cfg.portal_dir:
            paths.append(Path(self.cfg.portal_dir) / PORTAL_REQUEST)
        handled = json.loads(self.store.get_state(HANDLED_KEY) or "[]")
        out = []
        for p in paths:
            if not p.exists() and not p.is_symlink():
                continue
            req = read_request_file(p)
            if p.parent.name == REQUEST_DIR:
                try:
                    p.unlink()   # ours to remove; the portal's file is read-only here
                except OSError:
                    pass
            if req and p.name == PORTAL_REQUEST:
                # The portal's file stays in place (read-only here), so remember its
                # last id on its own: it can never be handled twice, however many
                # CLI requests come in between.
                if req["id"] == self.store.get_state("backfill:portal_last"):
                    continue
                self.store.set_state("backfill:portal_last", req["id"])
            if req and req["id"] not in handled:
                out.append(req)
                handled = (handled + [req["id"]])[-50:]
        self.store.set_state(HANDLED_KEY, json.dumps(handled))
        return out

    def handle(self, req: dict, uidvalidity: int) -> None:
        job = self.job()
        action = req["action"]
        now = int(self.runner.clock())
        if action == "estimate":
            if job and job["status"] in ("running", "estimating"):
                log.warning("backfill estimate refused: a backfill is already %s", job["status"])
                return
            ceiling = int(self.store.get_state(self.runner._key("last_uid")) or 0)
            golive = int(self.store.get_state(self.runner._key("golive")) or self.runner.clock())
            job = {"id": req["id"], "status": "estimating", "folder": self.cfg.imap_folder,
                   "uidvalidity": uidvalidity, "ceiling": ceiling, "golive": golive,
                   "since": req.get("since"), "until": req.get("until"), "limit": req.get("limit"),
                   "candidates": None, "scanned": 0, "selected": 0, "settled_by_lists": 0,
                   "created": now, "processed": 0, "model_calls": 0, "spend_usd": 0.0, "reason": "",
                   # The vendor the estimate (and the portal's disclosure) named.
                   "provider": self.cfg.provider}
            self._set_uids([])
            self.store.set_state("backfill:queue", "")
            self._save(job)
            return
        if not job or job.get("status") in (None, "none", "cancelled", "done"):
            log.warning("backfill %s refused: no backfill to act on", action)
            return
        if action == "cancel":
            job["status"], job["reason"] = "cancelled", "cancelled on request"
        elif action == "pause" and job["status"] == "running":
            job["status"], job["reason"] = "paused", "paused on request"
        elif action == "resume" and job["status"] == "paused":
            if job.get("provider") != self.cfg.provider:
                job["reason"] = VENDOR_CHANGED
                log.warning("backfill resume refused: %s", VENDOR_CHANGED)
            else:
                job["status"], job["reason"] = "running", ""
        elif action == "start":
            problem = self._start_problem(job, req, now)
            if problem:
                job["reason"] = problem
                log.warning("backfill start refused: %s", problem)
            else:
                job["status"], job["reason"], job["started"] = "running", "", now
        self._save(job)

    def _start_problem(self, job: dict, req: dict, now: int) -> str:
        if job["status"] != "estimated":
            return f"start needs a finished estimate; this backfill is {job['status']}"
        if job.get("provider") != self.cfg.provider:
            return VENDOR_CHANGED
        if req["estimate_id"] != job["id"]:
            return "the estimate_id does not match the current estimate; estimate again"
        if now - job.get("estimated_at", 0) > ESTIMATE_TTL:
            return "the estimate is more than a day old; estimate again"
        if job["est_usd"] > job["budget_left_usd"] and not req.get("allow_partial"):
            return ("the estimate is more than the budget left this month; "
                    "confirm with allow_partial to run until the budget reserve")
        return ""

    # -- one slice per poll -----------------------------------------------------
    def step(self, conn, uidvalidity: int) -> None:
        for req in self._pending_requests():
            self.handle(req, uidvalidity)
        job = self.job()
        if not job or job["status"] not in ("estimating", "running"):
            return
        if job["uidvalidity"] != uidvalidity:
            job["status"], job["reason"] = "cancelled", "the folder was rebuilt (UIDVALIDITY changed)"
            self._save(job)
            return
        if job.get("provider") != self.cfg.provider:
            # Older mail goes only to the vendor the estimate and its disclosure named.
            job["status"] = "paused" if job["status"] == "running" else "cancelled"
            job["reason"] = VENDOR_CHANGED
            log.warning("backfill %s: %s", job["status"], VENDOR_CHANGED)
            self._save(job)
            return
        if job["status"] == "estimating":
            self._estimate_slice(conn, job)
        else:
            self._run_slice(conn, job)
        self._save(job)

    def _estimate_slice(self, conn, job: dict) -> None:
        queue = json.loads(self.store.get_state("backfill:queue") or "null")
        if queue is None:
            typ, data = conn.uid("SEARCH", None, "ALL")
            if typ != "OK":
                raise imaplib.IMAP4.error("UID SEARCH failed")
            from .imap import _parse_uids
            queue = sorted((u for u in _parse_uids(data) if u <= job["ceiling"]), reverse=True)
            job["candidates"] = len(queue)
        selected = self._uids()
        since = dt.date.fromisoformat(job["since"]) if job.get("since") else None
        until = dt.date.fromisoformat(job["until"]) if job.get("until") else None
        limit = job.get("limit")
        budget = ESTIMATE_PER_POLL
        while queue and budget > 0 and not (limit and len(selected) >= limit):
            chunk, queue = queue[:FETCH_CHUNK], queue[FETCH_CHUNK:]
            budget -= len(chunk)
            uid_set = ",".join(str(u) for u in chunk)
            typ, data = conn.uid("FETCH", uid_set, f"(UID INTERNALDATE BODY.PEEK[HEADER]<0.{HEADER_BYTES}>)")
            if typ != "OK":
                raise imaplib.IMAP4.error("UID FETCH failed")
            found = {}
            for item in data or []:
                if isinstance(item, tuple) and len(item) == 2:
                    m = re.search(rb"UID (\d+)", item[0])
                    if m:
                        found[int(m.group(1))] = (item[0], item[1])
            for uid in chunk:
                if uid not in found or (limit and len(selected) >= limit):
                    continue
                job["scanned"] += 1
                meta, header = found[uid]
                t = imaplib.Internaldate2tuple(meta)
                if t is None or time.mktime(t) >= job["golive"] - GOLIVE_GRACE:
                    continue      # new mail: the live runner's, not ours
                day = dt.date(t.tm_year, t.tm_mon, t.tm_mday)
                if (since and day < since) or (until and day > until):
                    continue
                if self.store.has_decision(f"{job['folder']}:{job['uidvalidity']}:{uid}"):
                    continue
                selected.append(uid)
                ex = extract(header, Limits(body_chars=100), self.cfg.trusted_authserv)
                hits = lists.check(self.an.lists, ex.from_addr, ex.from_domain, ex.subject)
                d = decide.pre_model(ex, hits)
                if d is not None and d.rule in ("protected_verified", "blocklist"):
                    job["settled_by_lists"] += 1
        self._set_uids(selected)
        self.store.set_state("backfill:queue", json.dumps(queue))
        job["selected"] = len(selected)
        if not queue or (limit and len(selected) >= limit):
            self.store.set_state("backfill:queue", "")
            self._finish_estimate(job)

    def per_call_usd(self) -> tuple[float, bool]:
        """Average cost per model call so far, or a conservative default."""
        n, cost = self.store.usage_totals(f"{self.cfg.provider}/{self.cfg.model}")
        if n >= 20:
            return cost / n, True
        return providers.cost(self.cfg, DEFAULT_IN_TOKENS, DEFAULT_OUT_TOKENS), False

    def _finish_estimate(self, job: dict) -> None:
        calls = max(job["selected"] - job["settled_by_lists"], 0)
        per_call, measured = self.per_call_usd()
        spend = self.store.spend_this_month()
        usable = self.cfg.monthly_budget_usd * (1 - RESERVE_BUDGET)
        per_hour = int(self.cfg.max_per_hour * (1 - RESERVE_CALLS))
        per_day = int(self.cfg.max_per_day * (1 - RESERVE_CALLS))
        days, rest = divmod(calls, max(per_day, 1))
        hours = days * 24 + -(-rest // max(per_hour, 1))
        job.update({
            "status": "estimated", "estimated_at": int(self.runner.clock()),
            "est_calls": calls, "est_usd": round(calls * per_call, 4),
            "per_call_usd": round(per_call, 6), "per_call_measured": measured,
            "budget_usd": self.cfg.monthly_budget_usd, "spent_this_month_usd": round(spend, 4),
            "budget_left_usd": round(max(usable - spend, 0.0), 4),
            "est_hours": hours, "rate_limits": {"per_hour": per_hour, "per_day": per_day},
        })
        job["fits_budget"] = job["est_usd"] <= job["budget_left_usd"]
        job["calls_that_fit"] = min(calls, int(job["budget_left_usd"] / per_call)) if per_call else calls

    def _room(self) -> str:
        """Why the backfill must wait now, or ''. New mail always keeps its share."""
        if self.cfg.paused():
            return "kill switch"
        if self.an.classifier is None:
            return "model off"
        if self.store.calls_since(3600) >= self.cfg.max_per_hour * (1 - RESERVE_CALLS):
            return "hourly limit (keeping room for new mail)"
        if self.store.calls_since(86400) >= self.cfg.max_per_day * (1 - RESERVE_CALLS):
            return "daily limit (keeping room for new mail)"
        if self.store.spend_this_month() >= self.cfg.monthly_budget_usd * (1 - RESERVE_BUDGET):
            return "budget"
        return ""

    def _run_slice(self, conn, job: dict) -> None:
        from .imap import _fetch_raw
        uids = self._uids()
        done = job["processed"]
        n = 0
        while done < len(uids) and n < RUN_PER_POLL:
            wait = self._room()
            if wait == "budget":
                job["reason"] = f"waiting: this month's budget is used up; carries on from {_next_month()}"
                break
            if wait:
                job["reason"] = f"waiting: {wait}"
                break
            job["reason"] = ""
            uid = uids[done]
            key = f"{job['folder']}:{job['uidvalidity']}:{uid}"
            if not self.store.has_decision(key):
                raw = _fetch_raw(conn, uid, 1_000_000)
                if raw is not None:
                    before_calls, before_spend = self.store.usage_totals()
                    self.an.analyze(raw, key)
                    after_calls, after_spend = self.store.usage_totals()
                    job["model_calls"] += after_calls - before_calls
                    job["spend_usd"] = round(job["spend_usd"] + after_spend - before_spend, 6)
            done += 1
            n += 1
        job["processed"] = done
        if done >= len(uids):
            job["status"], job["reason"], job["finished"] = "done", "", int(self.runner.clock())


def status_lines(job: dict | None) -> list[str]:
    """Human summary for the CLI (the portal reads the JSON)."""
    if not job or job.get("status") in (None, "none"):
        return [f"No backfill. Start with: {cli()} backfill estimate [--since YYYY-MM-DD] [--limit N]"]
    rng = f"{job.get('since') or 'the start'} to {job.get('until') or 'go-live'}"
    out = [f"Backfill {job['id']}: {job['status']}" + (f" ({job['reason']})" if job.get("reason") else ""),
           f"  Folder {job['folder']}, {rng}" + (f", at most {job['limit']}" if job.get("limit") else "")]
    if job["status"] == "estimating":
        out.append(f"  Reading headers: {job['scanned']} of {job.get('candidates') or '?'}")
    if "est_calls" in job:
        basis = "average so far" if job.get("per_call_measured") else "conservative default"
        out += [f"  {job['selected']} messages; {job['settled_by_lists']} settled by your lists without the model",
                f"  Estimated {job['est_calls']} model calls, about ${job['est_usd']:.2f} "
                f"(${job['per_call_usd']:.5f} a call, {basis})",
                f"  Budget left this month: ${job['budget_left_usd']:.2f} of ${job['budget_usd']:.2f} "
                f"(10% is kept for new mail)",
                f"  At the rate limits ({job['rate_limits']['per_hour']}/hour, {job['rate_limits']['per_day']}/day "
                f"for backfill) it takes about {_duration(job['est_hours'])}"]
        if not job.get("fits_budget"):
            out.append(f"  About {job.get('calls_that_fit', 0):,} of the {job['est_calls']:,} calls fit in what's left "
                       f"this month. With --allow-partial it stops there and carries on from {_next_month()}. "
                       "Or narrow it with --since or --limit.")
    if job["status"] in ("running", "paused", "done"):
        out.append(f"  Progress: {job['processed']} of {job['selected']}, "
                   f"{job['model_calls']} model calls, ${job['spend_usd']:.2f}")
    if job["status"] == "estimated":
        out.append(f"  To run it: {cli()} backfill start {job['id']}"
                   + (" --allow-partial" if not job.get("fits_budget") else ""))
    return out


def _duration(hours: int) -> str:
    if hours > 48:
        return f"{round(hours / 24)} days ({hours} hours)"
    return f"{hours} hour{'s' if hours != 1 else ''}"
