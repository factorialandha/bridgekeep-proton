"""Pages. Each handler gets a Request that already passed the gate in web.py."""

from __future__ import annotations

import datetime as dt
import functools
import hashlib
import json
from importlib import resources
import time
from urllib.parse import urlencode
from dataclasses import dataclass
from functools import wraps
from pathlib import Path

import jinja2
import segno
from markupsafe import Markup

from . import __version__, analyzer_db, auth, hoststatus, secret_drop, sources, totp, vendors
from .db import DB
from .portal_config import PortalConfig
from .settings import Settings
from .web import CSP_APP, App, Request, Response, redirect, text

STALE_AFTER = 5 * 60   # a health.json older than this means the analyzer is stalled


def fingerprint_lines(fp: str) -> list[str]:
    """32 hex pairs as four lines of eight, easy to compare by eye."""
    pairs = fp.split(":") if fp else []
    return [" ".join(pairs[i:i + 8]) for i in range(0, len(pairs), 8)]


def cli_urls(s: Settings) -> list[str]:
    if not s.lan:
        return [f"http://localhost:{s.public_port}"]
    return [f"https://{h}:{s.public_port}" for h in s.extra_hosts]


@dataclass
class Context:
    settings: Settings
    db: DB
    env: jinja2.Environment


def make_env() -> jinja2.Environment:
    # P11: autoescape everything. Templates never use |safe on data.
    env = jinja2.Environment(loader=jinja2.PackageLoader("portal", "templates"),
                             autoescape=True, undefined=jinja2.StrictUndefined,
                             trim_blocks=True, lstrip_blocks=True)
    env.globals["asset"] = asset
    env.filters["ago"] = ago
    env.filters["when"] = when
    env.filters["short_when"] = short_when
    env.filters["sender"] = sender
    env.filters["why"] = why
    env.filters["iso"] = iso
    return env


# The analyzer's rule codes (analyzer/decide.py, pipeline.py) in plain words.
_WHY = {
    "protected_verified": "Your Never trash list, sender verified",
    "protected_unverified": "Your Never trash list, but the sender isn't verified",
    "blocklist": "Your Always trash list",
    "protected_keyword": "A protected subject word",
    "feedback_trusted": "You said this sender is fine before",
    "lookalike_domain": "Domain looks like one you protect",
    "disagree_injection": "Hidden text aimed at AI filters",
    "disagree_auth": "Sender failed its signature check",
    "parse_limit": "Too large to check",
    "no_model": "AI is off",
    "budget_cap": "Monthly AI budget reached, not checked",
    "rate_cap_hour": "Hourly AI limit reached, not checked",
    "rate_cap_day": "Daily AI limit reached, not checked",
    "model_error": "The AI's answer was unusable",
}


def why(r) -> str:
    """Why the analyzer did what it did, for a log row. Falls back to its own explain text."""
    def f(k):
        try:
            return r[k]
        except (KeyError, IndexError, TypeError):
            return getattr(r, k, None)
    rule, conf, label = f("rule") or "", f("confidence"), f("label") or ""
    try:
        conf = float(conf) if conf is not None else None
    except (TypeError, ValueError):
        conf = None
    if rule in ("threshold", "review_band", "model_keep") and conf is not None:
        pct = f"{round(conf * 100):d}%"
        if label in ("spam", "phishing"):
            tail = {"threshold": "sure enough to trash", "review_band": "not sure enough"}.get(rule, "below Review")
            return f"AI: {pct} {label}, {tail}"
        return f"AI: {pct} not spam"
    return _WHY.get(rule) or str(f("explain") or "")


# Old server-rendered pages that the React frontend (/app) now replaces. A signed-in
# GET of one goes to its /app page, keeping the query (Review's and the log entry's
# "Never trash this sender" links carry ?add=...&value=...). Pages not listed here
# (vendor, go-live, unsubscribe, sign-in) stay server-rendered.
SPA_PAGES = {
    "/": "/app/", "/review": "/app/review", "/log": "/app/log", "/lists": "/app/lists",
    "/analyzer": "/app/analyzer", "/settings": "/app/settings", "/audit": "/app/audit", "/more": "/app/more",
    "/log/entry": "/app/log/entry", "/backfill": "/app/backfill", "/analyzer/vendor": "/app/analyzer/vendor",
}


def web_built() -> bool:
    """True when the React frontend is built into this install (portal/web -> web_dist)."""
    try:
        return resources.files("portal").joinpath("web_dist", "index.html").is_file()
    except (FileNotFoundError, NotADirectoryError):
        return False


@functools.lru_cache(maxsize=None)
def asset(name: str) -> str:
    """/static/<name>?v=<content hash>: a new build changes the URL, so a browser
    never pairs new pages with a stylesheet or script it cached from the old one."""
    try:
        data = resources.files("portal").joinpath("static", name).read_bytes()
    except (FileNotFoundError, IsADirectoryError):
        return f"/static/{name}"
    return f"/static/{name}?v={hashlib.sha256(data).hexdigest()[:12]}"


def sender(addr: str) -> Markup:
    """An address that may wrap only after the @, never mid-domain."""
    local, at, domain = str(addr).rpartition("@")
    if not at:
        return Markup.escape(addr)
    return Markup.escape(local) + Markup("@<wbr>") + Markup.escape(domain)


def ago(ts: float | None) -> str:
    if not ts:
        return "never"
    secs = max(0, int(time.time() - float(ts)))
    if secs < 60:
        return "just now"
    for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if secs >= size:
            n = secs // size
            return f"{n} {unit}{'' if n == 1 else 's'} ago"
    return "just now"


def when(ts: float | None) -> str:
    """Local time of the host (the container gets TZ from compose)."""
    if not ts:
        return ""
    return dt.datetime.fromtimestamp(float(ts)).astimezone().strftime("%d %b %Y, %H:%M")


def live_fields(data: dict) -> dict:
    """The live-mode numbers health.json carries (counts as ints, text cleaned)."""
    def n(v):
        return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None
    agree = data.get("agreement") if isinstance(data.get("agreement"), dict) else {}
    problem = data.get("mode_problem")
    return {
        "requested": "live" if data.get("mode_requested") == "live" else "shadow",
        "problem": "".join(c for c in problem if c.isprintable())[:200] if isinstance(problem, str) else "",
        **{k: n(data.get(k)) for k in ("moved_today", "move_cap", "moved_back_today", "shadow_since",
                                        "would_review", "would_quarantine")},
        "agreement": {k: n(agree.get(k)) for k in ("corrections", "model_agreed", "said_spam_was_fine", "missed_spam")},
    }


def iso(ts: float | None) -> str:
    return dt.datetime.fromtimestamp(float(ts)).astimezone().isoformat(timespec="minutes") if ts else ""


def short_when(ts: float | None, now: float | None = None) -> str:
    """09:34 today, "Yesterday 09:34", "21 Nov" this year, else "21 Nov 2025"."""
    if not ts:
        return ""
    t = dt.datetime.fromtimestamp(float(ts)).astimezone()
    n = dt.datetime.fromtimestamp(now or time.time()).astimezone()
    if t.date() == n.date():
        return t.strftime("%H:%M")
    if t.date() == (n - dt.timedelta(days=1)).date():
        return "Yesterday " + t.strftime("%H:%M")
    return t.strftime("%d %b") if t.year == n.year else t.strftime("%d %b %Y")


def analyzer_health(settings: Settings, directory: str | None = None) -> dict:
    p = Path(directory or settings.analyzer_data) / "health.json"
    empty = {"detail": "", "ts": 0.0, "mode": "shadow", "live_available": False, "live": {}, "model": "", "spend": None, "budget": None,
             "settings_problems": [], "provider": "", "provider_label": "", "model_name": ""}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"state": "not_set_up", **empty}
    except (OSError, ValueError):
        return {"state": "unreadable", **empty}
    if not isinstance(data, dict):
        return {"state": "unreadable", **empty}
    try:
        ts = float(data.get("ts", 0))
    except (TypeError, ValueError):
        ts = 0.0
    status = str(data.get("status", ""))
    state = "ok" if status == "ok" else (status if status in ("retrying", "bridge_unreachable") else "unknown")
    if ts and time.time() - ts > STALE_AFTER:
        state = "stalled"
    out = {"state": state, "detail": str(data.get("detail", ""))[:200], "ts": ts,
           "mode": "live" if data.get("mode") == "live" else "shadow",
           # An analyzer that can move mail reports mode_requested (live-mode contract).
           "live_available": isinstance(data.get("mode_requested"), str),
           "live": live_fields(data),
           "model": str(data.get("model", ""))[:40], "spend": None, "budget": None,
           "provider": str(data.get("provider", ""))[:20],
           "provider_label": vendors.label(str(data.get("provider", ""))), "model_name": str(data.get("model_name", ""))[:100],
           "settings_problems": [str(x)[:200] for x in data.get("settings_problems", [])[:20]]
           if isinstance(data.get("settings_problems"), list) else []}
    for k, src in (("spend", "spend_month_usd"), ("budget", "budget_usd")):
        try:
            out[k] = float(data[src])
        except (KeyError, TypeError, ValueError):
            pass
    return out


def build(ctx: Context) -> App:
    app = App(ctx)
    db, s = ctx.db, ctx.settings

    def render(req: Request, name: str, status: int = 200, **kw) -> Response:
        kw.setdefault("health", None)
        if "review_waiting" not in kw:
            counter = getattr(ctx, "review_waiting", None)
            signed = bool(req.session and req.session.kind == "admin")
            kw["review_waiting"] = counter() if (counter and signed) else 0
        kw.setdefault("error", None)
        kw.setdefault("lan", s.lan)
        signed_in = bool(req.session and req.session.kind == "admin")
        # Versions only for a signed-in admin: the sign-in page doesn't advertise them.
        kw.setdefault("versions", hoststatus.versions(sources.get(s).host_status_dir) if signed_in else {})
        kw.setdefault("lan_nudge", s.lan and req.session is not None and req.session.kind == "admin"
                      and not auth.has_totp(db))
        page = ctx.env.get_template(name).render(
            product=s.product_name, version=__version__, csrf=req.session.csrf if req.session else "",
            signed_in=bool(req.session and req.session.kind == "admin"), path=req.path, **kw)
        return Response(status, page.encode())

    def anon(req: Request) -> auth.Session:
        if req.session is None:
            req.session = auth.new_session(db, "anon", req.ip)
        return req.session

    def admin_only(fn):
        @wraps(fn)
        def inner(req: Request) -> Response:
            if not auth.is_claimed(db):
                return redirect("/claim")
            if req.session is None or req.session.kind != "admin":
                return redirect("/login")
            return fn(req)
        return inner

    def step_up(fn):
        """P8: actions that need the password and a fresh code again."""
        @wraps(fn)
        def inner(req: Request) -> Response:
            if time.time() - req.session.reauth_at > s.reauth_window:
                # After confirming, go back to the page the form was on (a POST path would 405).
                back = req.path if req.method == "GET" else req.field("back", "/")
                return render(req, "reauth.html", 401, error=None, next=back, totp_on=auth.has_totp(db))
            return fn(req)
        return admin_only(inner)

    def throttled(req: Request, what: str) -> int:
        return max(auth.locked_for(db, f"{what}:{req.ip}"), auth.locked_for(db, f"{what}:*"))

    def failed(req: Request, what: str) -> None:
        auth.record_failure(db, f"{what}:{req.ip}")
        # A global counter too, with a bigger allowance, so many source
        # addresses can't share out the guesses.
        auth.record_failure(db, f"{what}:*", free=auth.FREE_ATTEMPTS_GLOBAL)

    def wait_msg(secs: int) -> str:
        return f"Too many attempts. Wait {secs} second{'s' if secs != 1 else ''} and try again."

    # --- claim (P6) ----------------------------------------------------------

    @app.route("GET", "/claim")
    def claim_get(req: Request) -> Response:
        if auth.is_claimed(db):
            return redirect("/login")
        if req.session and req.session.kind == "claim":
            return redirect("/claim/admin")
        anon(req)
        return render(req, "claim.html", error=None)

    @app.route("POST", "/claim")
    def claim_post(req: Request) -> Response:
        if auth.is_claimed(db):
            return redirect("/login")
        wait = throttled(req, "claim")
        if wait:
            return render(req, "claim.html", 429, error=wait_msg(wait))
        if not auth.check_claim_code(db, req.field("code")):
            failed(req, "claim")
            db.audit("claim code rejected", ip=req.ip, result="failed")
            return render(req, "claim.html", 401, error=(
                "That code doesn't match, or it has expired. Codes last an hour. "
                "Get a new one with: ./bridgekeep portal code"))
        auth.clear_failures(db, f"claim:{req.ip}")
        auth.consume_claim_code(db)  # works once: a second visitor can't also start claiming
        req.session = auth.upgrade_session(db, req.session, "claim", req.ip)
        db.audit("claim code accepted", ip=req.ip)
        return redirect("/claim/admin")

    def enrollment(req: Request) -> dict:
        if not req.session.pending_totp:
            auth.set_pending_totp(db, req.session, totp.new_secret())
        secret = req.session.pending_totp
        uri = totp.uri(secret, "admin", s.product_name)
        qr = segno.make(uri, error="m").svg_inline(scale=5, dark="#000", light="#fff", border=3)
        # segno's SVG is generated from our own URI, never from request data.
        return {"qr": Markup(qr), "secret": totp.grouped(secret)}

    @app.route("GET", "/claim/admin")
    def claim_admin_get(req: Request) -> Response:
        if auth.is_claimed(db):
            return redirect("/login")
        if req.session is None or req.session.kind != "claim":
            return redirect("/claim")
        return render(req, "claim_admin.html", error=None, **enrollment(req))

    @app.route("POST", "/claim/admin")
    def claim_admin_post(req: Request) -> Response:
        if auth.is_claimed(db):
            return redirect("/login")
        if req.session is None or req.session.kind != "claim" or not req.session.pending_totp:
            return redirect("/claim")
        pw, confirm, code = req.field("password"), req.field("confirm"), req.field("code").strip()
        # The authenticator is optional (owner decision, 24 Nov): an empty code skips it.
        with_totp = bool(code)
        problem = auth.password_problem(pw, confirm, with_totp)
        step = -1
        if not problem and with_totp:
            step = totp.verify(req.session.pending_totp, code)
            if step is None:
                problem = ("That code didn't work. Check the time on your phone is set "
                           "automatically, then enter the code showing now. Or leave it empty to skip.")
        if problem:
            return render(req, "claim_admin.html", 400, error=problem, **enrollment(req))
        auth.create_admin(db, pw, req.session.pending_totp if with_totp else "", step)
        req.session = auth.upgrade_session(db, req.session, "admin", req.ip)
        db.audit("admin created", target="with authenticator" if with_totp else "password only", ip=req.ip)
        return redirect("/")

    # --- sign in -------------------------------------------------------------

    @app.route("GET", "/login")
    def login_get(req: Request) -> Response:
        if not auth.is_claimed(db):
            return redirect("/claim")
        if req.session and req.session.kind == "admin":
            return redirect("/")
        anon(req)
        return render(req, "login.html", error=None, totp_on=auth.has_totp(db))

    @app.route("POST", "/login")
    def login_post(req: Request) -> Response:
        if not auth.is_claimed(db):
            return redirect("/claim")
        wait = throttled(req, "login")
        if wait:
            return render(req, "login.html", 429, error=wait_msg(wait), totp_on=auth.has_totp(db))
        if not auth.verify_admin(db, req.field("password"), req.field("code")):
            failed(req, "login")
            db.audit("sign-in failed", ip=req.ip, result="failed")
            return render(req, "login.html", 401, error="The password or the code is wrong.",
                          totp_on=auth.has_totp(db))
        auth.clear_failures(db, f"login:{req.ip}")
        req.session = auth.upgrade_session(db, req.session, "admin", req.ip)
        db.audit("signed in", ip=req.ip)
        return redirect("/")

    @app.route("POST", "/logout")
    def logout(req: Request) -> Response:
        if req.session and req.session.kind == "admin":
            db.audit("signed out", ip=req.ip)
        auth.end_session(db, req.session)
        req.session = None
        return redirect("/login")

    @app.route("POST", "/reauth")
    @admin_only
    def reauth(req: Request) -> Response:
        nxt = req.field("next", "/")
        wait = throttled(req, "login")
        if wait:
            return render(req, "reauth.html", 429, error=wait_msg(wait), next=nxt, totp_on=auth.has_totp(db))
        if not auth.verify_admin(db, req.field("password"), req.field("code")):
            failed(req, "login")
            db.audit("re-authentication failed", ip=req.ip, result="failed")
            return render(req, "reauth.html", 401, error="The password or the code is wrong.", next=nxt,
                          totp_on=auth.has_totp(db))
        auth.mark_reauth(db, req.session)
        db.audit("re-authenticated", ip=req.ip)
        return redirect(nxt)

    # --- pages ---------------------------------------------------------------

    @app.route("GET", "/")
    def home(req: Request) -> Response:
        if not auth.is_claimed(db):
            return redirect("/claim")
        if req.session is None or req.session.kind != "admin":
            return redirect("/login")
        return status_page(req)

    @admin_only
    def status_page(req: Request) -> Response:
        account = sources.get(s)
        pc = PortalConfig(account.config_dir)
        health = analyzer_health(s, account.analyzer_dir)
        card = None
        if health["state"] != "not_set_up":
            try:
                card = analyzer_db.AnalyzerDB(account.analyzer_dir).scorecard(14)
            except analyzer_db.Unavailable:
                card = None
        return render(req, "status.html", health=health, port=s.public_port, totp_on=auth.has_totp(db),
                      urls=cli_urls(s), host=hoststatus.load(account.host_status_dir), card=card,
                      paused=pc.paused(), config_writable=pc.writable())

    def settings_view(req: Request, status: int = 200, **kw) -> Response:
        on = auth.has_totp(db)
        kw.setdefault("notice", req.arg("done"))
        kw.setdefault("pw_error", None)
        kw.setdefault("totp_error", None)
        kw.setdefault("alerts_error", None)
        drop = secret_drop.SecretDrop(s.secret_requests, sources.get(s).host_status_dir)
        return render(req, "settings.html", status, port=s.public_port, totp_on=on, urls=cli_urls(s),
                      alerts=drop.state()["discord_webhook"], test_alert=drop.state()["test_alert"],
                      alerts_writable=drop.writable(),
                      fingerprint=fingerprint_lines(s.fingerprint),
                      **({} if on else enrollment(req)), **kw)

    @app.route("GET", "/app")
    @admin_only
    def web_app(req: Request) -> Response:
        """The React frontend's page shell (portal/web). Data comes from /api/..."""
        try:
            body = resources.files("portal").joinpath("web_dist", "index.html").read_bytes()
        except (FileNotFoundError, NotADirectoryError):
            return text(404, "The new portal pages aren't built into this image yet.")
        return Response(200, body, headers={"Content-Security-Policy": CSP_APP})

    @app.route("GET", "/more")
    @admin_only
    def more_page(req: Request) -> Response:
        return render(req, "more.html")

    @app.route("GET", "/settings")
    @admin_only
    def settings_page(req: Request) -> Response:
        return settings_view(req)

    @app.route("POST", "/settings/password")
    @step_up
    def change_password(req: Request) -> Response:
        problem = auth.password_problem(req.field("password"), req.field("confirm"), auth.has_totp(db))
        if problem:
            return settings_view(req, 400, notice="", pw_error=problem)
        with db.lock:
            db.execute("UPDATE admin SET pw_hash = ?, updated = ? WHERE id = 1",
                       (auth.hash_password(req.field("password")), time.time()))
            auth.end_other_sessions(db, req.session)   # this one continues
        db.audit("admin password changed", ip=req.ip)
        return redirect("/settings?done=password")

    @app.route("POST", "/settings/totp/on")
    @step_up
    def totp_on(req: Request) -> Response:
        if auth.has_totp(db):
            return redirect("/settings")
        secret = req.session.pending_totp
        step = totp.verify(secret, req.field("code")) if secret else None
        if step is None:
            return settings_view(req, 400, notice="", totp_error=(
                "That code didn't work. Check the time on your phone is set automatically, "
                "then enter the code showing now."))
        auth.set_totp(db, secret, step)
        auth.set_pending_totp(db, req.session, "")
        auth.end_other_sessions(db, req.session)
        db.audit("authenticator turned on", ip=req.ip)
        return redirect("/settings?done=totp-on")

    @app.route("POST", "/settings/totp/off")
    @admin_only
    def totp_off(req: Request) -> Response:
        # Always asks for the password and a current code here, whatever the
        # step-up window says, and the password must be one that is allowed
        # without an authenticator (15+ characters, not a common one).
        wait = throttled(req, "login")
        if wait:
            return settings_view(req, 429, notice="", totp_error=wait_msg(wait))
        pw = req.field("password")
        if not auth.verify_admin(db, pw, req.field("code")):
            failed(req, "login")
            db.audit("authenticator turn-off refused", ip=req.ip, result="failed")
            return settings_view(req, 401, notice="", totp_error="The password or the code is wrong.")
        if auth.password_problem(pw, pw, with_totp=False):
            return settings_view(req, 400, notice="", totp_error=(
                f"Without an authenticator your password needs at least {auth.MIN_PASSWORD_ALONE} characters "
                "and mustn't be a common one. Change your password first, then turn it off."))
        auth.set_totp(db, "")
        auth.mark_reauth(db, req.session)
        auth.end_other_sessions(db, req.session)
        db.audit("authenticator turned off", ip=req.ip)
        return redirect("/settings?done=totp-off")

    @app.route("GET", "/portal.crt")
    def certificate(req: Request) -> Response:
        """The portal's public certificate, to install as trusted on your devices."""
        p = Path(s.data_dir) / "tls" / "cert.pem"
        if not s.lan or not p.exists():
            return text(404, "Not found")
        return Response(200, p.read_bytes(), "application/x-x509-ca-cert",
                        headers={"Content-Disposition": 'attachment; filename="bridgekeep-portal.crt"'},
                        cache="no-cache")

    @app.route("GET", "/audit")
    @admin_only
    def audit_page(req: Request) -> Response:
        rows = db.all("SELECT ts, action, target, ip, result FROM audit ORDER BY id DESC LIMIT 500")
        return render(req, "audit.html", rows=rows)

    from . import analyzer_pages
    analyzer_pages.register(app, ctx, render, admin_only)
    from . import unsub_pages
    unsub_pages.register(app, ctx, render, admin_only, step_up)
    from . import config_pages
    config_pages.register(app, ctx, render, admin_only, step_up,
                          analyzer_health=lambda: analyzer_health(s, sources.get(s).analyzer_dir),
                          settings_view=settings_view)
    from . import backfill_pages
    backfill_pages.register(app, ctx, render, admin_only, step_up,
                            analyzer_health=lambda: analyzer_health(s, sources.get(s).analyzer_dir))
    from . import api
    api.register(app, ctx, throttled=throttled, failed=failed, wait_msg=wait_msg,
                 analyzer_health=lambda: analyzer_health(s, sources.get(s).analyzer_dir),
                 cli_urls=cli_urls, ago=ago, short_when=short_when, when=when, why=why,
                 fingerprint_lines=fingerprint_lines)

    def to_spa(path: str, page):
        @wraps(page)
        def handler(req: Request) -> Response:
            if req.session is not None and req.session.kind == "admin" and web_built():
                q = urlencode(req.query, doseq=True)
                return redirect(SPA_PAGES[path] + (f"?{q}" if q else ""))
            return page(req)
        return handler

    for path in SPA_PAGES:
        app.routes[("GET", path)] = to_spa(path, app.routes[("GET", path)])
    return app
