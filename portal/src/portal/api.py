"""JSON API for the React pages (portal/web). Same rules as the HTML pages.

* Same origin only; a POST needs the Origin check and the session's CSRF token
  in X-CSRF-Token (web.App.check_post), and a JSON object body.
* Not signed in: 401 {"error", "signed_out": true}. Step-up needed: 401
  {"error", "step_up": true}; the page then calls /api/reauth and retries once.
* Errors are {"error": "<a plain sentence>"} with the HTML pages' status codes.
* Secrets are never returned: only on/off, the last 4 characters and when.
* Times are unix seconds, with a formatted string beside them where the page shows one.
"""

from __future__ import annotations

import math
import time
from functools import wraps

import segno

from . import (
    __version__,
    analyzer_db,
    auth,
    broker,
    hoststatus,
    sources,
    status_model,
    totp,
    vendors,
)
from .config_pages import LIST_FIELD, LIST_HELP, LIST_LABELS, PERCENT
from .portal_config import SETTINGS, ConfigError, PortalConfig
from .secret_drop import SECRETS, DropError, SecretDrop
from .unsub_pages import call_service
from .web import Request, Response, api_error, json_response

SIGNED_OUT = "Sign in again to continue."
STEP_UP = "Confirm it's you to do this."


def register(app, ctx, *, throttled, failed, wait_msg, analyzer_health, cli_urls, ago, short_when, when, why,
             fingerprint_lines) -> None:
    db, s = ctx.db, ctx.settings
    account = sources.get(s)
    cfg = PortalConfig(account.config_dir, account.curated_dir)
    drop = SecretDrop(s.secret_requests, account.host_status_dir)

    def signed_in(req: Request) -> bool:
        return bool(req.session and req.session.kind == "admin" and auth.is_claimed(db))

    def api_admin(fn):
        @wraps(fn)
        def inner(req: Request) -> Response:
            if not signed_in(req):
                return api_error(401, SIGNED_OUT, signed_out=True)
            return fn(req)
        return inner

    def api_step_up(fn):
        @wraps(fn)
        def inner(req: Request) -> Response:
            if time.time() - req.session.reauth_at > s.reauth_window:
                return api_error(401, STEP_UP, step_up=True)
            return fn(req)
        return api_admin(inner)

    def body(req: Request) -> dict:
        return req.json or {}

    def health() -> dict:
        return analyzer_health()

    def review_waiting() -> int:
        counter = getattr(ctx, "review_waiting", None)
        return counter() if counter else 0

    # --- session ------------------------------------------------------------

    @app.route("GET", "/api/session")
    def session(req: Request) -> Response:
        if not signed_in(req):
            return json_response(200, {"signed_in": False, "csrf": "", "product": s.product_name})
        v = hoststatus.versions(account.host_status_dir)
        return json_response(200, {
            "signed_in": True, "csrf": req.session.csrf, "product": s.product_name,
            "mode": health().get("mode", "shadow"), "review_waiting": review_waiting(),
            "totp_on": auth.has_totp(db),
            "versions": {"bridgekeep": v["bridgekeep"], "commit": v["commit"], "portal": __version__,
                         "portal_commit": hoststatus.build_commit(), "portal_stale": "portal" in v["update_ready"],
                         "bridge": v["bridge"]},
        })

    @app.route("POST", "/api/reauth")
    @api_admin
    def reauth(req: Request) -> Response:
        b = body(req)
        pw, code = b.get("password"), b.get("code", "")
        if not isinstance(pw, str) or not isinstance(code, str):
            return api_error(400, "The password or the code is wrong.")
        wait = throttled(req, "login")
        if wait:
            return api_error(429, wait_msg(wait))
        if not auth.verify_admin(db, pw, code):
            failed(req, "login")
            db.audit("re-authentication failed", ip=req.ip, result="failed")
            return api_error(401, "The password or the code is wrong.")
        auth.mark_reauth(db, req.session)
        db.audit("re-authenticated", ip=req.ip)
        return json_response(200, {"ok": True})

    # --- status -------------------------------------------------------------

    @app.route("GET", "/api/status")
    @api_admin
    def status(req: Request) -> Response:
        h = health()
        card = None
        if h["state"] != "not_set_up":
            try:
                card = analyzer_db.AnalyzerDB(account.analyzer_dir).scorecard(14)
            except analyzer_db.Unavailable:
                card = None
        data = status_model.build(
            health=h, host=hoststatus.load(account.host_status_dir),
            versions=hoststatus.versions(account.host_status_dir), review_waiting=review_waiting(),
            paused=cfg.paused(), card=card, lan=s.lan, urls=cli_urls(s), portal_version=__version__,
            config_writable=cfg.writable(), ago=ago)
        return json_response(200, data)

    # --- review -------------------------------------------------------------

    @app.route("GET", "/api/review")
    @api_admin
    def review(req: Request) -> Response:
        try:
            rows = ctx.review_items()
        except analyzer_db.Unavailable as e:
            return json_response(200, {"items": [], "unavailable": str(e).split(":")[0]})
        items = [{
            "id": r["id"], "from_addr": r["from_addr"], "subject": r["subject"], "ts": int(r["ts"]),
            "when": short_when(r["ts"]), "confidence": r["confidence"], "label": r["label"] or None,
            "reason": r["reason"] or None, "explain": r["explain"] or "",
        } for r in rows]
        return json_response(200, {"items": items})

    @app.route("POST", "/api/review/verdict")
    @api_admin
    def verdict(req: Request) -> Response:
        b = body(req)
        rid, v = b.get("id"), b.get("verdict")
        if not isinstance(rid, int) or isinstance(rid, bool) or v not in ("keep", "trash", "undo"):
            return api_error(400, "That isn't an answer the portal knows.")
        if not ctx.record_verdict(rid, v, req.ip):
            return api_error(404, "That message isn't in the log any more.")
        return json_response(200, {"ok": True})

    # --- analyzer -----------------------------------------------------------

    # What the analyzer reports it enforces, for keys settings.yaml doesn't set
    # (it then uses analyzer.yaml, which can differ from the portal's defaults).
    IN_USE = {"model.monthly_budget_usd": "budget"}

    def shown_settings(h: dict | None = None) -> tuple[dict, str, list[str]]:
        try:
            current, problem = cfg.settings(), ""
            saved = cfg.saved_settings()
        except ConfigError as e:
            current, problem, saved = {k: v[3] for k, v in SETTINGS.items()}, str(e), set()
        h = h or {}
        for k, hk in IN_USE.items():
            v, (_t, lo, hi, _d) = h.get(hk), SETTINGS[k]
            if k not in saved and isinstance(v, (int, float)) and not isinstance(v, bool) and lo <= v <= hi:
                current[k] = float(v)
        out = {}
        for k, v in current.items():
            if k in PERCENT:
                v = round(v * 100, 2)
            if isinstance(v, float) and v.is_integer():
                v = int(v)
            out[k] = v
        return out, problem, sorted(k for k in SETTINGS if k not in saved)

    @app.route("GET", "/api/analyzer")
    @api_admin
    def analyzer(req: Request) -> Response:
        h = health()
        vendor = h.get("provider") or "anthropic"
        key = drop.state()["anthropic_api_key"]
        settings, problem, unsaved = shown_settings(h)
        checked, scores = getattr(ctx, "spam_scores", lambda: (0, []))()
        return json_response(200, {
            "mode": h.get("mode", "shadow"), "live_available": bool(h.get("live_available")),
            "mode_requested": cfg.mode_requested(), "paused": cfg.paused(),
            "vendor": vendor, "vendor_label": vendors.label(vendor) or vendor, "model_name": h.get("model_name", ""),
            "model_state": h.get("model", ""), "spend": h.get("spend"), "budget": h.get("budget"),
            "key": {"on": key["on"], "last4": key["last4"], "pending": key["pending"], "when": key["when"]},
            "settings": settings, "settings_problem": problem, "unsaved": unsaved, "problems": h.get("settings_problems", []),
            "defaults": {k: (round(v[3] * 100) if k in PERCENT else v[3]) for k, v in SETTINGS.items()},
            "preview": {"checked": checked, "scores": [round(x, 3) for x in scores]},
            "writable": cfg.writable(), "key_writable": drop.writable(),
        })

    def settings_values(raw) -> dict | None:
        """The page's settings object (thresholds as whole percents) as
        check_settings values, or None when it isn't one."""
        if not isinstance(raw, dict):
            return None
        vals: dict = {}
        for k, (typ, *_rest) in SETTINGS.items():
            v = raw.get(k)
            if typ is bool:
                if not isinstance(v, bool):
                    return None
                vals[k] = v
                continue
            if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
                vals[k] = None             # out of range: check_settings names it
                continue
            vals[k] = round(v / 100, 4) if k in PERCENT else v
        return vals

    @app.route("POST", "/api/analyzer/settings")
    @api_step_up
    def save_settings(req: Request) -> Response:
        vals = settings_values(body(req).get("settings", body(req)))
        if vals is None:
            return api_error(400, "Some values are out of range. Check the numbers.")
        try:
            changed = cfg.save_settings(vals)
        except ConfigError:
            q, r = vals.get("thresholds.quarantine"), vals.get("thresholds.review")
            above = isinstance(q, float) and isinstance(r, float) and r > q
            return api_error(400, "Review has to be lower than Trash." if above
                             else "Some values are out of range. Check the numbers.")
        if changed:
            db.audit("analyzer settings changed", target=", ".join(changed), ip=req.ip)
        return json_response(200, {"ok": True, "changed": changed})

    # Back to shadow is the safe direction: signed in is enough. Going live
    # needs step-up and an explicit confirm, and only once the analyzer says
    # it can move mail (health.json reports mode_requested).
    @app.route("GET", "/api/analyzer/live")
    @api_admin
    def live(req: Request) -> Response:
        h = health()
        return json_response(200, {"available": bool(h.get("live_available")), "live": h.get("live") or {},
                                   "paused": cfg.paused()})

    @app.route("POST", "/api/analyzer/mode")
    @api_admin
    def mode(req: Request) -> Response:
        want = body(req).get("mode")
        if want == "live":
            if time.time() - req.session.reauth_at > s.reauth_window:
                return api_error(401, STEP_UP, step_up=True)
            if not health().get("live_available"):
                return api_error(409, "Live mode isn't available yet: this version of the analyzer can only log.")
            if body(req).get("confirm") is not True:
                return api_error(400, "Confirm that new mail may be moved.")
        elif want != "shadow":
            return api_error(400, "Choose shadow or live.")
        try:
            cfg.set_mode(want)
        except ConfigError as e:
            return api_error(500, str(e))
        db.audit(f"analyzer: {want} mode", ip=req.ip)
        return json_response(200, {"ok": True})

    # AI vendor: review shows the vendor's disclosure; the switch sends the
    # fields and key to the host's drop box. The key is never echoed back.
    def vendor_current() -> dict:
        h = health()
        p = h.get("provider") or "anthropic"
        return {"provider": p, "label": vendors.label(p), "model": h.get("model_name") or ""}

    def vendor_fields(req: Request) -> dict:
        b = body(req)
        return {k: (b[k][:300] if isinstance(b.get(k), str) else "")
                for k in ("provider", "model", "endpoint", "price_in", "price_out")}

    @app.route("GET", "/api/analyzer/vendor")
    @api_admin
    def vendor_get(req: Request) -> Response:
        st = dict(drop.state()["ai_vendor"])
        res = st.get("result") or ""
        st["result"] = res[len("refused: "):] if res.startswith("refused: ") else res
        return json_response(200, {
            "current": vendor_current(),
            "vendors": {k: {"label": v.label, "model_hint": v.model_hint, "key_placeholder": v.key_placeholder,
                            "needs_price": v.needs_price}
                        for k, v in vendors.VENDORS.items()},
            "state": {k: st.get(k) for k in ("provider", "model", "when", "result", "pending")},
            "drop_writable": drop.writable(), "no_price": health().get("model") == "no_price",
        })

    @app.route("POST", "/api/analyzer/vendor/review")
    @api_step_up
    def vendor_review(req: Request) -> Response:
        try:
            f = vendors.check(vendor_fields(req))
        except vendors.VendorError as e:
            return api_error(400, str(e))
        v = vendors.VENDORS[f["provider"]]
        return json_response(200, {"fields": f, "label": v.label, "disclosure": vendors.DISCLOSURE[f["provider"]],
                                   "key_placeholder": v.key_placeholder,
                                   "current_provider": vendor_current()["provider"]})

    @app.route("POST", "/api/analyzer/vendor")
    @api_step_up
    def vendor_set(req: Request) -> Response:
        try:
            f = vendors.check(vendor_fields(req))
        except vendors.VendorError as e:
            return api_error(400, str(e))
        key = body(req).pop("key", "")
        try:
            if not isinstance(key, str):
                raise vendors.VendorError(vendors.VENDORS[f["provider"]].key_hint)
            key = vendors.check_key(f["provider"], key)
            drop.request_vendor(f, key)
        except (vendors.VendorError, DropError) as e:
            return api_error(400, str(e))
        finally:
            key = ""
        db.audit("AI vendor: change requested", target=f"{f['provider']} {f['model']}", ip=req.ip)
        return json_response(200, {"ok": True})

    @app.route("POST", "/api/analyzer/pause")
    @api_admin
    def pause(req: Request) -> Response:
        try:
            cfg.set_paused(True)
        except ConfigError as e:
            return api_error(500, str(e))
        db.audit("analyzer paused", ip=req.ip)
        return json_response(200, {"ok": True})

    @app.route("POST", "/api/analyzer/resume")
    @api_step_up
    def resume(req: Request) -> Response:
        try:
            cfg.set_paused(False)
        except ConfigError as e:
            return api_error(500, str(e))
        db.audit("analyzer resumed", ip=req.ip)
        return json_response(200, {"ok": True})

    @app.route("POST", "/api/secrets/set")
    @api_step_up
    def secret_set(req: Request) -> Response:
        b = body(req)
        name, value = b.get("name"), b.get("value")
        if name not in SECRETS or not isinstance(value, str):
            return api_error(400, "Not a setting the portal knows.")
        try:
            drop.request(name, "set", value)
        except DropError as e:
            return api_error(400, str(e))        # DropError never contains the value
        finally:
            value = ""
            b.pop("value", None)
        db.audit(f"{SECRETS[name][0]}: change requested", ip=req.ip)
        return json_response(200, {"ok": True})

    @app.route("POST", "/api/secrets/remove")
    @api_step_up
    def secret_remove(req: Request) -> Response:
        name = body(req).get("name")
        if name not in SECRETS:
            return api_error(400, "Not a setting the portal knows.")
        try:
            drop.request(name, "remove")
        except DropError as e:
            return api_error(400, str(e))
        db.audit(f"{SECRETS[name][0]}: removal requested", ip=req.ip)
        return json_response(200, {"ok": True})

    # --- log ----------------------------------------------------------------

    @app.route("GET", "/api/log")
    @api_admin
    def log(req: Request) -> Response:
        query = ctx.log_query(req.arg)
        try:
            rows, card, verdicts, before = ctx.log_data(query)
        except analyzer_db.Unavailable as e:
            return json_response(200, {"rows": [], "card": None, "filters": [], "older": None,
                                       "unavailable": str(e).split(":")[0]})
        return json_response(200, {
            "rows": [{
                "id": r["id"], "from_addr": r["from_addr"], "subject": r["subject"], "ts": int(r["ts"]),
                "when": short_when(r["ts"]), "full_when": when(r["ts"]), "action": r["action"],
                "applied": r["applied"], "moved_to": r["moved_to"] or None, "moved_back": r["moved_back"],
                "why": why(r), "verdict": verdicts.get(r["key"], ""),
            } for r in rows],
            "card": {k: card.get(k, 0) for k in ("seen", "quarantine", "review", "protected", "answered")},
            "filters": [{"key": k, "label": v[0]} for k, v in analyzer_db.FILTERS.items()],
            "older": str(before) if before else None,
        })

    @app.route("GET", "/api/log/entry")
    @api_admin
    def log_entry(req: Request) -> Response:
        raw = req.arg("id")
        if not (raw.isascii() and raw.isdigit()) or len(raw) > 18:
            return api_error(400, "That isn't a log entry.")
        try:
            got = ctx.log_entry(int(raw))
        except analyzer_db.Unavailable as e:
            return json_response(200, {"row": None, "verdict": "", "unsub": None,
                                       "unavailable": str(e).split(":")[0]})
        if got is None:
            return api_error(404, "That message isn't in the log any more.")
        r, verdict, unsub = got
        row = {k: r[k] for k in ("id", "key", "from_addr", "subject", "action", "applied", "moved_to", "moved_back",
                                 "explain", "confidence", "verified", "injections", "error", "rule", "mode",
                                 "model", "prompt_version")}
        row.update({"ts": int(r["ts"]), "when": short_when(r["ts"]), "full_when": when(r["ts"]), "why": why(r),
                    "label": r["label"] or None, "reason": r["reason"] or None, "moved_to": r["moved_to"] or None})
        if unsub and unsub["method"] == "one_click":
            unsub = {"method": "one_click", "host": unsub["host"]}
        elif unsub:
            unsub = {"method": "mailto", "mailto": unsub["mailto"]}
        return json_response(200, {"row": row, "verdict": verdict, "unsub": unsub})

    # One-click unsubscribe: by decision id only, the analyzer's service reads
    # the link. Step-up, an explicit confirm, and audited before and after.
    NO_UNSUB = "This message has no one-click unsubscribe."

    @app.route("POST", "/api/unsubscribe")
    @api_step_up
    def unsubscribe(req: Request) -> Response:
        rid = body(req).get("id")
        if isinstance(rid, bool) or not isinstance(rid, int) or not 0 < rid < 10 ** 18:
            return api_error(400, NO_UNSUB)
        adb = analyzer_db.AnalyzerDB(account.analyzer_dir)
        try:
            u = adb.unsubscribe(rid)
            row = adb.get(rid)
        except analyzer_db.Unavailable:
            return api_error(503, "The mail log can't be read right now. Check the Status page.")
        if u is None or u["method"] != "one_click" or row is None:
            return api_error(400, NO_UNSUB)
        if body(req).get("confirm") is not True:
            return api_error(400, "Confirm the unsubscribe first.")
        db.audit("unsubscribe requested", target=f"decision {rid}: {u['host']}", ip=req.ip)
        out = call_service(s.unsubscribe_url, rid)
        db.audit("unsubscribe", target=f"decision {rid}: {out['host'] or u['host']}", ip=req.ip,
                 result=out["result"])
        return json_response(200, {"result": out["result"], "detail": out["detail"],
                                   "host": out["host"] or u["host"]})

    # --- lists --------------------------------------------------------------

    def _s(v) -> str:
        return "" if v is None else str(v)

    @app.route("GET", "/api/lists")
    @api_admin
    def lists(req: Request) -> Response:
        rows, problems = cfg.rows()
        out = []
        for key, label in LIST_LABELS.items():
            out.append({"key": key, "label": label, "help": LIST_HELP[key], "field": LIST_FIELD[key][0], "entries": [{
                "index": r.index, "value": r.value, "kind": r.kind, "subdomains": bool(r.subdomains),
                "reason": _s(r.reason), "expires": _s(r.expires), "added": _s(r.added), "source": r.source,
            } for r in rows if r.list == key]})
        return json_response(200, {
            "lists": out,
            "problems": [{"text": p.text, "list": p.list, "index": p.index, "value": p.value, "fix": p.fix}
                         for p in problems],
            "removed": [{"list": k, "label": LIST_LABELS[k], "value": v}
                        for k, v in sorted(cfg.removed()) if k in LIST_LABELS],
            "writable": cfg.writable(), "paused": cfg.paused(),
        })

    def strs(b: dict, *keys: str) -> list[str] | None:
        vals = [b.get(k, "") for k in keys]
        return vals if all(isinstance(v, str) for v in vals) else None

    @app.route("POST", "/api/lists/add")
    @api_step_up
    def lists_add(req: Request) -> Response:
        b = body(req)
        got = strs(b, "list", "value", "reason", "expires")
        if got is None or got[0] not in LIST_LABELS or not isinstance(b.get("subdomains", False), bool):
            return api_error(400, "Not a list the portal knows.")
        list_name, raw, reason, expires = got[0], got[1].strip(), got[2].strip(), got[3]
        # One box per list: an "@" means an exact address, anything else a domain.
        kind = "pattern" if list_name == "keywords" else ("address" if "@" in raw else "domain")
        try:
            value = cfg.add(list_name, kind, raw, reason or "Added in the portal",
                            subdomains=b.get("subdomains", False), expires=expires)
        except ConfigError as e:
            return api_error(400, str(e))
        db.audit(f"list: added {kind}", target=f"{list_name}: {value}", ip=req.ip)
        return json_response(200, {"ok": True, "value": value})

    @app.route("POST", "/api/lists/remove")
    @api_step_up
    def lists_remove(req: Request) -> Response:
        b = body(req)
        got = strs(b, "list", "value", "source")
        index = b.get("index", -1)
        if got is None or got[0] not in LIST_LABELS or not isinstance(index, int) or isinstance(index, bool):
            return api_error(400, "Not a list the portal knows.")
        list_name, value, source = got
        try:
            if source == "file":
                cfg.remove_file_entry(list_name, value)
            else:
                cfg.remove(list_name, index, value)
        except ValueError:
            return api_error(409, "That entry has changed. Reload the page.")
        except ConfigError as e:
            return api_error(409, str(e))
        db.audit("list: removed" + (" (from file)" if source == "file" else ""),
                 target=f"{list_name}: {value}", ip=req.ip)
        return json_response(200, {"ok": True})

    # Restore puts a filter back to work: step-up, the same as /lists/restore.
    @app.route("POST", "/api/lists/restore")
    @api_step_up
    def lists_restore(req: Request) -> Response:
        b = body(req)
        got = strs(b, "list", "value")
        if got is None or got[0] not in LIST_LABELS:
            return api_error(400, "Not a list the portal knows.")
        try:
            cfg.restore_file_entry(*got)
        except ConfigError as e:
            return api_error(409, str(e))
        db.audit("list: restored (from file)", target=f"{got[0]}: {got[1]}", ip=req.ip)
        return json_response(200, {"ok": True})

    # --- settings -----------------------------------------------------------

    def pending_secret(req: Request) -> str:
        if not req.session.pending_totp:
            auth.set_pending_totp(db, req.session, totp.new_secret())
        return req.session.pending_totp

    @app.route("GET", "/api/settings")
    @api_admin
    def settings(req: Request) -> Response:
        on = auth.has_totp(db)
        st = drop.state()
        a, t = st["discord_webhook"], st["test_alert"]
        out = {
            "lan": s.lan, "urls": cli_urls(s), "fingerprint": fingerprint_lines(s.fingerprint), "port": s.public_port,
            "totp_on": on, "min_password": auth.MIN_PASSWORD if on else auth.MIN_PASSWORD_ALONE,
            "alerts": {"on": a["on"], "last4": a["last4"], "pending": a["pending"], "when": a["when"],
                       "when_text": when(a["when"]) if a["when"] else "", "result": a["result"]},
            "test_alert": {"pending": t["pending"], "result": t["result"]},
            "alerts_writable": drop.writable(),
        }
        if not on:
            out["totp_secret"] = totp.grouped(pending_secret(req))
        return json_response(200, out)

    @app.route("GET", "/api/settings/totp.svg")
    @api_admin
    def totp_svg(req: Request) -> Response:
        if auth.has_totp(db):
            return api_error(404, "The authenticator is already on.")
        uri = totp.uri(pending_secret(req), "admin", s.product_name)
        svg = segno.make(uri, error="m").svg_inline(scale=5, dark="#000", light="#fff", border=3)
        return Response(200, svg.encode(), "image/svg+xml")

    @app.route("POST", "/api/settings/password")
    @api_step_up
    def change_password(req: Request) -> Response:
        got = strs(body(req), "password", "confirm")
        if got is None:
            return api_error(400, "Type the new password twice.")
        problem = auth.password_problem(got[0], got[1], auth.has_totp(db))
        if problem:
            return api_error(400, problem)
        with db.lock:
            db.execute("UPDATE admin SET pw_hash = ?, updated = ? WHERE id = 1",
                       (auth.hash_password(got[0]), time.time()))
            auth.end_other_sessions(db, req.session)   # this one continues
        db.audit("admin password changed", ip=req.ip)
        return json_response(200, {"ok": True})

    @app.route("POST", "/api/settings/totp/on")
    @api_step_up
    def totp_on(req: Request) -> Response:
        if auth.has_totp(db):
            return api_error(409, "The authenticator is already on.")
        code = body(req).get("code")
        secret = req.session.pending_totp
        step = totp.verify(secret, code) if secret and isinstance(code, str) else None
        if step is None:
            return api_error(400, "That code didn't work. Check the time on your phone is set automatically, "
                                  "then enter the code showing now.")
        auth.set_totp(db, secret, step)
        auth.set_pending_totp(db, req.session, "")
        auth.end_other_sessions(db, req.session)
        db.audit("authenticator turned on", ip=req.ip)
        return json_response(200, {"ok": True})

    # Always asks for the password and a current code, whatever the step-up
    # window says (as /settings/totp/off).
    @app.route("POST", "/api/settings/totp/off")
    @api_admin
    def totp_off(req: Request) -> Response:
        got = strs(body(req), "password", "code")
        if got is None:
            return api_error(401, "The password or the code is wrong.")
        wait = throttled(req, "login")
        if wait:
            return api_error(429, wait_msg(wait))
        if not auth.verify_admin(db, got[0], got[1]):
            failed(req, "login")
            db.audit("authenticator turn-off refused", ip=req.ip, result="failed")
            return api_error(401, "The password or the code is wrong.")
        if auth.password_problem(got[0], got[0], with_totp=False):
            return api_error(400, f"Without an authenticator your password needs at least {auth.MIN_PASSWORD_ALONE} "
                                  "characters and mustn't be a common one. Change your password first, then turn it off.")
        auth.set_totp(db, "")
        auth.mark_reauth(db, req.session)
        auth.end_other_sessions(db, req.session)
        db.audit("authenticator turned off", ip=req.ip)
        return json_response(200, {"ok": True})

    @app.route("POST", "/api/alerts/test")
    @api_admin
    def alerts_test(req: Request) -> Response:
        try:
            drop.request("test_alert", "test")
        except DropError as e:
            return api_error(400, str(e))
        db.audit("test alert requested", ip=req.ip)
        return json_response(200, {"ok": True})

    # --- Proton sign-in (through the Bridge container's login broker) --------
    # The portal passes on what the admin typed and shows the broker's state;
    # it never sees the Bridge password. Starting a sign-in and signing out
    # need step-up; the steps in between only continue a sign-in the broker
    # already holds, and cancelling is the safe direction.
    def brk() -> broker.Broker:
        return broker.Broker(s.broker_socket)

    BROKER_ERRORS = {
        400: "That doesn't look right. Check what you typed.",
        403: "The sign-in service refused the portal. Run ./bridgekeep doctor on the host.",
        409: "The sign-in moved on. The page now shows the current step.",
        413: "That's too long.",
        429: "Too many sign-in attempts. Wait a few minutes and try again.",
    }

    def proton_view(view: dict) -> dict:
        busy = view["state"] in ("signing_in", "waiting_2fa", "waiting_mailbox_password", "waiting_human")
        return {"available": True, **view, "mail_paused": busy}

    def text_field(b: dict, name: str, cap: int) -> str | None:
        v = b.get(name)
        if not isinstance(v, str) or not v or len(v) > cap or any(ord(c) < 32 or ord(c) == 127 for c in v):
            return None
        return v

    def to_broker(req: Request, endpoint: str, payload: dict, what: str, target: str = "") -> Response:
        try:
            code, view = brk().call("POST", endpoint, payload)
        except broker.Unavailable as e:
            return api_error(503, str(e), available=False)
        finally:
            payload.clear()
        if code != 200:
            # The broker's error bodies are {"error": ...}, not a status: ask
            # for the current one so the page can show where the sign-in is.
            try:
                current = proton_view(brk().status())
            except broker.Unavailable:
                current = None
            return api_error(code if code in BROKER_ERRORS else 502,
                             BROKER_ERRORS.get(code, "The sign-in service had a problem. Try again."),
                             proton=current)
        db.audit(what, target=target, ip=req.ip, result="error" if view["error"] else "ok")
        if view["state"] == "signed_in" and endpoint in ("/login", "/2fa", "/mailbox-password", "/human-verification"):
            db.audit("proton: signed in", target=view["account"], ip=req.ip)
        return json_response(200, proton_view(view))

    @app.route("GET", "/api/proton")
    @api_admin
    def proton_status(req: Request) -> Response:
        try:
            return json_response(200, proton_view(brk().status()))
        except broker.Unavailable as e:
            return json_response(200, {"available": False, "state": "", "account": "", "error": str(e),
                                       "hv_url": "", "step_expires": None, "mail_paused": False})

    @app.route("POST", "/api/proton/login")
    @api_step_up
    def proton_login(req: Request) -> Response:
        b = body(req)
        user, password = text_field(b, "username", 254), text_field(b, "password", 1024)
        b.pop("password", None)
        if not user or not password:
            password = ""
            return api_error(400, "Type your Proton address and password.")
        return to_broker(req, "/login", {"username": user, "password": password}, "proton: sign-in started", user)

    @app.route("POST", "/api/proton/2fa")
    @api_admin
    def proton_2fa(req: Request) -> Response:
        code = body(req).get("code")
        code = code.replace(" ", "") if isinstance(code, str) else ""
        if not (code.isascii() and code.isdigit() and 6 <= len(code) <= 8):
            return api_error(400, "The code is the 6 digits your authenticator app shows.")
        return to_broker(req, "/2fa", {"code": code}, "proton: 2FA code sent")

    @app.route("POST", "/api/proton/mailbox-password")
    @api_admin
    def proton_mailbox(req: Request) -> Response:
        b = body(req)
        password = text_field(b, "password", 1024)
        b.pop("password", None)
        if not password:
            return api_error(400, "Type your mailbox password.")
        return to_broker(req, "/mailbox-password", {"password": password}, "proton: mailbox password sent")

    @app.route("POST", "/api/proton/human-verification")
    @api_admin
    def proton_human(req: Request) -> Response:
        return to_broker(req, "/human-verification", {}, "proton: human check done")

    @app.route("POST", "/api/proton/cancel")
    @api_admin
    def proton_cancel(req: Request) -> Response:
        return to_broker(req, "/cancel", {}, "proton: sign-in cancelled")

    @app.route("POST", "/api/proton/logout")
    @api_step_up
    def proton_logout(req: Request) -> Response:
        if body(req).get("confirm") is not True:
            return api_error(400, "Confirm signing out first. Mail stops until you sign in again.")
        return to_broker(req, "/logout", {}, "proton: signed out")

    # --- audit --------------------------------------------------------------

    @app.route("GET", "/api/audit")
    @api_admin
    def audit(req: Request) -> Response:
        rows = db.all("SELECT id, ts, action, target, ip, result FROM audit ORDER BY id DESC LIMIT 500")
        return json_response(200, {"rows": [{
            "id": r["id"], "when": when(r["ts"]), "action": r["action"], "target": r["target"] or "",
            "ip": r["ip"] or "", "result": r["result"] or "",
        } for r in rows]})

    # --- older mail (backfill) ------------------------------------------------

    @app.route("GET", "/api/backfill")
    @api_admin
    def backfill(req: Request) -> Response:
        st = ctx.backfill_state()
        job = st["job"]
        text = (ctx.backfill_disclosure(job, st["provider"])
                if job and job["status"] == "estimated" and job["estimated"] else "")
        return json_response(200, {k: st[k] for k in ("job", "pending", "provider", "vendor", "stale",
                                                       "model_state", "writable")} | {"disclosure": text})

    def backfill_do(req: Request, action: str, what: str, **kw) -> Response:
        status, err, req_body = ctx.backfill_checks(action, **kw)
        if req_body is None:
            return api_error(status, err)
        err = ctx.backfill_write(req_body, what, req.ip)
        return api_error(500, err) if err else json_response(200, {"ok": True})

    @app.route("POST", "/api/backfill/estimate")
    @api_admin
    def backfill_estimate(req: Request) -> Response:
        got = strs(body(req), "since", "until", "limit")
        if got is None:
            return api_error(400, "From, To and At most must be text.")
        return backfill_do(req, "estimate", "estimate requested",
                           form={k: v[:20] for k, v in zip(("since", "until", "limit"), got)})

    @app.route("POST", "/api/backfill/start")
    @api_step_up
    def backfill_start(req: Request) -> Response:
        b = body(req)
        got = strs(b, "estimate_id", "provider")
        partial = b.get("allow_partial", False)
        if got is None or not isinstance(partial, bool):
            return api_error(400, "That estimate has changed or is out of date. Check the numbers and start again.")
        return backfill_do(req, "start", "backfill started", form={}, provider_field=got[1],
                           allow_partial=partial, estimate_id=got[0])

    @app.route("POST", "/api/backfill/pause")
    @api_admin
    def backfill_pause(req: Request) -> Response:
        return backfill_do(req, "pause", "backfill paused", form={})

    @app.route("POST", "/api/backfill/resume")
    @api_step_up
    def backfill_resume(req: Request) -> Response:
        return backfill_do(req, "resume", "backfill resumed", form={})

    @app.route("POST", "/api/backfill/cancel")
    @api_admin
    def backfill_cancel(req: Request) -> Response:
        return backfill_do(req, "cancel", "backfill cancelled", form={})
