"""Protected senders (never-trash list, blocklist, keywords) and the analyzer's
Pause switch, written to the portal's own folder for the analyzer to read."""

from __future__ import annotations

import re

from . import sources
from . import vendors
from .secret_drop import SECRETS, DropError, SecretDrop
from .portal_config import SETTINGS, ConfigError, PortalConfig
from .web import Request, Response, redirect

LIST_LABELS = {"protect": "Never trash", "block": "Always trash", "keywords": "Protected subject words"}
LIST_HELP = {
    "protect": "Always kept, whatever the AI thinks. This wins over both other lists.",
    "block": "Trashed, but only when the mail really comes from that address (it passes DMARC).",
    "keywords": "Mail with these words in the subject is never trashed. At most it goes to Review.",
}
LIST_FIELD = {"protect": ("Address or domain", "Address or domain"),
              "block": ("Exact address", "Exact address"),
              "keywords": ("Words in the subject", "Words in the subject")}
# One choice in the add form = a list and what it matches.
TARGETS = [("protect:address", "Never trash: an exact address"),
           ("protect:domain", "Never trash: a whole domain"),
           ("block:address", "Always trash: an exact address"),
           ("keywords:pattern", "Protected subject words: words in the subject")]


# The form shows thresholds as percentages.
PERCENT = ("thresholds.quarantine", "thresholds.review")


def _form_values(req: Request) -> tuple[dict, dict]:
    """(values for check_settings, raw form strings to refill the form)."""
    raw = {k: req.field(k.replace(".", "_")) for k in SETTINGS if k != "model.enabled"}
    vals: dict = {"model.enabled": req.field("model_enabled") == "on"}
    for k, v in raw.items():
        try:
            n = float(v)
        except ValueError:
            vals[k] = None
            continue
        vals[k] = round(n / 100, 4) if k in PERCENT else n
    raw["model.enabled"] = "on" if vals["model.enabled"] else ""
    return vals, raw


def _review_above(vals: dict) -> bool:
    q, r = vals.get("thresholds.quarantine"), vals.get("thresholds.review")
    return isinstance(q, float) and isinstance(r, float) and r > q


def register(app, ctx, render, admin_only, step_up, analyzer_health=None, settings_view=None) -> None:
    db = ctx.db
    account = sources.get(ctx.settings)
    cfg = PortalConfig(account.config_dir, account.curated_dir)
    drop = SecretDrop(ctx.settings.secret_requests, account.host_status_dir)

    def page(req: Request, status: int = 200, error: str = "", form: dict | None = None) -> Response:
        rows, problems = cfg.rows()
        if not form and req.arg("add") in dict(TARGETS):
            form = {"target": req.arg("add"), "list": req.arg("add").partition(":")[0]}
            # "Never trash this sender" links from Review and the log fill in the address.
            v = req.arg("value").strip()
            if v and len(v) <= 254 and v.isprintable():
                form["value"] = v
        hint = req.arg("hint").strip().lower().lstrip("*.")
        hint = hint if re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", hint) and len(hint) <= 253 else ""
        removed = sorted(x for x in cfg.removed() if x[0] in LIST_LABELS)
        return render(req, "lists.html", status, rows=rows, problems=problems, labels=LIST_LABELS, hint=hint,
                      removed=removed,
                      help=LIST_HELP, targets=TARGETS, fields=LIST_FIELD,
                      writable=cfg.writable(), paused=cfg.paused(), done=req.arg("done"),
                      error=error or None, form=form or {})

    @app.route("GET", "/lists")
    @admin_only
    def protected(req: Request) -> Response:
        return page(req)

    @app.route("POST", "/lists/add")
    @step_up
    def add(req: Request) -> Response:
        list_name, kind = req.field("list"), req.field("kind")
        if req.field("target"):
            list_name, _, kind = req.field("target").partition(":")
        raw = req.field("value").strip()
        if kind == "auto":
            # One box per list: an "@" means an exact address, anything else a domain.
            kind = {"protect": "address" if "@" in raw else "domain", "block": "address" if "@" in raw else "domain",
                    "keywords": "pattern"}.get(list_name, "")
        form = {k: req.field(k) for k in ("value", "reason", "expires", "subdomains")}
        form["target"] = f"{list_name}:{kind}"
        form["list"] = list_name
        reason = req.field("reason").strip() or "Added in the portal"
        try:
            value = cfg.add(list_name, kind, raw, reason,
                            subdomains=req.field("subdomains") == "on", expires=req.field("expires"))
        except ConfigError as e:
            return page(req, 400, str(e), form)
        db.audit(f"list: added {kind}", target=f"{list_name}: {value}", ip=req.ip)
        return redirect(f"/lists?done=added#list-{list_name}")

    @app.route("POST", "/lists/remove")
    @step_up
    def remove(req: Request) -> Response:
        list_name, value = req.field("list"), req.field("value")
        if req.field("confirm") != "yes":
            if list_name not in LIST_LABELS:
                return redirect("/lists")
            return render(req, "lists_remove.html", 200, list=list_name, label=LIST_LABELS[list_name],
                          index=req.field("index"), value=value, from_file=req.field("source") == "file")
        try:
            if req.field("source") == "file":
                if list_name not in LIST_LABELS:
                    return redirect("/lists")
                cfg.remove_file_entry(list_name, value)
            else:
                cfg.remove(list_name, int(req.field("index")), value)
        except ValueError:
            return redirect("/lists")
        except ConfigError as e:
            return page(req, 409, str(e))
        db.audit("list: removed" + (" (from file)" if req.field("source") == "file" else ""),
                 target=f"{list_name}: {value}", ip=req.ip)
        return redirect("/lists?done=removed")

    @app.route("POST", "/lists/restore")
    @step_up
    def restore(req: Request) -> Response:
        list_name, value = req.field("list"), req.field("value")
        if list_name not in LIST_LABELS:
            return redirect("/lists")
        try:
            cfg.restore_file_entry(list_name, value)
        except ConfigError as e:
            return page(req, 409, str(e))
        db.audit("list: restored (from file)", target=f"{list_name}: {value}", ip=req.ip)
        return redirect("/lists?done=restored")

    def settings_page(req: Request, status: int = 200, error: str = "", form: dict | None = None,
                      key_error: str = "") -> Response:
        try:
            current = cfg.settings()
            unreadable = ""
        except ConfigError as e:
            current, unreadable = {k: v[3] for k, v in SETTINGS.items()}, str(e)
        shown = {k: (round(v * 100, 2) if k in PERCENT else v) for k, v in current.items()}
        shown = {k: (int(v) if isinstance(v, float) and v.is_integer() else v) for k, v in shown.items()}
        checked, scores = getattr(ctx, "spam_scores", lambda: (0, []))()
        if form:
            shown = form
        health = analyzer_health() if analyzer_health else {"settings_problems": []}
        vendor = health.get("provider") or "anthropic"
        return render(req, "analyzer_settings.html", status, vendor=vendor, health=health,
                      live_requested=cfg.mode_requested() == "live",
                      vendor_label=vendors.label(vendor) or vendor, vendor_model=health.get("model_name", ""), s=shown, writable=cfg.writable(),
                      secrets=drop.state(), drop_writable=drop.writable(), key_error=key_error,
                      done=req.arg("done"), error=error or unreadable or None,
                      problems=health.get("settings_problems", []), defaults=SETTINGS,
                      spend=health.get("spend"), budget=health.get("budget"), mode=health.get("mode", "shadow"),
                      checked=checked, scores=",".join(f"{x:.3f}" for x in scores),
                      would=_would(scores, current))

    def _would(scores: list[float], current: dict) -> dict:
        q, r = float(current["thresholds.quarantine"]), float(current["thresholds.review"])
        return {"trash": sum(x >= q for x in scores), "review": sum(r <= x < q for x in scores)}

    @app.route("GET", "/analyzer")
    @admin_only
    def analyzer_settings(req: Request) -> Response:
        return settings_page(req)

    @app.route("POST", "/analyzer/settings")
    @step_up
    def save_analyzer_settings(req: Request) -> Response:
        vals, raw = _form_values(req)
        try:
            changed = cfg.save_settings(vals)
        except ConfigError:
            msg = ("Review has to be lower than Trash." if _review_above(vals)
                   else "Some values are out of range. Check the numbers below.")
            return settings_page(req, 400, msg, raw)
        if changed:
            db.audit("analyzer settings changed", target=", ".join(changed), ip=req.ip)
        return redirect("/analyzer?done=saved")

    # Secrets: write-only, through the host's drop box. The value is never
    # echoed back into a form, logged, or audited.
    def secret_back(req: Request, name: str) -> str:
        return "/analyzer" if name == "anthropic_api_key" else "/settings"

    def secret_error(req: Request, name: str, msg: str) -> Response:
        if name == "anthropic_api_key":
            return settings_page(req, 400, key_error=msg)
        return settings_view(req, 400, notice="", alerts_error=msg)

    @app.route("POST", "/secrets/set")
    @step_up
    def secret_set(req: Request) -> Response:
        name = req.field("name")
        if name not in SECRETS:
            return redirect("/settings")
        value = req.field("value")
        try:
            drop.request(name, "set", value)
        except DropError as e:
            return secret_error(req, name, str(e))
        finally:
            value = ""
            req.form.pop("value", None)
        db.audit(f"{SECRETS[name][0]}: change requested", ip=req.ip)
        return redirect(secret_back(req, name) + "?done=secret-sent")

    @app.route("POST", "/secrets/remove")
    @step_up
    def secret_remove(req: Request) -> Response:
        name = req.field("name")
        if name not in SECRETS:
            return redirect("/settings")
        if req.field("confirm") != "yes":
            return render(req, "secret_remove.html", 200, secret=name, back=secret_back(req, name),
                          what=("Remove the Claude API key?" if name == "anthropic_api_key" else "Turn off Discord alerts?"),
                          detail=("The analyzer goes back to your lists and rules only." if name == "anthropic_api_key"
                                  else "Bridgekeep stops posting to your Discord channel. You'd need the webhook URL to turn them back on."),
                          button=("Remove the key" if name == "anthropic_api_key" else "Turn off alerts"))
        try:
            drop.request(name, "remove")
        except DropError as e:
            return secret_error(req, name, str(e))
        db.audit(f"{SECRETS[name][0]}: removal requested", ip=req.ip)
        return redirect(secret_back(req, name) + "?done=secret-sent")

    @app.route("POST", "/alerts/test")
    @admin_only
    def alerts_test(req: Request) -> Response:
        try:
            drop.request("test_alert", "test")
        except DropError as e:
            return secret_error(req, "discord_webhook", str(e))
        db.audit("test alert requested", ip=req.ip)
        return redirect("/settings?done=test-sent#alerts")

    # AI vendor: choose, then a confirm page with the vendor's disclosure,
    # where the key is typed (so it's never carried in a hidden field).
    def vendor_page(req: Request, status: int = 200, error: str = "", form: dict | None = None) -> Response:
        health = analyzer_health() if analyzer_health else {}
        current = vendor_page_current()
        if not form:
            form = {"provider": current["provider"], "model": current["model"]}
        return render(req, "analyzer_vendor.html", status, form=form, current=current, vendors=vendors.VENDORS,
                      state=drop.state()["ai_vendor"], drop_writable=drop.writable(), error=error or None,
                      no_price=health.get("model") == "no_price", done=req.arg("done"))

    def vendor_form(req: Request) -> dict:
        return {k: req.field(k)[:300] for k in ("provider", "model", "endpoint", "price_in", "price_out")}

    @app.route("GET", "/analyzer/vendor")
    @admin_only
    def vendor_get(req: Request) -> Response:
        return vendor_page(req)

    @app.route("POST", "/analyzer/vendor/review")
    @step_up
    def vendor_review(req: Request) -> Response:
        form = vendor_form(req)
        try:
            fields = vendors.check(form)
        except vendors.VendorError as e:
            return vendor_page(req, 400, str(e), form)
        return render(req, "analyzer_vendor_confirm.html", 200, f=fields, v=vendors.VENDORS[fields["provider"]],
                      disclosure=vendors.DISCLOSURE[fields["provider"]], key_error=None,
                      current=vendor_page_current())

    def vendor_page_current() -> dict:
        health = analyzer_health() if analyzer_health else {}
        p = health.get("provider") or "anthropic"
        return {"provider": p, "label": vendors.label(p), "model": health.get("model_name") or ""}

    @app.route("POST", "/analyzer/vendor")
    @step_up
    def vendor_set(req: Request) -> Response:
        form = vendor_form(req)
        try:
            fields = vendors.check(form)
        except vendors.VendorError as e:
            return vendor_page(req, 400, str(e), form)
        key = req.field("value")
        req.form.pop("value", None)
        try:
            key = vendors.check_key(fields["provider"], key)
            drop.request_vendor(fields, key)
        except (vendors.VendorError, DropError) as e:
            key = ""
            return render(req, "analyzer_vendor_confirm.html", 400, f=fields, v=vendors.VENDORS[fields["provider"]],
                          disclosure=vendors.DISCLOSURE[fields["provider"]], key_error=str(e),
                          current=vendor_page_current())
        key = ""
        db.audit("AI vendor: change requested", target=f"{fields['provider']} {fields['model']}", ip=req.ip)
        return redirect("/analyzer/vendor?done=sent")

    # Shadow / live. Back to shadow is the safe direction: no step-up. Going
    # live asks first and needs step-up, and only once the analyzer says it
    # can move mail (health.json reports mode_requested).
    @app.route("POST", "/analyzer/mode")
    @admin_only
    def mode(req: Request) -> Response:
        if req.field("mode") == "shadow":
            try:
                cfg.set_mode("shadow")
            except ConfigError as e:
                return settings_page(req, 500, str(e))
            db.audit("analyzer: shadow mode", ip=req.ip)
            return redirect("/analyzer?done=shadow#mode")
        return redirect("/analyzer#mode")

    @app.route("POST", "/analyzer/live")
    @step_up
    def go_live(req: Request) -> Response:
        health = analyzer_health() if analyzer_health else {}
        if not health.get("live_available"):
            return settings_page(req, 409, "Live mode isn't available yet: this version of the analyzer can only log.")
        if req.field("confirm") != "yes":
            return render(req, "analyzer_live.html", 200, live=health.get("live", {}), paused=cfg.paused())
        try:
            cfg.set_mode("live")
        except ConfigError as e:
            return settings_page(req, 500, str(e))
        db.audit("analyzer: live mode", ip=req.ip)
        return redirect("/analyzer?done=live#mode")

    # Pausing is the safe direction: no step-up. Resuming puts the analyzer
    # back to work (in live mode, moving mail), so it needs one.
    @app.route("POST", "/analyzer/pause")
    @admin_only
    def pause(req: Request) -> Response:
        try:
            cfg.set_paused(True)
        except ConfigError as e:
            return page(req, 500, str(e))
        db.audit("analyzer paused", ip=req.ip)
        return redirect(_back(req))

    @app.route("POST", "/analyzer/resume")
    @step_up
    def resume(req: Request) -> Response:
        try:
            cfg.set_paused(False)
        except ConfigError as e:
            return page(req, 500, str(e))
        db.audit("analyzer resumed", ip=req.ip)
        return redirect(_back(req))


def _back(req: Request) -> str:
    return "/lists" if req.field("back") == "/lists" else "/"
