"""One-click unsubscribe (analyzer PR #49). The portal never fetches a
sender's link itself: it asks the analyzer's unsubscribe service, by decision
id only, and the service reads the link from the decision log. Only when an
admin presses the button (step-up, audited), never automatically."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from . import sources
from .analyzer_db import AnalyzerDB, Unavailable
from .web import Request, Response, redirect

RESULTS = {"done", "failed", "refused"}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None          # a 3xx is then raised as HTTPError, and call_service calls it "failed"


def call_service(url: str, decision_id: int, timeout: float = 30) -> dict:
    body = json.dumps({"decision_id": decision_id}).encode()
    req = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/json"})
    # No proxies (the service is on an internal network only) and no
    # redirects: the portal only ever talks to the unsubscribe service.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(req, timeout=timeout) as r:
            raw = r.read(4096)
    except urllib.error.HTTPError as e:
        if not 400 <= e.code < 600:   # a redirect, whatever its body says
            return {"result": "failed", "detail": "The unsubscribe service answered with a redirect, which the portal doesn't follow. Check the Status page.",
                    "host": ""}
        raw = e.read(4096)
    except (urllib.error.URLError, OSError, TimeoutError):
        return {"result": "failed", "detail": "The unsubscribe service isn't reachable. Check the Status page, then try again.",
                "host": ""}
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    result = data.get("result") if data.get("result") in RESULTS else "failed"
    clean = lambda v, n: "".join(ch for ch in str(v or "") if ch.isprintable())[:n]  # noqa: E731
    return {"result": result, "detail": clean(data.get("detail"), 300), "host": clean(data.get("host"), 253)}


def register(app, ctx, render, admin_only, step_up) -> None:
    db = ctx.db
    adb = AnalyzerDB(sources.get(ctx.settings).analyzer_dir)

    @app.route("POST", "/unsubscribe")
    @step_up
    def unsubscribe(req: Request) -> Response:
        try:
            rid = int(req.field("id"))
        except ValueError:
            return redirect("/log")
        back = f"/log/entry?id={rid}"
        try:
            u = adb.unsubscribe(rid)
            row = adb.get(rid)
        except Unavailable:
            return redirect(back)
        if u is None or u["method"] != "one_click" or row is None:
            return redirect(back)
        if req.field("confirm") != "yes":
            return render(req, "unsubscribe.html", 200, rid=rid, host=u["host"], sender=row["from_addr"], out=None)
        db.audit("unsubscribe requested", target=f"decision {rid}: {u['host']}", ip=req.ip)
        out = call_service(ctx.settings.unsubscribe_url, rid)
        db.audit("unsubscribe", target=f"decision {rid}: {out['host'] or u['host']}", ip=req.ip,
                 result=out["result"])
        return render(req, "unsubscribe.html", 200, rid=rid, host=out["host"] or u["host"],
                      sender=row["from_addr"], out=out)
