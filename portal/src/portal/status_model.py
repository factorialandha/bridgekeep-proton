"""The Status page as data, for /api/status: the same answers status.html
works out, computed in Python so the React page only lays them out."""

from __future__ import annotations


def _money(v: float | None) -> str:
    return f"${v:.2f}"


def _need(level: str, text: str, how: str = "", href: str = "", action: str = "") -> dict:
    out = {"level": level, "text": text}
    if how:
        out["how"] = how
    if href:
        out["href"] = href
    if action:
        out["action"] = action
    return out


def needs(health: dict, host: dict, versions: dict, review_waiting: int, paused: bool) -> list[dict]:
    """What's broken ("bad"), then what needs the admin ("todo"), in status.html's order."""
    b, st = host.get("bridge"), host.get("storage")
    bad: list[dict] = []
    todo: list[dict] = []
    if not b:
        bad.append(_need("bad", "Bridge hasn't reported yet"))
    else:
        if b["health"] not in ("healthy", "starting", "paused"):
            bad.append(_need("bad", f"Bridge is {b['health']}", "Run ./bridgekeep doctor on the host."))
        if b["health"] == "paused":
            todo.append(_need("todo", "Bridge is stopped on purpose", "Run ./bridgekeep start on the host to start it."))
        if not b["signed_in"]:
            bad.append(_need("bad", "Bridge isn't signed in to Proton", "Sign in again on the Proton account page.",
                             href="/app/proton", action="Sign in"))
        if b["update_waiting"]:
            todo.append(_need("todo", f"Bridge {b['update_waiting']} is ready to install",
                              "Run ./bridgekeep deploy-update on the host. It keeps a rollback."))
    if health.get("state") in ("stalled", "bridge_unreachable", "unknown"):
        bad.append(_need("bad", "The analyzer isn't checking mail", "Run ./bridgekeep doctor on the host."))
    if health.get("model") == "no_key":
        todo.append(_need("todo", "The AI has no API key, so only your lists and rules decide", href="/analyzer#api-key"))
    if health.get("model") == "budget_cap":
        todo.append(_need("todo", "This month's AI budget is used up", href="/analyzer"))
    if st and st.get("low"):
        bad.append(_need("bad", "The disk is nearly full", "Free some space, or Bridge stops syncing."))
    if versions.get("update_ready"):
        todo.append(_need("todo", "A Bridgekeep update is ready", "Run ./bridgekeep setup on the host."))
    if host.get("docker", {}).get("old"):
        todo.append(_need("todo", "Docker is older than 28", "Update Docker Engine on the host."))
    front: list[dict] = []
    if review_waiting:
        front.append(_need("todo", f"{review_waiting} message{'s' if review_waiting != 1 else ''} waiting in Review",
                           href="/app/review"))
    if paused:
        front.append(_need("todo", "The analyzer is paused", action="resume"))
    return bad + front + todo


def build(*, health: dict, host: dict, versions: dict, review_waiting: int, paused: bool, card: dict | None,
          lan: bool, urls: list[str], portal_version: str, config_writable: bool, ago) -> dict:
    b, st = host.get("bridge"), host.get("storage")
    n = needs(health, host, versions, review_waiting, paused)
    bad = [x for x in n if x["level"] == "bad"]
    headline = "Everything is working" if not bad else (
        bad[0]["text"] + (f" and {len(bad) - 1} more" if len(bad) > 1 else ""))

    glance = {
        "bridge": ("Running" if b["health"] == "healthy" else b["health"].capitalize()) if b else "—",
        "bridge_ok": bool(b and b["health"] == "healthy"),
        "messages": b["messages"] if b else None,
        "spend": health.get("spend"), "budget": health.get("budget"),
        "disk_free": st["free"] if st else None,
        "disk_used_pct": st.get("used_pct") if st else None,
    }

    def row(label, value, tone=""):
        r = {"label": label, "value": value}
        if tone:
            r["tone"] = tone
        return r

    # Bridge
    rows = []
    if b:
        h = b["health"]
        checked = f"checked {ago(b['ts'])}" + (": the host hasn't reported for a while" if b["stale"] else "")
        if h == "healthy":
            rows.append(row("Bridge", f"Running · {checked}", "ok"))
        elif h == "starting":
            rows.append(row("Bridge", f"Starting · {checked}", "warn"))
        elif h == "paused":
            rows.append(row("Bridge", "Stopped on purpose. Run ./bridgekeep start on the host to start it again.", "warn"))
        else:
            rows.append(row("Bridge", f"{h.capitalize()}. Run ./bridgekeep doctor on the host.", "bad"))
        if b["signed_in"]:
            rows.append(row("Proton sign-in", f"Signed in as {b['account']}" if b["account"] else "Signed in", "ok"))
        else:
            rows.append(row("Proton sign-in", f"Not signed in. {b['error'] or 'No saved sign-in.'} "
                                              "Sign in on the Proton account page.", "bad"))
        if b["messages"] is not None:
            v = f"{b['messages']:,} messages"
            if b["messages_prev"] is not None and b["messages"] > b["messages_prev"]:
                v += f" · still syncing: {b['messages'] - b['messages_prev']:,} more since the check before"
            rows.append(row("Mail sync", v))
        else:
            rows.append(row("Mail sync", "Not counted yet", "muted"))
        if b["update_waiting"]:
            rows.append(row("Updates", f"Bridge {b['update_waiting']} is ready to install", "warn"))
        elif b["update_scheduled"]:
            rows.append(row("Updates", f"Checked {b['update_when']}".strip(), "ok"))
        else:
            rows.append(row("Updates", "Not scheduled. Run ./bridgekeep setup to schedule nightly checks.", "warn"))
    else:
        rows.append(row("Bridge", "Not reported yet. The host reports every 5 minutes. If this stays, "
                                  "run ./bridgekeep doctor on the host.", "muted"))
    details = [{"label": "Bridge", "rows": rows}]

    # Mail analyzer
    rows = []
    state = health.get("state", "not_set_up")
    rows.append({
        "not_set_up": row("Analyzer", "Not set up. Run ./bridgekeep setup --analyzer on the host.", "muted"),
        "ok": row("Analyzer", f"Running · last check {ago(health.get('ts'))}", "ok"),
        "stalled": row("Analyzer", f"Stalled: no check since {ago(health.get('ts'))}. Run ./bridgekeep doctor.", "bad"),
        "bridge_unreachable": row("Analyzer", f"Can't reach Bridge. {health.get('detail', '')}".strip(), "bad"),
        "retrying": row("Analyzer", f"Retrying. {health.get('detail', '')}".strip(), "warn"),
    }.get(state, row("Analyzer", "Unknown. Run ./bridgekeep doctor.", "warn")))
    if state != "not_set_up":
        rows.append(row("Pause", "Paused: the analyzer checks nothing until you resume.", "warn") if paused
                    else row("Pause", "Not paused" + ("" if config_writable
                                                     else ". Run ./bridgekeep setup on the host to enable pausing.")))
        rows.append(row("Mode", "Live: moves new mail to AI-Review and AI-Quarantine" if health.get("mode") == "live"
                        else "Shadow: logs what it would do, moves nothing"))
    else:
        rows.append(row("Mode", "Not running", "muted"))
    model = health.get("model", "")
    if state != "not_set_up" and (model or health.get("spend") is not None):
        tone = ""
        if model == "off":
            v = "Off: rules and lists only"
        elif model == "no_key":
            v, tone = "No API key: rules and lists only", "muted"
        elif model == "no_price":
            v, tone = "No price: rules and lists only until the model's prices are set", "muted"
        elif model == "budget_cap":
            v, tone = "Budget reached: rules only until next month", "warn"
        elif model.startswith("rate_cap"):
            v, tone = "Paused: hourly or daily limit reached, rules only for now", "warn"
        else:
            v = "On"
        if health.get("provider_label"):
            v += f" · {health['provider_label']}" + (f", {health['model_name']}" if health.get("model_name") else "")
        if health.get("spend") is not None:
            v += f" · {_money(health['spend'])}" + (
                f" of ${health['budget']:.0f}" if health.get("budget") is not None else "") + " this month"
        rows.append(row("AI", v, tone))
    if card:
        v = (f"{card['seen']:,} checked: {card['quarantine']} would be trashed, {card['review']} for you to review"
             + (f", {card['protected']} protected senders kept" if card.get("protected") else ""))
        rows.append(row("Last 14 days", v + (f" · {card['errors']} errors" if card.get("errors") else ""),
                        "warn" if card.get("errors") else ""))
    details.append({"label": "Mail analyzer", "rows": rows})

    # Storage
    if st:
        rows = [row(label, value) for label, value in st.get("rows", [])]
        disk = f"{st['free']} free of {st['total']}" + (f" on {st['path']}" if st.get("path") else "")
        if st.get("used_pct") is not None:
            disk += f" · {st['used_pct']}% used"
        if st.get("low"):
            disk += ". Free some space, or Bridge will stop syncing when it runs out."
        rows.append(row("Disk", disk, "bad" if st.get("low") else ""))
    else:
        rows = [row("Storage", "Not reported yet. The host reports every 5 minutes.", "muted")]
    details.append({"label": "Storage", "rows": rows})

    # This portal
    access = (f"Your home network: {', '.join(urls)}" if lan
              else f"This computer only ({urls[0] if urls else ''}). To open it from other devices at home, see Settings.")
    ver = (f"Bridgekeep {versions['bridgekeep']}" + (f" ({versions['commit']})" if versions.get("commit") else "")
           if versions.get("bridgekeep") else "Bridgekeep (version shows within 5 minutes)")
    ver += f" · Portal {portal_version}" + (f" · Bridge {versions['bridge']}" if versions.get("bridge") else "")
    ready = versions.get("update_ready") or (not versions.get("trees_known") and versions.get("bridgekeep")
                                             and versions["bridgekeep"] != portal_version)
    if ready:
        ver += ". Update ready: run ./bridgekeep setup on the host to apply it" + (
            f" (the {' and '.join(versions['update_ready'])})" if versions.get("update_ready") else "") + "."
    rows = [row("Access", access), row("Versions", ver, "warn" if ready else "")]
    if host.get("docker"):
        d = host["docker"]
        rows.append(row("Docker", d.get("version", "") + (" · older than 28. Update Docker Engine." if d.get("old") else ""),
                        "warn" if d.get("old") else ""))
    details.append({"label": "This portal", "rows": rows})

    return {"summary": {"ok": not bad, "headline": headline}, "needs": n, "glance": glance, "details": details}
