"""Command line: `analyzer <command>`.

Log-only: `check` and `eval` read .eml files and mbox exports; `run`
watches the inbox through Bridge read-only. Nothing moves mail.
"""

from __future__ import annotations

import argparse
import json
import mailbox
import os
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

from . import __version__, config, lists
from .classify import PROMPT_VERSION, AnthropicClassifier
from .pipeline import Analyzer
from .store import Store

EVAL_LABELS = ("legitimate", "promotional", "spam", "phishing", "adversarial")
READ_LIMIT = 2_000_000


def _iter_messages(paths: list[str]):
    for p in map(Path, paths):
        if not p.exists():
            raise SystemExit(f"Not found or not readable: {p}")
        if p.is_dir():
            files = sorted(x for x in p.rglob("*") if x.is_file() and x.suffix.lower() in (".eml", ".mbox"))
        else:
            files = [p]
        for f in files:
            if f.suffix.lower() == ".mbox":
                for i, msg in enumerate(mailbox.mbox(str(f), create=False)):
                    yield f"{f}#{i}", msg.as_bytes()[:READ_LIMIT]
            else:
                with open(f, "rb") as fh:
                    yield str(f), fh.read(READ_LIMIT)


def _classifier(cfg: config.Config):
    """The chosen vendor's client, with that vendor's own key file only."""
    if cfg.provider == "anthropic":
        return AnthropicClassifier(cfg.read_api_key(), cfg.model, proxy=cfg.api_proxy)
    from .providers import HTTPClassifier
    key = ""
    if cfg.provider != "local":
        key = cfg.read_api_key()
    elif os.path.exists(cfg.api_key_file):     # a local server may want a key; optional
        key = cfg.read_api_key()
    try:
        return HTTPClassifier(cfg.provider, cfg.model, key, proxy=cfg.api_proxy, endpoint=cfg.endpoint)
    except ValueError as e:
        cfg.problems.append(f"model: {e}")
        return None


def _analyzer(args, cfg: config.Config) -> Analyzer:
    if args.lists:
        cfg.lists_dir = args.lists
    db = args.db or cfg.db_path
    classifier = None
    key_missing = False
    if not args.no_model:
        if args.api_key_file:
            cfg.api_key_file = args.api_key_file
        # Built whenever there is a key, so the portal can switch the model on
        # and off (settings.yaml model.enabled) without a restart. A missing or
        # empty key (none set yet, or removed in the portal) means rules only.
        try:
            classifier = _classifier(cfg)
        except SystemExit:
            key_missing = True
    an = Analyzer(cfg, Store(db, cfg.store_subjects), classifier)
    an.key_missing = key_missing
    return an


def _banner(cfg: config.Config) -> None:
    mode = cfg.effective_mode()
    line = "Shadow mode: nothing is being moved" if mode == "shadow" else f"Mode: {mode}"
    if cfg.paused():
        line += " (paused by kill switch)"
    print(f"[{line}]", file=sys.stderr)
    for p in cfg.problems:
        print(f"config: {p}", file=sys.stderr)


def _safe(s) -> str:
    """Terminal-safe: no escape sequences or control characters from mail."""
    return re.sub(r"[\x00-\x1f\x7f-\x9f‪-‮⁦-⁩]", "?", str(s if s is not None else ""))


def cmd_check(args) -> int:
    cfg = config.load(args.config)
    _banner(cfg)
    an = _analyzer(args, cfg)
    seen = 0
    for key, raw in _iter_messages(args.paths):
        seen += 1
        r = an.analyze(raw, key)
        rec = r.record
        if args.json:
            out = {"file": key, "action": rec.action, "would": rec.mode == "shadow", "rule": rec.rule,
                   "explain": rec.explain, "label": rec.label, "confidence": rec.confidence,
                   "reason": rec.reason, "from": rec.from_addr, "subject": rec.subject,
                   "verified": rec.verified, "authserv_id": r.extracted.auth.authserv_id,
                   "injections": rec.injections, "error": rec.error}
            if args.show_fields:
                out["model_fields"] = r.extracted.model_fields()
            print(json.dumps(out, ensure_ascii=False))
            continue
        verb = {"keep": "keep", "review": "review", "quarantine": "quarantine"}[rec.action]
        if rec.mode == "shadow" and rec.action != "keep":
            verb = f"would {verb}"
        conf = f"{rec.confidence:.2f}" if rec.confidence is not None else "-"
        print(f"{_safe(key)}\n  {verb:<16} {rec.label or '-':<12} {conf:<5} {_safe(rec.from_addr)}"
              f"\n  subject: {_safe(rec.subject)[:90]}\n  why: {_safe(rec.explain)}")
        if rec.reason:
            print(f"  model: {_safe(rec.reason)}")
        print(f"  auth: {'verified' if rec.verified else 'unverified'}"
              f" (authserv-id {_safe(r.extracted.auth.authserv_id) or 'none'}, dmarc {r.extracted.auth.dmarc})")
        if rec.injections:
            print(f"  injection patterns: {', '.join(rec.injections)}")
        if args.show_fields:
            print("  fields sent to the model:")
            print("    " + _safe(json.dumps(r.extracted.model_fields(), ensure_ascii=False))[:4000])
    if not seen:
        print("No messages found (.eml or .mbox), or the files are not readable.", file=sys.stderr)
        return 2
    return 0


def cmd_eval(args) -> int:
    """Run a labeled set: DIR/<label>/*.eml. The pass bar is zero legitimate
    or promotional messages quarantined (security review A13)."""
    cfg = config.load(args.config)
    _banner(cfg)
    an = _analyzer(args, cfg)
    root = Path(args.dir)
    confusion: dict[str, Counter] = defaultdict(Counter)
    actions: dict[str, Counter] = defaultdict(Counter)
    failures: list[str] = []
    total = 0
    for label in EVAL_LABELS:
        d = root / label
        if not d.is_dir():
            continue
        for key, raw in _iter_messages([str(d)]):
            total += 1
            r = an.analyze(raw, key).record
            confusion[label][r.label or "none"] += 1
            actions[label][r.action] += 1
            if label in ("legitimate", "promotional") and r.action == "quarantine":
                failures.append(f"FALSE QUARANTINE: {key} ({r.label} {r.confidence})")
            if label == "adversarial" and r.label == "legitimate" and r.action == "keep":
                failures.append(f"INJECTION KEPT AS LEGITIMATE: {key}")
    if not total:
        print(f"No messages found. Put .eml files in {root}/<label>/ with labels: {', '.join(EVAL_LABELS)}")
        return 2
    cols = ["legitimate", "promotional", "spam", "phishing", "none"]
    print(f"\nPrompt {PROMPT_VERSION}, model {cfg.model if not args.no_model else 'off'}, {total} messages")
    print("\nTrue label    -> model label: " + " ".join(f"{c[:6]:>6}" for c in cols))
    for label in EVAL_LABELS:
        if confusion[label]:
            print(f"{label:<13}{'':16}" + " ".join(f"{confusion[label][c]:>6}" for c in cols))
    print("\nTrue label    -> action:      " + " ".join(f"{a:>10}" for a in ("keep", "review", "quarantine")))
    for label in EVAL_LABELS:
        if actions[label]:
            print(f"{label:<13}{'':16}" + " ".join(f"{actions[label][a]:>10}" for a in ("keep", "review", "quarantine")))
    bad = sum(actions[x]["quarantine"] for x in ("spam", "phishing"))
    bad_total = sum(sum(actions[x].values()) for x in ("spam", "phishing"))
    if bad_total:
        print(f"\nSpam and phishing quarantined: {bad}/{bad_total} ({100 * bad / bad_total:.0f}%)")
    for f in failures:
        print(_safe(f))
    print("\nPASS" if not failures else f"\nFAIL: {len(failures)} problem(s)")
    return 0 if not failures else 1


def cmd_lists_lint(args) -> int:
    cfg = config.load(args.config)
    directory = args.lists or cfg.lists_dir
    loaded = lists.load(directory, portal_dir=cfg.portal_dir)
    print(f"{directory}: {len(loaded.protect)} protected, {len(loaded.block)} blocked, "
          f"{len(loaded.keywords)} protected keywords")
    for p in loaded.problems:
        print(f"  {_safe(p)}")
    return 1 if loaded.problems else 0


def cmd_feedback(args) -> int:
    """How the model compares with the corrections made in the portal."""
    from . import feedback

    cfg = config.load(args.config)
    store = Store(args.db or cfg.db_path, cfg.store_subjects)
    stats = feedback.agreement(store)
    from .lists import shared_domain
    rows = store.db.execute(
        "SELECT from_addr, from_domain, label FROM feedback WHERE verified=1 AND from_domain IS NOT NULL").fetchall()
    counts: dict[str, list[int]] = {}
    for r in rows:
        sender = r["from_addr"] if shared_domain(r["from_domain"]) else r["from_domain"]
        if sender:
            c = counts.setdefault(sender, [0, 0])
            c[0 if r["label"] in feedback.NOT_SPAM else 1] += 1
    trusted = sorted((s for s, (ok, bad) in counts.items() if ok >= feedback.TRUSTED_AFTER and not bad),
                     key=lambda s: -counts[s][0])[:50]
    stats["never_quarantined"] = trusted
    if args.json:
        print(json.dumps(stats))
        return 0
    from .feedback import plural
    n, judged = stats["corrections"], stats["with_model_answer"]
    print(f"{plural(n, 'correction')} from the portal, {judged:,} on mail the model looked at.")
    if judged:
        print(f"The model agreed with you on {stats["model_agreed"]:,} of {judged:,} "
              f"({100 * stats['model_agreed'] // judged}%). It called {plural(stats['said_spam_was_fine'], 'good message')} "
              f"spam and missed {plural(stats['missed_spam'], 'spam message')}.")
    if trusted:
        print("Never quarantined: " + ", ".join(_safe(d)[:60] for d in trusted)
              + " (you've said not spam at least twice and never spam).")
    return 0


def cmd_log(args) -> int:
    cfg = config.load(args.config)
    store = Store(args.db or cfg.db_path, cfg.store_subjects)
    if args.show is not None:
        row = store.get(args.show)
        if row is None:
            print(f"No decision {args.show}")
            return 1
        for k in row.keys():
            print(f"{k:>15}: {_safe(row[k])}")
        return 0
    m = re.fullmatch(r"(\d+)([hd])", args.since)
    if not m:
        print("--since takes a number of hours or days, like 24h or 7d")
        return 2
    hours = int(m.group(1)) * (24 if m.group(2) == "d" else 1)
    rows = store.recent(hours, args.action)
    if args.json:
        for row in rows:
            print(json.dumps(dict(row), ensure_ascii=False))
        return 0
    for row in rows:
        verb = row["action"] if row["mode"] != "shadow" or row["action"] == "keep" else "would " + row["action"]
        conf = f"{row['confidence']:.2f}" if row["confidence"] is not None else "-"
        print(f"{row['id']:>6} {row['ts']} {verb:<16} {row['label'] or '-':<12} {conf:<5} "
              f"{_safe(row['from_addr'])[:40]:<40} {_safe(row['subject'])[:60]}")
    return 0


def cmd_run(args) -> int:
    """Watch the inbox through Bridge and log decisions. Shadow mode: moves nothing."""
    import logging

    from .imap import ShadowRunner

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = config.load(args.config)
    _banner(cfg)
    an = _analyzer(args, cfg)
    runner = ShadowRunner(cfg, an)
    if args.once:
        return 0 if runner.run_once() is not None else 1
    runner.run_forever()
    return 0


def cmd_imap_proxy(args) -> int:
    """Run the IMAP allowlist proxy between the analyzer and Bridge."""
    import logging

    from . import imapproxy

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    imapproxy.serve(imapproxy.load_config(args.config or os.environ.get("ANALYZER_CONFIG")))
    return 0


def cmd_unsubscribe_service(args) -> int:
    """Run the one-click unsubscribe service (its own container; see unsubscribe.py)."""
    import logging

    from . import unsubscribe

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = config.load(args.config)
    unsubscribe.serve(unsubscribe.Service(args.db or cfg.db_path, args.state), port=args.port)
    return 0


def cmd_provider_check(args) -> int:
    """Host-side check for scripts/analyzer-provider.sh. Prints the egress entry, or why not."""
    import ipaddress

    from . import providers
    if args.provider not in providers.PROVIDERS:
        print(f"unknown provider; use one of {', '.join(providers.PROVIDERS)}", file=sys.stderr)
        return 1
    if not re.fullmatch(r"[A-Za-z0-9._:/-]{1,100}", args.model or ""):
        print("the model name may use letters, digits and . _ : / - only", file=sys.stderr)
        return 1
    if args.provider == "local":
        try:
            ep = providers.check_local_endpoint(args.endpoint or "")
            ip = ipaddress.ip_address(ep.host)
            for net in args.refuse_net or []:
                if ip in ipaddress.ip_network(net, strict=False):
                    raise ValueError(f"that address is inside the Docker network {net}")
            if ep.port in (args.refuse_port or []):
                raise ValueError(f"port {ep.port} is published by a Bridgekeep container")
        except ValueError as e:
            print(f"local server: {e}", file=sys.stderr)
            return 1
    print(providers.egress_entry(args.provider, args.endpoint or ""))
    print(providers.DISCLOSURE[args.provider])
    return 0


def cmd_egress_proxy(args) -> int:
    """Run the outbound proxy that allows only the Claude API."""
    import logging

    from . import egressproxy

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    egressproxy.serve(egressproxy.load_config(args.config or os.environ.get("ANALYZER_CONFIG")))
    return 0


def cmd_health(args) -> int:
    """For the container healthcheck: 0 when the last poll worked recently."""
    import time

    cfg = config.load(args.config)
    try:
        data = json.loads(Path(cfg.health_file).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        print("no health data yet")
        return 1
    age = time.time() - float(data.get("ts", 0))
    print(f"{data.get('status')} {int(age)}s ago: {_safe(data.get('detail', ''))}")
    return 0 if data.get("status") == "ok" and age < 3 * cfg.poll_seconds + 120 else 1


def cmd_config(args) -> int:
    cfg = config.load(args.config)
    _banner(cfg)
    shown = {k: v for k, v in vars(cfg).items() if k != "problems"}
    shown["effective_mode"] = cfg.effective_mode()
    print(json.dumps(shown, indent=2, default=list))
    return 1 if cfg.problems else 0


def cmd_backfill(args) -> int:
    """Talk to the running analyzer through /data: it does the IMAP work."""
    from . import backfill as bf
    cfg = config.load(args.config)
    data_dir = str(Path(args.db or cfg.db_path).parent)
    if args.action == "status":
        try:
            job = json.loads((Path(data_dir) / bf.STATUS_FILE).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            job = None
        print("\n".join(bf.status_lines(job)))
        return 0
    req = {"id": bf.new_id(), "action": args.action}
    if args.action == "estimate":
        for k in ("since", "until", "limit"):
            if getattr(args, k) is not None:
                req[k] = getattr(args, k)
    if args.action == "start":
        req["estimate_id"] = args.estimate_id
        req["allow_partial"] = args.allow_partial
    try:
        bf.write_request(data_dir, req)
    except (bf.BadRequest, OSError) as e:
        print(f"backfill: {e}", file=sys.stderr)
        return 2
    if args.no_wait:
        print(f"Queued {args.action} ({req['id']}). See: {bf.cli()} backfill status")
        return 0
    want = {"estimate": {"estimated", "cancelled"}, "start": {"running", "done"},
            "pause": {"paused"}, "resume": {"running"}, "cancel": {"cancelled"}}[args.action]
    wait_id = req["id"] if args.action == "estimate" else None
    print("Waiting for the analyzer (it acts at its next poll; an estimate reads every header)...",
          file=sys.stderr)
    end = time.monotonic() + args.timeout
    job = None
    while time.monotonic() < end:
        try:
            job = json.loads((Path(data_dir) / bf.STATUS_FILE).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            job = None
        if job and (wait_id is None or job.get("id") == wait_id):
            if job.get("status") in want or (args.action == "start" and job.get("reason")
                                             and job.get("status") == "estimated"):
                break
        time.sleep(2)
    print("\n".join(bf.status_lines(job)))
    if not job or job.get("status") not in want:
        print(f"The analyzer has not acted on it yet (is it running?). Check: {bf.cli()} backfill status",
              file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="analyzer", description="Proton mail analyzer (shadow mode)")
    ap.add_argument("--version", action="version", version=f"analyzer {__version__}")
    ap.add_argument("--config", help=f"config file (default {config.DEFAULT_CONFIG_PATH})")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p, model=True):
        p.add_argument("--db", help="decision log database (default from config)")
        p.add_argument("--lists", help="folder holding curated.yaml and learned.yaml")
        if model:
            p.add_argument("--no-model", action="store_true", help="skip the model; deterministic rules only")
            p.add_argument("--api-key-file", help="file holding the Claude API key")

    p = sub.add_parser("check", help="analyze .eml files, folders or .mbox exports (moves nothing)")
    p.add_argument("paths", nargs="+")
    p.add_argument("--json", action="store_true")
    p.add_argument("--show-fields", action="store_true", help="print exactly what the model is sent")
    common(p)
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("eval", help="score a labeled set: DIR/<legitimate|promotional|spam|phishing|adversarial>/")
    p.add_argument("dir")
    common(p)
    p.set_defaults(func=cmd_eval)

    p = sub.add_parser("lists", help="never-trash list and blocklist")
    lsub = p.add_subparsers(dest="lcmd", required=True)
    lp = lsub.add_parser("lint", help="check curated.yaml, portal.yaml and learned.yaml")
    lp.add_argument("--lists")
    lp.set_defaults(func=cmd_lists_lint)

    p = sub.add_parser("log", help="show recent decisions")
    p.add_argument("--since", default="24h")
    p.add_argument("--action", choices=["keep", "review", "quarantine"])
    p.add_argument("--json", action="store_true")
    p.add_argument("show", nargs="?", type=int, help="show one decision by id")
    p.add_argument("--db")
    p.set_defaults(func=cmd_log)

    p = sub.add_parser("feedback", help="how the model compares with your corrections in the portal")
    p.add_argument("--json", action="store_true")
    p.add_argument("--db")
    p.set_defaults(func=cmd_feedback)

    p = sub.add_parser("run", help="watch the inbox via Bridge and log decisions (shadow mode)")
    p.add_argument("--once", action="store_true", help="one poll, then exit")
    common(p)
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("backfill", help="analyze mail from before go-live: estimate the cost first, then confirm")
    bsub = p.add_subparsers(dest="action", required=True)
    bp = bsub.add_parser("estimate", help="count older mail and estimate the cost (reads headers only)")
    bp.add_argument("--since", help="only mail received on or after this date (YYYY-MM-DD)")
    bp.add_argument("--until", help="only mail received on or before this date (YYYY-MM-DD)")
    bp.add_argument("--limit", type=int, help="at most this many messages, newest first")
    bp = bsub.add_parser("start", help="run a finished estimate")
    bp.add_argument("estimate_id", help="the id the estimate printed")
    bp.add_argument("--allow-partial", action="store_true",
                    help="run even though the estimate is more than the budget left (stops at the reserve)")
    for name, text in (("pause", "pause the backfill"), ("resume", "carry on after a pause"),
                       ("cancel", "stop the backfill for good"), ("status", "show progress")):
        bsub.add_parser(name, help=text)
    for bp in bsub.choices.values():
        bp.add_argument("--db", help=argparse.SUPPRESS)
        bp.add_argument("--no-wait", action="store_true", help="queue the request and return")
        bp.add_argument("--timeout", type=int, default=900, help="seconds to wait for the analyzer (default 900)")
    p.set_defaults(func=cmd_backfill)

    p = sub.add_parser("imap-proxy", help="run the IMAP allowlist proxy in front of Bridge")
    p.set_defaults(func=cmd_imap_proxy)

    p = sub.add_parser("egress-proxy", help="run the outbound proxy that allows only the Claude API")
    p.set_defaults(func=cmd_egress_proxy)

    p = sub.add_parser("unsubscribe-service", help="run the one-click unsubscribe service for the portal")
    p.add_argument("--db", help="decision log, opened read-only")
    p.add_argument("--state", default="/state/unsubscribe.json", help="attempts and the daily count")
    p.add_argument("--port", type=int, default=8025)
    p.set_defaults(func=cmd_unsubscribe_service)

    p = sub.add_parser("provider-check", help=argparse.SUPPRESS)   # used by scripts/analyzer-provider.sh
    p.add_argument("provider")
    p.add_argument("--model", default="")
    p.add_argument("--endpoint", default="")
    p.add_argument("--refuse-net", action="append")
    p.add_argument("--refuse-port", action="append", type=int)
    p.set_defaults(func=cmd_provider_check)

    p = sub.add_parser("health", help="exit 0 if the last IMAP poll succeeded recently")
    p.set_defaults(func=cmd_health)

    p = sub.add_parser("config", help="print the effective configuration and mode")
    p.set_defaults(func=cmd_config)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
