"""`python -m portal <command>`.

  serve        run the portal (the container's default)
  code         issue a new one-time claim code and print it (before the portal is claimed)
  reset-admin  forget the admin account and every session, then print a claim code (P7)
  info         where to open the portal, and the certificate fingerprint
  health       exit 0 if the portal answers (the container healthcheck)
"""

from __future__ import annotations

import argparse
import http.client
import logging
import signal
import ssl
import sys
from pathlib import Path

from . import __version__, auth, settings, tls
from .app import Context, build, cli_urls, make_env
from .db import DB
from .web import serve


def _ctx() -> Context:
    s = settings.load()
    return Context(s, DB(s.db_path), make_env())


def urls(s: settings.Settings) -> list[str]:
    return cli_urls(s)


def _print_code(ctx: Context, code: str) -> None:
    s = ctx.settings
    mins = s.claim_ttl // 60
    where = "\n              ".join(urls(s))
    pairs = s.fingerprint.split(":")
    grouped = "\n".join("    " + " ".join(pairs[i:i + 8]) for i in range(0, len(pairs), 8))
    extra = (f"\n  Your browser will warn about the certificate the first time. Continue only if it\n"
             f"  shows this fingerprint (SHA-256); that's how you know it's really this computer:\n{grouped}\n") if s.lan else (
             f"\n  Only this computer can open it. ./bridgekeep portal network on opens it to your home network.\n")
    print(f"""
  Bridgekeep portal: claim it to finish setup.

    1. Open   {where}
    2. Enter  {code}

  The code works once and lasts {mins} minutes. New code: ./bridgekeep portal code
{extra}""", flush=True)


def cmd_serve(_args) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)
    ctx = _ctx()
    if ctx.settings.problems:
        for p in ctx.settings.problems:
            print(f"portal: {p}", file=sys.stderr)
        return 2
    s = ctx.settings
    ssl_ctx = None
    if s.lan:
        cert, key, s.fingerprint, made = tls.ensure(s.data_dir, s.extra_hosts, s.product_name)
        ssl_ctx = tls.server_context(cert, key)
        logging.info("%s certificate, SHA-256 fingerprint %s", "new" if made else "existing", s.fingerprint)
    auth.prune(ctx.db, s.idle_timeout, s.absolute_timeout)
    if not auth.is_claimed(ctx.db):
        _print_code(ctx, auth.new_claim_code(ctx.db, s.claim_ttl))
    server = serve(build(ctx), s.listen_host, s.listen_port, ssl_ctx)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    if s.lan:
        logging.info("portal %s on your network (HTTPS): %s", __version__, "  ".join(urls(s)))
    else:
        logging.info("portal %s on this computer only: %s", __version__, urls(s)[0])
    try:
        server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        server.server_close()
    return 0


def _with_fingerprint(ctx: Context) -> Context:
    if ctx.settings.lan:
        cert = Path(ctx.settings.data_dir) / "tls" / "cert.pem"
        if cert.exists():
            ctx.settings.fingerprint = tls.fingerprint(cert.read_bytes())
    return ctx


def cmd_code(args) -> int:
    ctx = _with_fingerprint(_ctx())
    if auth.is_claimed(ctx.db):
        print("The portal is already claimed. To start over: ./bridgekeep portal reset-admin", file=sys.stderr)
        return 1
    if args.plain:   # for ./bridgekeep: the code alone, so copy changes can't break it
        print(auth.new_claim_code(ctx.db, ctx.settings.claim_ttl))
        return 0
    _print_code(ctx, auth.new_claim_code(ctx.db, ctx.settings.claim_ttl))
    return 0


def cmd_reset_admin(args) -> int:
    ctx = _with_fingerprint(_ctx())
    if auth.is_claimed(ctx.db) and not args.yes:
        print("This forgets the portal's admin password and authenticator, and signs everyone out.\n"
              "Run again with --yes to go ahead.", file=sys.stderr)
        return 1
    auth.reset_admin(ctx.db)
    ctx.db.audit("admin reset from the host", ip="host")
    _print_code(ctx, auth.new_claim_code(ctx.db, ctx.settings.claim_ttl))
    return 0


def cmd_info(_args) -> int:
    """Where to open the portal, for ./bridgekeep (one fact per line)."""
    ctx = _with_fingerprint(_ctx())
    s = ctx.settings
    print("mode=" + ("network" if s.lan else "local"))
    for u in urls(s):
        print("url=" + u)
    if s.fingerprint:
        print("fingerprint=" + s.fingerprint)
    print("claimed=" + ("yes" if auth.is_claimed(ctx.db) else "no"))
    print("authenticator=" + ("on" if auth.has_totp(ctx.db) else "off"))
    return 0


def cmd_health(_args) -> int:
    s = settings.load()
    try:
        if s.lan:
            # Loopback inside the container, to our own certificate.
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            c = http.client.HTTPSConnection("127.0.0.1", s.listen_port, timeout=5, context=ctx)
        else:
            c = http.client.HTTPConnection("127.0.0.1", s.listen_port, timeout=5)
        c.request("GET", "/healthz", headers={"Host": "localhost"})
        ok = c.getresponse().status == 200
    except OSError:
        ok = False
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="portal", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve").set_defaults(func=cmd_serve)
    c = sub.add_parser("code")
    c.add_argument("--plain", action="store_true", help="print only the code")
    c.set_defaults(func=cmd_code)
    r = sub.add_parser("reset-admin")
    r.add_argument("--yes", action="store_true")
    r.set_defaults(func=cmd_reset_admin)
    sub.add_parser("health").set_defaults(func=cmd_health)
    sub.add_parser("info").set_defaults(func=cmd_info)
    args = p.parse_args(argv)
    return args.func(args)
