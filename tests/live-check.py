#!/usr/bin/env python3
"""Live check against a logged-in Bridge, from a second container.

Run it with `make live-check` (or `make live-check SMTP=1`). That starts a
throwaway Python container on the `mail` network with this repo mounted
read-only. Standard library only, because the `mail` network has no internet.

It checks:
  - IMAP on bridge:1143 upgrades with STARTTLS, and the certificate verifies
    against the pinned bridge-cert.pem (nothing else is trusted)
  - login with the Bridge username and password from `info`
  - folders list, and INBOX opens read-only (nothing is changed)
  - with --smtp: SMTP on bridge:1025 with STARTTLS, login, and one test mail
    sent to your own address

The username and password are read from the terminal. They are never
taken from arguments or environment variables, so they don't end up in
shell history or `docker inspect`.
"""
import argparse
import getpass
import imaplib
import smtplib
import ssl
import sys
import time
from email.message import EmailMessage


def ok(msg):
    print(f"ok: {msg}")


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--host", default="bridge")
    p.add_argument("--imap-port", type=int, default=1143)
    p.add_argument("--smtp-port", type=int, default=1025)
    p.add_argument("--cafile", default="/w/bridge-cert.pem")
    p.add_argument("--smtp", action="store_true", help="also send one test mail to yourself")
    a = p.parse_args()

    try:
        ctx = ssl.create_default_context(cafile=a.cafile)
    except (OSError, ssl.SSLError) as e:
        fail(f"cannot load {a.cafile} ({e}); run `make cert` first")
    # Bridge's certificate is issued for 127.0.0.1, not "bridge". The chain is
    # still verified, against this one pinned certificate only.
    ctx.check_hostname = False
    # Python 3.13 adds VERIFY_X509_STRICT, which rejects some self-signed
    # certificates that are otherwise valid. Bridge's is one pinned file.
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT

    user = input("Bridge username (from `info`): ").strip()
    pw = getpass.getpass("Bridge password (from `info`, not your Proton password): ")
    if not user or not pw:
        fail("username and password are required")

    # IMAP
    try:
        imap = imaplib.IMAP4(a.host, a.imap_port, timeout=30)
    except OSError as e:
        fail(f"cannot connect to {a.host}:{a.imap_port} ({e}). Is bridge healthy, and is this on the mail network?")
    ok(f"connected to {a.host}:{a.imap_port}: {imap.welcome.decode(errors='replace')}")
    try:
        imap.starttls(ssl_context=ctx)
    except ssl.SSLError as e:
        fail(f"STARTTLS certificate check failed ({e}). Export the certificate again with `make cert`.")
    ok("IMAP STARTTLS, certificate matches bridge-cert.pem")
    try:
        imap.login(user, pw)
    except imaplib.IMAP4.error as e:
        fail(f"IMAP login refused ({e}). Use the username/password from `info`; if Proton ended the session, run `make init` and `login` again.")
    ok("IMAP login")
    typ, folders = imap.list()
    if typ != "OK":
        fail("IMAP LIST failed")
    ok(f"{len(folders)} folders")
    typ, data = imap.select("INBOX", readonly=True)
    if typ != "OK":
        fail("cannot open INBOX")
    ok(f"INBOX opened read-only: {int(data[0])} messages")
    imap.logout()

    if not a.smtp:
        print("live check passed (IMAP). Add SMTP=1 to also test sending.")
        return

    # SMTP (only reachable when BRIDGE_FORWARD_SMTP=true)
    try:
        smtp = smtplib.SMTP(a.host, a.smtp_port, timeout=30)
    except OSError as e:
        fail(f"cannot connect to {a.host}:{a.smtp_port} ({e}). SMTP is off by default: start bridge with BRIDGE_FORWARD_SMTP=true.")
    try:
        smtp.starttls(context=ctx)
    except ssl.SSLError as e:
        fail(f"SMTP STARTTLS certificate check failed ({e})")
    ok("SMTP STARTTLS, certificate matches bridge-cert.pem")
    try:
        smtp.login(user, pw)
    except smtplib.SMTPException as e:
        fail(f"SMTP login refused ({e})")
    ok("SMTP login")
    msg = EmailMessage()
    msg["From"] = user
    msg["To"] = user
    stamp = time.strftime("%Y-%m-%d %H:%M:%S %Z")
    msg["Subject"] = f"Bridgekeep live check {stamp}"
    msg.set_content("Sent by tests/live-check.py through the headless Bridge container.\n")
    smtp.send_message(msg)
    smtp.quit()
    ok(f'sent "Bridgekeep live check {stamp}" to {user}')
    print("live check passed (IMAP and SMTP). Look for the test mail in your inbox.")


if __name__ == "__main__":
    main()
