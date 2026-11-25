#!/usr/bin/env python3
"""Non-interactive IMAP login check, used by `./bridgekeep` (setup, status, doctor).

Runs in a throwaway container on the `mail` network, like tests/live-check.py,
but reads the Bridge password from a mounted file instead of the terminal, so
setup can prove the login without asking you to type anything.

  login-check.py --user you@proton.me --password-file /run/pw --cafile /w/bridge-cert.pem

Prints one line of JSON: {"ok": true, "messages": 18402} or
{"ok": false, "error": "..."}. Exit status 0 only when the login works.
Nothing is changed in the mailbox: it only asks STATUS of each folder.

"messages" is every message Bridge has: the sum over the folders a message
can be in only one of (Inbox, Archive, Sent, Drafts, Spam, Trash, Folders/...).
Labels/..., Starred and All Mail are views of those same messages, so they
are left out. (Bridge's All Mail is not a reliable total: on big mailboxes
it can lag far behind, which once made a finished sync look stuck.)
"""
import argparse
import imaplib
import json
import os
import ssl
import sys


def result(**kw):
    print(json.dumps(kw))
    sys.exit(0 if kw.get("ok") else 1)


OVERLAYS = {"all mail", "starred"}


def total_messages(imap):
    """Sum of MESSAGES over exclusive folders, or None if Bridge won't say."""
    try:
        typ, rows = imap.list()
    except imaplib.IMAP4.error:
        return None
    if typ != "OK":
        return None
    total, seen = 0, 0
    for row in rows or []:
        if not isinstance(row, bytes):
            continue
        line = row.decode("utf-8", "replace")
        if "\\noselect" in line.lower():
            continue
        name = line.rsplit(' "/" ', 1)[-1].strip() if ' "/" ' in line else line.rsplit(" ", 1)[-1]
        bare = name.strip('"')
        if any(ord(c) < 32 or ord(c) == 127 for c in bare):
            continue   # never put CR/LF or other controls into a command
        if bare.lower() in OVERLAYS or bare.lower().startswith("labels/") or bare.lower() == "labels":
            continue
        quoted = '"' + bare.replace("\\", "\\\\").replace('"', '\\"') + '"'
        try:
            typ, data = imap.status(quoted, "(MESSAGES)")
        except imaplib.IMAP4.error:
            continue
        if typ == "OK" and data and isinstance(data[0], bytes):
            part = data[0].decode("utf-8", "replace").upper().rsplit("MESSAGES", 1)[-1]
            digits = "".join(ch for ch in part if ch.isdigit())
            if digits:
                total += int(digits)
                seen += 1
    return total if seen else None


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="bridge")
    p.add_argument("--port", type=int, default=1143)
    p.add_argument("--user", required=True)
    p.add_argument("--password-file", required=True)
    p.add_argument("--cafile", required=True)
    # The sign-in broker's folder (bridge-credential volume): after a sign-in
    # from the admin portal its password and address win.
    p.add_argument("--credential-dir")
    a = p.parse_args()
    if a.credential_dir:
        cpw = os.path.join(a.credential_dir, "bridge_password")
        if os.path.isfile(cpw) and not os.path.islink(cpw):
            a.password_file = cpw
            try:
                with open(os.path.join(a.credential_dir, "bridge_username"), encoding="utf-8") as f:
                    u = f.read().strip()
                if u and not any(ord(c) < 32 or ord(c) == 127 for c in u):
                    a.user = u
            except OSError:
                pass

    try:
        with open(a.password_file, encoding="utf-8") as f:
            pw = f.read().strip()
    except OSError as e:
        result(ok=False, error=f"cannot read the saved Bridge password ({e.strerror})")
    try:
        ctx = ssl.create_default_context(cafile=a.cafile)
    except (OSError, ssl.SSLError):
        result(ok=False, error="cannot load Bridge's certificate")
    # Bridge's certificate is issued for 127.0.0.1; the chain is still checked
    # against this one pinned certificate.
    ctx.check_hostname = False
    # Python 3.13 adds VERIFY_X509_STRICT, which rejects self-signed
    # certificates that lack some extensions. Bridge's may; the chain is
    # still verified against the one pinned certificate.
    ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)

    try:
        imap = imaplib.IMAP4(a.host, a.port, timeout=30)
        imap.starttls(ssl_context=ctx)
    except ssl.SSLError:
        result(ok=False, error="Bridge's certificate changed; export it again")
    except OSError:
        result(ok=False, error="Bridge is not answering on the mail network")
    try:
        imap.login(a.user, pw)
    except imaplib.IMAP4.error:
        result(ok=False, error="Bridge refused the saved username and password (signed out?)")

    count = total_messages(imap)
    try:
        imap.logout()
    except imaplib.IMAP4.error:
        pass
    result(ok=True, messages=count)


if __name__ == "__main__":
    main()
