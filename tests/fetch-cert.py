#!/usr/bin/env python3
"""Print Bridge's TLS certificate (PEM), read from the IMAP STARTTLS handshake.

Used by `./bridgekeep` when `entrypoint export-cert` finds no cert.pem on
disk (Bridge 3 keeps its certificate in its encrypted vault). It runs in a
throwaway container on the internal `mail` network, which only Bridge and
Bridgekeep's own containers join, so this first fetch is trust-on-first-use
over a private network. Everything after it pins the certificate it prints.

  fetch-cert.py [--host bridge] [--port 1143]

Prints the PEM and exits 0, or prints one line to stderr and exits 1.
No login is attempted and nothing is sent but STARTTLS and LOGOUT.
"""
import argparse
import imaplib
import ssl
import sys


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="bridge")
    p.add_argument("--port", type=int, default=1143)
    a = p.parse_args()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we are fetching the certificate to pin
    try:
        imap = imaplib.IMAP4(a.host, a.port, timeout=30)
        imap.starttls(ssl_context=ctx)
        der = imap.sock.getpeercert(binary_form=True)
    except (OSError, imaplib.IMAP4.error, ssl.SSLError) as e:
        print(f"Bridge did not complete STARTTLS on {a.host}:{a.port} ({e})", file=sys.stderr)
        sys.exit(1)
    try:
        imap.logout()
    except (OSError, imaplib.IMAP4.error):
        pass
    if not der:
        print("Bridge sent no certificate", file=sys.stderr)
        sys.exit(1)
    sys.stdout.write(ssl.DER_cert_to_PEM_cert(der))


if __name__ == "__main__":
    main()
