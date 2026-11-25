#!/usr/bin/env bash
# Write Bridge's TLS certificate (PEM) to a file, for clients to pin.
#
#   scripts/export-cert.sh [--force] [OUT]   default OUT: bridge-cert.pem
#
# First from Bridge's own files (`entrypoint export-cert`); Bridge 3 keeps
# the certificate in its encrypted vault instead, so then from the IMAP
# STARTTLS handshake, read by a throwaway container on the internal `mail`
# network (tests/fetch-cert.py; the same fallback ./bridgekeep uses). Bridge
# must be running.
#
# Pin once: if OUT exists, it is never rewritten. The same certificate says
# "unchanged"; a different one is refused with both SHA-256 fingerprints,
# unless --force (after a Bridge reinstall, when a new certificate is expected).
set -euo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.."
force=false
[[ ${1:-} == --force ]] && { force=true; shift; }
out=${1:-bridge-cert.pem}
NETWORK=proton-bridge_mail
PYTHON_IMAGE=$(sed -n 's/^PYTHON_IMAGE *?= *//p' Makefile)
tmp=$(mktemp "${out}.XXXXXX")
trap 'rm -f -- "$tmp"' EXIT
if ! { docker compose exec -T bridge entrypoint export-cert 2>/dev/null \
       || docker run --rm --network "$NETWORK" --read-only --cap-drop ALL \
            --security-opt no-new-privileges:true --user 65534:65534 --log-driver none \
            -v "$PWD/tests/fetch-cert.py:/w/fetch-cert.py:ro" \
            "$PYTHON_IMAGE" python /w/fetch-cert.py; } >"$tmp" \
   || ! grep -q "BEGIN CERTIFICATE" "$tmp"; then
  echo "export-cert: could not read Bridge's certificate. Is Bridge running and healthy? (docker compose up -d, then ./bridgekeep status)" >&2
  exit 1
fi
fp() { openssl x509 -noout -fingerprint -sha256 -in "$1" 2>/dev/null | cut -d= -f2 || sha256sum "$1" | cut -d' ' -f1; }
if [[ -f $out ]]; then
  if cmp -s "$tmp" "$out"; then echo "$out unchanged" >&2; exit 0; fi
  if ! $force; then
    echo "export-cert: Bridge's certificate is not the one pinned in $out, so it was left alone." >&2
    echo "  pinned: $(fp "$out")" >&2
    echo "  Bridge: $(fp "$tmp")" >&2
    echo "  After a Bridge reinstall this is expected: delete $out and run this again (or pass --force)." >&2
    exit 1
  fi
  echo "export-cert: replacing the pinned certificate (--force)" >&2
fi
chmod 644 "$tmp"
mv -f -- "$tmp" "$out"
echo "wrote $out" >&2
