#!/usr/bin/env bash
# Verify a Proton Mail Bridge .deb before anything from it is used.
#
#   verify-deb.sh <package.deb> <expected-sha256> <signing-key-fingerprint> <pubkey-file>
#
# 1. The sha256 must match the pinned value exactly.
# 2. The package must carry a debsig "origin" signature (_gpgorigin member)
#    made by the pinned key. A debsig origin signature is a detached OpenPGP
#    signature over the concatenation of the other ar members, in order
#    (debian-binary, control.tar.*, data.tar.*). We check it with gpgv so no
#    trust database or debsig policy files are involved.
set -euo pipefail

deb=${1:?package path}
want_sha=${2:?expected sha256}
want_key=${3:?signing key fingerprint (40 hex digits)}
pubkey=${4:?public key file}

die() { echo "verify-deb: $*" >&2; exit 1; }

for t in ar gpg gpgv sha256sum; do
  command -v "$t" >/dev/null 2>&1 || die "required tool $t is not installed"
done

want_sha=$(tr '[:upper:]' '[:lower:]' <<<"$want_sha")
want_key=$(tr -d ' ' <<<"$want_key" | tr '[:lower:]' '[:upper:]')
[[ $want_sha =~ ^[0-9a-f]{64}$ ]] || die "BRIDGE_DEB_SHA256 is not a sha256 hex digest"
[[ $want_key =~ ^[0-9A-F]{40}$ ]] || die "BRIDGE_SIGNING_KEY must be a full 40-digit fingerprint (short and long key IDs are not accepted)"

got_sha=$(sha256sum "$deb" | cut -d' ' -f1)
[[ $got_sha == "$want_sha" ]] || die "sha256 mismatch: expected $want_sha, got $got_sha"
echo "verify-deb: sha256 OK ($got_sha)"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
deb_abs=$(readlink -f "$deb")
(cd "$work" && ar x "$deb_abs")

[[ -f $work/_gpgorigin ]] || die "package has no _gpgorigin signature member"

# Rebuild the signed payload in archive order, skipping signature members.
mapfile -t members < <(ar t "$deb_abs")
: >"$work/payload"
for m in "${members[@]}"; do
  [[ $m == _gpg* ]] && continue
  cat "$work/$m" >>"$work/payload"
done

# Make sure the key file we were handed is the pinned key before using it.
export GNUPGHOME="$work/gnupg"
mkdir -m 700 "$GNUPGHOME"
gpg --batch --quiet --import "$pubkey" 2>/dev/null || die "cannot import $pubkey"
fprs=$(gpg --batch --with-colons --fingerprint | awk -F: '$1=="fpr"{print $10}')
match=""
for f in $fprs; do
  if [[ $f == "$want_key" ]]; then match=$f; fi
done
[[ -n $match ]] || die "public key file does not contain key $want_key (has: $fprs)"
gpg --batch --quiet --export "$match" >"$work/keyring.gpg"

# On failure, print enough to tell a wrong payload layout from a key problem
# (expired or revoked key, unsupported algorithm). Diagnostics only: nothing
# here changes what is accepted.
diagnose() {
  {
    echo "---- verify-deb diagnostics ----"
    echo "ar members: ${members[*]}"
    echo "gpgv output:"; sed 's/^/  /' "$work/gpgv.log"
    echo "signature packets:"
    gpg --batch --list-packets "$work/_gpgorigin" 2>&1 | grep -E '^(:signature|\s+(version|digest algo|created|hashed subpkt 16|issuer fpr))' | sed 's/^/  /' | head -n 12
    echo "pinned key (pub/sub, validity, expiry):"
    gpg --batch --with-colons --list-keys "$match" 2>/dev/null | awk -F: '$1=="pub"||$1=="sub"{printf "  %s validity=%s algo=%s created=%s expires=%s keyid=%s caps=%s\n",$1,$2,$4,$6,$7,$5,$12}'
    echo "signature checked against other member combinations:"
    for combo in "data" "control data" "debian-binary data" "control" ; do
      : >"$work/alt"
      for part in $combo; do
        for m in "${members[@]}"; do [[ $m == "$part"* ]] && cat "$work/$m" >>"$work/alt"; done
      done
      if gpgv --keyring "$work/keyring.gpg" "$work/_gpgorigin" "$work/alt" >/dev/null 2>&1; then
        echo "  [$combo] -> GOOD"
      else
        echo "  [$combo] -> bad"
      fi
    done
    echo "--------------------------------"
  } >&2
}

if ! status=$(gpgv --status-fd 1 --keyring "$work/keyring.gpg" \
    "$work/_gpgorigin" "$work/payload" 2>"$work/gpgv.log"); then
  cat <<<"$status" >>"$work/gpgv.log"
  diagnose
  die "signature check failed (see diagnostics above)"
fi
signer=$(awk '$2=="VALIDSIG"{print $NF}' <<<"$status")
[[ $signer == "$match" || $(awk '$2=="VALIDSIG"{print $3}' <<<"$status") == "$match" ]] \
  || die "signature is valid but not made by $match"
echo "verify-deb: signature OK (key $match)"
