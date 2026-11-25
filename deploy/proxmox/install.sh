#!/usr/bin/env bash
# Bridgekeep on Proxmox VE in one command. In the Proxmox host's shell, as root:
#
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/factorialandha/bridgekeep-proton/preview/deploy/proxmox/install.sh)"
#
# Downloads Bridgekeep from GitHub (no git needed) to /root/bridgekeep, puts a
# `bridgekeep` command on this host, and runs setup, which makes Bridgekeep's
# own container (deploy/proxmox/proxmox.sh). Run the same command again to
# update: setup reuses the container and carries on.
#
# Setup options go after the command:  bash -c "$(curl ...)" _ --ctid 120 --yes
# The repository is public, so no token is needed. Optionally, GITHUB_TOKEN can
# hold a read-only token (useful against GitHub's anonymous rate limit).
# It goes only to api.github.com, never on a command line, and isn't saved.
set -euo pipefail
umask 022

REPO=factorialandha/bridgekeep-proton
REF=${BRIDGEKEEP_REF:-preview}
DIR=${BRIDGEKEEP_DIR:-/root/bridgekeep}
BIN=${BRIDGEKEEP_BIN:-/usr/local/sbin/bridgekeep}
API=https://api.github.com/repos/$REPO/tarball/$REF

if [[ -t 1 && -z ${NO_COLOR:-} ]]; then
  B=$'\e[1m' G=$'\e[32m' R=$'\e[31m' D=$'\e[2m' N=$'\e[0m'
else B='' G='' R='' D='' N=''; fi
ok()   { printf '  %s✓%s %s\n' "$G" "$N" "$*"; }
fail() {
  printf '  %s✗ %s%s\n' "$R" "$1" "$N" >&2
  [[ -n ${2:-} ]] && printf '    Fix: %s\n' "$2" >&2
  exit 1
}

printf '%sBridgekeep for Proxmox VE%s  %s(installs to %s)%s\n' "$B" "$N" "$D" "$DIR" "$N"
[[ $(id -u) == 0 ]] || fail "Run this as root in the Proxmox host's shell." "sudo -i, then run the command again"
command -v pct >/dev/null 2>&1 || fail "This isn't a Proxmox VE host (no pct)." "on another Linux host, use the git clone line in the README"
[[ $REF =~ ^[A-Za-z0-9._/-]+$ && $REF != *..* ]] || fail "BRIDGEKEEP_REF '$REF' isn't a branch or tag name."
if [[ -d $DIR/.git ]]; then
  fail "$DIR is a git checkout, so this won't overwrite it." "update it with: cd $DIR && git pull && ./bridgekeep setup"
fi
# Only ever replace an earlier download (or nothing): never someone's own folder.
if [[ -e $DIR || -L $DIR ]] && ! { [[ -d $DIR && ! -L $DIR ]] && { [[ -f $DIR/.bridgekeep/download ]] || [[ -z $(ls -A "$DIR") ]]; }; }; then
  fail "$DIR already exists and isn't an earlier Bridgekeep download, so this won't replace it." "move it out of the way, or install elsewhere: BRIDGEKEEP_DIR=/root/bridgekeep2 and the command again"
fi
# The token is only for the download: keep it out of everything run after this.
token=${GITHUB_TOKEN:-}
unset GITHUB_TOKEN

# Download into a folder next to $DIR (same disk, so the swap below is a rename).
mkdir -p "$(dirname "$DIR")"
stage=$(mktemp -d "$(dirname "$DIR")/.bridgekeep-new.XXXXXX")
trap 'rm -rf -- "$stage"' EXIT
mkdir "$stage/src"
if [[ -n $token ]]; then
  [[ $token =~ ^[A-Za-z0-9_]+$ ]] || fail "GITHUB_TOKEN doesn't look like a GitHub token."
fi
# The token goes to curl on stdin (-K -), so it's never in the process list.
# curl doesn't send it on to codeload.github.com when GitHub redirects there.
rc=0
{
  printf 'header = "Accept: application/vnd.github+json"\n'
  [[ -n $token ]] && printf 'header = "Authorization: Bearer %s"\n' "$token"
  true
} | curl -fsSL --proto '=https' --tlsv1.2 -K - -o "$stage/src.tgz" "$API" 2>"$stage/curl.err" || rc=$?
if (( rc != 0 )); then
  if grep -q ' 404' "$stage/curl.err" && [[ -z $token ]]; then
    fail "GitHub didn't find $REPO at $REF." \
      "check BRIDGEKEEP_REF names a branch or tag of $REPO; for a private copy, set GITHUB_TOKEN to a read-only token (docs/proxmox.md)"
  fi
  sed 's/^/    /' "$stage/curl.err" >&2
  fail "Downloading Bridgekeep ($REF) from GitHub failed." "check this host can reach api.github.com${token:+, and that the token can read $REPO}"
fi
top=$(tar -tzf "$stage/src.tgz" | sed -n 1p); top=${top%%/*}
commit=${top##*-}
[[ $commit =~ ^[0-9a-f]{7,40}$ ]] || fail "That download isn't a GitHub archive of $REPO."
tar -xzf "$stage/src.tgz" -C "$stage/src" --strip-components=1 --no-same-owner
[[ -f $stage/src/bridgekeep && -f $stage/src/deploy/proxmox/proxmox.sh ]] \
  || fail "The download has no Bridgekeep in it ($REF)."
# The file list is the copy's manifest: setup copies exactly these into the container.
(cd "$stage/src" && find . \( -type f -o -type l \) -print | sed 's|^\./||' | LC_ALL=C sort) >"$stage/files"
ok "Downloaded Bridgekeep $(head -n1 "$stage/src/VERSION" 2>/dev/null) ($REF, commit ${commit:0:7})"

# Swap it in. Host-side logs (.bridgekeep/) carry over; nothing else lives here.
mkdir -p "$stage/src/.bridgekeep"
[[ -d $DIR/.bridgekeep ]] && cp -a "$DIR/.bridgekeep/." "$stage/src/.bridgekeep/"
mv "$stage/files" "$stage/src/.bridgekeep/download-files"
printf 'commit=%s\nref=%s\n' "$commit" "$REF" >"$stage/src/.bridgekeep/download"
chown -R 0:0 "$stage/src" 2>/dev/null || true
chmod -R go-w "$stage/src"; chmod 755 "$stage/src"; chmod 700 "$stage/src/.bridgekeep"
if [[ -e $DIR ]]; then mv "$DIR" "$stage/old"; fi
mv "$stage/src" "$DIR"
ok "Installed in $DIR"

# `bridgekeep` anywhere on this host runs the checkout's command.
mkdir -p "$(dirname "$BIN")"
printf '#!/bin/bash\nexec %q "$@"\n' "$DIR/bridgekeep" >"$BIN.tmp" && chmod 755 "$BIN.tmp" && mv "$BIN.tmp" "$BIN"
ok "The bridgekeep command is ready ($BIN)"

trap - EXIT; rm -rf -- "$stage"; token=

# Piped in (curl ... | bash)? Setup's prompts read the terminal, not the pipe.
if [[ ! -t 0 ]] && { : </dev/tty; } 2>/dev/null; then exec </dev/tty; fi
exec bash "$DIR/deploy/proxmox/proxmox.sh" setup "$@"
