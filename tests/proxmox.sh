#!/usr/bin/env bash
# shellcheck disable=SC2015,SC2181  # a && ok || bad reads fine here
# Tests deploy/proxmox/proxmox.sh (./bridgekeep on a Proxmox VE host) against
# stand-ins for pct, pvesh, pvesm and pveam (tests/proxmox/): no Proxmox, no
# containers, no network. Runs as any user, from a git checkout.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
export PATH=$PWD/tests/proxmox:$PATH NO_COLOR=1 MOCK_ARCH=amd64
unset GITHUB_TOKEN BRIDGEKEEP_REF BRIDGEKEEP_DIR BRIDGEKEEP_BIN
# Setup refuses a checkout anyone else can change (it runs git there as root),
# so run from a private clone of this one.
# (CI checks out as another user: allow that one clone; this is the test, not setup.)
HOME=$work git config --global safe.directory "*" && HOME=$work git clone -q --no-hardlinks "$PWD" "$work/repo" \
  && cd "$work/repo" && rm -f "$work/.gitconfig" || exit 1
chmod -R go-w "$work/repo"
fails=0
ok() { echo "ok: $1"; }
bad() { echo "FAIL: $1"; fails=$((fails + 1)); sed 's/^/    /' "$PX/out" | tail -n 15; }
fresh() { export PX=$work/$1; mkdir -p "$PX/ct" "$PX/root"; : >"$PX/log"; }
run() { bash deploy/proxmox/proxmox.sh "$@" </dev/null >"$PX/out" 2>&1; }
has() { grep -q -- "$1" "$2"; }

# A new container: created unprivileged with what Docker needs, Docker
# installed, the checkout copied in, setup run there with only its own options.
fresh new
run setup --yes --memory 3072 --portal && ok "setup on a fresh host" || bad "setup on a fresh host"
args=$PX/ct/105/create-args
for want in "--unprivileged" "nesting=1,keyctl=1" "--arch" "local-lvm:20" "3072" "--tags" "--onboot" \
            "local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst" "bridge=vmbr0,firewall=1,ip=dhcp"; do
  has "$want" "$args" || bad "pct create without $want"
done
[[ $(grep -A1 -x -- --tags "$args" | tail -n1) == bridgekeep ]] && ok "container tagged bridgekeep" || bad "tag"
has docker-install "$PX/log" && ok "Docker installed in the container" || bad "Docker install"
dest=$PX/root/105/opt/bridgekeep
[[ -x $dest/bridgekeep && -f $dest/deploy/proxmox/proxmox.sh ]] && ok "checkout copied to /opt/bridgekeep" || bad "checkout copy"
if [[ -f $dest/.git/config ]] && ! grep -q '\[remote' "$dest/.git/config"; then ok "copy has no remote (no URL or credentials)"; else bad "copy keeps a remote"; fi
[[ $(stat -c %a "$dest") == 755 && -z $(find "$dest" -path "$dest/.git" -prune -o -perm /022 -print | head -n1) ]] \
  && ok "copy is root-only writable (the nightly job's rule)" || bad "copy permissions"
has "bridgekeep in 105: setup --yes --portal$" "$PX/log" && ok "setup gets --yes --portal, not the Proxmox options" || bad "setup args: $(grep 'bridgekeep in' "$PX/log")"
[[ ! -e $PX/root/105/root/bridgekeep-sync.tgz ]] && ok "copy's archive removed" || bad "archive left behind"

# Run again: same container, no reinstall; untracked state stays, deleted files go.
echo 'PORTAL_PORT=8443' >"$dest/.env"; mkdir -p "$dest/config"; echo pinned >"$dest/bridge-cert.pem"
echo gone >"$dest/old-file.txt"; echo old-file.txt >>"$dest/.bridgekeep/proxmox-files"
: >"$PX/log"
run setup --yes && ok "setup again" || bad "setup again"
! has "pct create" "$PX/log" && ! has docker-install "$PX/log" && ok "second run reuses the container and Docker" || bad "second run recreated"
[[ -f $dest/.env && -f $dest/bridge-cert.pem && -d $dest/config ]] && ok "untracked state kept (.env, certificate, config/)" || bad "state lost"
[[ ! -e $dest/old-file.txt ]] && ok "a file deleted upstream is deleted in the copy" || bad "stale file kept"

# Commands run in the container; status also says which container.
: >"$PX/log"
run status && has "Container      105 on Proxmox, running at 10.0.0.5" "$PX/out" && has "bridgekeep in 105: status$" "$PX/log" \
  && ok "status runs in the container" || bad "status"
run credentials && has "bridgekeep in 105: credentials$" "$PX/log" && ok "other commands run in the container" || bad "credentials"

# Several Bridgekeep containers: setup won't guess.
mkdir -p "$PX/ct/106"; printf 'hostname: bk2\ntags: bridgekeep;mail\n' >"$PX/ct/106/config"; echo running >"$PX/ct/106/state"
run setup --yes; [[ $? != 0 ]] && has "several Bridgekeep containers" "$PX/out" && ok "two containers: asks for --ctid" || bad "two containers"

# --ctid naming someone else's container: left alone.
printf 'hostname: web\ntags: other\n' >"$PX/ct/106/config"
: >"$PX/log"
run setup --yes --ctid 106; rc=$?
[[ $rc != 0 ]] && has "isn't Bridgekeep's" "$PX/out" && ! has "pct exec 106" "$PX/log" && ok "won't touch an existing container that isn't Bridgekeep's" || bad "used a foreign container"

# Option checks.
run setup --ip 192.168.1.50; [[ $? == 2 ]] && ok "--ip needs a prefix" || bad "--ip check"
run setup --gateway 192.168.1.1; [[ $? == 2 ]] && ok "--gateway needs --ip" || bad "--gateway check"

# Docker's signing key changed: nothing installed, a clear message.
fresh badkey
MOCK_BAD_KEY=1 run setup --yes; [[ $? != 0 ]] && has "signing key isn't the one" "$PX/out" && ok "a different Docker key stops setup" || bad "Docker key check"

# Docker can't start containers (old Proxmox, nesting off): says how to fix it.
fresh norun
MOCK_RUN_FAIL=1 run setup --yes; [[ $? != 0 ]] && has "update Proxmox" "$PX/out" && ok "Docker can't run: says to update Proxmox" || bad "Docker run check"

# arm64 host: an arm64 template.
fresh arm
MOCK_ARCH=arm64 run setup --yes && has "debian-13-standard_13.1-2_arm64" "$PX/ct/105/create-args" && has "^arm64$" "$PX/ct/105/create-args" \
  && ok "arm64 host gets an arm64 container" || bad "arm64"

# arm64 with no template listed: the unsigned linuxcontainers.org image is
# never downloaded without asking.
fresh armnone
MOCK_ARCH=arm64 MOCK_NO_TEMPLATES=1 run setup --yes; [[ $? != 0 ]] && has "unsigned image without asking" "$PX/out" && [[ ! -d $PX/ct/105 ]] \
  && ok "arm64 fallback refused under --yes" || bad "arm64 fallback under --yes"

# A checkout someone else can change: no git runs as root on it.
fresh unsafe
chmod g+w README.md
run setup --yes; [[ $? != 0 ]] && has "only root may be able to change it" "$PX/out" && has "not root-only: .*README.md" "$PX/out" && [[ ! -d $PX/ct/105 ]] \
  && ok "refuses a checkout others can write to" || bad "unsafe checkout"
chmod g-w README.md

# The one-command install (deploy/proxmox/install.sh): downloads a GitHub
# archive, no git, and setup copies exactly its files into the container.
sha=$(git rev-parse HEAD)
git archive --prefix="factorialandha-bridgekeep-proton-$sha/" HEAD | gzip >"$work/src.tgz"
export MOCK_TARBALL=$work/src.tgz
fresh dl
dl=$PX/host/bridgekeep
inst() { BRIDGEKEEP_DIR=$dl BRIDGEKEEP_BIN=$PX/host/bin/bridgekeep bash deploy/proxmox/install.sh "$@" </dev/null >"$PX/out" 2>&1; }
GITHUB_TOKEN=github_pat_TEST123 inst --yes --portal && ok "install command on a fresh host" || bad "install command"
[[ -x $dl/bridgekeep && ! -d $dl/.git && -f $dl/.bridgekeep/download ]] && ok "downloaded to the install folder, no git" || bad "install folder"
grep -q "commit=$sha" "$dl/.bridgekeep/download" && ok "records the downloaded commit" || bad "commit record"
! grep -q TEST123 "$PX/curl-args" && grep -q 'Authorization: Bearer github_pat_TEST123' "$PX/curl-cfg" \
  && ok "token goes to curl on stdin, never in its arguments" || bad "token handling"
grep -qx -- '--proto' "$PX/curl-args" && grep -q 'api.github.com/repos/factorialandha/bridgekeep-proton/tarball/preview' "$PX/curl-args" \
  && ok "https only, from GitHub's API" || bad "curl URL/options"
[[ -x $PX/host/bin/bridgekeep ]] && grep -q "exec $dl/bridgekeep" "$PX/host/bin/bridgekeep" && ok "bridgekeep command installed" || bad "host command"
c=$PX/root/105/opt/bridgekeep
[[ -x $c/bridgekeep && ! -d $c/.git ]] && cmp -s <(cd "$c" && find . \( -type f -o -type l \) ! -path './.bridgekeep/*' | sed 's|^\./||' | LC_ALL=C sort) <(LC_ALL=C sort "$dl/.bridgekeep/download-files") \
  && ok "container gets exactly the downloaded files" || bad "container copy from download"
has "bridgekeep in 105: setup --yes --portal$" "$PX/log" && ok "setup runs in the container with the options" || bad "setup args (download)"
has "run the install command again" "$PX/out" && ok "says how to update" || bad "update hint"
echo keep >"$dl/.bridgekeep/logs/old.log"; echo stray >"$dl/stray-file"
: >"$PX/log"
inst --yes && [[ -f $dl/.bridgekeep/logs/old.log && ! -e $dl/stray-file ]] && ! has "pct create" "$PX/log" \
  && ok "running it again updates in place, keeps logs, reuses the container" || bad "install again"
: >"$PX/curl-cfg"
MOCK_CURL_404=1 inst; [[ $? != 0 ]] && has "didn.t find factorialandha/bridgekeep-proton at preview" "$PX/out" && ! grep -q Authorization "$PX/curl-cfg" \
  && ok "not found: names the repo and branch" || bad "404 hint"
GITHUB_TOKEN='x" -o /tmp/evil' inst; [[ $? != 0 ]] && has "doesn't look like a GitHub token" "$PX/out" && ok "refuses a malformed token" || bad "token check"
mkdir -p "$PX/host/other"; echo mine >"$PX/host/other/notes.txt"
BRIDGEKEEP_DIR=$PX/host/other bash deploy/proxmox/install.sh </dev/null >"$PX/out" 2>&1; [[ $? != 0 ]] && has "isn't an earlier Bridgekeep download" "$PX/out" && [[ -f $PX/host/other/notes.txt ]] \
  && ok "won't replace a folder that isn't a Bridgekeep download" || bad "foreign folder guard"
GITHUB_TOKEN=github_pat_TEST123 inst --yes && ! has "GITHUB_TOKEN=" "$PX/env-host" \
  && ok "setup doesn't inherit GITHUB_TOKEN" || bad "token leaks to setup"
mkdir -p "$PX/host/gitco/.git"
BRIDGEKEEP_DIR=$PX/host/gitco bash deploy/proxmox/install.sh </dev/null >"$PX/out" 2>&1; [[ $? != 0 ]] && has "is a git checkout" "$PX/out" \
  && ok "won't overwrite a git checkout" || bad "git checkout guard"

# Nothing set up yet: commands say so.
fresh empty
run status; [[ $? == 1 ]] && has "isn't set up on this Proxmox host" "$PX/out" && ok "status before setup" || bad "status before setup"

(( fails == 0 )) && echo "proxmox: all passed" || { echo "proxmox: $fails failed"; exit 1; }
