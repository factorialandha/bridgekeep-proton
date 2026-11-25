#!/usr/bin/env bash
# Bridgekeep on Proxmox VE. ./bridgekeep, run on the Proxmox host, comes here.
#
#   ./bridgekeep setup   make a Debian container (LXC) for Bridgekeep if there
#                        isn't one, install Docker in it, copy this checkout's
#                        last commit in, and run ./bridgekeep setup there
#   ./bridgekeep shell   a root shell inside that container
#   ./bridgekeep ...     every other command runs inside the container
#
# Setup options (any others go on to ./bridgekeep setup in the container):
#   --ctid N  --hostname NAME  --storage STORAGE  --bridge vmbrN
#   --ip CIDR --gateway IP (default DHCP)  --disk GB  --memory MB  --cores N
#
# Docker is never installed on the Proxmox host itself: Proxmox advises
# against it, and a container keeps Bridgekeep in one piece that Proxmox's
# own backups, snapshots and restores cover. The container is unprivileged
# with nesting and keyctl, which Docker needs; it starts with the host.
#
# The container gets a fresh clone of this checkout (tracked files and
# history only: no untracked files, no remote URL or credentials, no host git
# config). No git runs as root inside the container.
set -euo pipefail
shopt -s inherit_errexit
umask 022

here=$(cd "$(dirname "$0")/../.." && pwd -P)
TAG=bridgekeep
DEST=/opt/bridgekeep
CT_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# Docker's apt signing key (https://docs.docker.com/engine/install/debian/).
DOCKER_KEY_FPR=9DC858229FC7DD38854AE2D88D81803C0EBFCD88
log_dir=$here/.bridgekeep/logs
YES=false
CLEANUP=''
trap '[[ -n $CLEANUP ]] && rm -rf "$CLEANUP"' EXIT

# --- output (as in ./bridgekeep) ------------------------------------------------

if [[ -t 1 && -z ${NO_COLOR:-} ]]; then
  B=$'\e[1m' G=$'\e[32m' R=$'\e[31m' Y=$'\e[33m' D=$'\e[2m' N=$'\e[0m'
else
  B='' G='' R='' Y='' D='' N=''
fi
say()  { printf '%s\n' "$*"; }
ok()   { printf '  %s✓%s %s\n' "$G" "$N" "$*"; }
note() { printf '  %s!%s %s\n' "$Y" "$N" "$*"; }
step() { printf '\n%s[%s/4] %s%s\n' "$B" "$1" "$2" "$N"; }
fail() {
  printf '  %s✗ %s%s\n' "$R" "$1" "$N" >&2
  [[ -n ${2:-} ]] && printf '    Fix: %s\n' "$2" >&2
  printf '    Then run %s./bridgekeep setup%s again; it carries on from here.\n' "$B" "$N" >&2
  exit 1
}
show_log() {
  printf '%s' "$D" >&2; tail -n 20 "$1" >&2 || true; printf '%s' "$N" >&2
  printf '    Full log: %s\n' "$1" >&2
}
ask() { # ask Y|N "Question" -> 0 for yes
  local def=$1; shift
  local hint="[y/N]"; [[ $def == Y ]] && hint="[Y/n]"
  if $YES || [[ ! -t 0 ]]; then [[ $def == Y ]]; return; fi
  local a; read -r -p "  $* $hint " a
  a=${a:-$def}
  [[ $a == [Yy]* ]]
}
run_quiet() { # LABEL LOGFILE CMD...: one line with a running clock, output to the log
  local label=$1 logf=$2; shift 2
  "$@" >"$logf" 2>&1 </dev/null &
  local pid=$! start=$SECONDS
  if [[ -t 1 ]]; then
    while kill -0 "$pid" 2>/dev/null; do
      printf '\r  %s… %d:%02d ' "$label" $(((SECONDS - start) / 60)) $(((SECONDS - start) % 60))
      sleep 1
    done
    printf '\r\e[K'
  fi
  wait "$pid"
}

# --- the container ---------------------------------------------------------------

# ct_run ID CMD...: run in the container as root, with a clean environment
# (nothing of the host's leaks in) and the host's terminal, so prompts work.
ct_run() {
  local ct=$1; shift
  local envs=(HOME=/root PATH="$CT_PATH" LANG=C.UTF-8 TERM="${TERM:-dumb}")
  [[ -n ${NO_COLOR:-} ]] && envs+=(NO_COLOR=1)
  pct exec "$ct" -- /usr/bin/env -i "${envs[@]}" "$@"
}

# Containers tagged bridgekeep, one ID per line.
tagged_cts() {
  local id
  pct list 2>/dev/null | awk 'NR > 1 {print $1}' | while read -r id; do
    pct config "$id" 2>/dev/null | grep -Eq "^tags: (.*[;, ])?$TAG([;, ].*)?$" && echo "$id"
  done
  return 0
}

ct_state() { pct status "$1" 2>/dev/null | awk '{print $2}'; }

# The container to use: --ctid, or the one tagged bridgekeep. Empty: none yet.
find_ct() {
  if [[ -n ${CTID:-} ]]; then echo "$CTID"; return; fi
  local ids n
  ids=$(tagged_cts)
  n=$(grep -c . <<<"$ids" || true)
  if (( n > 1 )); then
    fail "This host has several Bridgekeep containers: $(tr '\n' ' ' <<<"$ids")" "add --ctid N to say which one, for example ./bridgekeep setup --ctid $(head -n1 <<<"$ids")"
  fi
  echo "$ids"
}

ct_address() { # its first IPv4 address, empty while it has none
  ct_run "$1" sh -c "hostname -I 2>/dev/null | tr ' ' '\\n' | grep -E '^[0-9]+([.][0-9]+){3}\$' | grep -v '^127[.]' | head -n1" 2>/dev/null || true
}

# A storage that holds CONTENT (rootdir or vztmpl): the first PREFERRED one
# that's active, else the first active one.
pick_storage() {
  local content=$1; shift
  local list s
  list=$(pvesm status --content "$content" 2>/dev/null | awk 'NR > 1 && $3 == "active" {print $1}')
  for s in "$@"; do grep -qx "$s" <<<"$list" && { echo "$s"; return; }; done
  head -n1 <<<"$list"
}

# The newest Debian template for this CPU, downloaded to storage ST if it
# isn't there yet. Sets TMPL to its volume ID (st:vztmpl/name).
get_template() {
  local st=$1 logf=$log_dir/proxmox-template.log pat name v
  pat="debian-1[23]-standard_.*_${ARCH}\.tar\.(zst|xz|gz)$"
  name=$(pveam list "$st" 2>/dev/null | awk 'NR > 1 {print $1}' | grep -E "/$pat" | sort -V | tail -n1 || true)
  [[ -n $name ]] && { TMPL=$name; return; }
  run_quiet "Updating Proxmox's template list" "$logf" pveam update || true
  for v in 13 12; do
    name=$(pveam available --section system 2>/dev/null | awk '{print $2}' \
      | grep -E "^debian-$v-standard_.*_${ARCH}\.tar\.(zst|xz|gz)$" | sort -V | tail -n1 || true)
    [[ -n $name ]] && break
  done
  if [[ -n $name ]]; then
    run_quiet "Downloading $name" "$logf" pveam download "$st" "$name" \
      || { show_log "$logf"; fail "Downloading the Debian template failed." "pveam update && pveam download $st $name"; }
    TMPL=$st:vztmpl/$name; return
  fi
  [[ $ARCH == arm64 ]] || fail "Proxmox's template list has no Debian 12 or 13." "pveam update, then run this again"
  lxc_image "$st"
}

# arm64 ports of Proxmox may list no templates: take Debian 13's arm64 image
# from linuxcontainers.org (the LXC project), checked against its SHA256SUMS.
lxc_image() {
  local st=$1 base=https://images.linuxcontainers.org/images/debian/trixie/arm64/default
  local logf=$log_dir/proxmox-template.log build file path tmp want got
  say "  Proxmox lists no Debian template for arm64. Setup can download Debian 13 for arm64"
  say "  from linuxcontainers.org (the LXC project). It's checked against that server's"
  say "  checksum list, but nothing signs it: you're trusting that site's HTTPS alone."
  if $YES || [[ ! -t 0 ]]; then
    fail "Not downloading an unsigned image without asking." "run ./bridgekeep setup without --yes to confirm it, or download a Debian arm64 template yourself and pass --template STORAGE:vztmpl/NAME"
  fi
  ask N "Download it from linuxcontainers.org?" \
    || fail "No Debian template for arm64." "download a Debian arm64 template yourself and pass --template STORAGE:vztmpl/NAME"
  build=$(curl -fsSL "$base/" 2>>"$logf" | grep -o '[0-9]\{8\}_[0-9]\{2\}:[0-9]\{2\}/' | sort | tail -n1 || true)
  build=${build%/}
  [[ -n $build ]] || fail "No Debian arm64 image found at linuxcontainers.org." "check this host can reach images.linuxcontainers.org, or download a Debian arm64 template and run ./bridgekeep setup --template STORAGE:vztmpl/NAME"
  file="debian-13-default_${build%%_*}_arm64.tar.xz"
  path=$(pvesm path "$st:vztmpl/$file")
  if [[ ! -f $path ]]; then
    tmp=$(mktemp -d)
    # shellcheck disable=SC2016
    run_quiet "Downloading Debian 13 for arm64" "$logf" sh -c 'curl -fsSL -o "$1/rootfs.tar.xz" "$2/rootfs.tar.xz" && curl -fsSL -o "$1/SHA256SUMS" "$2/SHA256SUMS"' _ "$tmp" "$base/$build" \
      || { rm -rf "$tmp"; show_log "$logf"; fail "Downloading the Debian arm64 image failed." "check this host can reach images.linuxcontainers.org"; }
    want=$(awk '$NF == "rootfs.tar.xz" || $NF == "*rootfs.tar.xz" {print $1}' "$tmp/SHA256SUMS")
    got=$(sha256sum "$tmp/rootfs.tar.xz" | cut -d' ' -f1)
    if [[ -z $want || $want != "$got" ]]; then
      rm -rf "$tmp"; fail "The Debian arm64 image doesn't match its checksum, so it wasn't used." "run this again later; if it keeps failing, the download may have been tampered with"
    fi
    mkdir -p "$(dirname "$path")"; mv "$tmp/rootfs.tar.xz" "$path"; rm -rf "$tmp"
  fi
  TMPL=$st:vztmpl/$file
}

create_ct() {
  local ct=$1 st tst bridge net logf=$log_dir/proxmox-create.log
  st=${STORAGE:-$(pick_storage rootdir local-lvm local-zfs local)}
  [[ -n $st ]] || fail "No storage here can hold containers." "Datacenter > Storage: allow 'Container' content on one, or pass --storage NAME"
  tst=$(pick_storage vztmpl local)
  [[ -n $tst ]] || fail "No storage here can hold container templates." "Datacenter > Storage > local: allow 'Container template' content"
  bridge=${BRIDGE:-vmbr0}
  ip link show "$bridge" >/dev/null 2>&1 || fail "There's no network bridge $bridge on this host." "pass --bridge NAME (see: ip -br link | grep vmbr)"
  net="name=eth0,bridge=$bridge,firewall=1,ip=${IP:-dhcp}"
  [[ -n ${GATEWAY:-} ]] && net+=",gw=$GATEWAY"

  say "  Bridgekeep gets its own Debian container on this Proxmox host:"
  say "    Container  $ct \"$HOSTNAME_\" (unprivileged, Docker inside, starts with the host)"
  say "    Size       $CORES cores, $MEMORY MB memory, $DISK GB on $st"
  say "    Network    $bridge, ${IP:-DHCP}${GATEWAY:+ via $GATEWAY}"
  ask Y "Create it?" || { say "  Nothing was changed."; exit 0; }

  TMPL=$TEMPLATE
  [[ -n $TMPL ]] || get_template "$tst"
  run_quiet "Creating container $ct" "$logf" pct create "$ct" "$TMPL" \
    --arch "$ARCH" --ostype debian --hostname "$HOSTNAME_" \
    --unprivileged 1 --features nesting=1,keyctl=1 \
    --cores "$CORES" --memory "$MEMORY" --swap 1024 \
    --rootfs "$st:$DISK" --net0 "$net" \
    --onboot 1 --timezone host --tags "$TAG" \
    --description "Bridgekeep (Proton Bridge, AI analyzer, admin portal). Manage it with ./bridgekeep from its checkout on this host: $here" \
    || { show_log "$logf"; fail "Proxmox couldn't create the container." "see the log above"; }
  ok "Container $ct created from ${TMPL##*/}"
}

start_ct() {
  local ct=$1 ip i
  if [[ $(ct_state "$ct") != running ]]; then
    pct start "$ct" >>"$log_dir/proxmox-create.log" 2>&1 || { show_log "$log_dir/proxmox-create.log"; fail "Container $ct didn't start." "pct start $ct shows why"; }
  fi
  for ((i = 0; i < 90; i++)); do
    ip=$(ct_address "$ct"); [[ -n $ip ]] && break; sleep 1
  done
  [[ -n $ip ]] || fail "Container $ct has no network address after 90 seconds." "check DHCP on its bridge, or pass --ip 192.168.1.50/24 --gateway 192.168.1.1 (pct set $ct --net0 ...)"
  for ((i = 0; i < 30; i++)); do
    ct_run "$ct" getent hosts deb.debian.org >/dev/null 2>&1 && break; sleep 1
  done
  (( i < 30 )) || fail "Container $ct ($ip) can't look up names on the internet." "check the DNS server under the container's DNS settings in the Proxmox web UI"
  CT_IP=$ip
}

# Runs inside the container: Docker's own packages (the distro's are too old
# for the portal), from Docker's repository, its key checked by fingerprint.
# shellcheck disable=SC2016
DOCKER_INSTALL='set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg git make iproute2
curl -fsSL https://download.docker.com/linux/debian/gpg -o /tmp/docker.asc
# Exactly one key, the expected one; only that key goes in the keyring.
keys=$(gpg --show-keys --with-colons /tmp/docker.asc | awk -F: '"'"'$1 == "pub" {n++} $1 == "fpr" && !seen[n]++ {print $10}'"'"')
if [ "$keys" != "$1" ]; then echo "Docker key fingerprint is $(echo $keys), expected $1"; exit 3; fi
gh=$(mktemp -d)
gpg --homedir "$gh" --batch --quiet --import /tmp/docker.asc
install -m 0755 -d /etc/apt/keyrings
gpg --homedir "$gh" --batch --export "$1" > /etc/apt/keyrings/docker.gpg
chmod 0644 /etc/apt/keyrings/docker.gpg
rm -rf "$gh" /tmp/docker.asc /etc/apt/keyrings/docker.asc
. /etc/os-release
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $VERSION_CODENAME stable" > /etc/apt/sources.list.d/docker.list
apt-get update -qq
apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
docker info >/dev/null'

ensure_docker() {
  local ct=$1 logf=$log_dir/proxmox-docker.log img
  if ct_run "$ct" sh -c 'docker compose version && docker buildx version && docker info' >/dev/null 2>&1; then
    ok "Docker $(ct_run "$ct" docker version --format '{{.Server.Version}}' 2>/dev/null) is installed"
  else
    run_quiet "Installing Docker (a few minutes)" "$logf" ct_run "$ct" sh -c "$DOCKER_INSTALL" _ "$DOCKER_KEY_FPR" || {
      show_log "$logf"
      grep -q 'fingerprint' "$logf" && fail "Docker's signing key isn't the one Bridgekeep expects, so nothing was installed." "check https://docs.docker.com/engine/install/debian/ for a key change before going on"
      fail "Installing Docker in container $ct failed." "see the log above"
    }
    ok "Docker $(ct_run "$ct" docker version --format '{{.Server.Version}}' 2>/dev/null) installed"
  fi
  # Can Docker start a container in here? An unprivileged LXC needs nesting,
  # and some older Proxmox releases block runc's newer security checks.
  img=$(sed -n 's/^PYTHON_IMAGE *?= *//p' "$here/Makefile")
  run_quiet "Checking Docker can run containers" "$logf" ct_run "$ct" docker run --rm --network none "$img" true || {
    show_log "$logf"
    if grep -qi 'permission denied\|apparmor\|operation not permitted' "$logf"; then
      fail "Docker can't start containers inside container $ct." "update Proxmox (apt update && apt full-upgrade on this host, then reboot), and check the container has nesting on: pct set $ct --features nesting=1,keyctl=1"
    fi
    fail "Docker couldn't run a test container (it needs Docker Hub once)." "see the log above"
  }
  ok "Docker runs containers"
}

# Runs inside the container: unpack the new copy over $DEST. Files the last
# copy had and this one doesn't were deleted upstream, so they go too.
# Untracked files (.env, .bridgekeep/, config/, the pinned certificate) stay.
# shellcheck disable=SC2016
SYNC='set -eu
d=$1 in=/root/bridgekeep-sync
mkdir -p "$d/.bridgekeep"
old=$d/.bridgekeep/proxmox-files
if [ -f "$old" ]; then
  grep -vxF -f "$in.files" "$old" | while IFS= read -r f; do
    case $f in /*|*..*|.bridgekeep*|"") continue ;; esac
    rm -f -- "$d/$f"
  done || true
fi
rm -rf "$d/.git"
tar -xzf "$in.tgz" -C "$d" --no-same-owner
chown root:root "$d"; chmod 755 "$d"
mv "$in.files" "$old"; rm -f "$in.tgz"'

# Where this copy came from: a git checkout, or install.sh's download (no git).
downloaded() { [[ ! -d $here/.git && -f $here/.bridgekeep/download && -f $here/.bridgekeep/download-files ]]; }

sync_code() {
  local ct=$1 tmp logf=$log_dir/proxmox-copy.log commit
  tmp=$(mktemp -d); CLEANUP=$tmp
  if downloaded; then
    # Exactly the files install.sh downloaded (its manifest), nothing added here since.
    commit=$(sed -n 's/^commit=\([0-9a-f]\{7,40\}\)$/\1/p' "$here/.bridgekeep/download"); commit=${commit:0:7}
    grep -v -e '^/' -e '\.\.' -e '^\.bridgekeep' "$here/.bridgekeep/download-files" >"$tmp/files" || true
    tar -czf "$tmp/src.tgz" -C "$here" --no-recursion -T "$tmp/files" >"$logf" 2>&1 \
      || { show_log "$logf"; fail "Couldn't pack the downloaded copy." "run the install command again"; }
  else
    local g=(git -C "$here")
    [[ -d $here/.git ]] || fail "$here isn't a git checkout or a download from the install command." "run the install command in docs/proxmox.md"
    commit=$("${g[@]}" rev-parse --short HEAD)
    if "${g[@]}" status --porcelain --untracked-files=no | grep -q .; then
      note "This checkout has uncommitted changes; the container gets commit $commit without them."
    fi
    {
      git clone -q --no-hardlinks "$here" "$tmp/src" \
        && git -C "$tmp/src" remote remove origin \
        && git -C "$tmp/src" ls-files >"$tmp/files" \
        && tar -czf "$tmp/src.tgz" -C "$tmp/src" .
    } >"$logf" 2>&1 || { show_log "$logf"; fail "Couldn't copy this checkout." "see the log above"; }
  fi
  # shellcheck disable=SC2015
  pct push "$ct" "$tmp/src.tgz" /root/bridgekeep-sync.tgz --perms 0600 >>"$logf" 2>&1 \
    && pct push "$ct" "$tmp/files" /root/bridgekeep-sync.files --perms 0600 >>"$logf" 2>&1 \
    && ct_run "$ct" sh -c "$SYNC" _ "$DEST" >>"$logf" 2>&1 \
    || { show_log "$logf"; fail "Couldn't copy Bridgekeep into container $ct." "see the log above"; }
  rm -rf "$tmp"; CLEANUP=''
  ok "Bridgekeep $(head -n1 "$here/VERSION" 2>/dev/null) ($commit) copied to $DEST"
}

# --- commands --------------------------------------------------------------------

host_checks() {
  [[ $(id -u) == 0 ]] || fail "On Proxmox, run this as root." "sudo -i, then cd $here && ./bridgekeep setup"
  { command -v pct && command -v pvesm; } >/dev/null 2>&1 || fail "This doesn't look like a Proxmox VE host (no pct)." "run it on the Proxmox host, or BRIDGEKEEP_PROXMOX=off ./bridgekeep setup to install here directly"
  ARCH=$(dpkg --print-architecture 2>/dev/null || true)
  case $ARCH in
    amd64|arm64) ;;
    *) fail "Bridgekeep runs on amd64 or arm64, and this host is ${ARCH:-unknown}." ;;
  esac
  [[ ! -d $here/.git ]] || command -v git >/dev/null 2>&1 || fail "git is missing on this host." "apt-get install git"
  checkout_safe || fail "Setup runs git on this checkout as root, so only root may be able to change it." "keep the checkout root's own: chown -R root:root $here && chmod -R go-w $here (and its parent folders)"
}

# The checkout and every folder above it must be writable only by whoever runs
# this (root on a real host), as for the nightly job in ./bridgekeep: git runs
# here as root, and a repository's config can run commands.
checkout_safe() {
  local d=$here bad
  bad=$(find "$here" \( ! -user "$EUID" -o -perm /022 \) -print 2>/dev/null | head -n 5)
  while [[ $d != / ]]; do
    d=$(dirname "$d")
    [[ $(stat -c %u "$d") == 0 || $(stat -c %u "$d") == "$EUID" ]] \
      && (( (8#$(stat -c %a "$d") & 8#022) == 0 || (8#$(stat -c %a "$d") & 8#1000) != 0 )) \
      || bad+=$'\n'"$d"
  done
  [[ -z ${bad//$'\n'/} ]] && return 0
  grep . <<<"$bad" | sed 's/^/    not root-only: /' >&2
  return 1
}

cmd_setup() {
  local pass=() a
  CTID='' HOSTNAME_=bridgekeep STORAGE='' BRIDGE='' IP='' GATEWAY='' DISK=20 MEMORY=2048 CORES=2 TEMPLATE=''
  while (($#)); do
    a=$1
    case $a in
      --ctid|--hostname|--storage|--bridge|--ip|--gateway|--disk|--memory|--cores|--template)
        (($# >= 2)) || { say "$a needs a value"; exit 2; }
        case $a in
          --ctid) CTID=$2 ;; --hostname) HOSTNAME_=$2 ;; --storage) STORAGE=$2 ;;
          --bridge) BRIDGE=$2 ;; --ip) IP=$2 ;; --gateway) GATEWAY=$2 ;;
          --disk) DISK=$2 ;; --memory) MEMORY=$2 ;; --cores) CORES=$2 ;; --template) TEMPLATE=$2 ;;
        esac
        shift 2; continue ;;
      --yes|-y) YES=true; pass+=("$a") ;;
      *) pass+=("$a") ;;
    esac
    shift
  done
  [[ -z $CTID || $CTID =~ ^[0-9]+$ ]] || { say "--ctid is a number, like 105"; exit 2; }
  [[ $DISK =~ ^[0-9]+$ && $MEMORY =~ ^[0-9]+$ && $CORES =~ ^[0-9]+$ ]] || { say "--disk, --memory and --cores are whole numbers"; exit 2; }
  [[ $HOSTNAME_ =~ ^[A-Za-z0-9-]{1,63}$ ]] || { say "--hostname: letters, digits and dashes only"; exit 2; }
  [[ -z $IP || $IP =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]] || { say "--ip is an address with its prefix, like 192.168.1.50/24"; exit 2; }
  [[ -n $IP || -z $GATEWAY ]] || { say "--gateway goes with --ip"; exit 2; }

  mkdir -p "$log_dir"; chmod 700 "$here/.bridgekeep" 2>/dev/null || true
  say "${B}Bridgekeep setup on Proxmox VE${N}  ${D}(logs in .bridgekeep/logs/; safe to stop and run again)${N}"
  host_checks

  step 1 "Bridgekeep's container"
  local ct; ct=$(find_ct)
  if [[ -n $ct ]] && pct config "$ct" >/dev/null 2>&1; then
    tagged_cts | grep -qx "$ct" \
      || fail "Container $ct already exists and isn't Bridgekeep's, so setup leaves it alone." "choose a free number with --ctid, or leave --ctid out"
    ok "Using container $ct ($(pct config "$ct" | sed -n 's/^hostname: //p'))"
  else
    [[ -n $ct ]] || ct=$(pvesh get /cluster/nextid)
    create_ct "$ct"
  fi
  start_ct "$ct"
  ok "Container $ct is running at $CT_IP"

  step 2 "Docker in the container"
  ensure_docker "$ct"

  step 3 "Copying Bridgekeep in"
  sync_code "$ct"

  step 4 "Bridgekeep setup inside container $ct (its own steps follow)"
  # shellcheck disable=SC2016
  ct_run "$ct" bash -c 'cd "$1" && shift && exec ./bridgekeep "$@"' _ "$DEST" setup "${pass[@]}"

  say ""
  say "${B}Bridgekeep runs in Proxmox container $ct${N} ($CT_IP). It starts with this host."
  say "  The portal's address is the one setup printed above (in the container, at $CT_IP)."
  local bk=./bridgekeep where="From this folder on the Proxmox host"
  if downloaded; then bk=bridgekeep where="Anywhere on the Proxmox host"; fi
  say "  $where, every command works as usual:"
  say "    $bk status, $bk credentials, $bk portal code, ..."
  say "    $bk shell    a root shell inside the container"
  if downloaded; then
    say "  Update Bridgekeep: run the install command again (docs/proxmox.md):"
    say "    bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/factorialandha/bridgekeep-proton/preview/deploy/proxmox/install.sh)\""
    say "    (while the repository is private, the token version in docs/proxmox.md)"
  else
    say "  Update Bridgekeep: git pull && ./bridgekeep setup"
  fi
  say "  Your Proton sign-in lives in container $ct: keep its Proxmox backups encrypted."
}

ct_or_fail() {
  local ct; ct=$(find_ct)
  { [[ -n $ct ]] && pct config "$ct" >/dev/null 2>&1; } || { say "Bridgekeep isn't set up on this Proxmox host yet. Run ./bridgekeep setup" >&2; exit 1; }
  if [[ $(ct_state "$ct") != running ]]; then
    say "Bridgekeep's container $ct is stopped. Start it: pct start $ct (or ./bridgekeep setup)" >&2; exit 1
  fi
  echo "$ct"
}

forward() {
  local ct ip; ct=$(ct_or_fail)
  if [[ ${1:-} == status ]]; then
    ip=$(ct_address "$ct")
    printf '%-14s %s\n' "Container" "$ct on Proxmox, running${ip:+ at $ip}"
  fi
  # shellcheck disable=SC2016
  ct_run "$ct" bash -c 'cd "$1" 2>/dev/null || { echo "Bridgekeep isn'\''t in the container yet. Run ./bridgekeep setup"; exit 1; }; shift; exec ./bridgekeep "$@"' _ "$DEST" "$@"
}

CTID=''
case ${1:-help} in
  setup) shift; cmd_setup "$@" ;;
  shell) ct=$(ct_or_fail); exec pct enter "$ct" ;;
  help|-h|--help)
    BRIDGEKEEP_PROXMOX=off bash "$here/bridgekeep" help 2>&1 | sed '/^$/q' || true
    say ""
    say "On Proxmox VE these run inside Bridgekeep's own container (made by setup)."
    say "  ./bridgekeep shell        a root shell inside that container"
    say "  setup also takes --ctid N --hostname NAME --storage STORAGE --bridge vmbrN"
    say "    --ip CIDR --gateway IP --disk GB --memory MB --cores N"
    ;;
  *) forward "$@" ;;
esac
