#!/usr/bin/env bash
# Keep the running Bridge container up to date, without weakening verification.
#
#   scripts/auto-update.sh            # check; build and test an update if needed
#   scripts/auto-update.sh --force    # rebuild and test even if nothing is new
#   scripts/auto-update.sh --deploy   # swap in the tested update (./bridgekeep deploy-update)
#   scripts/auto-update.sh --no-deploy  # never deploy, even with AUTO_DEPLOY=true (nightly job)
#
# By default (the owner's choice) a scheduled run does NOT deploy: it pins,
# builds, verifies and smoke-tests the update, leaves it waiting as
# proton-bridge:candidate, writes .bridgekeep/update-waiting and logs
# "UPDATE WAITING". A person then runs `./bridgekeep deploy-update`
# (scripts/auto-update.sh --deploy).
#
# .bridgekeep/update-waiting is key=value lines, for `./bridgekeep status`:
#   version=3.28.0  go=go1.26.12  built=2026-11-25T04:31:07Z  reason=...
# AUTO_DEPLOY=true swaps it in straight away instead.
#
# Meant to run unattended once a day (Windows Task Scheduler, cron or systemd;
# see docs/operations.md). Each run:
#
#   1. Asks scripts/update-bridge.sh for the latest stable Bridge. That script
#      only accepts a release whose .deb is signed by the key committed in
#      keys/, pins its source hash and the Go release to build it with, and never
#      trusts a new key on its own (it needs --trust-key, which this script
#      never passes). A new signing key therefore stops the update.
#   2. Rebuilds when the Bridge version or the pinned Go release changed,
#      when no image exists for the pin, or when the image is older than
#      REBUILD_DAYS (picks up Debian security fixes). The build checks the
#      source (or the .deb) against the pins again. Works on amd64 and arm64.
#   3. Smoke-tests the new image (tests/smoke.sh) before it goes live.
#   4. Stops there and reports the waiting update (unless AUTO_DEPLOY=true).
#      --deploy swaps it in (docker compose up -d) and waits for the
#      healthcheck. If the new container does not become healthy, it rolls
#      back to the previous image.
#
# Nothing is deleted from the volume, and the login and keychain carry over.
# A pin bump is left as a change to bridge-version.env, so you can commit it.
set -euo pipefail
export MSYS_NO_PATHCONV=1   # Git Bash: do not rewrite /paths in docker arguments

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

IMAGE=${IMAGE:-proton-bridge}
REBUILD_DAYS=${REBUILD_DAYS:-7}
HEALTH_TIMEOUT=${HEALTH_TIMEOUT:-180}
AUTO_DEPLOY=${AUTO_DEPLOY:-false}
LOG_KEEP_LINES=${LOG_KEEP_LINES:-5000}   # trims auto-update.log to this
waiting_file=$root/.bridgekeep/update-waiting
force=false deploy_only=false
case ${1:-} in
  --force) force=true ;;
  --deploy) deploy_only=true ;;
  --no-deploy) AUTO_DEPLOY=false ;;   # the default; explicit for schedules
  "") ;;
  *) echo "usage: $0 [--force | --deploy | --no-deploy]" >&2; exit 2 ;;
esac
[[ $AUTO_DEPLOY == true || $AUTO_DEPLOY == false ]] || { echo "AUTO_DEPLOY must be true or false" >&2; exit 2; }
candidate="$IMAGE:candidate"

log() { printf '%s [auto-update] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
# Alerts (scripts/notify.sh; a no-op without a Discord webhook). Never fatal.
alert() { bash "$root/scripts/notify.sh" send "$@" 2>&1 | sed 's/^/  /' || true; }
die() {
  log "ERROR: $*"
  [[ ${deploy_only:-false} == true ]] || alert update_failed "$*"
  exit 1
}

# The documented schedules append to auto-update.log. Keep it from growing
# forever: trim in place (same file, so the open append handle stays valid).
logf=$root/auto-update.log
if [[ -f $logf ]] && (( $(wc -l <"$logf") > LOG_KEEP_LINES )); then
  tmp=$(mktemp)
  tail -n "$LOG_KEEP_LINES" "$logf" >"$tmp" && cat "$tmp" >"$logf"
  rm -f -- "$tmp"
fi

recipe_of() { # IMAGE: its bridgekeep.recipe label, or nothing
  docker image inspect -f '{{index .Config.Labels "bridgekeep.recipe"}}' "$1" 2>/dev/null || true
}
candidate_version() { # the Bridge version of the waiting :candidate, or nothing
  docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.version"}}' "$candidate" 2>/dev/null || true
}

command -v docker >/dev/null 2>&1 || die "docker not found"
docker info >/dev/null 2>&1 || die "Docker is not running"

pins() { # print VERSION GO_TOOLCHAIN from bridge-version.env
  # shellcheck source=/dev/null
  (source bridge-version.env && echo "$BRIDGE_VERSION ${GO_TOOLCHAIN:-none}")
}

read -r old_version old_go < <(pins)

wait_healthy() {
  local cid state deadline=$((SECONDS + HEALTH_TIMEOUT))
  cid=$(docker compose ps -q bridge)
  [[ -n $cid ]] || return 1
  while ((SECONDS < deadline)); do
    state=$(docker inspect -f '{{.State.Health.Status}}' "$cid" 2>/dev/null || echo gone)
    [[ $state == healthy ]] && return 0
    [[ $state == gone ]] && return 1
    sleep 5
  done
  return 1
}

deploy() { # VERSION: swap the tested :candidate in, roll back on failure
  local v=$1
  # Keep the current image as :previous for rollback.
  if docker image inspect "$IMAGE:local" >/dev/null 2>&1; then
    docker tag "$IMAGE:local" "$IMAGE:previous"
  fi
  docker tag "$candidate" "$IMAGE:$v"
  docker tag "$candidate" "$IMAGE:local"
  docker image rm "$candidate" >/dev/null

  if ! docker compose ps -q bridge 2>/dev/null | grep -q .; then
    rm -f -- "$waiting_file"
    log "bridge service is not running; new image is ready as $IMAGE:local (start it with docker compose up -d)"
    exit 0
  fi

  log "recreating bridge on $IMAGE:local"
  bash scripts/fix-volumes.sh "$IMAGE:local" || log "could not check the broker's volumes; portal sign-in may be unavailable"
  docker compose up -d --no-build bridge
  if wait_healthy; then
    rm -f -- "$waiting_file"
    log "updated: Bridge $v is running and healthy"
    # Services already running pick up compose changes that came with it
    # (e.g. the portal's broker mount); unchanged ones are left alone.
    mapfile -t running < <(docker compose ps --services --status running 2>/dev/null | grep -vx bridge)
    ((${#running[@]})) && { docker compose up -d --no-build --no-deps "${running[@]}" >/dev/null 2>&1 \
      || log "could not refresh ${running[*]}; run ./bridgekeep setup"; }
    exit 0
  fi

  log "new container did not become healthy within ${HEALTH_TIMEOUT}s; rolling back"
  if docker image inspect "$IMAGE:previous" >/dev/null 2>&1; then
    docker tag "$IMAGE:previous" "$IMAGE:local"
    docker compose up -d --no-build bridge
    wait_healthy && die "rolled back to the previous image; it is healthy again. Investigate before retrying."
  fi
  die "rollback did not bring bridge back to healthy; check docker compose logs bridge"
}

age_days() { # IMAGE_REF: whole days since it was built, or nothing if it doesn't exist
  local created
  created=$(docker image inspect -f '{{.Created}}' "$1" 2>/dev/null) || return 0
  echo $(( ( $(date +%s) - $(date -d "$created" +%s) ) / 86400 ))
}

# --deploy: swap in the update a scheduled run already built and tested.
if [[ $deploy_only == true ]]; then
  v=$(candidate_version)
  if [[ -z $v ]]; then
    rm -f -- "$waiting_file"
    die "no tested update is waiting. Run ./bridgekeep update first."
  fi
  log "deploying the tested update: Bridge $v"
  deploy "$v"
fi

# 1. Pin the latest stable release (verified with the committed key only).
log "checking for a newer Bridge (pinned: $old_version)"
if ! out=$(bash scripts/update-bridge.sh 2>&1); then
  printf '%s\n' "$out"
  die "update-bridge.sh failed; keeping the current container. A new signing key or a bad signature needs a person (see docs/operations.md)."
fi
printf '%s\n' "$out"
read -r version go_tc < <(pins)
recipe=$(bash scripts/build.sh --recipe)

# A tested update for this version is already waiting: say so again instead
# of rebuilding it every day. It is rebuilt once it is REBUILD_DAYS old.
waiting_age=$(age_days "$candidate")
if [[ $force != true && $go_tc == "$old_go" && $(candidate_version) == "$version" && $(recipe_of "$candidate") == "$recipe" ]] \
   && [[ -n $waiting_age ]] && (( waiting_age < REBUILD_DAYS )); then
  log "UPDATE WAITING: Bridge $version is built and smoke-tested but not running yet. Run: ./bridgekeep deploy-update"
  alert update_waiting "$version"
  exit 0
fi

# 2. Decide whether to rebuild.
running_age=$(age_days "$IMAGE:$version")
reason=""
if [[ $force == true ]]; then
  reason="forced"
elif [[ $version != "$old_version" ]]; then
  reason="new Bridge $version (was $old_version)"
elif [[ $go_tc != "$old_go" ]]; then
  reason="new Go toolchain $go_tc (was $old_go)"
elif [[ -z $running_age ]]; then
  reason="no image for $version yet"
elif [[ $(recipe_of "$IMAGE:local") != "$recipe" ]]; then
  reason="Bridgekeep's Bridge container changed (sign-in broker or startup script)"
elif (( running_age >= REBUILD_DAYS )); then
  reason="image is $running_age days old"
fi
if [[ -z $reason ]]; then
  log "up to date (Bridge $version); nothing to do"
  exit 0
fi
log "rebuilding: $reason"

bash scripts/build.sh -t "$candidate" || die "build failed; keeping the current container"

# 3. Smoke-test before it goes anywhere near the real volume.
IMAGE=$candidate bash tests/smoke.sh || die "smoke test failed on the new image; keeping the current container"

# 4. Leave the tested image waiting (the default), or swap it in.
if [[ $AUTO_DEPLOY != true ]]; then
  mkdir -p "$(dirname "$waiting_file")"
  printf 'version=%s\ngo=%s\nbuilt=%s\nreason=%s\n' \
    "$version" "$go_tc" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$reason" >"$waiting_file"
  log "UPDATE WAITING: Bridge $version is built and smoke-tested but not running yet. Run: ./bridgekeep deploy-update"
  alert update_waiting "$version"
  exit 0
fi
deploy "$version"
