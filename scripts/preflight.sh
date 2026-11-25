#!/usr/bin/env bash
# Check the Docker setup before make build/init/up and friends.
#
#   scripts/preflight.sh          # everything (compose targets)
#   scripts/preflight.sh build    # what an image build needs (no Compose)
#
# Catches the setups that fail later with confusing errors:
#   - no Docker CLI, or no daemon reachable
#   - no BuildKit (docker buildx): the image needs it. Where the plugin is
#     missing but the Docker socket is there (TrueNAS SCALE), build.sh runs
#     the build from Docker's CLI image, so that is only a note
#   - a CPU other than amd64/arm64
#   - no Compose v2 plugin ("docker compose ... unknown flag: --rm")
#   - in WSL, a Docker engine that isn't Docker Desktop (a note only). Git
#     Bash and Task Scheduler use Docker Desktop, so a second engine means a
#     second image and login volume.
#
# The Docker Desktop note appears only inside WSL. On a Linux host (the
# production setup) or in Git Bash, any Docker engine is fine.
# PREFLIGHT_ALLOW_OTHER_ENGINE=1 hides the note.
set -euo pipefail

die() { printf 'preflight: %s\n' "$*" >&2; exit 1; }
mode=${1:-all}

in_wsl=false
grep -qi microsoft /proc/version 2>/dev/null && in_wsl=true

desktop_hint="In Docker Desktop, open Settings > Resources > WSL integration, turn it on for this distro, then open a new WSL shell."

command -v docker >/dev/null 2>&1 \
  || die "docker not found. $($in_wsl && echo "$desktop_hint" || echo "Install Docker.")"

docker info >/dev/null 2>&1 \
  || die "cannot reach the Docker daemon. Start Docker Desktop$($in_wsl && echo ". $desktop_hint" || echo " (or dockerd)"). If it is running, check that your user may use it."

if ! docker buildx version >/dev/null 2>&1; then
  $in_wsl && die "BuildKit (the docker buildx plugin) is missing, and the image build needs it. $desktop_hint"
  # scripts/build.sh then builds from Docker's CLI image through the socket.
  [[ -S ${DOCKER_SOCK:-/var/run/docker.sock} ]] \
    || die "BuildKit (the docker buildx plugin) is missing, and the image build needs it. Debian/Ubuntu: sudo apt-get install docker-buildx (or docker-buildx-plugin from Docker's repository)."
  printf 'preflight: note: no docker buildx plugin here (normal on TrueNAS SCALE). The build runs from the docker:cli image instead; it needs Docker Hub access once.\n' >&2
fi

arch=$(docker info --format '{{.Architecture}}' 2>/dev/null || true)
case $arch in
  x86_64|amd64|aarch64|arm64) ;;
  *) die "this Docker engine runs on '$arch'. Only amd64 (x86_64) and arm64 (aarch64) are supported." ;;
esac

if [[ $mode != build ]] && ! docker compose version >/dev/null 2>&1; then
  if $in_wsl; then
    die "'docker compose' (the Compose v2 plugin) is missing. This docker CLI is probably Ubuntu's own docker.io package, not Docker Desktop's. Fix: $desktop_hint If 'which docker' still shows /usr/bin/docker from apt, remove that one first: sudo apt-get remove docker.io docker-compose."
  fi
  die "'docker compose' (the Compose v2 plugin) is missing. Install it (Debian/Ubuntu: sudo apt-get install docker-compose-v2, or docker-compose-plugin from Docker's repository)."
fi

if $in_wsl && [[ ${PREFLIGHT_ALLOW_OTHER_ENGINE:-0} != 1 ]]; then
  os=$(docker info --format '{{.OperatingSystem}}' 2>/dev/null || true)
  if [[ $os != *"Docker Desktop"* ]]; then
    # A warning, not a stop: Windows is a test machine, and testing against an
    # engine inside WSL is fine as long as you stay in that shell.
    printf 'preflight: note: this WSL shell uses its own Docker engine (%s), not Docker Desktop. Fine for testing, but run everything (including auto-update) from this WSL shell: Git Bash and Task Scheduler use Docker Desktop, which has a separate image and login volume. Set PREFLIGHT_ALLOW_OTHER_ENGINE=1 to hide this note.\n' "$os" >&2
  fi
fi

printf 'preflight: ok (%s, %s%s)\n' \
  "$(docker info --format '{{.OperatingSystem}}' 2>/dev/null)" "$arch" \
  "$([[ $mode == build ]] || echo ", compose $(docker compose version --short 2>/dev/null)")"
