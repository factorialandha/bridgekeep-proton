#!/usr/bin/env bash
# `docker build` with BuildKit, whatever Docker the host has.
#
#   scripts/docker-build.sh -t bridgekeep-portal:local portal/
#
# The portal's Dockerfile needs BuildKit (FROM --platform=$BUILDPLATFORM for
# its Node stage). Docker's legacy builder (Debian's docker.io 20.10, for one)
# leaves $BUILDPLATFORM empty and fails with "failed to parse platform". With a
# buildx plugin, use it; without one, run the build from Docker's own CLI image,
# which talks to the same daemon (the same fallback as scripts/build.sh).
set -euo pipefail
export MSYS_NO_PATHCONV=1

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

DOCKER_CLI_IMAGE=${DOCKER_CLI_IMAGE:-docker:28-cli@sha256:625d9431a9f54c5a2bc90f24f0e1c3d55b1349fd857dd85035f98c2c9acbdd4d}
if [[ ${BUILD_IN_CONTAINER:-} != 1 ]] && docker buildx version >/dev/null 2>&1; then
  exec env DOCKER_BUILDKIT=1 docker build "$@"
fi
sock=${DOCKER_SOCK:-/var/run/docker.sock}
[[ -S $sock ]] || {
  echo "build: BuildKit (docker buildx) is missing and there is no Docker socket at $sock to run it from a container. Run scripts/preflight.sh for how to install buildx." >&2
  exit 1
}
echo "build: no buildx plugin here; building with ${DOCKER_CLI_IMAGE%@*} in a container"
exec docker run --rm -v "$sock:/var/run/docker.sock" -v "$root:$root:ro" -w "$root" \
  -e DOCKER_BUILDKIT=1 "$DOCKER_CLI_IMAGE" docker build "$@"
