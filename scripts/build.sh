#!/usr/bin/env bash
# Build the Bridge image from the pins in bridge-version.env.
#
#   scripts/build.sh -t proton-bridge:local [more docker build args...]
#   scripts/build.sh --recipe   # print the recipe hash and exit
#
# Every image gets the label bridgekeep.recipe: a hash of the files the image
# is made from besides the pins (Dockerfile, docker/, broker/, keys/). The
# nightly update rebuilds when it differs from the running image's, so a
# change to the entrypoint or broker reaches the host like a Bridge update.
#
# BRIDGE_BUILD=source (default) builds Bridge from source on amd64 or arm64.
# BRIDGE_BUILD=deb uses Proton's signed .deb (amd64 only).
# Used by `make build` and scripts/auto-update.sh, so both build the same way.
set -euo pipefail
export MSYS_NO_PATHCONV=1   # Git Bash: do not rewrite /paths in docker arguments

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

recipe() {
  find Dockerfile docker broker keys -type f -print0 | LC_ALL=C sort -z \
    | xargs -0 sha256sum | sha256sum | cut -c1-16
}
if [[ ${1:-} == --recipe ]]; then recipe; exit 0; fi

# shellcheck source=/dev/null
source bridge-version.env
build=${BRIDGE_BUILD:-source}
case $build in
  source|deb) ;;
  *) echo "build: BRIDGE_BUILD must be source or deb, not '$build'" >&2; exit 2 ;;
esac

# The image needs BuildKit (docker buildx). Where the host's docker CLI has
# no buildx plugin and you cannot install one (TrueNAS SCALE), run the build
# from Docker's own CLI image instead. It talks to the same daemon through its
# socket, so the image lands in the host's image store as usual.
# BUILD_IN_CONTAINER=1 forces this path.
DOCKER_CLI_IMAGE=${DOCKER_CLI_IMAGE:-docker:28-cli@sha256:625d9431a9f54c5a2bc90f24f0e1c3d55b1349fd857dd85035f98c2c9acbdd4d}
docker_build=(env DOCKER_BUILDKIT=1 docker build)
# BUILDX=1: call buildx directly, for its multi-platform and push options (CI
# publishing; see scripts/publish-images.sh).
if [[ ${BUILDX:-} == 1 ]]; then
  docker_build=(docker buildx build)
elif [[ ${BUILD_IN_CONTAINER:-} == 1 ]] || ! docker buildx version >/dev/null 2>&1; then
  sock=${DOCKER_SOCK:-/var/run/docker.sock}
  [[ -S $sock ]] || {
    echo "build: BuildKit (docker buildx) is missing and there is no Docker socket at $sock to run it from a container. Run scripts/preflight.sh for how to install buildx." >&2
    exit 1
  }
  echo "build: no buildx plugin here; building with ${DOCKER_CLI_IMAGE%@*} in a container"
  docker_build=(docker run --rm -v "$sock:/var/run/docker.sock" -v "$root:$root" -w "$root"
                -e DOCKER_BUILDKIT=1 "$DOCKER_CLI_IMAGE" docker build)
fi

echo "build: Bridge ${BRIDGE_VERSION} from ${build} for $(docker info --format '{{.Architecture}}' 2>/dev/null)"
exec "${docker_build[@]}" \
  --build-arg BRIDGE_BUILD="$build" \
  --build-arg BRIDGE_VERSION="${BRIDGE_VERSION:-}" \
  --build-arg BRIDGE_DEB_SHA256="${BRIDGE_DEB_SHA256:-}" \
  --build-arg BRIDGE_SIGNING_KEY="${BRIDGE_SIGNING_KEY:-}" \
  --build-arg BRIDGE_SOURCE_H1="${BRIDGE_SOURCE_H1:-}" \
  --build-arg BRIDGE_SOURCE_COMMIT="${BRIDGE_SOURCE_COMMIT:-}" \
  --build-arg GO_TOOLCHAIN="${GO_TOOLCHAIN:-}" \
  --label "bridgekeep.recipe=$(recipe)" \
  "$@" .
