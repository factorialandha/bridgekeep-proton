#!/usr/bin/env bash
# CI only: build the Bridge (or analyzer) image for amd64 and arm64, push it
# to the private registry in images.env, and sign it.
#
#   scripts/publish-images.sh bridge|analyzer
#
# Runs only from Outpost on main or preview (protected runs). It needs these
# from the job's environment, never from a file:
#   GHCR_USER, GHCR_TOKEN          registry login: the package owner and a classic
#                                  token with write:packages (Outpost secret)
#   COSIGN_PRIVATE_KEY, COSIGN_PASSWORD
#                                  the signing key for this branch. Preview: the
#                                  shared Outpost secrets COSIGN_PRIVATE_KEY and
#                                  COSIGN_PASSWORD. Main: its own key, held only
#                                  in the main-signing environment (secrets
#                                  COSIGN_MAIN_PRIVATE_KEY, COSIGN_MAIN_PASSWORD)
#                                  and passed in under these two names.
#   OUTPOST_BRANCH, OUTPOST_COMMIT, OUTPOST_REPOSITORY  set by Outpost
#
# Tags:
#   preview -> :preview, :<version>-preview, :preview-<commit12>
#   main    -> :latest,  :<version>,         :main-<commit12>
# The analyzer gets the same tags (its version is the repository commit).
#
# Every tag points at one signed multi-arch index. The signature covers the
# index and each platform's image (cosign --recursive) and carries
# repo=<this repository>, branch=<branch> and commit=<commit>, which
# pull-image.sh requires (the key may also sign other projects' images).
# Before anything is built, the key's public half must match this branch's
# public key (main: keys/cosign-main.pub, preview: keys/cosign.pub) and must
# not be the other branch's key; if this branch's file isn't committed yet, the public key is printed so it can be,
# and nothing is published (a warning, not a failure). The private key and password are only ever
# passed to cosign by name (-e VAR), never printed, written to a file or put
# into a build argument or layer.
set -euo pipefail
cd "$(dirname "$0")/.."

die() { echo "publish: $*" >&2; exit 1; }
what=${1:-}
case $what in bridge|analyzer) ;; *) die "usage: $0 bridge|analyzer" ;; esac

branch=${OUTPOST_BRANCH:-} commit=${OUTPOST_COMMIT:-}
case $branch in
  main|preview) ;;
  *) die "publishes only from main or preview, not '${branch:-unset}'" ;;
esac
[[ $commit =~ ^[0-9a-f]{40}$ ]] || die "OUTPOST_COMMIT must be a full commit hash"
for v in GHCR_USER GHCR_TOKEN COSIGN_PRIVATE_KEY COSIGN_PASSWORD; do
  [[ -n ${!v:-} ]] || die "$v is not set (see docs/images.md, 'One-time setup')"
done

# shellcheck source=/dev/null
source images.env
# shellcheck source=/dev/null
source bridge-version.env
[[ ${OUTPOST_REPOSITORY:-} == "$IMAGE_SOURCE_REPO" ]] \
  || die "publishes only from $IMAGE_SOURCE_REPO, not '${OUTPOST_REPOSITORY:-unset}'"

# The key must be the one this branch's hosts trust: main has its own key
# (keys/cosign-main.pub), preview keeps keys/cosign.pub. cosign public-key
# prints only the public half.
if [[ $branch == main ]]; then pubkey=keys/cosign-main.pub other=keys/cosign.pub
else pubkey=keys/cosign.pub other=keys/cosign-main.pub; fi
derived=$(docker run --rm --user "$(id -u):$(id -g)" -e COSIGN_PRIVATE_KEY -e COSIGN_PASSWORD -e HOME=/tmp \
  "$COSIGN_IMAGE" public-key --key env://COSIGN_PRIVATE_KEY 2>/dev/null) \
  || die "cosign could not read COSIGN_PRIVATE_KEY with COSIGN_PASSWORD"
grep -q -- '-----BEGIN PUBLIC KEY-----' <<<"$derived" || die "cosign did not print a public key"
# Never sign one branch's images with the other branch's key, even if a
# pipeline change hands this job the wrong secret.
if [[ -s $other && $(printf '%s\n' "$derived") == "$(cat "$other")" ]]; then
  die "this $branch job was given the key for $other, not $pubkey; not publishing (see docs/images.md, 'One-time setup')"
fi
if [[ ! -s $pubkey ]]; then
  echo "::warning::$pubkey is not committed yet, so $branch hosts couldn't verify an image. Nothing was published. Commit the public key below as $pubkey."
  printf '%s\n' "$derived"
  exit 0
fi
[[ $(printf '%s\n' "$derived") == "$(cat "$pubkey")" ]] \
  || die "COSIGN_PRIVATE_KEY does not match $pubkey; not publishing. If the key was replaced on purpose, commit its public half (printed below) as $pubkey.$(printf '\n%s' "$derived")"
BUILDKIT_IMAGE=moby/buildkit:v0.20.2@sha256:c457984bd29f04d6acc90c8d9e717afe3922ae14665f3187e0096976fe37b1c8
BINFMT_IMAGE=tonistiigi/binfmt:qemu-v9.2.2@sha256:1b804311fe87047a4c96d38b4b3ef6f62fca8cd125265917a9e3dc3c996c39e6
PLATFORMS=${PLATFORMS:-linux/amd64,linux/arm64}

if [[ $what == bridge ]]; then
  repo=$IMAGE_REGISTRY/$BRIDGE_IMAGE_NAME version=$BRIDGE_VERSION
else
  repo=$IMAGE_REGISTRY/$ANALYZER_IMAGE_NAME version=""
fi
short=${commit:0:12}
if [[ $branch == main ]]; then
  tags=(latest "main-$short"); [[ -n $version ]] && tags+=("$version")
else
  tags=(preview "preview-$short"); [[ -n $version ]] && tags+=("$version-preview")
fi
tag_args=()
for t in "${tags[@]}"; do tag_args+=(-t "$repo:$t"); done

# Registry login and builder live in throwaway folders, so the token never
# outlives this job (Outpost also deletes the job's home afterwards).
work=$(mktemp -d)
builder=bridgekeep-publish-$$
cleanup() {
  docker buildx rm "$builder" >/dev/null 2>&1 || true
  rm -rf -- "$work"
}
trap cleanup EXIT
export DOCKER_CONFIG=$work/docker
mkdir -p "$DOCKER_CONFIG"
# Keep finding CLI plugins (buildx) installed under the usual config folder.
[[ -d $HOME/.docker/cli-plugins ]] && ln -s "$HOME/.docker/cli-plugins" "$DOCKER_CONFIG/cli-plugins"
printf '%s' "$GHCR_TOKEN" | docker login "${IMAGE_REGISTRY%%/*}" -u "$GHCR_USER" --password-stdin >/dev/null

# arm64 layers run their RUN steps under emulation (Bridge itself is still
# cross-compiled natively in the source stage).
if [[ ! -e /proc/sys/fs/binfmt_misc/qemu-aarch64 && $(uname -m) != aarch64 ]]; then
  docker run --privileged --rm "$BINFMT_IMAGE" --install arm64 >/dev/null
fi
docker buildx create --name "$builder" --driver docker-container \
  --driver-opt "image=$BUILDKIT_IMAGE" >/dev/null

meta=$work/metadata.json
common=(--builder "$builder" --platform "$PLATFORMS" --provenance=mode=max --sbom=true
        --build-arg "IMAGE_REVISION=$commit" --metadata-file "$meta" --push "${tag_args[@]}")
echo "publish: building $repo for $PLATFORMS (${tags[*]})"
if [[ $what == bridge ]]; then
  BUILDX=1 bash scripts/build.sh "${common[@]}"
else
  tree=$(git rev-parse "$commit:analyzer") && [[ $tree =~ ^[0-9a-f]{40}$ ]] || die "could not read the analyzer/ tree hash"
  docker buildx build "${common[@]}" --build-arg "ANALYZER_TREE=$tree" analyzer/
fi

digest=$(sed -n 's/.*"containerimage.digest": *"\(sha256:[0-9a-f]\{64\}\)".*/\1/p' "$meta" | head -n1)
[[ -n $digest ]] || die "could not read the pushed digest from the build metadata"
echo "publish: pushed $repo@$digest"

# Sign by digest, never by tag. The key comes from the environment only.
tlog=false; [[ ${COSIGN_TLOG:-false} == true ]] && tlog=true
docker run --rm --user "$(id -u):$(id -g)" \
  -e COSIGN_PRIVATE_KEY -e COSIGN_PASSWORD -e DOCKER_CONFIG=/cfg -e HOME=/tmp \
  -v "$DOCKER_CONFIG:/cfg:ro" \
  "$COSIGN_IMAGE" sign --yes --recursive --key env://COSIGN_PRIVATE_KEY \
  --tlog-upload="$tlog" \
  -a "repo=$IMAGE_SOURCE_REPO" -a "commit=$commit" -a "branch=$branch" \
  "$repo@$digest"
echo "publish: signed $repo@$digest"
printf 'digest=%s\n' "$digest" >>"${GITHUB_OUTPUT:-/dev/null}"
