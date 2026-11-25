#!/usr/bin/env bash
# Pull the published Bridge (or analyzer) image instead of building it, and
# only if it is signed with this branch's key for this repository and branch:
# keys/cosign-main.pub on main (main has its own key), keys/cosign.pub
# everywhere else.
#
#   scripts/pull-image.sh bridge      # -> proton-bridge:local and :<version>
#   scripts/pull-image.sh analyzer [--allow-other-commit]
#                                     # -> proton-analyzer:local
#
# Exit codes:
#   0  pulled, signature verified, pins checked, smoke-tested (bridge), tagged
#   4  no published image to use here (not signed in to the registry, nothing
#      published for this version, no public key for this branch yet): build
#      locally.
#      A correctly signed image built for other pins or another commit (the
#      channel tag hasn't caught up yet) is also 4.
#   1  a bad or missing signature, or a failed smoke test: it stops, and does
#      not fall back to building, so a person can look at it.
#
# Which image: first the one built from exactly this checkout's commit
# (:<branch>-<commit12>), else this branch's channel (:preview or :latest).
# The signature must carry repo=<IMAGE_SOURCE_REPO> and branch=<this branch>,
# and for the commit tag also commit=<this commit>, so a retagged image from
# the other channel, or one the same key signed for another project, fails.
# Bridge: its version and source commit must match bridge-version.env.
# Analyzer: it must be built from this checkout's commit or from an identical
# analyzer/ folder (same git tree hash), unless --allow-other-commit. Either way it is pulled by the digest the signature
# covers, never by tag, and smoke-tested before it is tagged :local.
#
# The images are private for now, so the host needs a registry login once:
#   docker login ghcr.io -u <github user>     (a token with read:packages)
# The verification runs cosign from the pinned image in images.env, with
# read-only access to that login.
set -euo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.."
root=$PWD

say() { printf 'pull: %s\n' "$*" >&2; }
skip() { say "$*"; exit 4; }
die() { say "$*"; exit 1; }

what=${1:-} allow_other=false
case $what in bridge|analyzer) ;; *) echo "usage: $0 bridge|analyzer [--allow-other-commit]" >&2; exit 2 ;; esac
[[ ${2:-} == --allow-other-commit ]] && allow_other=true

# shellcheck source=/dev/null
source images.env
# shellcheck source=/dev/null
source bridge-version.env
IMAGE=${IMAGE:-proton-bridge}
ANALYZER_IMAGE=${ANALYZER_IMAGE:-proton-analyzer}

if [[ $what == bridge ]]; then repo=$IMAGE_REGISTRY/$BRIDGE_IMAGE_NAME; else repo=$IMAGE_REGISTRY/$ANALYZER_IMAGE_NAME; fi

commit=$(git rev-parse HEAD 2>/dev/null || true)
[[ $commit =~ ^[0-9a-f]{40}$ ]] || skip "this folder is not a git checkout, so there is no commit to match an image to"
# main hosts take only main's builds; anything else follows preview.
# Each has its own key: main images are signed only with keys/cosign-main.pub.
signed_branch=preview channel=preview pubkey=keys/cosign.pub
[[ $(git rev-parse --abbrev-ref HEAD 2>/dev/null) == main ]] \
  && signed_branch=main channel=latest pubkey=keys/cosign-main.pub
[[ -s $pubkey ]] || skip "no $pubkey in this checkout yet, so there is nothing to verify against"
[[ -n ${IMAGE_SOURCE_REPO:-} ]] || die "images.env has no IMAGE_SOURCE_REPO"
commit_tag=$signed_branch-${commit:0:12}
candidates=("$commit_tag" "$channel")

cfg=${DOCKER_CONFIG:-$HOME/.docker}
if ! { [[ -f $cfg/config.json ]] && grep -q "\"${IMAGE_REGISTRY%%/*}\"" "$cfg/config.json"; }; then
  skip "not signed in to ${IMAGE_REGISTRY%%/*}. Run docker login ${IMAGE_REGISTRY%%/*} -u <github user> with a classic token that has read:packages (https://github.com/settings/tokens/new?scopes=read:packages)."
fi
if grep -q '"credsStore"\|"credHelpers"' "$cfg/config.json"; then
  say "note: Docker keeps this login in a credential helper, which the verifier can't read; if verification can't reach the registry, log in again without the helper"
fi

tlog_flag=--insecure-ignore-tlog=true
[[ ${COSIGN_TLOG:-false} == true ]] && tlog_flag=--insecure-ignore-tlog=false

# cosign verify TAG -> prints the signed digest, or fails. The signature must
# carry repo= and branch=<signed_branch>, and for the commit tag commit=<this commit>.
# COSIGN_BIN runs a local cosign instead of the pinned image (tests only).
verify() {
  local out want=(-a "repo=$IMAGE_SOURCE_REPO" -a "branch=$signed_branch")
  [[ $1 == "$repo:$commit_tag" ]] && want+=(-a "commit=$commit")
  if [[ -n ${COSIGN_BIN:-} ]]; then
    out=$(DOCKER_CONFIG=$cfg "$COSIGN_BIN" verify --key "$root/$pubkey" "${want[@]}" "$tlog_flag" --output json "$1" 2>"$work/verify.err") || return 1
  else
    out=$(docker run --rm --user "$(id -u):$(id -g)" -e DOCKER_CONFIG=/cfg -e HOME=/tmp \
            -v "$cfg:/cfg:ro" -v "$root/$pubkey:/cosign.pub:ro" \
            "$COSIGN_IMAGE" verify --key /cosign.pub "${want[@]}" "$tlog_flag" --output json "$1" 2>"$work/verify.err") || return 1
  fi
  sed -n 's/.*"docker-manifest-digest": *"\(sha256:[0-9a-f]\{64\}\)".*/\1/p' <<<"$out" | head -n1
}

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

ref="" digest=""
for t in "${candidates[@]}"; do
  if ! docker buildx imagetools inspect "$repo:$t" >/dev/null 2>"$work/inspect.err" \
     && ! docker manifest inspect "$repo:$t" >/dev/null 2>>"$work/inspect.err"; then
    continue   # not published (or no access); try the next tag
  fi
  if digest=$(verify "$repo:$t") && [[ -n $digest ]]; then ref=$repo:$t; break; fi
  cat "$work/verify.err" >&2
  die "Not using it: $repo:$t is published but not signed for $signed_branch$([[ $t == "$commit_tag" ]] && echo " at commit ${commit:0:12}") by $pubkey. Someone may have tampered with it, or the signing key changed. Nothing was installed. To carry on without it, build locally: ./bridgekeep setup --build."
done
if [[ -z $ref ]]; then
  if grep -qi 'denied\|unauthorized' "$work/inspect.err"; then
    skip "the registry refused access to $repo. The login needs a classic token with read:packages (https://github.com/settings/tokens/new?scopes=read:packages); run docker login ${IMAGE_REGISTRY%%/*} again with one."
  fi
  skip "no published image for this checkout (${candidates[*]})"
fi

say "verified $ref ($digest); pulling it"
docker pull -q "$repo@$digest" >/dev/null || die "pull of $repo@$digest failed"

label() { docker image inspect -f "{{index .Config.Labels \"$1\"}}" "$repo@$digest"; }
if [[ $what == bridge ]]; then
  # Correctly signed but for other pins: usually the channel tag hasn't caught
  # up with this commit yet. Not tampering, so build locally (exit 4).
  [[ $(label org.opencontainers.image.version) == "$BRIDGE_VERSION" ]] \
    || skip "the published image is Bridge $(label org.opencontainers.image.version), but this checkout pins $BRIDGE_VERSION; building locally instead"
  [[ $(label io.bridgekeep.bridge-commit) == "$BRIDGE_SOURCE_COMMIT" ]] \
    || skip "the published image was built from Bridge commit $(label io.bridgekeep.bridge-commit), not the pinned ${BRIDGE_SOURCE_COMMIT:0:12}; building locally instead"
  docker tag "$repo@$digest" "$IMAGE:pulled"
  IMAGE=$IMAGE:pulled bash tests/smoke.sh >"$work/smoke.log" 2>&1 \
    || { tail -n 20 "$work/smoke.log" >&2; docker image rm "$IMAGE:pulled" >/dev/null 2>&1 || true; die "the pulled image failed the smoke test"; }
  docker tag "$repo@$digest" "$IMAGE:$BRIDGE_VERSION"
  docker tag "$repo@$digest" "$IMAGE:local"
  docker image rm "$IMAGE:pulled" >/dev/null 2>&1 || true
  say "ready: $IMAGE:local is Bridge $BRIDGE_VERSION from $ref"
else
  # The analyzer is published only when analyzer/ changes, so the channel
  # image is usually from an older commit: fine if analyzer/ is identical.
  rev=$(label org.opencontainers.image.revision)
  tree=$(git rev-parse HEAD:analyzer 2>/dev/null || true)
  img_tree=$(label io.bridgekeep.analyzer-tree)
  if [[ $rev != "$commit" ]] && ! { [[ -n $tree && $img_tree == "$tree" ]]; } && ! $allow_other; then
    skip "the published analyzer image was built from different analyzer code (${rev:0:12}) than this checkout's ${commit:0:12}; building locally instead (scripts/pull-image.sh analyzer --allow-other-commit uses it anyway)"
  fi
  # The same checks as make analyzer-smoke: offline, read-only, unprivileged.
  if ! { docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true \
           --user "$(id -u):$(id -g)" -v "$root/analyzer/tests/fixtures:/mail:ro" \
           "$repo@$digest" check --no-model --db :memory: /mail \
         && docker run --rm --network none --read-only --cap-drop ALL "$repo@$digest" config; } >"$work/smoke.log" 2>&1; then
    tail -n 20 "$work/smoke.log" >&2
    die "the pulled analyzer image failed its smoke test"
  fi
  docker tag "$repo@$digest" "$ANALYZER_IMAGE:local"
  say "ready: $ANALYZER_IMAGE:local from $ref"
fi
printf '%s@%s\n' "$repo" "$digest"
