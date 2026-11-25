#!/usr/bin/env bash
# Give the sign-in broker's two volumes the owner and mode the image expects.
#
#   scripts/fix-volumes.sh [IMAGE]   # default: the Bridge image, :local
#
# Docker fills a new named volume from the first container that mounts it.
# When that container's image has no such folder (an image from before the
# broker, or the portal starting first), the volume's root is root:root 0755
# and the broker, which runs as the bridge user, can't use it. Bridge then
# runs without the broker and portal sign-in is unavailable. This sets
#   broker-sock        2750 bridge:10010   (the portal can connect, not write)
#   bridge-credential  2750 bridge:10011   (imap-proxy reads, nobody else)
# from a throwaway root container with no network. Volumes that don't exist
# yet are left for the image to create. Run by setup and before a Bridge
# update is swapped in; safe to run any time.
set -euo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.." || exit 1
project=$(sed -n 's/^name: *//p' compose.yaml)
image=${1:-${IMAGE:-proton-bridge}:local}
BRIDGE_UID=10001 BROKER_GID=10010 CRED_GID=10011

args=() script=""
for spec in "broker-sock:/s:$BROKER_GID" "bridge-credential:/c:$CRED_GID"; do
  IFS=: read -r vol dir gid <<<"$spec"
  docker volume inspect "${project}_$vol" >/dev/null 2>&1 || continue
  args+=(-v "${project}_$vol:$dir")
  script+="[ \"\$(stat -c %u:%g:%a $dir)\" = $BRIDGE_UID:$gid:2750 ] || { chown $BRIDGE_UID:$gid $dir && chmod 2750 $dir && echo \"fixed $vol\"; }; "
done
((${#args[@]})) || exit 0
docker image inspect "$image" >/dev/null 2>&1 || { echo "fix-volumes: no image $image yet; skipped" >&2; exit 0; }
docker run --rm --network none --user 0:0 --cap-drop ALL --cap-add CHOWN --cap-add FOWNER --cap-add FSETID \
  --security-opt no-new-privileges:true --log-driver none --entrypoint /bin/sh \
  "${args[@]}" "$image" -c "$script"
