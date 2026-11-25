#!/usr/bin/env bash
# Smoke test for a built image, no Proton account needed.
#
# Checks: runs as non-root on a read-only root filesystem with all capabilities
# dropped; first-run keychain init works and survives a restart; Bridge starts,
# stays up and stores its vault key in the pass keychain; a second container
# on a private network can reach the IMAP and SMTP forwarders (SMTP is
# enabled here; it is off by default).
#
# Without a logged-in account Bridge does not open its IMAP/SMTP listeners,
# so this cannot check protocol greetings or the healthcheck. It prints a
# greeting if one arrives. Full end-to-end checks need a real login.
set -euo pipefail
export MSYS_NO_PATHCONV=1   # Git Bash: do not rewrite /paths in docker arguments

IMAGE=${IMAGE:-proton-bridge:local}
id=smoke-$$-$RANDOM
net=$id-net
vol=$id-data
ctr=$id-bridge

cleanup() {
  docker rm -f "$ctr" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  docker volume rm "$vol" >/dev/null 2>&1 || true
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; docker logs "$ctr" 2>&1 | tail -n 50 >&2 || true; exit 1; }
pass() { echo "ok: $*"; }

docker network create "$net" >/dev/null
docker volume create "$vol" >/dev/null

# shellcheck disable=SC2054  # commas are part of the --tmpfs option
hardening=(--read-only --tmpfs /tmp:size=64m,mode=1777 --cap-drop ALL --security-opt no-new-privileges:true)

# 1. Non-root, and refuses to start without a login.
uid=$(docker run --rm "${hardening[@]}" -v "$vol:/home/bridge" --entrypoint id "$IMAGE" -u)
[[ $uid != 0 ]] || fail "container runs as root"
pass "runs as uid $uid"

if docker run --rm "${hardening[@]}" -v "$vol:/home/bridge" "$IMAGE" run >/dev/null 2>&1; then
  fail "run started without a completed login"
fi
pass "run refuses to start before init"

# 2. Keychain persists across containers.
gpgid1=$(docker run --rm "${hardening[@]}" -v "$vol:/home/bridge" --entrypoint bash "$IMAGE" \
  -c 'entrypoint keychain-init && cat ~/.password-store/.gpg-id')
gpgid2=$(docker run --rm "${hardening[@]}" -v "$vol:/home/bridge" --entrypoint bash "$IMAGE" \
  -c 'entrypoint keychain-init && cat ~/.password-store/.gpg-id')
[[ -n $gpgid1 && $gpgid1 == "$gpgid2" ]] || fail "keychain changed between runs ($gpgid1 vs $gpgid2)"
docker run --rm "${hardening[@]}" -v "$vol:/home/bridge" --entrypoint bash "$IMAGE" \
  -c 'echo s3cret | pass insert -e smoke/test >/dev/null && [ "$(pass show smoke/test)" = s3cret ] && pass rm -f smoke/test >/dev/null' \
  || fail "pass store cannot round-trip a secret"
pass "keychain created once and reused ($gpgid1)"

# 3. Bridge up, forwarded to a second container over the private network.
docker run -d --name "$ctr" --network "$net" --network-alias bridge \
  "${hardening[@]}" -v "$vol:/home/bridge" -e BRIDGE_REQUIRE_INIT=false -e FORWARD_SMTP=true "$IMAGE" >/dev/null

running() { [[ $(docker inspect -f '{{.State.Running}}' "$ctr" 2>/dev/null) == true ]]; }

# Bridge creates its vault and puts the vault key into the keychain on start.
ok=false
for _ in $(seq 1 40); do
  running || fail "bridge container exited"
  if docker exec "$ctr" bash -c 'test -f ~/.config/protonmail/bridge-v3/vault.enc &&
       find ~/.password-store -name "*.gpg" -type f | grep -q .' 2>/dev/null; then
    ok=true; break
  fi
  sleep 3
done
$ok || fail "Bridge did not create its vault and store the vault key in pass"
pass "Bridge created its vault; vault key stored in the pass keychain"

sleep 15
running || fail "bridge container exited after start-up"
pass "Bridge still running after start-up"

reach() { # port: TCP connect from a second container on the private network
  docker run --rm --network "$net" --entrypoint bash "$IMAGE" -c \
    "exec 3<>/dev/tcp/bridge/$1 && (timeout 5 head -n1 <&3 || true)" | tr -d '\r'
}
for p in 1143 1025; do
  if out=$(reach "$p"); then
    pass "forwarder on bridge:$p reachable from a second container${out:+ (greeting: $out)}"
  else
    fail "cannot connect to bridge:$p from a second container"
  fi
done

docker exec "$ctr" bash -c 'touch /usr/local/bin/x' 2>/dev/null && fail "root filesystem is writable"
pass "root filesystem read-only"

# 4. Unknown commands are refused (no arbitrary-command passthrough).
docker run --rm "${hardening[@]}" -v "$vol:/home/bridge" "$IMAGE" bash -c true >/dev/null 2>&1 \
  && fail "entrypoint ran an arbitrary command"
pass "entrypoint refuses unknown commands"

echo "smoke test passed"
