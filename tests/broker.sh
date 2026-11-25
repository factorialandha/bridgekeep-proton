#!/usr/bin/env bash
# shellcheck disable=SC2015  # "check && ok || bad": ok only prints
# Tests the sign-in broker (broker/) against the stand-in for Bridge's CLI
# (tests/signin/mock_bridge.go) and a stand-in daemon. No Proton account.
#
#   tests/broker.sh          # needs go and curl; CI runs it in the golang image
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
work=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; rm -rf -- "$work"' EXIT
(cd tests/signin && go build -buildvcs=false -o "$work/mockbridge" .) || exit 1
(cd broker && go vet ./... && go build -buildvcs=false -o "$work/broker" .) || exit 1

# Bridge stand-in: --cli is the mock CLI; anything else is the daemon, which
# just waits (and says so in a file, so we can see it stop and start).
cat >"$work/bridge" <<EOF
#!/usr/bin/env bash
for a in "\$@"; do [[ \$a == --cli ]] && exec "$work/mockbridge"; done
echo up >>"$work/daemon.log"
trap 'echo down >>"$work/daemon.log"; exit 0' TERM
while :; do sleep 0.2; done
EOF
chmod +x "$work/bridge"

fails=0
ok() { echo "ok: $*"; }
bad() { echo "FAIL: $*"; fails=$((fails + 1)); }
sock=$work/run/broker.sock
api() { # METHOD PATH [JSON] -> body; HTTP code in $work/code
  curl -s -o "$work/body" -w '%{http_code}' --unix-socket "$sock" -X "$1" \
    -H 'Content-Type: application/json' ${3:+--data "$3"} "http://broker$2" >"$work/code"
  cat "$work/body"
}
code() { cat "$work/code"; }
state() { api GET /status | sed -n 's/.*"state":"\([a-z_0-9]*\)".*/\1/p'; }
wait_state() { # WANT [SECONDS]
  local i
  for ((i = 0; i < ${2:-20} * 10; i++)); do [[ $(state) == "$1" ]] && return 0; sleep 0.1; done
  return 1
}
start() { # ENV=... for the mock
  rm -rf -- "$work/run" "$work/cred" "$work/daemon.log"; mkdir -p "$work/run" "$work/cred"
  env "$@" BRIDGE_BIN="$work/bridge" BROKER_SOCKET="$sock" BROKER_CRED_DIR="$work/cred" \
    BROKER_PEER_UIDS="$(id -u)" "$work/broker" 2>>"$work/broker.log" &
  bpid=$!
  for _ in $(seq 50); do [[ -S $sock ]] && break; sleep 0.1; done
}
stop() { kill "$bpid" 2>/dev/null; wait "$bpid" 2>/dev/null; }

# 1. Plain sign-in.
start
[[ $(state) == signed_out ]] && ok "starts signed out" || bad "start state $(state)"
[[ $(stat -c %a "$sock") == 660 ]] && ok "socket is 0660" || bad "socket mode $(stat -c %a "$sock")"
api POST /login '{"username":"me@proton.me","password":"pw"}' >/dev/null
[[ $(code) == 200 ]] || bad "login answered $(code)"
if wait_state signed_in; then ok "sign in, no 2FA"; else bad "sign in: $(api GET /status)"; fi
[[ $(cat "$work/cred/bridge_password" 2>/dev/null) == GEN-pw_123 ]] && ok "Bridge password saved" || bad "credential not saved"
[[ $(stat -c %a "$work/cred/bridge_password") == 440 ]] && ok "credential is 0440" || bad "credential mode"
[[ $(grep -c up "$work/daemon.log") == 2 && $(grep -c down "$work/daemon.log") == 1 ]] \
  && ok "daemon stopped for the CLI and started again" || bad "daemon log: $(tr '\n' ' ' <"$work/daemon.log")"
api GET /status | grep -q 'GEN-pw' && bad "status leaks the Bridge password" || ok "status never shows the Bridge password"
grep -q 'GEN-pw\|"pw"' "$work/broker.log" && bad "log leaks a password" || ok "log holds no password"

# 2. Sign out (the stand-in forgets between runs, so start it signed in).
stop; rm -rf -- "$work/run" "$work/daemon.log"; mkdir -p "$work/run"
env MOCK_SIGNEDIN=1 BRIDGE_BIN="$work/bridge" BROKER_SOCKET="$sock" BROKER_CRED_DIR="$work/cred" \
  BROKER_PEER_UIDS="$(id -u)" "$work/broker" 2>>"$work/broker.log" &
bpid=$!
for _ in $(seq 50); do [[ -S $sock ]] && break; sleep 0.1; done
[[ $(state) == signed_in ]] && ok "starts signed in when it holds a credential" || bad "resting state $(state)"
api POST /logout '{}' >/dev/null
if wait_state signed_out; then ok "sign out"; else bad "sign out: $(api GET /status)"; fi
[[ ! -e $work/cred/bridge_password ]] && ok "credential removed on sign out" || bad "credential kept"
stop

# 3. 2FA, with a wrong code first.
start MOCK_2FA=1
api POST /login '{"username":"me@proton.me","password":"pw"}' >/dev/null
wait_state waiting_2fa && ok "asks for 2FA" || bad "no 2FA state: $(api GET /status)"
api GET /status | grep -q '"step_expires":[0-9]' && ok "step has an expiry" || bad "no step_expires"
api POST /2fa '{"code":"12345a"}' >/dev/null; [[ $(code) == 400 ]] && ok "bad code format: 400" || bad "bad code format: $(code)"
api POST /mailbox-password '{"password":"x"}' >/dev/null; [[ $(code) == 409 ]] && ok "wrong step: 409" || bad "wrong step: $(code)"
api POST /2fa '{"code":"999999"}' >/dev/null
wait_state signed_out && api GET /status | grep -q '2FA code' && ok "wrong code: back to signed out, with the reason" || bad "wrong code: $(api GET /status)"
api POST /login '{"username":"me@proton.me","password":"pw"}' >/dev/null
wait_state waiting_2fa
api POST /2fa '{"code":"123456"}' >/dev/null
wait_state signed_in && ok "right code: signed in" || bad "2FA sign-in: $(api GET /status)"
stop

# 4. Mailbox password, human verification, cancel.
start MOCK_MBOX=1
api POST /login '{"username":"me@proton.me","password":"pw"}' >/dev/null
wait_state waiting_mailbox_password && api POST /mailbox-password '{"password":"mb"}' >/dev/null
wait_state signed_in && ok "mailbox password" || bad "mailbox password: $(api GET /status)"
stop
start MOCK_HV=1
api POST /login '{"username":"me@proton.me","password":"pw"}' >/dev/null
wait_state waiting_human && api GET /status | grep -q '"hv_url":"https://verify.proton.me/' && ok "human verification link" || bad "hv: $(api GET /status)"
api POST /human-verification '{}' >/dev/null
wait_state signed_in && ok "after human verification: signed in" || bad "hv sign-in: $(api GET /status)"
stop
start MOCK_2FA=1
api POST /login '{"username":"me@proton.me","password":"pw"}' >/dev/null
wait_state waiting_2fa && api POST /cancel '{}' >/dev/null
wait_state signed_out && ok "cancel" || bad "cancel: $(api GET /status)"
[[ $(tail -n1 "$work/daemon.log") == up ]] && ok "daemon back after cancel" || bad "daemon not back after cancel"

# 5. Input checks and limits.
api POST /login '{"username":"me@proton.me","password":"p\nw"}' >/dev/null; [[ $(code) == 400 ]] && ok "control character: 400" || bad "control char: $(code)"
api POST /login '{"username":"me@proton.me"}' >/dev/null; [[ $(code) == 400 ]] && ok "missing field: 400" || bad "missing field: $(code)"
api POST /login "{\"username\":\"$(head -c 5000 /dev/zero | tr '\0' a)\"}" >/dev/null; [[ $(code) == 413 ]] && ok "big body: 413" || bad "big body: $(code)"
api GET /login >/dev/null; [[ $(code) == 405 ]] && ok "wrong method: 405" || bad "wrong method: $(code)"
for _ in 1 2 3 4 5; do
  api POST /login '{"username":"me@proton.me","password":"wrong"}' >/dev/null
  wait_state signed_out 10
done
api POST /login '{"username":"me@proton.me","password":"pw"}' >/dev/null
[[ $(code) == 429 ]] && grep -q . "$work/body" && ok "sixth sign-in in 15 minutes: 429" || bad "rate limit: $(code)"
api GET /status | grep -q 'address and password' && ok "wrong password explained" || bad "wrong password: $(api GET /status)"
stop

# 6. Peer check: only the listed UIDs.
start
kill "$bpid"; wait "$bpid" 2>/dev/null
env BRIDGE_BIN="$work/bridge" BROKER_SOCKET="$sock" BROKER_CRED_DIR="$work/cred" BROKER_PEER_UIDS=99999 \
  "$work/broker" 2>>"$work/broker.log" &
bpid=$!
for _ in $(seq 50); do [[ -S $sock ]] && break; sleep 0.1; done
api GET /status >/dev/null; [[ $(code) == 403 ]] && ok "other UID: 403" || bad "peer check: $(code)"
stop

# 7. The daemon dying on its own takes the broker down (the container restarts).
start
pkill -f "$work/bridge" ; sleep 1
kill -0 "$bpid" 2>/dev/null && bad "broker kept running without Bridge" || ok "Bridge exiting stops the broker"

if ((fails)); then echo "$fails broker test(s) failed"; exit 1; fi
echo "broker tests passed"
