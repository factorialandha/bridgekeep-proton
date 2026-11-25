#!/usr/bin/env bash
# Tests scripts/bridge-signin.sh against a stand-in for Bridge's CLI
# (tests/signin/mock_bridge.go: the same ishell/readline versions Bridge
# 3.27 pins, and Bridge's exact prompt strings). No Proton account needed.
#
#   tests/signin.sh          # needs go and `script` (util-linux); CI runs it
#                            # in the pinned golang image
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
# -buildvcs=false: CI mounts the checkout under another owner, and git then
# refuses to read it ("dubious ownership"); the stand-in needs no VCS stamp.
(cd tests/signin && go build -buildvcs=false -o "$work/mockbridge" .)

export BRIDGE_CLI_CMD=$work/mockbridge BRIDGEKEEP_SECRETS=$work/sec
fails=0

# check NAME MODE "typed input" WANT_RC WANT_PASSWORD [ENV=1 ...]
check() {
  local name=$1 mode=$2 input=$3 want_rc=$4 want_pw=$5 rc got
  shift 5
  rm -rf -- "$work/sec"
  set +e
  printf '%b' "$input" | env "$@" script -qec "bash scripts/bridge-signin.sh $mode" /dev/null >"$work/out" 2>&1
  rc=$?
  set -e
  got=$(cat "$work/sec/bridge_password" 2>/dev/null || true)
  if [[ $mode == show ]]; then got=$(sed -n 's/^Password: //p' "$work/out" | tr -d '\r'); fi
  if [[ $rc == "$want_rc" && $got == "$want_pw" ]]; then
    echo "ok: $name"
  else
    echo "FAIL: $name (exit $rc, want $want_rc; password '${got}', want '${want_pw}')"
    sed 's/^/    /' "$work/out"
    fails=$((fails + 1))
  fi
}

pw=GEN-pw_123
check "sign in, no 2FA"                login 'me@proton.me\npw\n'              0 "$pw" X=1
check "sign in with 2FA"               login 'me@proton.me\npw\n123456\n'      0 "$pw" MOCK_2FA=1
# Self-update and telemetry were turned off after that sign-in.
if grep -q 'autoupdate=false telemetry=false' .bridgekeep/logs/signin.log; then
  echo "ok: self-update and telemetry turned off"
else
  echo "FAIL: self-update/telemetry not turned off"; fails=$((fails + 1))
fi
check "2FA and mailbox password"       login 'me@proton.me\npw\n123456\nmb\n'  0 "$pw" MOCK_2FA=1 MOCK_MBOX=1
check "human verification, then 2FA"   login 'me@proton.me\npw\n\n123456\n'    0 "$pw" MOCK_HV=1 MOCK_2FA=1
check "security key offered, use code" login 'me@proton.me\npw\n123456\n'      0 "$pw" MOCK_FIDOTOTP=1
check "wrong password"                 login 'me@proton.me\nnope\n'            1 ""    X=1
check "wrong 2FA code"                 login 'me@proton.me\npw\n000000\n'      1 ""    MOCK_2FA=1
check "capture, signed in"             capture ''                              0 "$pw" MOCK_SIGNEDIN=1
check "capture, account still loading"  capture ''                              0 "$pw" MOCK_SIGNEDIN=1 MOCK_LOCKED=2 SIGNIN_LOCKED_RETRY=0
check "capture, locked too long"       capture ''                              1 ""    MOCK_SIGNEDIN=1 MOCK_LOCKED=99 SIGNIN_LOCKED_RETRY=1 SIGNIN_LOCKED_WAIT=2
check "capture, no account"            capture ''                              3 ""    X=1
check "show, nothing saved"            show ''                                 0 "$pw" MOCK_SIGNEDIN=1
[[ ! -e $work/sec/bridge_password ]] || { echo "FAIL: show wrote a file"; fails=$((fails + 1)); }
# Secret files: 0400 and owned by 10002 as root, else 0600 and this user's.
want_mode=600 want_owner=$(id -u)
[[ $(id -u) == 0 ]] && want_mode=400 want_owner=10002
check "file modes after sign-in"       login 'me@proton.me\npw\n'              0 "$pw" X=1
if [[ $(stat -c '%a %u' "$work/sec/bridge_password") == "$want_mode $want_owner" && $(stat -c %a "$work/sec") == 700 ]]; then
  echo "ok: secret saved as $want_mode, owner $want_owner, folder 700"
else
  echo "FAIL: secret is $(stat -c '%a %u' "$work/sec/bridge_password"), folder $(stat -c %a "$work/sec"); want $want_mode $want_owner, 700"; fails=$((fails + 1))
fi
if [[ $(stat -c %a .bridgekeep/logs/signin.log) == 600 && $(stat -c %a .bridgekeep/logs) == 700 ]]; then
  echo "ok: sign-in log is private"
else
  echo "FAIL: sign-in log or folder is readable by others"; fails=$((fails + 1))
fi

# Secrets inside the checkout are refused, even in a folder this user owns.
# (A name of our own, so a developer's real folder is never touched.)
tsec=.signin-test-secrets-$$
for inside in "$PWD/$tsec" "./$tsec" .; do
  set +e
  printf 'me@proton.me\npw\n' | env BRIDGEKEEP_SECRETS="$inside" X=1 script -qec "bash scripts/bridge-signin.sh login" /dev/null >"$work/out" 2>&1
  rc=$?
  set -e
  if [[ $rc == 1 && ! -e $tsec && ! -e bridge_password ]] && grep -q 'Secrets must live outside the checkout' "$work/out"; then
    echo "ok: refused secrets inside the checkout ($inside)"
  else
    echo "FAIL: secrets inside the checkout ($inside) not refused (exit $rc)"; sed 's/^/    /' "$work/out"; fails=$((fails + 1))
  fi
done
# A symlink outside that points back into the checkout is refused too.
ln -s "$PWD" "$work/link"
set +e
printf '' | env BRIDGEKEEP_SECRETS="$work/link/$tsec" script -qec "bash scripts/bridge-signin.sh login" /dev/null >"$work/out" 2>&1
rc=$?
set -e
if [[ $rc == 1 && ! -e $tsec ]]; then echo "ok: refused a symlink into the checkout"; else echo "FAIL: symlink into the checkout not refused (exit $rc)"; fails=$((fails + 1)); fi

if (( fails > 0 )); then echo "$fails signin test(s) failed"; exit 1; fi
echo "signin tests passed"
