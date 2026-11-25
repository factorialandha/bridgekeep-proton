#!/usr/bin/env bash
# Sign in to Proton through Bridge's CLI, and capture the IMAP/SMTP
# credentials Bridge generates, without anyone typing CLI commands.
#
#   scripts/bridge-signin.sh capture   # already signed in: save the credentials
#   scripts/bridge-signin.sh login     # sign in (asks address, password, 2FA),
#                                      # then save the credentials
#   scripts/bridge-signin.sh show      # print the credentials once (nothing saved)
#
# Exit codes: 0 done; 3 no signed-in account (capture/show); 1 anything else.
#
# How it works. Bridge's CLI reads plain lines from stdin and doesn't need a
# terminal. This script runs it as a coprocess, watches what it prints, and
# answers each prompt as it appears: the address and password you typed at
# the start, then the 2FA code (asked only if Bridge wants one, so it's
# fresh), the mailbox password (only for two-password accounts), and "no" to
# the security-key question (a key can't reach the container). Human
# verification shows the link and waits for Enter. After "added
# successfully" it turns off Bridge's self-update and telemetry, runs
# `info`, takes the first Username/Password pair, and sends `exit`.
#
# Secrets: nothing goes into arguments, environment variables or logs. The
# CLI container is bridge-init (log driver none). Your Proton password is
# held only in this shell's memory and written only to the CLI's stdin. The
# Bridge password is written to $BRIDGEKEEP_SECRETS/bridge_password (default
# /etc/bridgekeep/secrets, a root-owned 0700 folder outside the checkout),
# mode 0400 and owned by the analyzer's UID 10002; sudo is used when not root.
# Bridge's own stderr (its log lines, no passwords) goes to
# .bridgekeep/logs/signin.log, mode 600, overwritten on each run.
#
# Bridge's service must not be running (it holds the login); this script
# stops `bridge` first and starts it again afterwards if it was running.
#
# BRIDGE_CLI_CMD overrides the CLI command (tests use a stand-in).
set -euo pipefail
export MSYS_NO_PATHCONV=1

cd "$(dirname "$0")/.."
mode=${1:-}
case $mode in capture|login|show) ;; *) echo "usage: $0 capture|login|show" >&2; exit 2 ;; esac

sec=${BRIDGEKEEP_SECRETS:-}
if [[ -z $sec && -f .env ]]; then sec=$(sed -n 's/^BRIDGEKEEP_SECRETS=//p' .env | tail -n1); fi
sec=${sec:-/etc/bridgekeep/secrets}   # outside the checkout, root-only
# Secrets never go inside the checkout, whoever owns the folder: a relative
# path, a symlink or ../ tricks are resolved first.
top=$(pwd -P)
gtop=$(git rev-parse --show-toplevel 2>/dev/null || true)
sec_real=$(realpath -m -- "$sec")
for t in "$top" ${gtop:+"$(realpath -m -- "$gtop")"}; do
  if [[ $sec_real == "$t" || $sec_real == "$t"/* ]]; then
    printf 'Secrets must live outside the checkout: %s is inside %s. Set BRIDGEKEEP_SECRETS to a folder elsewhere (default /etc/bridgekeep/secrets).\n' "$sec" "$t" >&2
    exit 1
  fi
done
logdir=.bridgekeep/logs
(umask 077 && mkdir -p "$logdir")
chmod 700 .bridgekeep "$logdir" 2>/dev/null || true
# One sign-in's worth of Bridge log at a time, readable only by this user.
(umask 077 && : >"$logdir/signin.log")
chmod 600 "$logdir/signin.log"
TIMEOUT=${SIGNIN_TIMEOUT:-300}   # seconds to wait for Bridge between prompts
LOCKED_WAIT=${SIGNIN_LOCKED_WAIT:-300}   # how long `info` may say "currently locked"
LOCKED_RETRY=${SIGNIN_LOCKED_RETRY:-5}   # seconds between tries
locked_said=0 started=$SECONDS
cli_cmd=${BRIDGE_CLI_CMD:-docker compose run --rm -T --no-deps bridge-init cli}

say() { printf '%s\n' "$*" >&2; }
tty_in() { # VAR PROMPT [s]: read a line from the person; s = don't echo it
  local __reply=""
  if [[ -n ${3:-} ]]; then
    IFS= read -r -s -p "$2" __reply </dev/tty || true; printf '\n' >/dev/tty
  else
    IFS= read -r -p "$2" __reply </dev/tty || true
  fi
  printf -v "$1" '%s' "$__reply"
}

# --- stop the service while the CLI runs ------------------------------------
was_running=false
if [[ -z ${BRIDGE_CLI_CMD:-} ]] && docker compose ps -q bridge 2>/dev/null | grep -q .; then
  was_running=true
  docker compose stop bridge >/dev/null 2>&1
fi
cleanup() {
  [[ -n ${bpid:-} ]] && kill "$bpid" 2>/dev/null || true
  $was_running && docker compose up -d bridge >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- ask for the sign-in details up front ----------------------------------
user="" pass=""
if [[ $mode == login ]]; then
  [[ -r /dev/tty ]] || { say "Signing in needs a terminal (your 2FA code is asked for)."; exit 1; }
  while [[ -z $user ]]; do tty_in user "Proton address: "; done
  while [[ -z $pass ]]; do tty_in pass "Proton password (not shown): " s; done
fi

# --- run the CLI and talk to it ---------------------------------------------
# shellcheck disable=SC2086  # cli_cmd is a command line
coproc BRIDGE { exec $cli_cmd 2>>"$logdir/signin.log"; }
bpid=$BRIDGE_PID
# Own copies of the pipe ends: bash closes BRIDGE[] as soon as the CLI exits.
exec {out}<&"${BRIDGE[0]}" {in}>&"${BRIDGE[1]}"
send() { printf '%s\n' "$1" >&"$in"; }

# phases: login -> settings -> info -> finished
got_user="" got_pass="" fail="" buf=""
if [[ $mode == login ]]; then send login; phase=login; else send info; phase=info; fi

handle_line() { # a full line of CLI output
  local l=${1%$'\r'}
  case $phase in
    login)
      case $l in
        *"was added successfully"*)
          # One at a time: a yes/no question reads the next line we send.
          phase=settings; send "updates autoupdates disable" ;;
        *"Cannot login"*|*"Too many attempts"*)
          fail=${l#*Cannot login: }; fail=${fail#*Cannot login:}; send exit ;;
        http*://*) hv_url=$l ;;
      esac ;;
    settings)
      case $l in
        *"already set to NOT automatically install updates"*) send "telemetry disable" ;;
        *"Usage diagnostics collection is disabled"*) phase=info; send info ;;
      esac ;;
    info)
      case $l in
        *"No active accounts"*|*"Please login to"*) fail=nouser; send exit ;;
        *"is currently locked"*)
          # Bridge is still unlocking or loading the account (a big mailbox
          # right after a start): ask again, for up to LOCKED_WAIT seconds.
          if (( SECONDS - started < LOCKED_WAIT )); then
            if (( locked_said++ % 6 == 0 )); then
              w=$((SECONDS - started)); say "Bridge is still loading your mailbox; waiting… ($((w / 60)):$(printf '%02d' $((w % 60))))"
            fi
            sleep "$LOCKED_RETRY"; send info
          else
            fail="Bridge kept the account locked for $((LOCKED_WAIT / 60)) minutes; try again in a few minutes"; send exit
          fi ;;
        *"Please choose"*) fail="Bridge has more than one account; use the CLI by hand (docker compose run --rm bridge-init cli)"; send exit ;;
        Username:*) [[ -z $got_user ]] && { got_user=${l#Username:}; got_user=${got_user#"${got_user%%[![:space:]]*}"}; } ;;
        Password:*)
          if [[ -z $got_pass ]]; then
            got_pass=${l#Password:}; got_pass=${got_pass#"${got_pass%%[![:space:]]*}"}
            phase=finished; send exit
          fi ;;
      esac ;;
  esac
}

handle_prompt() { # text since the last newline: a prompt waiting for an answer
  local code mbox
  if [[ $phase == settings ]]; then
    case $buf in
      *"stop bridge from doing this? yes/"*": ") send yes; send "telemetry disable" ;;
      *"disable usage diagnostics collection? yes/"*": ") send yes; phase=info; send info ;;
      *) return 1 ;;
    esac
    buf=""; return 0
  fi
  [[ $phase == login ]] || return 1
  case $buf in
    *"Username: ") send "$user" ;;
    *"Password: ") send "$pass" ;;
    *"Two factor code: ")
      tty_in code "2FA code from your authenticator app: "
      send "$code" ;;
    *"Mailbox password: ")
      tty_in mbox "Mailbox password (your account has a second password; not shown): " s
      send "$mbox"; mbox="" ;;
    *"security key for Two-factor authentication? yes/"*": ")
      send no ;;   # a USB key can't reach the container: use the app code
    *) return 1 ;;
  esac
  buf=""
}

hv_url=""
while :; do
  if ! IFS= read -r -N1 -t "$TIMEOUT" -u "$out" ch; then
    [[ -n $buf ]] && handle_line "$buf"
    break   # EOF (CLI exited) or timeout
  fi
  if [[ $ch == $'\n' ]]; then
    if [[ $buf == *"Human Verification requested"* ]]; then hv_pending=1; fi
    handle_line "$buf"
    if [[ -n ${hv_pending:-} && -n $hv_url ]]; then
      say ""
      say "Proton wants to check you're human. Open this link in a browser, finish the check,"
      say "then press Enter here:"
      say "  $hv_url"
      tty_in _ ""
      send ""; hv_pending="" hv_url=""
    fi
    buf=""
  else
    buf+=$ch
    (( ${#buf} > 4096 )) && buf=${buf: -1024}
    handle_prompt || true
  fi
done
pass=""
exec {in}>&- {out}<&-
wait "$bpid" 2>/dev/null || true
bpid=""

# --- result -------------------------------------------------------------------
if [[ $mode == login && $phase == login ]]; then
  [[ -n $fail ]] || fail="Bridge stopped before it confirmed the sign-in (see $logdir/signin.log)"
  case $fail in
    *[Ss]ecurity\ key*) say "Sign-in failed: this account needs a security key, which can't reach the container. Add an authenticator app to your Proton account (Settings > Account and password > Two-factor authentication)." ;;
    *) say "Sign-in failed: $fail" ;;
  esac
  exit 1
fi
if [[ -n $fail && $fail != nouser ]]; then say "$fail"; exit 1; fi
if [[ $fail == nouser || -z $got_pass ]]; then
  [[ $mode == login ]] && say "Signed in, but Bridge didn't show the credentials (see $logdir/signin.log)."
  exit 3
fi

if [[ $mode == show ]]; then
  printf 'Username: %s\nPassword: %s\n' "$got_user" "$got_pass"
  got_pass=""
  exit 0
fi

# Where we can't be root: a folder this user owns (tests, a development
# checkout pointing BRIDGEKEEP_SECRETS at its own folder) gets 0600 files
# owned by this user. The default /etc/bridgekeep/secrets is never
# user-writable, so a normal install always takes the root path.
if [[ $(id -u) == 0 ]]; then
  as_root() { "$@"; }; owner_mode=root
elif [[ -O $sec || ( ! -e $sec && -O $(dirname "$sec") ) ]]; then
  owner_mode=user
else
  as_root() { sudo "$@"; }; owner_mode=root
fi
if [[ $owner_mode == root ]]; then
  as_root install -d -m 0700 -o 0 -g 0 "$sec" \
    || { say "Could not create $sec (needs root)."; exit 1; }
  put_secret() { # NAME, value on stdin: 0400, owned by the containers' user (10002)
    # shellcheck disable=SC2016
    as_root sh -c 'rm -f -- "$1" && umask 077 && cat >"$1" && chown 10002:10002 "$1" && chmod 0400 "$1"' sh "$sec/$1"
  }
else
  (umask 077 && mkdir -p "$sec") && chmod 700 "$sec"
  put_secret() { rm -f -- "$sec/$1" && (umask 077 && cat >"$sec/$1"); }
  say "note: saved as your own user in $sec (not root); containers can't read it until it's owned by 10002"
fi
printf '%s' "$got_pass" | put_secret bridge_password || { say "Could not save the password in $sec."; exit 1; }
printf '%s' "$got_user" | put_secret bridge_username || { say "Could not save the username in $sec."; exit 1; }
got_pass=""
# A copy saved by an earlier sign-in from the admin portal would win over
# this one (imap-proxy and the checks prefer it): drop it.
if [[ -z ${BRIDGE_CLI_CMD:-} ]]; then
  docker compose run --rm --no-deps -T --entrypoint /bin/rm bridge \
    -f /run/bridge-credential/bridge_password /run/bridge-credential/bridge_username >/dev/null 2>&1 \
    || echo "warning: could not remove the copy from an earlier portal sign-in; if mail stops, sign in again from the portal" >&2
fi
printf '%s\n' "$got_user"   # stdout: the signed-in address, for the caller
