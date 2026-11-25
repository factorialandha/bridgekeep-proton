#!/usr/bin/env bash
# The admin portal's write-only drop box for the Claude API key and the
# Discord webhook. The portal never holds or reads back a secret: it leaves
# one small request file here, and root (this script, from the host's watch
# timer) checks it and installs the value into $BRIDGEKEEP_SECRETS.
#
#   scripts/secret-requests.sh init    create the request folder (setup, as root)
#   scripts/secret-requests.sh apply   act on waiting requests (health-watch, as root)
#
# The folder ($BRIDGEKEEP_SECRET_REQUESTS, default
# /var/lib/bridgekeep/secret-requests, like the status folder, on TrueNAS
# too: requests are short-lived) is owned by the portal's user 10003, mode 0700. One request per
# file, written as NAME.tmp and renamed to NAME.req:
#   secret=anthropic_api_key | discord_webhook | test_alert | ai_vendor
#   action=set | remove | test
#   id=<8-32 hex>
#   value=<the new key or webhook URL>          (set only; optional for ai_vendor)
#   provider=, model=, endpoint=, price_in=, price_out=   (ai_vendor only)
#
# ai_vendor runs scripts/analyzer-provider.sh with --key-stdin --yes: it checks
# every field again, alerts Discord ("AI vendor changed") and rewrites
# analyzer.yaml. An empty key keeps the one saved for that vendor.
#
# Each request is moved into a root-only inbox first (a symlink moves as a
# link), then checked there: a regular file, one link, owned by 10003, at most
# 1 KiB. Values must match a strict one-line format. A value only ever goes
# to the installer on stdin: never in argv, a log, or the result file.
#
# Before a secret changes, an alert goes to the CURRENT Discord webhook (a
# new webhook gets one too), so a change you didn't make is noticed. Each
# secret can change at most once per CHANGE_MINUTES (10).
#
# The outcome goes to $BRIDGEKEEP_STATUS_DIR/secrets.env (0640, group 10003),
# which the portal shows: set or off, the last 4 characters, when, and the
# result of the last request (ok, or a reason). Never the value.
set -euo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.."

say() { printf '%s [secrets] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }
envval() { [[ -f .env ]] && sed -n "s/^$1=//p" .env | tail -n1 || true; }

sec=${BRIDGEKEEP_SECRETS:-$(envval BRIDGEKEEP_SECRETS)}; sec=${sec:-/etc/bridgekeep/secrets}
req=${BRIDGEKEEP_SECRET_REQUESTS:-$(envval BRIDGEKEEP_SECRET_REQUESTS)}
req=${req:-/var/lib/bridgekeep/secret-requests}
ndir=${NOTIFY_DIR:-$(envval BRIDGEKEEP_NOTIFY_DIR)}; ndir=${ndir:-/var/lib/bridgekeep/notify}
state=$ndir/state
status_dir=${BRIDGEKEEP_STATUS_DIR:-/var/lib/bridgekeep/status}
PORTAL_UID=${PORTAL_UID:-10003}
CHANGE_MINUTES=${CHANGE_MINUTES:-10}
TEST_MINUTES=${TEST_MINUTES:-2}
provider_sh=scripts/analyzer-provider.sh
# Tests only: a stand-in, never when root (the host's timer runs as root).
[[ $(id -u) != 0 && -n ${ANALYZER_PROVIDER_SH:-} ]] && provider_sh=$ANALYZER_PROVIDER_SH
export BRIDGEKEEP_SECRETS=$sec NOTIFY_DIR=$ndir

valid_key() { [[ $1 =~ ^sk-ant-[A-Za-z0-9_-]{20,200}$ ]]; }
valid_hook() { [[ $1 =~ ^https://(discord\.com|discordapp\.com|canary\.discord\.com|ptb\.discord\.com)/api/webhooks/[0-9]{15,22}/[A-Za-z0-9_-]{40,100}$ ]]; }
notify() { bash scripts/notify.sh "$@" 2>&1 | sed 's/^/  /' >&2 || true; }

# results: state/secrets.env, root-only; copied to the status folder for the portal.
results=$state/secrets.env
put_result() { # KEY VALUE ... (plain values only)
  local tmp k v
  tmp=$(mktemp "$state/.secrets.XXXXXX")
  [[ -f $results ]] && cp -- "$results" "$tmp"
  while (( $# >= 2 )); do
    k=$1 v=$(LC_ALL=C tr -cd 'A-Za-z0-9 ._:,()/+-' <<<"$2" | cut -c1-120); shift 2
    grep -v "^$k=" "$tmp" >"$tmp.n" || true; printf '%s=%s\n' "$k" "$v" >>"$tmp.n"; mv -f -- "$tmp.n" "$tmp"
  done
  printf 'ts=%s\n' "$(date +%s)" | { grep -v '^ts=' "$tmp" || true; cat; } >"$tmp.n"; mv -f -- "$tmp.n" "$tmp"
  mv -f -- "$tmp" "$results"
  if install -d -m 0750 "$status_dir" 2>/dev/null; then
    local out; out=$(mktemp "$status_dir/.secrets.env.XXXXXX") || return 0
    chgrp "$PORTAL_UID" "$out" 2>/dev/null || true
    if ! { cat -- "$results" >"$out" && chmod 640 "$out" && mv -f -- "$out" "$status_dir/secrets.env"; }; then rm -f -- "$out"; fi
  fi
}

install_key() { # value on stdin; empty means "remove": the compose secret file stays, empty
  if [[ $(id -u) == 0 ]]; then
    install -d -m 0700 -o 0 -g 0 "$sec"
    # shellcheck disable=SC2016
    sh -c 'rm -f -- "$1" && umask 077 && cat >"$1" && chown 10002:10002 "$1" && chmod 0400 "$1"' sh "$sec/anthropic_api_key"
  else   # tests and development: a folder of this user's own
    (umask 077 && mkdir -p "$sec") && rm -f -- "$sec/anthropic_api_key" && (umask 077 && cat >"$sec/anthropic_api_key")
  fi
}

restart_analyzer() {
  command -v docker >/dev/null 2>&1 || return 0
  if [[ -n $(docker compose ps -q analyzer 2>/dev/null) ]]; then
    if docker compose up -d --force-recreate --no-deps analyzer >/dev/null 2>&1; then say "restarted the analyzer with the new key"
    else say "couldn't restart the analyzer; run ./bridgekeep doctor"; fi
  fi
}

too_soon() { # NAME MINUTES -> 0 (and prints minutes left) while a change is too recent
  local f=$state/secret-last-$1 last now
  [[ -f $f ]] || return 1
  read -r last <"$f" || return 1
  now=$(date +%s)
  (( now - last < $2 * 60 )) || return 1
  echo $(( ($2 * 60 - (now - last) + 59) / 60 ))
}

handle() { # FILE (already in the inbox and checked)
  local f=$1 secret action id value left last4 v_provider='' v_model='' v_endpoint='' v_in='' v_out=''
  secret=$(sed -n 's/^secret=\([a-z_]*\)$/\1/p' "$f" | head -n1)
  action=$(sed -n 's/^action=\([a-z]*\)$/\1/p' "$f" | head -n1)
  id=$(sed -n 's/^id=\([0-9a-f]\{8,32\}\)$/\1/p' "$f" | head -n1)
  value=$(sed -n 's/^value=//p' "$f" | head -n1 | tr -d '\r')
  if [[ $secret == ai_vendor ]]; then
    v_provider=$(sed -n 's/^provider=\(anthropic\|openai\|gemini\|local\)$/\1/p' "$f" | head -n1)
    v_model=$(sed -n 's/^model=\([A-Za-z0-9][A-Za-z0-9._:/-]\{0,99\}\)$/\1/p' "$f" | head -n1)
    v_endpoint=$(sed -n 's#^endpoint=\(https\?://[][A-Za-z0-9.:-]\{1,260\}\(/[A-Za-z0-9._~/-]\{0,100\}\)\?\)$#\1#p' "$f" | head -n1)
    v_in=$(sed -n 's/^price_in=\([0-9]\{1,4\}\(\.[0-9]\{1,6\}\)\?\)$/\1/p' "$f" | head -n1)
    v_out=$(sed -n 's/^price_out=\([0-9]\{1,4\}\(\.[0-9]\{1,6\}\)\?\)$/\1/p' "$f" | head -n1)
  fi
  rm -f -- "$f"
  case $secret:$action in
    anthropic_api_key:set|anthropic_api_key:remove|discord_webhook:set|discord_webhook:remove|test_alert:test|ai_vendor:set) ;;
    *) say "ignored a request that isn't one the portal may make"; value=; return 0 ;;
  esac
  [[ -n $id ]] || { say "ignored a $secret request without an id"; value=; return 0; }

  if [[ $secret == test_alert ]]; then
    if left=$(too_soon test_alert "$TEST_MINUTES"); then
      put_result test_alert_id "$id" test_alert_result "wait $left min"
    elif [[ ! -f $sec/discord_webhook ]]; then
      put_result test_alert_id "$id" test_alert_result "no webhook set"
    else
      date +%s >"$state/secret-last-test_alert"
      if bash scripts/notify.sh test 2>/dev/null; then put_result test_alert_id "$id" test_alert_result ok
      else put_result test_alert_id "$id" test_alert_result "Discord did not accept it"; fi
    fi
    return 0
  fi

  if left=$(too_soon "$secret" "$CHANGE_MINUTES"); then
    say "refused a $secret change: the last one was under $CHANGE_MINUTES minutes ago"
    put_result "${secret}_id" "$id" "${secret}_result" "refused: changed less than $CHANGE_MINUTES minutes ago, try again in $left min"
    value=; return 0
  fi
  if [[ $secret == ai_vendor ]]; then
    vendor "$id"; value=; return 0
  fi
  if [[ $action == set ]]; then
    if [[ $secret == anthropic_api_key ]] && ! valid_key "$value"; then
      put_result "${secret}_id" "$id" "${secret}_result" "refused: not a Claude API key (sk-ant-...)"; value=; return 0
    fi
    if [[ $secret == discord_webhook ]] && ! valid_hook "$value"; then
      put_result "${secret}_id" "$id" "${secret}_result" "refused: not a Discord webhook URL"; value=; return 0
    fi
    last4=${value: -4}
  fi

  # Tell the current channel first, so a change you didn't make is noticed.
  local what=removed; [[ $action == set ]] && what="changed, ending ${last4}"
  case $secret in
    anthropic_api_key) notify send secret_changed "Claude API key $what" ;;
    discord_webhook)   notify send secret_changed "Discord webhook $what" ;;
  esac

  case $secret:$action in
    anthropic_api_key:set)
      printf '%s' "$value" | install_key; value=
      restart_analyzer
      put_result anthropic_api_key set anthropic_api_key_last4 "$last4" anthropic_api_key_when "$(date +%s)" \
                 anthropic_api_key_id "$id" anthropic_api_key_result ok ;;
    anthropic_api_key:remove)
      install_key </dev/null
      restart_analyzer
      put_result anthropic_api_key off anthropic_api_key_last4 "" anthropic_api_key_when "$(date +%s)" \
                 anthropic_api_key_id "$id" anthropic_api_key_result ok ;;
    discord_webhook:set)
      # notify.sh configure sends a test to the new webhook and saves it only if Discord takes it.
      if printf '%s\n' "$value" | bash scripts/notify.sh configure >/dev/null 2>&1; then
        value=
        notify send secret_changed "Discord webhook changed, ending ${last4}"
        put_result discord_webhook set discord_webhook_last4 "$last4" discord_webhook_when "$(date +%s)" \
                   discord_webhook_id "$id" discord_webhook_result ok
      else
        value=
        put_result discord_webhook_id "$id" discord_webhook_result "refused: Discord did not accept a test message with it"
        return 0
      fi ;;
    discord_webhook:remove)
      # Directly, not `notify.sh remove`: that one uses sudo when not root.
      if ! rm -f -- "$sec/discord_webhook" || [[ -e $sec/discord_webhook || -L $sec/discord_webhook ]]; then
        put_result discord_webhook_id "$id" discord_webhook_result "could not remove the webhook file (see /var/log/bridgekeep/health-watch.log on the host)"
        return 0
      fi
      put_result discord_webhook off discord_webhook_last4 "" discord_webhook_when "$(date +%s)" \
                 discord_webhook_id "$id" discord_webhook_result ok ;;
  esac
  date +%s >"$state/secret-last-$secret"
  say "applied a $secret $action from the portal"
}

vendor() { # ID; uses value and v_* from handle (which already checked the 10-minute limit)
  local id=$1 args err
  if [[ -z $v_provider || -z $v_model ]]; then
    put_result ai_vendor_id "$id" ai_vendor_result "refused: not a vendor and model the portal may choose"; return 0
  fi
  if [[ $value == *[![:graph:]]* || ${#value} -gt 220 ]]; then
    put_result ai_vendor_id "$id" ai_vendor_result "refused: that API key has characters a key can't have"; return 0
  fi
  args=("$v_provider" --model "$v_model")
  if [[ $v_provider == local ]]; then
    [[ -n $v_endpoint ]] || { put_result ai_vendor_id "$id" ai_vendor_result "refused: not a server address"; return 0; }
    args+=(--endpoint "$v_endpoint")
  fi
  if [[ -n $v_in && -n $v_out ]]; then args+=(--price-in "$v_in" --price-out "$v_out"); fi
  err=$(mktemp "$state/.vendor.XXXXXX")
  # The key goes on stdin only; an empty line keeps the saved one.
  if printf '%s\n' "$value" | bash "$provider_sh" "${args[@]}" --key-stdin --yes >/dev/null 2>"$err"; then
    put_result ai_vendor_provider "$v_provider" ai_vendor_model "$v_model" ai_vendor_when "$(date +%s)" \
               ai_vendor_id "$id" ai_vendor_result ok
    if [[ $v_provider == anthropic && -n $value ]]; then
      put_result anthropic_api_key set anthropic_api_key_last4 "${value: -4}" anthropic_api_key_when "$(date +%s)"
    fi
    date +%s >"$state/secret-last-ai_vendor"
    say "applied an AI vendor change from the portal: $v_provider $v_model"
  else
    # analyzer-provider.sh says why on its last line (never the key).
    local why; why=$(grep -v '^[[:space:]]*$' "$err" | tail -n1 | sed 's/^analyzer-provider: //; s/; /, /g')
    put_result ai_vendor_id "$id" ai_vendor_result "refused: ${why:-the host could not switch; see /var/log/bridgekeep/health-watch.log}"
    sed 's/^/  /' "$err" >&2
  fi
  rm -f -- "$err"; value=
}

apply() {
  [[ -d $req && ! -L $req ]] || return 0
  (umask 077 && mkdir -p "$state/secret-inbox")
  local f held n=0
  for f in "$req"/*.req; do
    [[ -e $f || -L $f ]] || continue
    held=$state/secret-inbox/$(date +%s%N).$n; n=$((n + 1))
    mv -f -- "$f" "$held" 2>/dev/null || continue
    if [[ -L $held || ! -f $held ]] || [[ $(stat -c '%h %u' "$held") != "1 $PORTAL_UID" ]] || (( $(stat -c %s "$held") > 1024 )); then
      say "ignored a request file that isn't a small regular file of the portal's own"; rm -f -- "$held"; continue
    fi
    handle "$held"
  done
}

init() {
  if [[ -L $req ]]; then say "$req is a symbolic link; remove it and run setup again"; exit 1; fi
  install -d -m 0755 -o 0 -g 0 "$(dirname "$req")"
  install -d -m 0700 -o "$PORTAL_UID" -g "$PORTAL_UID" "$req"
}

# Neither folder may be inside the checkout.
top=$(pwd -P)
for p in "$sec" "$req" "$ndir"; do
  r=$(realpath -m -- "$p")
  if [[ $r == "$top" || $r == "$top"/* ]]; then say "$p must be outside the checkout ($top)."; exit 1; fi
done

case ${1:-} in
  init)  init ;;
  apply) (umask 077 && mkdir -p "$state") && apply ;;
  *)     echo "usage: $0 init|apply" >&2; exit 2 ;;
esac
