#!/usr/bin/env bash
# Bridgekeep alerts to a Discord channel (optional). Runs on the host only:
# the webhook URL never enters a container, and only the host talks to
# discord.com, so no container's egress allowlist needs it.
#
#   scripts/notify.sh init                 create the state and spool folders (setup, as root)
#   scripts/notify.sh configure            ask for the webhook URL, send a test, save it
#   scripts/notify.sh remove               forget the webhook (alerts off)
#   scripts/notify.sh status               configured or not (never prints the URL)
#   scripts/notify.sh test                 send a test message
#   scripts/notify.sh send EVENT [DETAIL]  send one alert (host scripts call this)
#   scripts/notify.sh flush                send alerts that containers left in the spool
#
# Events, each with fixed wording (DETAIL fills in a version, a reason, ...):
#   login_expired    Bridge is signed out of Proton
#   update_waiting   a new Bridge is built and tested, waiting for approval
#   update_failed    the nightly update stopped (e.g. a new signing key)
#   health_failed    a container is unhealthy or stopped
#   health_recovered it is healthy again
#   budget_cap       the analyzer hit its spending cap
#   disk_low         the disk holding Bridgekeep's data is nearly full
#   secret_changed   the API key or webhook was changed from the portal
#   analyzer_mode_changed  the analyzer switched between shadow (log only) and live (moves mail)
#   move_cap         live mode reached its daily limit of moves; log only until tomorrow
#   imap_refused     in live mode, the IMAP proxy refused an analyzer command (a bug or tampering)
#   test             a test message
#
# The same event with the same detail is sent at most once per REMIND_HOURS
# (login_expired and health_failed: every 6 hours while it lasts; others:
# 24), and at most MAX_PER_HOUR messages go out in any hour. Sending is best
# effort: with no webhook, no curl or Discord down, `send` and `flush` log a
# line and exit 0, so they never break the job that called them.
#
# Containers can't reach Discord. They drop a small file in their own spool
# folder (docs/alerts.md), and `flush`, run by root from the host's watch
# timer, sends it:
#   $NOTIFY_DIR/spool/analyzer  owned by 10002 (analyzer, imap-proxy), mounted at /run/bridgekeep/alerts
#   $NOTIFY_DIR/spool/portal    owned by 10003 (admin portal), mounted at /run/bridgekeep/alerts
# One alert per file, written as NAME.tmp and renamed to NAME.alert:
#   event=budget_cap
#   detail=monthly cap 5 USD reached
# Each folder may only send its own events (see allowed_from below).
#
# The webhook lives in $BRIDGEKEEP_SECRETS/discord_webhook (default
# /etc/bridgekeep/secrets), root-owned and 0400. No container mounts it.
set -euo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.."

say() { printf '%s [notify] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }

sec=${BRIDGEKEEP_SECRETS:-}
if [[ -z $sec && -f .env ]]; then sec=$(sed -n 's/^BRIDGEKEEP_SECRETS=//p' .env | tail -n1); fi
sec=${sec:-/etc/bridgekeep/secrets}
dir=${NOTIFY_DIR:-}
if [[ -z $dir && -f .env ]]; then dir=$(sed -n 's/^BRIDGEKEEP_NOTIFY_DIR=//p' .env | tail -n1); fi
dir=${dir:-/var/lib/bridgekeep/notify}
hook_file=$sec/discord_webhook
state=$dir/state
MAX_PER_HOUR=${MAX_PER_HOUR:-10}
CURL=${NOTIFY_CURL:-curl}   # tests point this at a stand-in

# Neither folder may be inside the checkout (the same rule as bridge-signin.sh).
top=$(pwd -P)
for p in "$sec" "$dir"; do
  r=$(realpath -m -- "$p")
  if [[ $r == "$top" || $r == "$top"/* ]]; then
    say "Secrets and alert state must live outside the checkout: $p is inside $top."; exit 1
  fi
done

message() { # EVENT DETAIL -> the text, or nothing for an unknown event
  # The detail goes inside inline code, so Discord never turns it into a
  # link or markup (clean() has already removed any backtick).
  local d=""
  [[ -n $2 ]] && d="\`$2\`"
  case $1 in
    login_expired)    echo "Bridge is signed out of Proton, so mail isn't syncing${d:+ ($d)}. On the host, run: ./bridgekeep relogin" ;;
    update_waiting)   echo "Bridge ${d:-update} is built and tested, and waiting for your OK. On the host, run: ./bridgekeep deploy-update" ;;
    update_failed)    echo "The nightly Bridge update stopped${d:+: $d}. Nothing was changed. On the host, run: ./bridgekeep status" ;;
    health_failed)    echo "Something isn't healthy${d:+: $d}. On the host, run: ./bridgekeep doctor" ;;
    health_recovered) echo "Healthy again${d:+: $d}." ;;
    budget_cap)       echo "The analyzer reached its monthly model budget${d:+ ($d)}, so it's sorting with your rules and lists only until the 1st. Nothing to do unless you want to raise the budget on the portal's Analyzer page." ;;
    ai_vendor_changed) echo "The AI vendor that analyzes your mail was changed${d:+: $d}. If you didn't do this, stop the analyzer now. On the host, run: ./bridgekeep status" ;;
    disk_low)         echo "The disk holding Bridgekeep is nearly full${d:+ ($d)}. Bridge stops syncing when it runs out. On the host, run: ./bridgekeep status" ;;
    analyzer_mode_changed) echo "The analyzer's mode changed${d:+: $d}. If you didn't do this, switch it back to Shadow on the portal's Analyzer page, or on the host run: ./bridgekeep analyzer shadow" ;;
    move_cap)         echo "The analyzer reached its daily limit of mail moves${d:+ ($d)}, so it only logs until tomorrow. Change the limit on the portal's Analyzer page." ;;
    imap_refused)     echo "The analyzer tried something its mail proxy doesn't allow${d:+ ($d)}. That means a bug or tampering. Switch it back to Shadow on the portal's Analyzer page, or on the host run: ./bridgekeep analyzer shadow" ;;
    secret_changed)   echo "Changed from the admin portal: ${d:-a secret}. If this wasn't you, change the portal password and on the host run: ./bridgekeep doctor" ;;
    test)             echo "Test message: Bridgekeep alerts reach this channel." ;;
  esac
}
remind_hours() { case $1 in login_expired|health_failed) echo "${REMIND_HOURS:-6}" ;; test|secret_changed|ai_vendor_changed|analyzer_mode_changed|imap_refused) echo 0 ;; *) echo "${REMIND_HOURS:-24}" ;; esac; }
allowed_from() { # SPOOL_NAME EVENT
  case $1:$2 in
    analyzer:budget_cap|analyzer:login_expired|analyzer:health_failed|analyzer:health_recovered) return 0 ;;
    analyzer:analyzer_mode_changed|analyzer:move_cap|analyzer:imap_refused) return 0 ;;
    portal:login_expired|portal:update_waiting) return 0 ;;
  esac
  return 1
}

# Details are short plain text: letters, digits, spaces and . , : ; _ / ( ) + = # -
# Everything else (quotes, backslashes, backticks, @, <, newlines, ...) is
# dropped, so a detail can't break the JSON or mention anyone, and message()
# shows it as inline code, so a URL in it is never a clickable link.
clean() { LC_ALL=C tr -cd 'A-Za-z0-9 .,:;_/()+=#-' <<<"${1:-}" | cut -c1-200; }
valid_hook() { [[ $1 =~ ^https://(discord\.com|discordapp\.com|canary\.discord\.com|ptb\.discord\.com)/api/webhooks/[0-9]{15,22}/[A-Za-z0-9_-]{40,100}$ ]]; }

read_hook() { [[ -f $hook_file && ! -L $hook_file ]] && head -c 300 "$hook_file" | tr -d '\r\n'; }

post() { # TEXT -> 0 when Discord took it. The URL goes to curl on stdin, never in argv.
  local url=$1 text=$2 host
  host=$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo host)
  host=$(clean "$host")
  command -v "$CURL" >/dev/null 2>&1 || { say "curl is not installed, so alerts can't be sent"; return 1; }
  # allowed_mentions parse=[]: nothing in the message can ping anyone.
  printf 'url = "%s"\ndata-binary = "{\\"username\\": \\"Bridgekeep\\", \\"content\\": \\"**%s**: %s\\", \\"allowed_mentions\\": {\\"parse\\": []}}"\n' \
    "$url" "$host" "$text" \
    | "$CURL" -sS --fail --proto '=https' --max-time 20 --retry 2 --retry-delay 5 \
        -H 'Content-Type: application/json' -o /dev/null -K - 2>/dev/null
}

ensure_state() { (umask 077 && mkdir -p "$state") && chmod 700 "$state"; }

# send EVENT DETAIL [force]: dedup, rate cap, post. Always returns 0 unless force.
send() {
  local ev=$1 detail text url key now last_key last_at hours
  detail=$(clean "${2:-}")
  text=$(message "$ev" "$detail")
  [[ -n $text ]] || { say "unknown event '$ev', not sent"; return 0; }
  url=$(read_hook || true)
  if [[ -z $url ]]; then say "no Discord webhook set up, so '$ev' was only logged: $text"; return 0; fi
  valid_hook "$url" || { say "the saved webhook doesn't look like a Discord webhook URL; run: ./bridgekeep alerts"; return 0; }
  ensure_state
  now=$(date +%s) key=$(printf '%s|%s' "$ev" "$detail" | sha256sum | cut -c1-16)
  hours=$(remind_hours "$ev")
  if [[ -f $state/last-$ev ]]; then
    read -r last_at last_key <"$state/last-$ev" || true
    if [[ ${last_key:-} == "$key" && $hours -gt 0 ]] && (( now - ${last_at:-0} < hours * 3600 )); then
      say "'$ev' was already sent $(( (now - last_at) / 60 )) minutes ago; not repeating it yet"; return 0
    fi
  fi
  # Rate cap: timestamps of what went out in the last hour.
  touch "$state/sent"
  awk -v t=$((now - 3600)) '$1 > t' "$state/sent" >"$state/sent.tmp" && mv "$state/sent.tmp" "$state/sent"
  # secret_changed and a mode change always go out: a change you didn't make must never be capped away.
  if [[ $ev != secret_changed && $ev != analyzer_mode_changed ]] && (( $(wc -l <"$state/sent") >= MAX_PER_HOUR )); then
    say "already sent $MAX_PER_HOUR alerts this hour; '$ev' was only logged: $text"; return 0
  fi
  if post "$url" "$text"; then
    printf '%s %s\n' "$now" "$key" >"$state/last-$ev"
    printf '%s %s\n' "$now" "$ev" >>"$state/sent"
    say "sent '$ev' to Discord"
  else
    say "Discord didn't accept '$ev' (network, a deleted webhook, or rate limiting); it was only logged: $text"
  fi
  return 0
}

# flush: move each *.alert out of a spool folder into a root-only folder
# first (a symlink moves as a link, so nothing can be swapped in after the
# checks), then check it there: a regular file, one link, owned by that
# folder's owner, at most 1 KiB, an event that folder may send.
flush() {
  local name spool f inbox owner ev detail n=0
  ensure_state
  inbox=$state/inbox; (umask 077 && mkdir -p "$inbox")
  for spool in "$dir"/spool/*/; do
    [[ -d $spool && ! -L ${spool%/} ]] || continue
    name=$(basename "$spool")
    [[ $name =~ ^[a-z]+$ ]] || continue
    owner=$(stat -c %u "$spool")
    for f in "$spool"*.alert; do
      [[ -e $f || -L $f ]] || continue
      local held
      held=$inbox/$name.$(date +%s%N).$n; n=$((n + 1))
      mv -f -- "$f" "$held" 2>/dev/null || continue
      if [[ -L $held || ! -f $held ]] || [[ $(stat -c '%h %u' "$held") != "1 $owner" ]] || (( $(stat -c %s "$held") > 1024 )); then
        say "ignored an alert file from $name that isn't a small regular file of its own"; rm -f -- "$held"; continue
      fi
      ev=$(sed -n 's/^event=\([a-z_]*\)$/\1/p' "$held" | head -n1)
      detail=$(sed -n 's/^detail=//p' "$held" | head -n1)
      rm -f -- "$held"
      if ! allowed_from "$name" "$ev"; then say "ignored '$ev' from $name (not one it may send)"; continue; fi
      # Each folder gets its own MAX_PER_HOUR, so a noisy container can't use
      # up the host's own alerts.
      touch "$state/sent-$name"
      awk -v t=$(($(date +%s) - 3600)) '$1 > t' "$state/sent-$name" >"$state/sent-$name.tmp" && mv "$state/sent-$name.tmp" "$state/sent-$name"
      if (( $(wc -l <"$state/sent-$name") >= MAX_PER_HOUR )); then
        say "$name already sent $MAX_PER_HOUR alerts this hour; dropped '$ev'"; continue
      fi
      printf '%s %s\n' "$(date +%s)" "$ev" >>"$state/sent-$name"
      send "$ev" "$name: $detail"
    done
  done
}

as_root() { if [[ $(id -u) == 0 ]]; then "$@"; else sudo "$@"; fi; }

configure() {
  local url
  [[ -t 0 ]] && printf 'Paste the Discord webhook URL (Server Settings > Integrations > Webhooks > Copy Webhook URL), or press Enter to skip: ' >&2
  IFS= read -rs url || true
  [[ -t 0 ]] && echo >&2
  url=$(tr -d ' \r\n' <<<"$url")
  [[ -n $url ]] || { echo "Skipped. Alerts stay off; turn them on later with ./bridgekeep alerts." >&2; return 0; }
  valid_hook "$url" || { echo "That isn't a Discord webhook URL. It should look like https://discord.com/api/webhooks/<numbers>/<token>." >&2; return 1; }
  if ! post "$url" "$(message test "")"; then
    echo "Discord didn't accept a test message with that URL, so it wasn't saved. Check that the webhook still exists and the host can reach discord.com." >&2
    return 1
  fi
  if [[ $(id -u) == 0 ]] || ! { [[ -O $sec ]] || [[ ! -e $sec && -O $(dirname "$sec") ]]; }; then
    as_root install -d -m 0700 -o 0 -g 0 "$sec"
    # shellcheck disable=SC2016
    printf '%s\n' "$url" | as_root sh -c 'rm -f -- "$1" && umask 077 && cat >"$1" && chown 0:0 "$1" && chmod 0400 "$1"' sh "$hook_file"
  else   # a folder of this user's own (tests, development)
    (umask 077 && mkdir -p "$sec") && chmod 700 "$sec"
    rm -f -- "$hook_file"; (umask 077 && printf '%s\n' "$url" >"$hook_file")
  fi
  echo "Alerts are on: a test message was sent to the channel." >&2
}

init() { # root: state 0700 root; each spool 0700, owned by the one container user that writes it
  as_root install -d -m 0755 -o 0 -g 0 "$dir" "$dir/spool"
  as_root install -d -m 0700 -o 0 -g 0 "$state"
  as_root install -d -m 0700 -o 10002 -g 10002 "$dir/spool/analyzer"
  as_root install -d -m 0700 -o 10003 -g 10003 "$dir/spool/portal"
}

case ${1:-} in
  init)      init ;;
  configure) configure ;;
  remove)    as_root rm -f -- "$hook_file"; echo "Alerts are off." >&2 ;;
  status)    if [[ -n $(read_hook 2>/dev/null || as_root cat "$hook_file" 2>/dev/null || true) ]]; then echo "on (Discord)"; else echo "off"; fi ;;
  test)      url=$(read_hook || true); [[ -n $url ]] || { echo "No Discord webhook is set up. Run ./bridgekeep alerts." >&2; exit 1; }
             if post "$url" "$(message test "")"; then echo "Sent." >&2; else echo "Discord didn't accept it." >&2; exit 1; fi ;;
  send)      [[ -n ${2:-} ]] || { echo "usage: $0 send EVENT [DETAIL]" >&2; exit 2; }; send "$2" "${3:-}" ;;
  flush)     flush ;;
  *)         echo "usage: $0 init|configure|remove|status|test|send EVENT [DETAIL]|flush" >&2; exit 2 ;;
esac
