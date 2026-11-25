#!/usr/bin/env bash
# Every few minutes (root, from the host's watch timer): send alerts that
# containers left in the spool, check the containers' health, and now and
# then prove the Bridge sign-in still works. Problems go to Discord through
# scripts/notify.sh (nothing happens there if no webhook is set up).
#
#   scripts/health-watch.sh            one round (the timer runs this every 5 minutes)
#
# A container that is unhealthy or stopped on two rounds in a row raises
# health_failed; when it is healthy again, health_recovered. Containers that
# were never created (the analyzer profile is off) are not checked.
# The sign-in check (a real IMAP login from a throwaway container, like
# `./bridgekeep status`) runs at most every LOGIN_CHECK_MINUTES (default 30);
# Bridge refusing the saved password raises login_expired.
#
# Apart from applying an API key or webhook the admin portal asked for
# (scripts/secret-requests.sh, which may restart the analyzer for a new key)
# and one config fix-up below (also restarting the analyzer once), it never
# changes anything: no restarts, no deploys.
#
# Services paused with ./bridgekeep stop (listed in state/paused) are not
# checked and raise no alerts; while Bridge is paused the portal shows it as
# paused (the sign-in check needs a healthy Bridge, so it is skipped too).
set -uo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.." || exit 1
root=$PWD

say() { printf '%s [watch] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
notify() { bash scripts/notify.sh send "$@" 2>&1 | sed 's/^/  /'; }

sec=${BRIDGEKEEP_SECRETS:-}
dir=${NOTIFY_DIR:-}
if [[ -f .env ]]; then
  [[ -n $sec ]] || sec=$(sed -n 's/^BRIDGEKEEP_SECRETS=//p' .env | tail -n1)
  [[ -n $dir ]] || dir=$(sed -n 's/^BRIDGEKEEP_NOTIFY_DIR=//p' .env | tail -n1)
fi
export BRIDGEKEEP_SECRETS=${sec:-/etc/bridgekeep/secrets}
export NOTIFY_DIR=${dir:-/var/lib/bridgekeep/notify}
state=$NOTIFY_DIR/state
(umask 077 && mkdir -p "$state") || { say "cannot create $state (run as root)"; exit 1; }
LOGIN_CHECK_MINUTES=${LOGIN_CHECK_MINUTES:-30}
NETWORK=proton-bridge_mail
PYTHON_IMAGE=$(sed -n 's/^PYTHON_IMAGE *?= *//p' Makefile)

# 1. Alerts from containers, then secrets the portal asked to set.
bash scripts/notify.sh flush 2>&1 | sed 's/^/  /'
[[ -f scripts/secret-requests.sh ]] && { bash scripts/secret-requests.sh apply 2>&1 | sed 's/^/  /'; }

# 1b. Installs from before #29 got analyzer.yaml with the old $5 budget, which
# the portal never showed (it shows $20 until you save). The owner chose $20, so
# change that exact, untouched line once and restart the analyzer to load it.
# shellcheck disable=SC2016  # literal $ signs
old_budget='  monthly_budget_usd: 5       # at roughly $0.0001 per message this is ~50,000 messages'
# shellcheck disable=SC2016
new_budget='  monthly_budget_usd: 20      # at the cap: no more model calls this month, rules and lists only (about $0.0001 a message)'
if [[ -f config/analyzer.yaml && ! -L config/analyzer.yaml ]] && grep -qxF -- "$old_budget" config/analyzer.yaml; then
  if OLD=$old_budget NEW=$new_budget awk '$0 == ENVIRON["OLD"] { print ENVIRON["NEW"]; next } { print }' \
       config/analyzer.yaml >config/analyzer.yaml.new \
     && cat config/analyzer.yaml.new >config/analyzer.yaml && rm -f config/analyzer.yaml.new; then
    say "analyzer budget: the old \$5 default is now \$20, as chosen"
    if docker compose --profile analyzer ps -q analyzer 2>/dev/null | grep -q .; then
      docker compose --profile analyzer restart analyzer >/dev/null 2>&1 && say "analyzer restarted to load it"
    fi
  fi
fi

if ! { command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; }; then
  say "Docker is not running"
  notify health_failed "Docker is not running"
  exit 0
fi

# 2. Container health. state/watch-<service>: consecutive bad rounds.
health() { # SERVICE -> healthy | unhealthy | starting | exited | ... | absent
  local cid; cid=$(docker compose ps -a -q "$1" 2>/dev/null | head -n1)
  [[ -n $cid ]] || { echo absent; return; }
  docker inspect -f '{{if .State.Health}}{{if eq .State.Status "running"}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null || echo absent
}
bridge_ok=false
# Paused by ./bridgekeep stop: skipped only while actually stopped. Anything
# that started a paused service again (setup, a sign-in, a new API key,
# make up) ends its pause, so alerts are never lost to a stale mark.
paused=" "
if [[ -f $state/paused ]]; then
  for svc in $(tr -cs 'a-z-' ' ' <"$state/paused"); do
    case $(health "$svc") in
      exited|created|absent|dead) [[ $paused == *" $svc "* ]] || paused+="$svc " ;;
      *) say "$svc is running again; its pause is over" ;;
    esac
  done
  if [[ $paused == " " ]]; then rm -f -- "$state/paused"
  else tmp=$(mktemp "$state/.paused.XXXXXX") && tr ' ' '\n' <<<"${paused# }" | sed '/^$/d' >"$tmp" && mv -f -- "$tmp" "$state/paused"; fi
fi
for svc in bridge imap-proxy egress-proxy analyzer; do
  f=$state/watch-$svc
  if [[ $paused == *" $svc "* ]]; then rm -f -- "$f"; continue; fi
  h=$(health "$svc")
  case $h in
    absent) [[ $svc == bridge ]] || continue ;;&
    healthy|running)
      [[ $svc == bridge ]] && bridge_ok=true
      if [[ -s $f ]] && (( $(cat "$f") >= 2 )); then
        say "$svc is healthy again"; notify health_recovered "$svc"
      fi
      rm -f -- "$f" ;;
    starting) ;;   # give it its start period
    *)
      n=$(( $(cat "$f" 2>/dev/null || echo 0) + 1 )); echo "$n" >"$f"
      say "$svc is $h (round $n)"
      (( n >= 2 )) && notify health_failed "$svc is $h" ;;
  esac
done

# 3. Sign-in, now and then, only while Bridge itself is healthy.
last=$state/login-checked
if $bridge_ok && { [[ ! -f $last ]] || (( $(date +%s) - $(stat -c %Y "$last") >= LOGIN_CHECK_MINUTES * 60 )); }; then
  touch "$last"
  user=$(cat "$BRIDGEKEEP_SECRETS/bridge_username" 2>/dev/null || true)
  pw=$BRIDGEKEEP_SECRETS/bridge_password
  if [[ -z $user || ! -f $pw || ! -f bridge-cert.pem ]]; then
    say "no saved sign-in or certificate yet; skipping the sign-in check"
  else
    owner=$(stat -c %u:%g "$pw")
    # After a sign-in from the portal, the broker's copy (bridge-credential
    # volume, group 10011) is the current one.
    cred=()
    credvol="$(sed -n 's/^name: *//p' compose.yaml)_bridge-credential"   # compose.yaml pins the project name
    if docker volume inspect "$credvol" >/dev/null 2>&1; then
      cred=(-v "$credvol":/c:ro --group-add 10011)
    fi
    res=$(docker run --rm --network "$NETWORK" --read-only --cap-drop ALL \
            --security-opt no-new-privileges:true --user "$owner" --log-driver none \
            -v "$root/tests/login-check.py:/w/login-check.py:ro" \
            -v "$root/bridge-cert.pem:/w/bridge-cert.pem:ro" \
            -v "$pw:/run/pw:ro" "${cred[@]}" \
            "$PYTHON_IMAGE" python /w/login-check.py --user "$user" --password-file /run/pw --cafile /w/bridge-cert.pem \
            ${cred:+--credential-dir /c} 2>/dev/null)
    rc=$?
    err=$(sed -n 's/.*"error": *"\([^"]*\)".*/\1/p' <<<"$res")
    msgs=$(sed -n 's/.*"messages": *\([0-9][0-9]*\).*/\1/p' <<<"$res")
    # For the portal's Status page (bridge.env below): the last check's result.
    prev=$(sed -n 's/^messages=//p' "$state/login-result" 2>/dev/null || true)
    prev_ts=$(sed -n 's/^checked=//p' "$state/login-result" 2>/dev/null || true)
    printf 'rc=%s\nchecked=%s\nmessages=%s\nerror=%s\nprev_messages=%s\nprev_checked=%s\n' \
      "$rc" "$(date +%s)" "$msgs" "$err" "$prev" "$prev_ts" >"$state/login-result"
    f=$state/watch-login
    if (( rc == 0 )); then
      [[ -f $f ]] && { say "Bridge sign-in works again"; notify health_recovered "Bridge sign-in"; }
      rm -f -- "$f"
    elif [[ $err == *"refused the saved username and password"* ]]; then
      echo expired >"$f"; say "Bridge refused the saved sign-in"; notify login_expired
    else
      echo failed >"$f"; say "sign-in check failed: ${err:-exit $rc}"; notify health_failed "sign-in check: ${err:-no answer}"
    fi
  fi
fi

# 4. Status files for the admin portal's Status page (it mounts this folder
# read-only and needs no Docker access): key=value lines, one value per line,
# 0640 in a 0750 folder, group 10003 (the portal's user), so only root and
# the portal read them (bridge.env holds the Proton address). Each is
# written to a temp file and renamed into place.
STATUS_DIR=${BRIDGEKEEP_STATUS_DIR:-/var/lib/bridgekeep/status}
v() { LC_ALL=C tr -d '\000-\037\177"\\`' <<<"${1:-}" | cut -c1-200; }   # one plain line
put_status() { # NAME, key=value lines on stdin
  local tmp
  tmp=$(mktemp "$STATUS_DIR/.$1.XXXXXX") || return 0
  chgrp 10003 "$tmp" 2>/dev/null || true   # not root (tests): stays this user's group
  if ! { cat >"$tmp" && chmod 640 "$tmp" && mv -f -- "$tmp" "$STATUS_DIR/$1"; }; then rm -f -- "$tmp"; fi
}
if install -d -m 0750 "$STATUS_DIR" 2>/dev/null; then
  chgrp 10003 "$STATUS_DIR" 2>/dev/null || true
  now=$(date +%s)

  # storage.env: scripts/storage.sh's own output, checked line by line.
  if [[ -f scripts/storage.sh ]] && st=$(bash scripts/storage.sh 2>/dev/null); then
    grep -E '^[a-z_]+=[A-Za-z0-9 ._/:+-]{0,200}$' <<<"$st" | put_status storage.env
    if grep -qx 'low=yes' <<<"$st"; then
      free=$(sed -n 's/^disk_free_bytes=//p' <<<"$st")
      human=$(numfmt --to=si --suffix=B --format=%.1f "${free:-0}" 2>/dev/null || echo "${free:-0} bytes")
      notify disk_low "$human free"
    fi
  fi

  # host.env: what the portal can't see from its container.
  dv=$(docker version -f '{{.Server.Version}}' 2>/dev/null | LC_ALL=C tr -cd '0-9A-Za-z.+-' | cut -c1-40)
  { printf 'docker_version=%s\n' "$dv"; bash scripts/versions.sh 2>/dev/null; printf 'ts=%s\n' "$now"; } | put_status host.env

  # bridge.env: the same facts ./bridgekeep status shows.
  case $(health bridge) in
    healthy) bh=healthy ;; starting) bh=starting ;; unhealthy) bh=unhealthy ;; *) bh="not running" ;;
  esac
  [[ $paused == *" bridge "* ]] && bh=paused   # ./bridgekeep stop
  lr() { sed -n "s/^$1=//p" "$state/login-result" 2>/dev/null; }
  signed=no; [[ $(lr rc) == 0 ]] && signed=yes
  account=$(cat "$BRIDGEKEEP_SECRETS/bridge_username" 2>/dev/null || true)
  sched=no when=""
  if [[ -f /etc/systemd/system/bridgekeep-update.timer ]] && systemctl is-enabled bridgekeep-update.timer >/dev/null 2>&1; then
    sched=yes; when=$(sed -n 's/^OnCalendar=\*-\*-\* \(..:..\).*/nightly at \1/p' /etc/systemd/system/bridgekeep-update.timer)
  elif [[ -f /etc/cron.d/bridgekeep ]]; then
    sched=yes; when=$(awk 'NF >= 2 {printf "nightly at %02d:%02d", $2, $1; exit}' /etc/cron.d/bridgekeep)
  elif command -v midclt >/dev/null 2>&1 && midclt call cronjob.query 2>/dev/null | grep -q 'Bridgekeep auto-update'; then
    sched=yes; when="TrueNAS cron job"
  fi
  waiting=$(sed -n 's/^version=//p' .bridgekeep/update-waiting 2>/dev/null || true)
  lastline=$(tail -n1 /var/log/bridgekeep/auto-update.log 2>/dev/null || true)
  {
    printf 'bridge_health=%s\n' "$bh"
    printf 'signed_in=%s\n' "$signed"
    printf 'account=%s\n' "$(v "$account")"
    printf 'sign_in_error=%s\n' "$(v "$(lr error)")"
    printf 'messages=%s\n' "$(lr messages | tr -cd 0-9)"
    printf 'messages_ts=%s\n' "$(lr checked | tr -cd 0-9)"
    printf 'messages_prev=%s\n' "$(lr prev_messages | tr -cd 0-9)"
    printf 'messages_prev_ts=%s\n' "$(lr prev_checked | tr -cd 0-9)"
    printf 'update_scheduled=%s\n' "$sched"
    printf 'update_when=%s\n' "$(v "$when")"
    printf 'update_waiting_version=%s\n' "$(v "$waiting" | tr -cd '0-9A-Za-z.+-')"
    printf 'last_update_line=%s\n' "$(v "$lastline")"
    printf 'paused=%s\n' "$(v "$(xargs <<<"$paused")")"
    printf 'ts=%s\n' "$now"
  } | put_status bridge.env
fi
exit 0
