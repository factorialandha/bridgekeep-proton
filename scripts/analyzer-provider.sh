#!/usr/bin/env bash
# Choose who analyzes the mail: Anthropic (default), OpenAI, Google Gemini,
# or your own local server (Ollama, LM Studio, llama.cpp; OpenAI-compatible).
# Run by `make analyzer-init` and by the admin portal's host-side drop box
# (after step-up). Root only: it writes the vendor's key and the one host the
# egress proxy may reach.
#
#   scripts/analyzer-provider.sh PROVIDER --model NAME [--endpoint URL]
#                                [--price-in USD --price-out USD] [--key-stdin] [--yes]
#
#   PROVIDER   anthropic | openai | gemini | local
#   --model    the vendor's model name, e.g. claude-haiku-5-5
#   --endpoint local only: http(s)://IP-or-name:port/v1. A name is looked up
#              once, here, and the address is pinned.
#   --price-in / --price-out   USD per million tokens. Needed for OpenAI and
#              Gemini (prices differ by plan); until set, the model is not used.
#   --key-stdin  read the API key from stdin (the portal); otherwise asked
#              with `read -s`. Keys never go on the command line.
#   --yes      don't ask to confirm (the portal already did, with step-up)
#
# Before the switch it sends an "AI vendor changed" alert to your Discord
# channel, so a change you didn't make is noticed.
set -euo pipefail

cd "$(dirname "$0")/.."
image="${ANALYZER_IMAGE:-proton-analyzer}:local"
if [ -z "${BRIDGEKEEP_SECRETS:-}" ] && [ -f .env ]; then
  BRIDGEKEEP_SECRETS=$(sed -n 's/^BRIDGEKEEP_SECRETS=//p' .env | tail -n1)
fi
sec="${BRIDGEKEEP_SECRETS:-/etc/bridgekeep/secrets}"
cfg=config/analyzer.yaml

die() { echo "analyzer-provider: $*" >&2; exit 1; }
as_root=()
[ "$(id -u)" -eq 0 ] || as_root=(sudo)

provider="${1:-}"; shift || true
model="" endpoint="" price_in="" price_out="" key_stdin=0 yes=0
while [ $# -gt 0 ]; do
  case "$1" in
    --model) model="${2:-}"; shift 2 ;;
    --endpoint) endpoint="${2:-}"; shift 2 ;;
    --price-in) price_in="${2:-}"; shift 2 ;;
    --price-out) price_out="${2:-}"; shift 2 ;;
    --key-stdin) key_stdin=1; shift ;;
    --yes) yes=1; shift ;;
    *) die "unknown option $1" ;;
  esac
done
case "$provider" in anthropic|openai|gemini|local) ;; *) die "choose anthropic, openai, gemini or local" ;; esac
# Only Claude has a default: other vendors' model names change often, so
# you type the name exactly as your vendor's console or server shows it.
[ -n "$model" ] || { [ "$provider" = anthropic ] && model=claude-haiku-5-5; } \
  || die "--model is needed: the model name exactly as your vendor's console or server shows it"
name_of() { case $1 in anthropic) echo Anthropic ;; openai) echo OpenAI ;; gemini) echo "Google Gemini" ;; local) echo "your local server" ;; *) echo "$1" ;; esac; }
[ -f "$cfg" ] || die "$cfg is missing. Run: ./bridgekeep setup --analyzer"
docker image inspect "$image" >/dev/null 2>&1 || die "the analyzer isn't installed yet. Run: ./bridgekeep setup --analyzer"

num='^[0-9]{1,4}(\.[0-9]{1,6})?$'
if [ -n "$price_in$price_out" ]; then
  [[ $price_in =~ $num && $price_out =~ $num ]] || die "--price-in and --price-out must both be numbers (USD per million tokens)"
fi

refuse=()
if [ "$provider" = local ]; then
  # Pin one address: resolve a name here, once.
  host=$(sed -E 's#^[a-z]+://\[?([^]/:]+)\]?.*#\1#' <<<"$endpoint")
  if ! [[ $host =~ ^[0-9.]+$ || $host =~ : ]]; then
    ip=$(getent ahostsv4 "$host" | awk 'NR==1 {print $1}')
    [ -n "$ip" ] || die "could not look up $host"
    endpoint=${endpoint/"$host"/"$ip"}
    echo "Using $host at $ip (pinned)."
  fi
  # Never Docker's own networks (Bridge's mail network above all) or a port a
  # Bridgekeep container publishes. The check itself runs in the analyzer image.
  while read -r net; do [ -n "$net" ] && refuse+=(--refuse-net "$net"); done < <(
    docker network ls -q | xargs -r docker network inspect --format '{{range .IPAM.Config}}{{println .Subnet}}{{end}}')
  while read -r port; do [ -n "$port" ] && refuse+=(--refuse-port "$port"); done < <(
    docker ps --format '{{.Ports}}' | grep -oE ':[0-9]+->' | tr -d ':->' | sort -u)
fi

out=$(docker run --rm --network none --entrypoint python "$image" -P -m analyzer provider-check \
      "$provider" --model "$model" --endpoint "$endpoint" "${refuse[@]}") || exit 1
entry=$(sed -n 1p <<<"$out")
echo
sed -n '2,$p' <<<"$out"
echo "The egress proxy will allow only: $entry"
from=$(sed -n '/^model:/,/^[^ #]/ s/^  provider:[[:space:]]*\([a-z]*\).*/\1/p' "$cfg" | head -n1)
from=${from:-anthropic}
if [ "$yes" = 0 ]; then
  if [ "$from" != "$provider" ]; then
    echo "Mail fields will go to $(name_of "$provider") instead of $(name_of "$from")."
  fi
  read -r -p "Use $(name_of "$provider") ($model)? [y/N] " ok
  [[ $ok =~ ^[Yy] ]] || die "nothing changed"
fi

# The key: one file per vendor, never shared between vendors.
keyfile="$sec/${provider}_api_key"
key=""
if [ "$key_stdin" = 1 ]; then
  IFS= read -r key || true
elif [ "$provider" != local ] || [ "$yes" = 0 ]; then
  read -r -s -p "API key for $(name_of "$provider")$( [ "$provider" = local ] && echo ' (Enter for none)') (not shown): " key; echo
fi
if [ -n "$key" ]; then
  case "$provider" in
    anthropic) [[ $key =~ ^sk-ant-[A-Za-z0-9_-]{20,200}$ ]] ;;
    openai)    [[ $key =~ ^sk-[A-Za-z0-9_-]{20,200}$ ]] ;;
    gemini)    [[ $key =~ ^AIza[0-9A-Za-z_-]{35}$ ]] ;;
    local)     [[ $key =~ ^[!-~]{1,200}$ ]] ;;
  esac || die "that doesn't look like a $(name_of "$provider") API key; nothing changed"
fi
if [ -z "$key" ] && [ "$provider" != local ] && ! "${as_root[@]}" test -s "$keyfile"; then
  die "no API key for $(name_of "$provider"); nothing changed"
fi

# Tell the channel first, so a switch you didn't make is noticed.
bash scripts/notify.sh send ai_vendor_changed "from $from to $provider $model" || true

"${as_root[@]}" install -d -m 0700 -o 0 -g 0 "$sec"
if [ -n "$key" ]; then
  # shellcheck disable=SC2016
  printf '%s' "$key" | "${as_root[@]}" sh -c 'umask 077 && cat > "$1" && chown 10002:10002 "$1" && chmod 0400 "$1"' sh "$keyfile"
fi
for v in anthropic openai gemini local; do   # compose mounts all four; empty means none
  f="$sec/${v}_api_key"
  # shellcheck disable=SC2016  # $1 expands in the inner shell
  "${as_root[@]}" test -f "$f" || printf '' | "${as_root[@]}" sh -c 'umask 077 && cat > "$1" && chown 10002:10002 "$1" && chmod 0400 "$1"' sh "$f"
done

# Rewrite only the vendor lines of the model section; keep everything else.
tmp=$(mktemp)
sed -E '/^model:/,/^[^ #]/ { /^  (provider|name|endpoint|price_in_per_mtok|price_out_per_mtok|api_key_file):/d }' "$cfg" > "$tmp"
lines="  provider: $provider\n  name: $model"
[ "$provider" = local ] && lines="$lines\n  endpoint: $endpoint"
[ -n "$price_in" ] && lines="$lines\n  price_in_per_mtok: $price_in\n  price_out_per_mtok: $price_out"
# shellcheck disable=SC2001  # sed turns each \n into an escaped newline for `a\`
sed -i "/^model:/a\\
$(sed 's/\\n/\\\n/g' <<<"$lines")" "$tmp"
sed -i '/^egress_proxy:/,/^[^ #]/ { /^  allow:/d }' "$tmp"   # the proxy follows model.provider now
cat "$tmp" > "$cfg" && rm -f "$tmp"
echo "Saved: $(name_of "$provider"), $model."

if docker compose ps --status running --services 2>/dev/null | grep -qx analyzer; then
  docker compose --profile analyzer up -d --force-recreate egress-proxy analyzer >/dev/null
  echo "Restarted the analyzer and its egress proxy."
fi
