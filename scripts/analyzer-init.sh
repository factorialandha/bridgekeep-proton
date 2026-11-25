#!/usr/bin/env bash
# One-time setup for the AI analyzer (log-only). Safe to run again: it never
# overwrites a file that already exists.
#
#   make analyzer-init                       # asks for what it needs
#   scripts/analyzer-init.sh --non-interactive   # for `bridgekeep setup`: never asks
#
# Writes:
#   config/                      settings, never-trash list, Bridge's certificate
#                                (git-ignored; nothing secret)
#   $BRIDGEKEEP_SECRETS          default /etc/bridgekeep/secrets, OUTSIDE the
#                                checkout: the folder root-owned 0700, each file
#                                owned by the containers' user (10002) and 0400.
#     bridge_username            the Bridge IMAP username (from `info`)
#     bridge_password            the Bridge password (from `info`)
#     anthropic_api_key          optional; empty means "no model, rules only"
#     openai_api_key, gemini_api_key, local_api_key
#                                empty unless you pick that vendor
#                                (scripts/analyzer-provider.sh, or the portal)
#     analyzer_imap_token        random, generated here
#
# Secrets are read with `read -s` and passed through stdin, so they are never
# echoed, never in shell history and never on a command line. Run it in WSL
# or Linux; it uses sudo for the secrets folder when you are not root.
set -euo pipefail

cd "$(dirname "$0")/.."
image="${ANALYZER_IMAGE:-proton-analyzer}:local"
# Compose reads BRIDGEKEEP_SECRETS from .env, so this script must too.
if [ -z "${BRIDGEKEEP_SECRETS:-}" ] && [ -f .env ]; then
  BRIDGEKEEP_SECRETS=$(sed -n 's/^BRIDGEKEEP_SECRETS=//p' .env | tail -n1)
fi
sec="${BRIDGEKEEP_SECRETS:-/etc/bridgekeep/secrets}"
interactive=1
[ "${1:-}" = "--non-interactive" ] && interactive=0

die() { echo "analyzer-init: $*" >&2; exit 1; }

if ! docker image inspect "$image" >/dev/null 2>&1; then
  die "the analyzer image $image is not built yet. Run: make analyzer-build (no make, e.g. TrueNAS: bash scripts/make.sh analyzer-build)"
fi

as_root=()
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null || die "the secrets folder $sec needs root. Run this as root, or set BRIDGEKEEP_SECRETS to a folder you own."
  as_root=(sudo)
fi

# The secrets folder: root-owned, 0700. Nothing else on the host can list it.
"${as_root[@]}" install -d -m 0700 -o 0 -g 0 "$sec"

have() { "${as_root[@]}" test -f "$sec/$1"; }

put() {  # name; the value comes on stdin
  # shellcheck disable=SC2016  # $1 expands in the inner shell
  "${as_root[@]}" sh -c 'umask 077 && cat > "$1" && chown 10002:10002 "$1" && chmod 0400 "$1"' sh "$sec/$1"
  echo "wrote $sec/$1"
}

ask() {  # name, prompt, optional(0/1)
  have "$1" && return 0
  [ "$interactive" = 1 ] || { [ "$3" = 1 ] && return 0; die "$sec/$1 is missing and --non-interactive was given"; }
  local value
  read -r -s -p "$2: " value
  echo
  if [ -z "$value" ]; then
    [ "$3" = 1 ] && return 0
    die "nothing entered; run this again when you have it"
  fi
  printf '%s' "$value" | put "$1"
}

# Earlier versions kept secrets in ./secrets inside the checkout. Move them.
if [ -d secrets ] && [ "$(cd secrets && pwd -P)" != "$(cd "$sec" 2>/dev/null && pwd -P || echo none)" ]; then
  for f in bridge_password anthropic_api_key analyzer_imap_token bridge_username; do
    if [ -f "secrets/$f" ] && ! have "$f"; then
      put "$f" < "secrets/$f"
      rm -f "secrets/$f"
      echo "  (moved from ./secrets/$f)"
    fi
  done
  rmdir secrets 2>/dev/null || true
fi

# Bridge username. `bridgekeep setup` saves it; otherwise ask.
if ! have bridge_username; then
  [ "$interactive" = 1 ] || die "$sec/bridge_username is missing and --non-interactive was given"
  read -r -p "Bridge IMAP username (from 'info' in bridge-init, usually your address): " user
  printf '%s' "$user" | put bridge_username
fi
user=$("${as_root[@]}" cat "$sec/bridge_username")
case "$user" in
  *[!A-Za-z0-9@._+-]*|'') die "the Bridge username in $sec/bridge_username does not look like an address" ;;
esac

ask bridge_password "Bridge password (from 'info', NOT your Proton password)" 0
provider=anthropic
if [ "$interactive" = 1 ] && [ ! -f config/analyzer.yaml ] && ! have anthropic_api_key; then
  echo "Which AI should analyze your mail? anthropic (default), openai, gemini, local (your own server, e.g. Ollama)"
  read -r -p "AI vendor [anthropic]: " provider
  provider=${provider:-anthropic}
  case "$provider" in anthropic|openai|gemini|local) ;; *) die "choose anthropic, openai, gemini or local" ;; esac
fi
if [ "$provider" = anthropic ]; then
  ask anthropic_api_key "Anthropic API key (a dedicated key with a spend limit; Enter to run without a model)" 1
fi
model=on
for v in anthropic openai gemini local; do   # compose needs every file to exist; empty means none
  have "${v}_api_key" || printf '' | put "${v}_api_key"
done
if [ "$provider" = anthropic ] && [ "$("${as_root[@]}" wc -c < "$sec/anthropic_api_key")" -eq 0 ]; then
  model=off
fi

if ! have analyzer_imap_token; then
  docker run --rm --network none --entrypoint python "$image" -P -c \
    'import secrets; print(secrets.token_urlsafe(32), end="")' | put analyzer_imap_token
fi

# Files `bridgekeep setup` (or you) wrote directly: give them to the
# containers' user, readable by it only. Compose mounts each file on its own.
for f in bridge_username bridge_password anthropic_api_key openai_api_key gemini_api_key local_api_key analyzer_imap_token; do
  if have "$f"; then
    "${as_root[@]}" chown 10002:10002 "$sec/$f"
    "${as_root[@]}" chmod 0400 "$sec/$f"
  fi
done

mkdir -p config/lists
if [ ! -f config/analyzer.yaml ]; then
  sed -e "s/you@proton\.me/$user/" analyzer/examples/analyzer.yaml > config/analyzer.yaml
  echo "wrote config/analyzer.yaml"
fi
if [ "$model" = off ]; then
  # Only model.enabled, whatever the spacing after it.
  sed -i '/^model:/,/^[^ #]/ s/^\(  enabled:\)[[:space:]]*true\b/\1 false/' config/analyzer.yaml
  echo "No API key: the analyzer uses rules and lists only. You can add a key later in the portal's Settings."
fi
if [ "$provider" != anthropic ]; then
  read -r -p "Model name, exactly as your vendor's console or server shows it: " model_name
  extra=()
  if [ "$provider" = local ]; then
    read -r -p "Server address, e.g. http://192.168.1.50:11434/v1: " ep
    extra+=(--endpoint "$ep")
  else
    echo "The monthly budget cap needs this model's price, from your plan's pricing page:"
    read -r -p "  USD per million input tokens: " pin
    read -r -p "  USD per million output tokens: " pout
    extra+=(--price-in "$pin" --price-out "$pout")
  fi
  bash scripts/analyzer-provider.sh "$provider" --model "$model_name" "${extra[@]}"
fi
if [ ! -f config/lists/curated.yaml ]; then
  # Empty: the example entries (billing@mybank.example...) are for reading, not for a real install.
  cp analyzer/examples/lists/empty.yaml config/lists/curated.yaml
  echo "wrote an empty config/lists/curated.yaml (add senders on the portal's Lists page)"
fi

if [ ! -f config/bridge-cert.pem ]; then
  if [ -f bridge-cert.pem ]; then
    cp bridge-cert.pem config/bridge-cert.pem && echo "copied the pinned bridge-cert.pem to config/"
  elif ! bash scripts/export-cert.sh config/bridge-cert.pem; then
    die "could not export Bridge's certificate. Start Bridge (docker compose up -d) and run this again."
  fi
fi

echo
echo "Ready. Start it with:  docker compose --profile analyzer up -d"
echo "It waits for Bridge on its own and only analyzes mail that arrives from then on."
echo "It only logs what it would do. See: docker compose run --rm --no-deps analyzer log --since 24h"
