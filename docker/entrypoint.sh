#!/usr/bin/env bash
# Entrypoint for the headless Proton Mail Bridge image.
#
#   run          (default) start Bridge non-interactively plus socat forwarders
#   init         first-run setup: create keychain, open the Bridge CLI (login, info)
#   cli          open the Bridge CLI on an existing setup (stop `run` first)
#   export-cert  print Bridge's TLS certificate (PEM) to stdout
#   healthcheck  exit 0 if Bridge is up and answers IMAP and SMTP greetings
#   version      print the Bridge version
set -euo pipefail

BRIDGE_BIN=${BRIDGE_BIN:-/usr/local/lib/proton-bridge/bridge}
BRIDGE_IMAP_PORT=${BRIDGE_IMAP_PORT:-1143}   # where Bridge listens, on 127.0.0.1
BRIDGE_SMTP_PORT=${BRIDGE_SMTP_PORT:-1025}
FORWARD_IMAP_PORT=${FORWARD_IMAP_PORT:-1143} # where socat listens, on FORWARD_BIND_ADDRS
FORWARD_SMTP_PORT=${FORWARD_SMTP_PORT:-1025}
FORWARD_BIND_ADDRS=${FORWARD_BIND_ADDRS:-}   # space separated; empty = every non-loopback IPv4
FORWARD_IMAP=${FORWARD_IMAP:-true}            # turn each forwarder on or off
FORWARD_SMTP=${FORWARD_SMTP:-false}         # SMTP is off unless asked for
FORWARD_MAX_CHILDREN=${FORWARD_MAX_CHILDREN:-32} # per listener; shares pids_limit with Bridge
BRIDGE_RUN_ARGS=${BRIDGE_RUN_ARGS:---noninteractive}
BRIDGE_LOG_LEVEL=${BRIDGE_LOG_LEVEL:-info}
BRIDGE_REQUIRE_INIT=${BRIDGE_REQUIRE_INIT:-true}
# The sign-in broker (broker/): runs Bridge for us and lets the admin portal
# sign it in over /run/broker/broker.sock. Off when its socket folder isn't
# mounted, or with BROKER=off.
BROKER_BIN=${BROKER_BIN:-/usr/local/bin/bridgekeep-broker}
BROKER=${BROKER:-auto}
GPG_KEY_UID=${GPG_KEY_UID:-Proton Bridge (container keychain) <bridge@localhost>}

export GNUPGHOME=${GNUPGHOME:-$HOME/.gnupg}
export PASSWORD_STORE_DIR=${PASSWORD_STORE_DIR:-$HOME/.password-store}
BRIDGE_CONFIG_DIR=$HOME/.config/protonmail/bridge-v3

log() { printf '[entrypoint] %s\n' "$*" >&2; }
die() { log "error: $*"; exit 1; }

check_home() {
  [[ -w $HOME ]] || die "$HOME is not writable by uid $(id -u). If you mount a host folder, chown it to $(id -u):$(id -g)."
  umask 077
}

# Create a passphrase-less GPG key and a pass store on first run. The key
# protects the Bridge vault password at rest inside the volume; the volume
# itself is the secret (see docs/operations.md).
ensure_keychain() {
  check_home
  mkdir -p "$GNUPGHOME"
  chmod 700 "$GNUPGHOME"

  local fpr
  fpr=$(gpg --batch --with-colons --list-secret-keys 2>/dev/null | awk -F: '$1=="fpr"{print $10; exit}')

  if [[ -s $PASSWORD_STORE_DIR/.gpg-id ]]; then
    # Existing keychain: never regenerate, only check it still works.
    [[ -n $fpr ]] || die "pass store exists but its GPG secret key is missing from $GNUPGHOME. Restore the volume from backup; generating a new key would orphan the Bridge vault."
    check_vault_readable
    return
  fi

  # No pass store yet. If Bridge data exists, the keychain was lost: stop.
  if is_initialised; then
    die "Bridge vault exists but the pass store is gone ($PASSWORD_STORE_DIR/.gpg-id missing). Refusing to create a new keychain over it. Restore the volume from backup, or wipe the volume and run init again."
  fi

  if [[ -z $fpr ]]; then
    log "first run: generating keychain GPG key"
    gpg --batch --pinentry-mode loopback --passphrase '' \
      --quick-generate-key "$GPG_KEY_UID" default default never >/dev/null 2>&1 \
      || die "gpg key generation failed"
    fpr=$(gpg --batch --with-colons --list-secret-keys | awk -F: '$1=="fpr"{print $10; exit}')
  fi
  [[ -n $fpr ]] || die "no GPG secret key available"
  log "initialising pass store for key $fpr"
  pass init "$fpr" >/dev/null || die "pass init failed"
}

# Decrypt one stored secret to prove the keychain still opens the vault key.
check_vault_readable() {
  local entry
  entry=$(find "$PASSWORD_STORE_DIR" -name '*.gpg' -type f 2>/dev/null | head -n1)
  if [[ -z $entry ]]; then
    is_initialised && die "Bridge vault exists but the pass store holds no secrets; the vault cannot be unlocked. Restore from backup or re-run init on a fresh volume."
    return 0
  fi
  gpg --batch --quiet --decrypt "$entry" >/dev/null 2>&1 \
    || die "cannot decrypt $entry with the keychain GPG key; the vault is unreadable. Restore the volume from backup."
}

is_initialised() {
  [[ -f $BRIDGE_CONFIG_DIR/vault.enc ]]
}

listen_addrs() {
  if [[ -n $FORWARD_BIND_ADDRS ]]; then
    # shellcheck disable=SC2086  # split the space-separated list
    printf '%s\n' $FORWARD_BIND_ADDRS
  else
    hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.' | grep -v '^127\.' || true
  fi
}

pids=()

start_forwarders() {
  if [[ $FORWARD_IMAP != true && $FORWARD_SMTP != true ]]; then
    log "forwarders disabled"; return
  fi
  local addrs
  mapfile -t addrs < <(listen_addrs)
  ((${#addrs[@]})) || die "no non-loopback address to bind forwarders to; set FORWARD_BIND_ADDRS"
  for a in "${addrs[@]}"; do
    if [[ $FORWARD_IMAP == true ]]; then
      log "forwarding $a:$FORWARD_IMAP_PORT -> 127.0.0.1:$BRIDGE_IMAP_PORT (IMAP)"
      socat "TCP4-LISTEN:$FORWARD_IMAP_PORT,bind=$a,fork,reuseaddr,max-children=$FORWARD_MAX_CHILDREN" "TCP4:127.0.0.1:$BRIDGE_IMAP_PORT" &
      pids+=($!)
    fi
    if [[ $FORWARD_SMTP == true ]]; then
      log "forwarding $a:$FORWARD_SMTP_PORT -> 127.0.0.1:$BRIDGE_SMTP_PORT (SMTP)"
      socat "TCP4-LISTEN:$FORWARD_SMTP_PORT,bind=$a,fork,reuseaddr,max-children=$FORWARD_MAX_CHILDREN" "TCP4:127.0.0.1:$BRIDGE_SMTP_PORT" &
      pids+=($!)
    fi
  done
}

stop_all() {
  log "stopping"
  for p in "${pids[@]}"; do kill -TERM "$p" 2>/dev/null || true; done
  wait || true
}

use_broker() {
  local d=${BROKER_SOCKET_DIR:-/run/broker}
  [[ $BROKER != off && -x $BROKER_BIN ]] || return 1
  [[ -d $d && -w $d ]] && return 0
  # Not quiet: without it the portal can't sign in. Usually broker-sock was
  # created by another container first; `docker volume rm` it and start again.
  [[ -e $d ]] && echo "entrypoint: $d is not writable by $(id -u); running Bridge without the sign-in broker" >&2
  return 1
}

cmd_run() {
  ensure_keychain
  # With the broker, a fresh volume is fine: sign in from the portal.
  if [[ $BRIDGE_REQUIRE_INIT == true ]] && ! is_initialised && ! use_broker; then
    die "Bridge has not been set up in this volume yet. Run the one-time login first:
    docker compose run --rm bridge-init
then start the service again. (Set BRIDGE_REQUIRE_INIT=false to skip this check.)"
  fi

  trap stop_all TERM INT
  start_forwarders

  if use_broker; then
    # The broker starts Bridge, stops it while the CLI signs in, starts it
    # again, and exits if Bridge dies, so the wait below still works.
    BRIDGE_BIN=$BRIDGE_BIN BRIDGE_RUN_ARGS=$BRIDGE_RUN_ARGS BRIDGE_LOG_LEVEL=$BRIDGE_LOG_LEVEL \
      "$BROKER_BIN" </dev/null &
    pids+=("$!")
    log "sign-in broker started (pid $!)"
  else
    # shellcheck disable=SC2086  # BRIDGE_RUN_ARGS is a list of flags
    "$BRIDGE_BIN" $BRIDGE_RUN_ARGS --log-level "$BRIDGE_LOG_LEVEL" </dev/null &
    local bridge_pid=$!
    pids+=("$bridge_pid")
    log "Bridge started (pid $bridge_pid)"
  fi

  # Exit as soon as Bridge or any forwarder dies, so the restart policy kicks in.
  local rc=0
  wait -n "${pids[@]}" || rc=$?
  log "a supervised process exited (status $rc)"
  stop_all
  exit "$(( rc == 0 ? 1 : rc ))"
}

cmd_init() {
  ensure_keychain
  cat >&2 <<'EOF'

  Proton Mail Bridge first-run setup
  ----------------------------------
  At the >>> prompt:
    login      sign in (username, password, then 2FA code if enabled)
    info       show the IMAP/SMTP username and the Bridge-generated password
               (mail clients use THESE, not your Proton password)
    help       if it lists an automatic-updates setting, turn it off: this
               image is updated by rebuilding, not by Bridge downloading
               updates into the volume
    exit       leave; the session is saved in the volume

  Then start the service:  docker compose up -d

  This session's output is not kept in docker logs (log driver "none"),
  because "info" prints the Bridge password. If you started it some other
  way, add --log-driver none.

EOF
  exec "$BRIDGE_BIN" --cli --log-level "$BRIDGE_LOG_LEVEL"
}

cmd_cli() {
  ensure_keychain
  exec "$BRIDGE_BIN" --cli --log-level "$BRIDGE_LOG_LEVEL"
}

cmd_export_cert() {
  local cert
  cert=$(find "$HOME/.config/protonmail" -name cert.pem -type f 2>/dev/null | head -n1)
  [[ -n $cert ]] || die "no cert.pem under ~/.config/protonmail (Bridge 3 keeps it in its vault); use scripts/export-cert.sh, which reads it from the STARTTLS handshake"
  cat "$cert"
}

# Speak just enough of the protocol to see Bridge answer, then sign off
# politely. A bare connect-and-close makes Bridge log "connection reset by
# peer" on every check.
#   probe PORT GREETING_PREFIX GOODBYE_COMMAND
probe() (
  exec 3<>"/dev/tcp/127.0.0.1/$1" || exit 1
  IFS= read -r -t 5 line <&3 || exit 1
  [[ $line == "$2"* ]] || exit 1
  printf '%s\r\n' "$3" >&3
  IFS= read -r -t 5 _ <&3 || true   # wait for the server's goodbye, then close
)

cmd_healthcheck() {
  pgrep -f "$BRIDGE_BIN" >/dev/null || { echo "bridge not running"; exit 1; }
  probe "$BRIDGE_IMAP_PORT" "* OK" "a1 LOGOUT" 2>/dev/null || { echo "IMAP $BRIDGE_IMAP_PORT not answering"; exit 1; }
  probe "$BRIDGE_SMTP_PORT" "220" "QUIT" 2>/dev/null || { echo "SMTP $BRIDGE_SMTP_PORT not answering"; exit 1; }
  echo ok
}

case "${1:-run}" in
  run) cmd_run ;;
  init) cmd_init ;;
  cli) cmd_cli ;;
  export-cert) cmd_export_cert ;;
  healthcheck) cmd_healthcheck ;;
  version) exec "$BRIDGE_BIN" --version ;;
  keychain-init) ensure_keychain; log "keychain ready" ;;
  *) die "unknown command '$1' (run, init, cli, export-cert, healthcheck, version, keychain-init)" ;;
esac
