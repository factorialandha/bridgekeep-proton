#!/usr/bin/env bash
# shellcheck disable=SC2015,SC2016  # a && ok || bad reads fine here; backticks are literal
# Tests scripts/secret-requests.sh (the portal's write-only drop box for the
# API key and webhook) with the curl stand-in: no Discord, no Docker. Runs as
# any user; PORTAL_UID is set to this user so its own files count as the portal's.
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
export BRIDGEKEEP_SECRETS=$work/sec NOTIFY_DIR=$work/notify BRIDGEKEEP_SECRET_REQUESTS=$work/req \
  BRIDGEKEEP_STATUS_DIR=$work/status NOTIFY_CURL=$PWD/tests/notify/curl MOCK_CURL_LOG=$work/curl.log \
  PATH="$work/bin:$PATH"
PORTAL_UID=$(id -u); export PORTAL_UID
mkdir -p "$work/bin" "$work/req" "$work/sec"
printf '#!/bin/sh\nexit 1\n' >"$work/bin/docker"; chmod +x "$work/bin/docker"   # no Docker here
key=sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz012345
hook=https://discord.com/api/webhooks/123456789012345678/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdEfGhIjKlMnOpQrStUvWx
fails=0
ok() { echo "ok: $1"; }
bad() { echo "FAIL: $1"; fails=$((fails + 1)); }
r() { grep "^$1=" "$work/status/secrets.env" | cut -d= -f2-; }
request() { # NAME secret action id [value]
  { printf 'secret=%s\naction=%s\nid=%s\n' "$2" "$3" "$4"; [[ -n ${5:-} ]] && printf 'value=%s\n' "$5"; } >"$work/req/$1.tmp"
  mv "$work/req/$1.tmp" "$work/req/$1.req"
}
apply() { bash scripts/secret-requests.sh apply 2>"$work/err"; }

# A webhook first (configure tests it through the stand-in curl).
request a discord_webhook set 0000aaaa "$hook"; apply
[[ $(cat "$work/sec/discord_webhook") == "$hook" && $(r discord_webhook) == set && $(r discord_webhook_last4) == "${hook: -4}" ]] \
  && ok "webhook installed; status shows set and the last 4" || { bad "webhook install"; cat "$work/err"; }
grep -q 'AbCdEfGhIj' "$work/status/secrets.env" "$work/err" && bad "the webhook leaked into status or the log" || ok "webhook not in status or log"

# The key: the current channel is told first, then it's installed.
rm -f "$MOCK_CURL_LOG"
request b anthropic_api_key set 0000bbbb "$key"; apply
[[ $(cat "$work/sec/anthropic_api_key") == "$key" && $(r anthropic_api_key) == set && $(r anthropic_api_key_last4) == 2345 && $(r anthropic_api_key_result) == ok ]] \
  && ok "key installed" || { bad "key install"; cat "$work/err"; }
grep -q 'Changed from the admin portal: `Claude API key changed, ending 2345`' "$MOCK_CURL_LOG" && ok "alert sent before the key changed" || bad "no alert for the key"
grep -rq "$key" "$work/status" "$work/err" "$MOCK_CURL_LOG" "$work/notify" && bad "the key leaked" || ok "key not in status, log, alert or state"
[[ -z $(ls -A "$work/req") && -z $(ls -A "$work/notify/state/secret-inbox") ]] && ok "requests consumed, inbox empty" || bad "files left"

# secret_changed gets through even when the hourly alert cap is used up.
mkdir -p "$work/notify/state"; for _ in $(seq 10); do echo "$(date +%s) x"; done >"$work/notify/state/sent"
rm -f "$MOCK_CURL_LOG" "$work/notify/state/secret-last-anthropic_api_key"
request b2 anthropic_api_key set 0000bbb2 "$key"; apply
grep -q 'Claude API key changed' "$MOCK_CURL_LOG" && ok "secret_changed is never capped" || bad "secret_changed capped"

# At most one change per secret per 10 minutes.
request c anthropic_api_key set 0000cccc "sk-ant-api03-ZZZZZZZZZZZZZZZZZZZZZZZZZZ"; apply
[[ $(cat "$work/sec/anthropic_api_key") == "$key" && $(r anthropic_api_key_result) == refused:* && $(r anthropic_api_key_id) == 0000cccc ]] \
  && ok "second change within 10 minutes refused" || bad "rate limit ($(r anthropic_api_key_result))"
rm -f "$work/notify/state/secret-last-anthropic_api_key"

# Bad formats are refused with a reason; nothing changes.
request d anthropic_api_key set 0000dddd 'sk-ant-short'; apply
[[ $(cat "$work/sec/anthropic_api_key") == "$key" && $(r anthropic_api_key_result) == "refused: not a Claude API key (sk-ant-...)" ]] \
  && ok "malformed key refused" || bad "malformed key ($(r anthropic_api_key_result))"
rm -f "$work/notify/state/secret-last-discord_webhook"
request e discord_webhook set 0000eeee 'https://evil.example/api/webhooks/1/x'; apply
[[ $(cat "$work/sec/discord_webhook") == "$hook" && $(r discord_webhook_result) == "refused: not a Discord webhook URL" ]] && ok "non-Discord webhook refused" || bad "webhook format"

# A new webhook: the old channel is told, then the new one.
rm -f "$MOCK_CURL_LOG"
hook2=https://discord.com/api/webhooks/223456789012345678/ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210_-ZyXwVuTsRqPoNmLkJiHgFeDc
request e2 discord_webhook set 0000eee2 "$hook2"; apply
[[ $(grep -c '^url = ' "$MOCK_CURL_LOG") == 3 && $(sed -n 1p "$MOCK_CURL_LOG") == "url = \"$hook\"" && $(cat "$work/sec/discord_webhook") == "$hook2" ]] \
  && ok "webhook change: old channel told, new one tested and told" || { bad "webhook change alerts"; cat "$MOCK_CURL_LOG"; }
hook=$hook2
request f anthropic_api_key frobnicate 0000ffff; apply
[[ $(r anthropic_api_key_id) == 0000eeee || $(r anthropic_api_key_id) == 0000dddd ]] && grep -q "isn't one the portal may make" "$work/err" \
  && ok "unknown action ignored" || bad "unknown action"

# A symlink, a hard link and a big file are not acted on.
printf 'value=%s\n' "$key" >"$work/target"
ln -s "$work/target" "$work/req/s.req"
ln "$work/target" "$work/req/h.req"
head -c 2000 /dev/zero | tr '\0' a >"$work/req/big.req"
apply
[[ $(grep -c "isn't a small regular file" "$work/err") == 3 && -f $work/target && -z $(ls -A "$work/req") ]] \
  && ok "symlink, hard link and oversized requests ignored" || { bad "link checks"; cat "$work/err"; }

# Remove: the key file stays (compose needs it) but is empty; status says off.
request g anthropic_api_key remove 0000a0a0; apply
[[ -f $work/sec/anthropic_api_key && ! -s $work/sec/anthropic_api_key && $(r anthropic_api_key) == off && -z $(r anthropic_api_key_last4) ]] \
  && ok "key removed, empty file kept" || bad "key remove"

# Test alert, rate-limited.
rm -f "$MOCK_CURL_LOG"
request t1 test_alert test 0000b0b0; apply
request t2 test_alert test 0000c0c0; apply
[[ $(grep -c '^url = ' "$MOCK_CURL_LOG") == 1 && $(r test_alert_result) == "wait "* ]] && ok "test alert sent once, then rate-limited" || bad "test alert"

# Webhook remove turns alerts off.
request w discord_webhook remove 0000d0d0; rm -f "$work/notify/state/secret-last-discord_webhook"; apply
[[ ! -e $work/sec/discord_webhook && $(r discord_webhook) == off ]] && ok "webhook removed" || bad "webhook remove"

# The status file is the portal's to read: 0640.
[[ $(stat -c %a "$work/status/secrets.env") == 640 ]] && ok "status file 0640" || bad "status mode"

# AI vendor: analyzer-provider.sh gets the fields as arguments and the key on stdin only.
cat >"$work/bin/provider-stub" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$STUB_LOG"
IFS= read -r key || true; printf 'stdin=%s\n' "$key" >>"$STUB_LOG"
[[ $1 == gemini && -z $key ]] && { echo "analyzer-provider: no API key for Google Gemini; nothing changed" >&2; exit 1; }
exit 0
STUB
chmod +x "$work/bin/provider-stub"
export ANALYZER_PROVIDER_SH=$work/bin/provider-stub STUB_LOG=$work/stub.log
okey=sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz012345
{ printf 'secret=ai_vendor\naction=set\nid=0000e0e0\nprovider=openai\nmodel=gpt-5-mini\nendpoint=\nprice_in=0.25\nprice_out=2\nvalue=%s\n' "$okey"; } >"$work/req/v1.req"; apply
[[ $(sed -n 1p "$STUB_LOG") == "openai --model gpt-5-mini --price-in 0.25 --price-out 2 --key-stdin --yes" \
   && $(sed -n 2p "$STUB_LOG") == "stdin=$okey" && $(r ai_vendor_result) == ok && $(r ai_vendor_provider) == openai ]] \
  && ok "vendor switched: fields as arguments, key on stdin" || { bad "vendor switch"; cat "$STUB_LOG" "$work/err"; }
grep -rq "$okey" "$work/status" "$work/err" && bad "the vendor key leaked" || ok "vendor key not in status or log"
request v2 ai_vendor set 0000e0e1; apply
[[ $(r ai_vendor_result) == refused:*minutes* ]] && ok "vendor change rate-limited" || bad "vendor rate limit ($(r ai_vendor_result))"
rm -f "$work/notify/state/secret-last-ai_vendor" "$STUB_LOG"
printf 'secret=ai_vendor\naction=set\nid=0000e0e2\nprovider=gemini\nmodel=gemini-2.5-flash\nprice_in=0.3\nprice_out=2.5\n' >"$work/req/v3.req"; apply
[[ $(r ai_vendor_result) == "refused: no API key for Google Gemini, nothing changed" && $(r ai_vendor_provider) == openai ]] \
  && ok "vendor refusal reason shown, nothing changed" || bad "vendor refusal ($(r ai_vendor_result))"
rm -f "$STUB_LOG"
printf 'secret=ai_vendor\naction=set\nid=0000e0e3\nprovider=local\nmodel=--endpoint\nendpoint=http://10.0.0.5:11434/v1\n' >"$work/req/v4.req"; apply
printf 'secret=ai_vendor\naction=set\nid=0000e0e4\nprovider=local\nmodel=llama3\nendpoint=--yes\n' >"$work/req/v5.req"; apply
[[ ! -e $STUB_LOG && $(r ai_vendor_result) == refused:* ]] && ok "option-like model or endpoint never reaches the script" || bad "vendor field checks"

# A request folder inside the checkout is refused.
BRIDGEKEEP_SECRET_REQUESTS=$PWD/req bash scripts/secret-requests.sh apply 2>/dev/null && bad "accepted a folder inside the checkout" || ok "folder inside the checkout refused"

(( fails == 0 )) || { echo "$fails secret-request test(s) failed"; exit 1; }
echo "all secret-request tests passed"
