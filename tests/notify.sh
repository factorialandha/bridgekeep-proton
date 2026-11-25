#!/usr/bin/env bash
# shellcheck disable=SC2015,SC1003,SC2016  # a && ok || bad reads fine here
# Tests scripts/notify.sh with a stand-in for curl (tests/notify/curl): no
# Discord, no network. Runs as any user; CI runs it in the signin job's image.
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
export BRIDGEKEEP_SECRETS=$work/sec NOTIFY_DIR=$work/notify NOTIFY_CURL=$PWD/tests/notify/curl MOCK_CURL_LOG=$work/curl.log
hook=https://discord.com/api/webhooks/123456789012345678/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdEfGhIjKlMnOpQrStUvWx
fails=0
ok() { echo "ok: $1"; }
bad() { echo "FAIL: $1"; fails=$((fails + 1)); }
n() { [[ -f $MOCK_CURL_LOG ]] && grep -c '^url = ' "$MOCK_CURL_LOG" || echo 0; }

# Not configured: send logs and exits 0, nothing goes out.
bash scripts/notify.sh send update_waiting 3.28.0 2>"$work/err" && [[ $(n) == 0 ]] && grep -q 'no Discord webhook' "$work/err" \
  && ok "no webhook: logged only, exit 0" || bad "no webhook"
[[ $(bash scripts/notify.sh status) == off ]] && ok "status off" || bad "status off"

# configure rejects a non-Discord URL and saves nothing.
if printf 'https://evil.example/api/webhooks/1/x\n' | bash scripts/notify.sh configure 2>/dev/null; then bad "accepted a non-Discord URL"
elif [[ -e $work/sec/discord_webhook ]]; then bad "saved a rejected URL"; else ok "configure refuses a non-Discord URL"; fi

# configure: a failed test message saves nothing.
if printf '%s\n' "$hook" | MOCK_CURL_FAIL=1 bash scripts/notify.sh configure 2>/dev/null || [[ -e $work/sec/discord_webhook ]]; then
  bad "saved a webhook whose test failed"; else ok "configure saves nothing when the test fails"; fi
rm -f "$MOCK_CURL_LOG"

# configure: test sent, then saved privately.
printf '%s\n' "$hook" | bash scripts/notify.sh configure 2>/dev/null
want="600 $(id -u)"; [[ $(id -u) == 0 ]] && want="400 0"
[[ $(stat -c '%a %u' "$work/sec/discord_webhook") == "$want" && $(cat "$work/sec/discord_webhook") == "$hook" && $(n) == 1 ]] \
  && ok "configure: test sent, webhook saved as $want" || bad "configure save ($(stat -c '%a %u' "$work/sec/discord_webhook" 2>/dev/null))"
[[ $(bash scripts/notify.sh status) == "on (Discord)" ]] && ok "status on, without printing the URL" || bad "status on"
bash scripts/notify.sh status | grep -q webhooks && bad "status printed the URL"

# The URL reaches curl on stdin only, never in its arguments.
grep '^ARGS' "$MOCK_CURL_LOG" | grep -q webhooks && bad "webhook URL in curl's arguments" || ok "webhook URL only on curl's stdin"
grep -q '"parse\\": \[\]' "$MOCK_CURL_LOG" && ok "mentions are switched off" || bad "allowed_mentions missing"

# send: once, then deduplicated; a new detail goes out.
rm -f "$MOCK_CURL_LOG"
bash scripts/notify.sh send update_waiting 3.28.0 2>/dev/null
bash scripts/notify.sh send update_waiting 3.28.0 2>/dev/null
[[ $(n) == 1 ]] && ok "same alert twice: sent once" || bad "dedup ($(n) sent)"
bash scripts/notify.sh send update_waiting 3.29.0 2>/dev/null
[[ $(n) == 2 ]] && ok "new detail: sent again" || bad "new detail ($(n) sent)"
grep -q 'Bridge `3.29.0` is built and tested' "$MOCK_CURL_LOG" && ok "fixed wording with the detail" || bad "wording"

# Details are cleaned: no quotes, backslashes, mentions, markup or newlines.
rm -f "$MOCK_CURL_LOG"
bash scripts/notify.sh send health_failed $'bridge "x" \\ @everyone <a href=y>\nline2' 2>/dev/null
c=$(grep '^data-binary' "$MOCK_CURL_LOG" | sed 's/\\"/Q/g')
[[ $c != *'"x"'* && $c != *@* && $c != *'<'* && $c != *'\\'* && $(grep -c '' "$MOCK_CURL_LOG") == 3 ]] \
  && ok "detail cleaned" || { bad "detail not cleaned"; cat "$MOCK_CURL_LOG"; }

# Unknown events are not sent.
rm -f "$MOCK_CURL_LOG"
bash scripts/notify.sh send rm_rf_everything x 2>/dev/null
[[ $(n) == 0 ]] && ok "unknown event not sent" || bad "unknown event sent"

# Rate cap.
rm -f "$MOCK_CURL_LOG"
for i in 1 2 3 4; do MAX_PER_HOUR=3 bash scripts/notify.sh send health_failed "case $i" 2>/dev/null; done
[[ $(n) -le 3 ]] && ok "at most MAX_PER_HOUR an hour" || bad "rate cap ($(n) sent)"
rm -f "$work/notify/state/sent" "$work/notify/state"/last-*

# Discord down: send still exits 0.
MOCK_CURL_FAIL=1 bash scripts/notify.sh send login_expired x 2>/dev/null && ok "Discord down: exit 0" || bad "Discord down broke the caller"

# flush: allowed events go out and the file is removed; others are dropped.
rm -f "$MOCK_CURL_LOG"; rm -f "$work/notify/state"/last-*
sp=$work/notify/spool; mkdir -p "$sp/analyzer" "$sp/portal"
printf 'event=budget_cap\ndetail=monthly cap 5 USD\n' >"$sp/analyzer/a1.alert"
printf 'event=update_waiting\ndetail=9.9\n' >"$sp/analyzer/a2.alert"     # not the analyzer's to send
printf 'event=login_expired\ndetail=broker https://x.example/y\n' >"$sp/portal/p1.alert"
printf 'event=budget_cap\n' >"$sp/analyzer/half.tmp"                       # still being written: left alone
head -c 2000 /dev/zero | tr '\0' a >"$sp/analyzer/big.alert"
ln -s "$work/sec/discord_webhook" "$sp/analyzer/steal.alert"
bash scripts/notify.sh flush 2>"$work/err"
[[ $(n) == 2 ]] && grep -q 'analyzer: monthly cap 5 USD' "$MOCK_CURL_LOG" && grep -q '(`portal: broker https://x.example/y`)' "$MOCK_CURL_LOG" \
  && ok "flush sends allowed events with their source" || { bad "flush sent $(n)"; cat "$work/err"; }
grep -q 'ignored .update_waiting. from analyzer' "$work/err" && ok "flush drops events a folder may not send" || bad "flush allowlist"
grep -qF '9.9' "$MOCK_CURL_LOG" && bad "flush sent a disallowed event"   # -F: a random hex hostname can match 9.9 as a regex
grep -q "$hook" <(grep '^data-binary' "$MOCK_CURL_LOG") && bad "a symlink leaked the webhook" || ok "a symlinked alert file is not followed"
[[ -z $(find "$sp" -name '*.alert') && -f $sp/analyzer/half.tmp ]] && ok "flush empties the spool, leaves .tmp files" || bad "spool left: $(ls -A "$sp"/*)"
[[ -z $(ls -A "$work/notify/state/inbox") ]] && ok "nothing left in the inbox" || bad "inbox not empty"

# A URL in a detail only ever appears inside inline code (never a link).
grep -q '`[^`]*https://x.example/y`' "$MOCK_CURL_LOG" && ! sed 's/`[^`]*`//g' "$MOCK_CURL_LOG" | grep -q x.example \
  && ok "links in details are shown as inline code" || bad "a detail URL is outside inline code"

# Each spool folder has its own hourly cap.
rm -f "$MOCK_CURL_LOG" "$work/notify/state"/last-* "$work/notify/state"/sent*
for i in 1 2 3 4; do printf 'event=budget_cap\ndetail=n%s\n' "$i" >"$sp/analyzer/c$i.alert"; done
MAX_PER_HOUR=2 bash scripts/notify.sh flush 2>"$work/err"
[[ $(n) == 2 ]] && grep -q 'analyzer already sent 2 alerts this hour' "$work/err" && ok "per-folder hourly cap" || bad "per-folder cap ($(n) sent)"

# State inside the checkout is refused.
NOTIFY_DIR=$PWD/.notify-test-$$ bash scripts/notify.sh send test 2>"$work/err" && bad "state inside the checkout accepted" \
  || { grep -q 'outside the checkout' "$work/err" && [[ ! -e .notify-test-$$ ]] && ok "state inside the checkout refused"; }

if (( fails > 0 )); then echo "$fails notify test(s) failed"; exit 1; fi
echo "notify tests passed"
