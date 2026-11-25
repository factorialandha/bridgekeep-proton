# AI email analyzer

**Using the analyzer?** Read [docs/analyzer.md](../docs/analyzer.md). You set
it up with `./bridgekeep setup --analyzer` and change everything in the admin
portal. This file is the developer reference: internals, the offline
evaluation tool, and the files the portal writes.

Classifies mail with Claude Haiku 5.5 (or another vendor) and records what it
**would** do. In shadow mode, the default, that is all: nothing moves. In
live mode, switched on in the portal, new mail it flags moves into the
AI-Review or AI-Quarantine folder (never Trash, never deleted), and a "Not
spam" answer moves it back (see [Live mode](#live-mode)). `check` and `eval` read
`.eml` files and `.mbox` exports; `run` watches the inbox through Bridge,
through `imap-proxy`, which holds the Bridge password and forwards only a
short list of commands. `egress-proxy` is its only way out
to the internet, and it allows the Claude API only. All three run next to
Bridge with `docker compose --profile analyzer up -d` (below). See the scoping doc, section 6A.

## What happens to each message

1. **Extract** (`extract.py`, `text.py`). Sender, subject, Proton's
   authentication result, link domains, attachment types and up to 3,000
   characters of visible body text. HTML is turned into plain text; hidden
   text (`display:none`, zero-size fonts, white on white, comments) and
   zero-width characters are removed. Attachments are never opened. Size,
   part-count, depth and time limits apply; a message that hits one is left
   alone.
2. **Check authentication** (`auth.py`). Only the topmost
   `Authentication-Results` header is read, and only if Proton's server
   wrote it. A sender counts as verified only when DMARC passed for exactly
   the From domain.
3. **Pre-scan** (`prescan.py`). Looks for text aimed at AI filters ("ignore
   previous instructions", fake system messages, fake delimiters, base64
   payloads), including in the hidden text removed in step 1.
4. **Lists** (`lists.py`). A DMARC-verified match on your never-trash list
   skips the model and keeps the message. A verified blocklist match skips
   the model and would quarantine it.
5. **Classify** (`classify.py`). One isolated request per message, no tools,
   fields wrapped in random-token delimiters, JSON schema enforced by the API
   and checked again in code. Any error, refusal or odd answer means "keep".
6. **Decide** (`decide.py`). Spam or phishing at 0.97 or above: quarantine.
   From 0.70: review. Everything else: keep. Then the safety rules, which can
   only lower the action: a protected sender that is not verified goes to
   review at most, a protected subject keyword is never quarantined, and a
   "legitimate" verdict on a message with an injection attempt or failed
   DMARC goes to review. A lookalike of a protected domain goes to review.
7. **Log** (`store.py`). SQLite: sender, subject, label, confidence, the
   model's reason and the rule that acted. Never the body. 90-day retention.

The model sees only the output of `Extracted.model_fields()`.
`analyzer check --show-fields` prints exactly that for any message.

## Run the offline test on your own mail (Linux or WSL)

Export a few hundred messages as `.eml` files (Proton web: open a message,
More, Export; or save from a mail client) and sort them into folders by what
they really are:

```
mail-eval/
  legitimate/   promotional/   spam/   phishing/   adversarial/
```

Copy `tests/fixtures/adversarial/*.eml` into `adversarial/`, and add any real
injection attempts you find. Then, from the repo root:

```bash
make analyzer-build
make analyzer-init        # stores your API key (typed without echo) in /etc/bridgekeep/secrets
sec=${BRIDGEKEEP_SECRETS:-/etc/bridgekeep/secrets}

# Rules only, no API calls:
docker run --rm --network none -v "$PWD/mail-eval:/mail:ro" \
  proton-analyzer:local eval --no-model --db :memory: /mail

# With Claude Haiku 5.5 (about $0.0001 per message):
docker run --rm -v "$PWD/mail-eval:/mail:ro" \
  -v "$sec/anthropic_api_key:/run/secrets/anthropic_api_key:ro" \
  -v "$PWD/analyzer/examples/lists:/config/lists:ro" \
  -v analyzer-eval:/data proton-analyzer:local eval /mail
```

The pass bar is **zero** legitimate or promotional messages quarantined, and
no adversarial message kept as legitimate. `eval` exits non-zero otherwise.
The run also prints a confusion table and how much spam would have been
caught. On Windows, run these in WSL, not Git Bash.

To see one message in detail, including the authserv-id Proton stamped
(check it is under `protonmail.ch` or `proton.me`; if not, set
`trusted_authserv` in the config):

```bash
docker run --rm -v "$PWD/mail-eval:/mail:ro" \
  -v "$sec/anthropic_api_key:/run/secrets/anthropic_api_key:ro" \
  proton-analyzer:local check --show-fields --db :memory: /mail/legitimate/some-message.eml
```

## Running it next to Bridge (Linux or WSL)

Bridge must be logged in and healthy first (`docs/testing.md`, steps 1 to 3).
Then, from the repo root:

```bash
make analyzer-build
make analyzer-init        # asks for the Bridge username and password from `info`, and an optional API key
docker compose --profile analyzer up -d
docker compose --profile analyzer ps          # all four should say healthy within a few minutes
```

`analyzer-init` writes `config/` in the checkout (settings, your
never-trash list, Bridge's certificate; git-ignored, nothing secret) and the
secrets (Bridge username and password, API key, a random proxy token)
**outside the checkout**, in `/etc/bridgekeep/secrets`. That folder is
root-only (0700) and each file is owned by the containers' user (10002),
mode 0400. Set `BRIDGEKEEP_SECRETS` in `.env` to put them elsewhere. It uses
sudo for this when you are not root, never overwrites a file that exists,
and reads secrets without echo, so they stay out of shell history.

The API key is optional: press Enter and the analyzer runs on rules and
lists only. To add one later, enter it on the portal's Analyzer page.

`bridgekeep setup` runs `scripts/analyzer-init.sh --non-interactive`, which
never prompts: it uses the Bridge username and password setup saved, skips
the API key, and fails with a clear message if anything else is missing.

**Upgrading from an earlier version** that kept secrets in `./secrets`: run
`make analyzer-init` again. It moves each file to `/etc/bridgekeep/secrets`,
deletes the old copy and removes the empty `./secrets` folder. If that folder was ever synced, backed up or
copied anywhere (OneDrive, a NAS snapshot, another machine), rotate the
Anthropic API key and, if you can, the Bridge password: deleting the files
here does not reach those copies.

Watch what it would do:

```bash
docker compose --profile analyzer logs -f analyzer
docker compose run --rm --no-deps analyzer log --since 24h
docker compose run --rm --no-deps analyzer log 12        # one decision in full
```

Kill switch: `touch config/PAUSE` stops all analysis within one poll, and
`rm config/PAUSE` resumes. Stop everything with
`docker compose --profile analyzer down` (Bridge keeps running if you start
it again with plain `docker compose up -d`).

What the containers can reach:

| Container | Networks | Reaches | Secrets |
| --- | --- | --- | --- |
| `analyzer` | `analyzer-imap`, `analyzer-api` (both internal) | `imap-proxy`, `egress-proxy`, nothing else | API key, proxy token |
| `imap-proxy` | `mail` (internal), `analyzer-imap` | Bridge IMAP | Bridge password, proxy token |
| `egress-proxy` | `analyzer-api`, `api-egress` | `api.anthropic.com:443` only | none |

All three are read-only, drop every capability, run as UID 10002 and have
memory and process limits. Checked with Dovecot standing in for Bridge: mail
was analyzed through both proxies, and from inside `analyzer` the names
`bridge` and `api.anthropic.com` did not even resolve, `1.1.1.1` was
unreachable, and `/run/secrets` held no Bridge password.

## The IMAP allowlist proxy (`analyzer imap-proxy`)

The analyzer never holds the Bridge password, which can read, delete and
send everything (security review A1). It logs in to the proxy with a
separate random token. The proxy logs in to Bridge itself, over STARTTLS
with Bridge's pinned certificate, and forwards only:

- CAPABILITY, NOOP, LOGOUT (CAPABILITY is answered by the proxy itself)
- `EXAMINE` on the folders in `imap_proxy.folders` (default: INBOX only)
- `UID SEARCH ALL` and `UID SEARCH UID n:m`
- `UID FETCH` of UID, FLAGS, RFC822.SIZE, INTERNALDATE, ENVELOPE,
  BODYSTRUCTURE and `BODY.PEEK[...]` (never `BODY[]`, which marks mail read)

In live mode only, it also forwards SELECT, CREATE and `UID MOVE` of one
message between INBOX and the two AI folders, each checked again by the proxy
itself (see [Live mode](#live-mode)). Everything else (STORE, COPY, EXPUNGE,
DELETE, APPEND, IDLE, other folders, literals) is answered with NO and never
reaches Bridge. Three
refused commands end the session, since the analyzer never sends one. A
wrong token gets three tries. The link from the analyzer to the proxy is
plain text, on a Docker network only those two containers join.

`make analyzer-init` creates the token (`analyzer_imap_token` in the secrets folder). It
opens nothing but the allowlist.

Tested against Dovecot 2.3 over STARTTLS: new mail was analyzed, no message
was marked read, STORE, `BODY[]` and EXPUNGE were refused, and a wrong
certificate was refused.

## The egress proxy (`analyzer egress-proxy`)

The analyzer's networks have no route out (security review A2). The only
exit is this proxy, which accepts `CONNECT api.anthropic.com:443` and
nothing else: no other host or port, no plain HTTP, no names that resolve to
private or loopback addresses, and no tunnel over 64 MB or idle for two
minutes. TLS runs end to end to the API, so the proxy never sees mail
content; it logs only the host and byte counts. The analyzer uses it when
`model.proxy` is set, and ignores `HTTPS_PROXY` and similar variables.

Checked from the cloud: a call through the proxy reached the real API (and
was refused for the test key), and `example.com` was refused.

Accepted risk: the proxy cannot tell your key from someone else's. A fully
compromised analyzer could still send what it can read (new mail's
extracted fields) to `api.anthropic.com` under an attacker's key, for
example through the Files API. The proxy's byte limit, the analyzer's
read-only IMAP access and the absence of the Bridge password keep that
small, and it is why the analyzer only parses mail in a stdlib-only,
capability-free container.

## Watching the inbox (`analyzer run`)

`run` polls Bridge every `poll_seconds` and logs a decision for each new
message. In shadow mode it cannot change the mailbox:

- The folder is opened with `EXAMINE`, so the server refuses changes for the
  whole session, and messages are read with `BODY.PEEK`, so nothing is
  marked read.
- The client refuses to send anything but CAPABILITY, NOOP, LOGIN, LOGOUT,
  STARTTLS, EXAMINE, UID SEARCH and UID FETCH, and the proxy enforces the
  same list again on its side.
- The first run starts at the newest message: mail already in the inbox is
  never analyzed or sent to the model.
- If UIDVALIDITY changes it starts again from new mail, with no replay.
- The proxy's TLS to Bridge trusts only Bridge's exported certificate
  (`make cert`). To skip the proxy in a test, set `imap.tls: starttls` and
  point `imap.host` at Bridge.
- If IMAP keeps failing for 15 minutes, `analyzer health` reports
  `bridge_unreachable` with the command to sign Bridge in again.

It was tested against a real IMAP server (Dovecot), not against Bridge yet.

## Older mail (`analyzer backfill`)

Normally only mail that arrives after go-live is analyzed. "Arrives" is
Proton's own receive time (IMAP INTERNALDATE, which Bridge takes from
Proton's message time, not from the sender's Date header), so a sender cannot
backdate mail to dodge analysis. If the date can't be read, the message is
held and retried, never skipped. To look at mail
that was already in the inbox, ask for an estimate first, then confirm it.
Nothing older is read or sent anywhere until you do. It stays log-only.

```bash
./bridgekeep backfill estimate --since 2026-01-01 --limit 5000
#  Backfill 3f9a1c: estimated
#    4200 messages; 310 settled by your lists without the model
#    Estimated 3890 model calls, about $0.86 ($0.00022 a call, average so far)
#    Budget left this month: $17.40 of $20.00 (10% is kept for new mail)
#    At the rate limits (90/hour, 750/day for backfill) it takes about 5 days (125 hours)
#    To run it: ./bridgekeep backfill start 3f9a1c
./bridgekeep backfill start 3f9a1c
./bridgekeep backfill status     # also: pause, resume, cancel
```

- The estimate reads headers only. It prices each call at the average cost
  so far, or at a cautious default until there are 20 real calls.
- `start` needs the id of an estimate less than a day old. If the estimate
  is more than the budget left, it also needs `--allow-partial`, and it then
  stops at the reserve.
- The running analyzer does the work, newest first, a few messages each poll
  after new mail. It keeps a quarter of the hourly and daily call limits and
  10% of the monthly budget for new mail. At the budget reserve it waits and
  carries on from the 1st. Raise `limits.max_per_hour` and `max_per_day` to make it faster.
- A message that is already in the log is never analyzed twice. The kill
  switch pauses it too.
- The admin portal does the same by writing `config/portal/backfill-request.json`
  (`{"id": "...", "action": "estimate|start|pause|resume|cancel", "since": "YYYY-MM-DD",
  "until": "...", "limit": N, "estimate_id": "...", "allow_partial": false}`),
  and it reads progress from `/data/backfill.json`.

## Alerts

The analyzer queues `budget_cap` once a month when it reaches the budget,
and imap-proxy queues `login_expired` once per outage when Bridge refuses
its sign-in. The host sends them to Discord (see `docs/alerts.md`). The
analyzer itself has no route to Discord.

## Settings and corrections from the portal

Everything you change day to day is changed in the admin portal, never by
editing files. Under the hood the portal writes three files into its own
folder (`/config/portal` here), and the analyzer picks each one up within one poll:

- `portal.yaml`: your never-trash and always-junk lists. Junk entries from the
  portal are exact addresses only.
- `settings.yaml`: model on/off, monthly budget ($0 to $1,000), the quarantine
  and review thresholds, hourly and daily model limits, and how often to
  check the inbox. Anything else in the file is ignored. A value out of range
  keeps the one from before and shows up in `settings_problems`.
- `feedback.jsonl`: your "not spam" / "spam" answers on single messages. For
  mail from a DMARC-verified domain, the model is told how you answered for
  that domain before. Once you have said "not spam" twice for a verified
  domain and never "spam", its mail is never quarantined, only sent to
  review at most. A spoofed copy that fails DMARC gets none of this.
  Clearing an answer in the portal removes it again (the portal writes
  `"label": "withdrawn"` for that message).

With no API key (none set yet, or removed in the portal) the analyzer keeps
running on rules and lists only, and status shows `no_key`.

## Choosing the AI vendor

Anthropic (Claude) is the default. You can switch to OpenAI, Google Gemini,
or a model on your own network (Ollama, LM Studio, llama.cpp, or anything
OpenAI-compatible) in the portal's Settings, or in `./bridgekeep setup`.
On the host the switch is done by `scripts/analyzer-provider.sh`, which:

- Keeps one key file per vendor (`anthropic_api_key`, `openai_api_key`,
  `gemini_api_key`, `local_api_key`). A key is never sent to another vendor.
- Points the egress proxy at that vendor's one host only, or at your local
  server's IP and port. A name is looked up once and the address pinned.
  The proxy refuses this machine, link-local addresses, Docker's own
  networks (Bridge's above all), ports Bridgekeep publishes, and Bridge's
  ports. Plain http is only allowed inside your network, and then mail
  crosses it unencrypted.
- Sends an "AI vendor changed" alert to your Discord channel before the
  switch.
- Uses the same prompt, the same fields and the same checks on the answer for
  every vendor. An answer is read up to 64 KB, redirects are never followed,
  and only the label, confidence and reason come out.

Who sees your mail: the vendor you choose receives the fields listed in
"What happens to each message". Check your plan's data-use terms. Google's
free Gemini tier and some OpenAI settings may use API data to improve their
products, so use a paid plan with data sharing off, or zero retention. A
local server keeps everything at home.

Prices: Claude Haiku's price is built in. For OpenAI and Gemini you enter
your plan's price per million tokens when you pick the model, because those
prices change and differ by plan. Until you do, the model isn't used (status
shows `no_price`). Local models cost $0, but the hourly and daily limits
still apply. Spend is tracked per vendor and model, so the backfill estimate
uses the right price.

## Unsubscribe

The portal shows an **Unsubscribe** button only where it will work and is
safe to use:

- DMARC passed for the sender, signed (DKIM) by that same domain.
- The sender offers standard one-click unsubscribe (RFC 8058), at an https
  address under that domain.
- The mail was not judged spam or phishing, and nothing else about it looked
  off.

Nothing ever confirms your address any other way. The analyzer only notes
the offer. When you press the button, the separate `unsubscribe` service
sends one standard unsubscribe request and nothing else: no images, no other
links, no redirects, never to an address inside your network. It tries at
most once per message and makes at most 20 requests a day. If the sender only
offers an email address for unsubscribing, the portal shows that address so
you can send the email yourself. Nothing here sends mail as you.

## Live mode

Shadow mode logs what the analyzer would do. Live mode does it: you switch it
on in the portal's Analyzer page (password again, an audit entry, and a
Discord alert), and switch it off there, with Pause, or on the host with
`./bridgekeep analyzer shadow`, which works with the portal down. The switch
is `<portal dir>/mode.json` (`mode.py`); anything odd about that file means
shadow.

What moves, and where:

- **Review** goes to `Folders/AI-Review`, **quarantine** to
  `Folders/AI-Quarantine` in Proton. The analyzer creates the two folders.
  Nothing goes to Trash, nothing is deleted or expunged, nothing is marked
  read. What you keep in those folders, and for how long, is up to you.
- Only mail analyzed in live mode that Proton received after the switch.
  Mail logged in shadow mode, backfilled mail and older mail never move.
- Never a sender on your protect list (also when it is on the block list
  too), and never mail whose subject has a protected keyword (codes,
  password resets): those stay in INBOX. A sender you've marked "not spam"
  twice goes to review at most.
- At most `limits.max_moves_per_day` moves a day (default 200, portal
  Analyzer page). Then log only until midnight UTC, and one alert.
- mode.json and PAUSE are read again right before every move.

**Not spam moves it back.** A legitimate or promotional answer in the portal
on a moved message moves it back to INBOX at the next poll, and it isn't
analyzed again. Every move and move back is in the `moves` table: the
decision, from and to folders, and where the message is now (from the
server's COPYUID).

The IMAP proxy checks all of it again for itself (security review of live
mode): it reads mode.json and PAUSE for every SELECT INBOX, CREATE and
UID MOVE; a uid is one number and folder names are compared exactly; it moves
mail back to INBOX only if it moved it there itself (its undo ledger); and it
keeps its own daily count on the `imap-proxy-state` volume, refusing the move
if it can't write it. In live mode, any refused command sends an
`imap_refused` alert (at most one an hour).

health.json shows `mode`, `mode_requested`, `mode_problem`, `live_since`,
`moved_today`, `moved_back_today`, `move_cap`, `shadow_since`, `would_review`,
`would_quarantine` and `agreement` for the portal's confirm page.

## Commands

| Command | What it does |
| --- | --- |
| `analyzer check PATH...` | Analyze files, folders or `.mbox` exports. `--no-model`, `--json`, `--show-fields` |
| `analyzer eval DIR` | Score a labeled folder set (above) |
| `analyzer lists lint [--lists DIR]` | Check `curated.yaml` and `learned.yaml`; exit 1 on any problem |
| `analyzer log [--since 24h] [--action quarantine] [ID]` | Show logged decisions |
| `analyzer feedback [--json]` | How the model compares with your corrections in the portal |
| `analyzer run [--once]` | Watch the inbox via Bridge and log decisions (read-only) |
| `analyzer backfill estimate\|start\|pause\|resume\|cancel\|status` | Analyze older mail, after a confirmed estimate (above) |
| `analyzer imap-proxy` | Run the IMAP allowlist proxy in front of Bridge |
| `analyzer egress-proxy` | Run the outbound proxy that allows only the Claude API |
| `analyzer unsubscribe-service` | Run the one-click unsubscribe service the portal calls (above) |
| `analyzer health` | Exit 0 if the last poll worked recently (for the healthcheck) |
| `analyzer config` | Print the effective configuration and mode |

## Configuration

`examples/analyzer.yaml` documents every setting, and `examples/lists/` shows
the list format. Paths below are on the host unless they start with `/`
(in the container). The never-trash list and blocklist come from
`config/lists/curated.yaml` (yours, edited by hand), `config/portal/portal.yaml`
(written by the admin portal, same format and trust) and `learned.yaml` (exact
addresses only, lower trust). Changes to any of them are picked up within
one poll.

The decision log is `/data/analyzer.db` (SQLite, rollback journal, so it can
be opened read-only). `state.schema_version` says which layout it uses.
`/data/health.json` holds `status` (`ok`, `retrying`, `bridge_unreachable`),
`detail`, `ts` (Unix seconds), `mode`, and the model's state: `model` (`on`,
`off`, `no_key`, `no_price`, `budget_cap`, `rate_cap_hour` or `rate_cap_day`), `spend_month_usd`
and `budget_usd`, `settings_problems` (portal settings that were refused, as
short sentences), `provider` and `model_name`, plus `skipped_pre_go_live`: how many messages were left
alone because Proton received them before go-live (each one is also logged
with its message key and `rule=pre_go_live`).

The model budget defaults to **$20 a month** (`model.monthly_budget_usd`).
Once this month's spend reaches it, the analyzer stops calling the model
until the 1st (UTC) and runs on rules and lists only; mail it would have
classified is logged as kept with rule `budget_cap`. Set the same limit on
the key itself in the Claude Console as a second stop.

Missing or invalid configuration always means shadow mode. `mode:` in
analyzer.yaml is always `shadow`; live mode is switched on only in the
portal (below). The kill switch is a file named `PAUSE` in
`config/` or `config/portal/` on the host (the portal's Pause button uses
the second); it is checked before every decision. In the container these
are `/config/PAUSE` (`pause_file`) and `/config/portal/PAUSE` (`portal_dir`).

Each list file is capped at 5,000 entries and 1 MB (`portal.yaml`: 256 KB).
List files are opened without following symlinks and must be regular files.
A file that breaks any of these rules, or no longer parses, is reported by
`analyzer lists lint`; while the analyzer runs, it keeps that file's last good
entries, so a bad write never drops a protected sender. Entries in
`portal.yaml` are always logged with source `portal`, and `PAUSE` only has to
exist (its contents are never read).

The API key is read from a file (default `/run/secrets/anthropic_api_key`),
never from an environment variable or the command line. Use a key dedicated
to this project, in its own Claude Console workspace with a spend limit
(security review A14).

## Tests

```bash
make analyzer-test     # unit tests in a throwaway Python container
```

The tests cover hidden-text stripping, forged and misplaced
authentication headers, MIME limits, list lint and lookalike rules, schema
validation, and an end-to-end check that a fully compromised model (one that
calls every adversarial fixture "legitimate, 0.99") still cannot get any of
them kept in the inbox.
