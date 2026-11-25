# The AI mail analyzer

The analyzer reads new mail in your Proton inbox through Bridge, decides
whether each message is legitimate, promotional, spam or phishing, and logs
what it would do. It's optional, and it starts in **shadow mode**, which only
logs. In **live mode** it moves flagged mail into two folders in your Proton
account. It never deletes mail and never moves it to Trash.

## Setting it up

`./bridgekeep setup` offers the analyzer at step 7 and asks which AI vendor to
use:

| Vendor | Default model | Key |
|---|---|---|
| Anthropic | Claude Haiku 5.5 | from the Claude Console |
| OpenAI | your choice | from the OpenAI platform |
| Google Gemini | your choice | from Google AI Studio |
| Local | any OpenAI-compatible server on your network (Ollama, LM Studio, llama.cpp) | if your server needs one |
| None | rules and lists only | none |

The key is typed hidden and saved outside the code folder, readable only by
the analyzer. You can switch vendor or change the key at any time on the
portal's **Analyzer** page. To add the analyzer later:
`./bridgekeep setup --analyzer`.

Use a key made for Bridgekeep alone, and set a spending limit on it with the
vendor too, as a second stop beside Bridgekeep's own budget.

## What happens to each message

1. **Extract.** The sender, subject, Proton's authentication result, link
   domains, attachment types, and up to 3,000 characters of visible text.
   HTML becomes plain text, hidden text and invisible characters are removed,
   and attachments are never opened.
2. **Check the sender.** A sender counts as verified only when Proton's own
   authentication header shows DMARC passed for exactly that domain.
3. **Look for tricks.** Text aimed at AI filters ("ignore previous
   instructions", fake system messages) is detected, including in the hidden
   text removed in step 1.
4. **Your lists.** A verified sender on your Never trash list is kept, and one
   on your Always trash list is quarantined, without asking the AI.
5. **Ask the AI.** One isolated request per message, with your past answers
   for that verified domain as context. Any error or odd answer means "keep".
6. **Decide.** Spam or phishing with high confidence (97% by default):
   quarantine. Less sure (from 70%): review. Otherwise: keep. Safety rules can
   then only make the result gentler. A protected subject word is never
   quarantined, an unverified sender that claims to be a protected one goes to
   Review at most, and a lookalike of a protected domain goes to Review.
7. **Log.** The sender, subject, verdict, confidence, reason and rule. Never
   the body. Kept for 90 days.

The AI vendor receives only the fields from step 1. The portal never shows or
sends anything else.

## Shadow mode and live mode

Shadow mode is the default. Watch the portal's **Review** and **Log** pages
for a while, correct what's wrong, and adjust the lists and how strict it is.

When you're happy, switch to live on the portal's **Analyzer** page. It shows
how shadow mode went, asks for your password again, and sends a Discord alert.
From then on:

- **Review** goes to `Folders/AI-Review` and **quarantine** to
  `Folders/AI-Quarantine` in Proton. The analyzer creates both folders.
  Nothing is marked read, moved to Trash or deleted. What you keep in those
  folders, and for how long, is up to you.
- Only mail Proton received after the switch moves. Mail logged in shadow
  mode, and older mail, never moves.
- A sender on your Never trash list, and mail with a protected subject word,
  always stays in the inbox.
- At most 200 moves a day by default (portal: **Analyzer > Advanced**). After
  that it only logs until midnight UTC, and you get one alert.
- Answering "not spam" on a moved message moves it back to the inbox.

To go back to shadow mode, use the portal's **Analyzer** page, press Pause, or
run `./bridgekeep analyzer shadow` on the host, which works even with the
portal down.

## Spending

- **Monthly budget:** $20 by default, anywhere from $0 to $1,000. Once this
  month's spend reaches it, the analyzer stops calling the AI until the 1st
  (UTC) and carries on with your rules and lists alone. Discord tells you.
- **Hourly and daily limits:** 120 an hour and 1,000 a day by default.
- Claude Haiku costs roughly $0.0001 to $0.0003 a message. Its price is
  built in. For OpenAI and Gemini you enter your plan's price when you choose
  the model; until then the AI isn't used. A local model costs nothing, but
  the limits still apply.

All of these are on the portal's **Analyzer** page. The Status page shows this
month's spend against the budget.

## Older mail

Only mail Proton received after setup is analyzed. Mail already in your inbox
is left alone unless you ask, on the portal's **Older mail** page or on the
host:

```sh
./bridgekeep backfill estimate --since 2026-01-01 --limit 5000
./bridgekeep backfill start <id from the estimate>
./bridgekeep backfill status        # also: pause, resume, cancel
```

The estimate reads headers only and shows how many messages, how many AI
calls, the cost, the budget left and how long it takes. Starting it confirms
that up to that many messages (their extracted fields, including up to 3,000
characters of text each) go to your AI vendor. It stays log-only, works newest
first, keeps part of the limits and 10% of the budget for new mail, and never
analyzes a message twice.

## Learning from you

Every "spam" or "not spam" answer on the **Review** and **Log** pages is
remembered:

- For mail from a verified domain, the AI is told how you answered for that
  domain before.
- Two "not spam" answers and no "spam" for a verified domain mean its mail is
  never quarantined again, only sent to Review at most.
- A forged copy that fails DMARC gets none of this.
- You can clear an answer again in the portal.

`./bridgekeep feedback` shows how often the AI agreed with you.

## Unsubscribe

The portal's Log offers a one-click **Unsubscribe** button for genuine
newsletters where it's safe. See [portal.md](portal.md#unsubscribe).

## Who sees your mail

The vendor you choose receives the extracted fields above for each new
message, and for older mail you confirm. Check your plan's data-use terms.
Google's free Gemini tier and some OpenAI settings may use API data to improve
their products, so use a paid plan with data sharing off, or zero retention. A
local model keeps everything at home. Over plain `http` (allowed only to an
address inside your network), mail crosses your network unencrypted.

## How it's isolated

The analyzer runs as three locked-down containers:

| Container | Can reach | Holds |
|---|---|---|
| `analyzer` | only the two proxies below | the AI key |
| `imap-proxy` | Bridge's IMAP | the Bridge password |
| `egress-proxy` | your chosen AI vendor's one address | nothing |

- The analyzer never holds the Bridge password. It signs in to `imap-proxy`
  with its own token, and the proxy forwards only a short list of read
  commands. In live mode it also allows moves between the inbox and the two AI
  folders, and checks the mode again for every move.
- The only way to the internet is `egress-proxy`, which allows only the
  vendor you chose. TLS runs end to end, so the proxy never sees mail.
- All three are read-only, drop every Linux capability, and have memory and
  process limits.

Technical details, tests and the offline evaluation tool:
[analyzer/README.md](../analyzer/README.md).
