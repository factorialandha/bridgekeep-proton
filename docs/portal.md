# The admin portal

The portal is Bridgekeep's web app. It runs in its own container on your
machine; there is no hosted service. By default only the machine itself can
open it (`http://127.0.0.1:8443`, or the next free port if 8443 is taken). Network mode makes
it an HTTPS website for your other devices at home. It works on phones and
follows your device's light or dark mode.

## Setting it up

`./bridgekeep setup` offers the portal at step 8 and asks whether to open it
to your home network. On Proxmox that defaults to yes, because otherwise only
the container could open it. To add it later: `./bridgekeep setup --portal`.

Then:

```sh
./bridgekeep portal
```

This prints the address, the certificate fingerprint (in network mode), and a
one-time **claim code** while the portal isn't claimed yet. Open the address,
enter the code, and choose an admin password. You can add an authenticator
app straight away or later in **Settings**. With one, every sign-in also asks
for a code, and the password can be shorter (12 characters instead of 15).

Claim codes last an hour and work once. `./bridgekeep portal code` prints a
new one.

## Pages

### Status

What needs you, then four numbers: Bridge's health, mail synced, AI spend this
month against your budget, and disk free. **Details** opens every service,
storage use, the schedule, and versions. When something needs you, such as
Bridge being signed out or an update waiting, it's listed at the top with
what to do.

### Review

Mail the analyzer wasn't sure about in the last 14 days. Answer **Spam or
not?** for each. Your answer teaches the analyzer about that sender, and in
live mode "not spam" moves the message back to your inbox. For a sender whose domain passes DMARC, two "not
spam" answers and no "spam" mean it's never quarantined again, only sent to
Review at most.

### Log

Everything the analyzer checked, newest first, with the action, the reason
and the rule that decided. Open an entry for the details, to correct it, to
add the sender to a list, or to unsubscribe (below). Message bodies are never
stored.

### Lists

Rules the analyzer always follows before it asks the AI. Changes apply within
a minute.

- **Never trash:** addresses or domains that are always kept, whatever the AI
  thinks. This wins over the other lists. Only mail that really comes from
  that sender (passing DMARC) is protected.
- **Always trash:** exact addresses that are always quarantined, but only when
  the mail really comes from that address.
- **Protected subject words:** mail with these words in the subject is never
  quarantined, only sent to Review at most. Useful for sign-in codes and
  password resets.

"Trash" here means the AI-Quarantine folder in live mode. Nothing is ever
moved to Proton's Trash or deleted.

### Analyzer

- **Mode:** shadow (log only) or live (moves mail to `AI-Review` and
  `AI-Quarantine`). Switching to live shows how shadow mode went first, asks
  for your password again, and sends a Discord alert. Pause stops all
  analysis at once.
- **AI vendor:** Anthropic (the default, Claude Haiku), OpenAI, Google Gemini,
  or a local OpenAI-compatible server such as Ollama or LM Studio. You type the
  key here; it's sent to the host and never shown again. Each vendor shows
  who receives your mail and what it costs. For OpenAI and Gemini you enter
  your plan's price per million tokens.
- **How strict:** how sure the AI must be before mail is quarantined or sent
  to Review.
- **Spending:** use the AI or not, the monthly budget, and hourly and daily
  limits.
- **Advanced:** how often to check for mail, and the most moves a day in live
  mode.

### Older mail

Mail from before setup is left alone unless you ask. Pick a date range and a
limit, get an estimate of how many messages, how many AI calls, what it costs
and how long it takes, then start it. It stays log-only, and you can pause
or cancel it at any time.

### Proton account

The Proton address Bridge reads mail from, and whether it's signed in. Sign
in again here if Proton ends the session, with your password, two-factor code
and mailbox password if you have one. Your Proton password goes straight to
Bridge; the portal never stores it.

### Settings

- **Access:** who can open the portal, its addresses, and its certificate
  fingerprint and download.
- **Admin password** and **Authenticator:** changing either asks for your
  password (and a code) again, and signs out every other session.
- **Alerts:** turn Discord alerts on with a webhook URL, replace it, or turn
  them off ([alerts.md](alerts.md)).

### Audit log

Every sign-in and change made in the portal, with time, action and address.
It can't be edited or deleted from the portal.

## Unsubscribe

An entry in the Log shows an **Unsubscribe** button only where it will work
and is safe:

- the mail passed DMARC and was signed (DKIM) by the sender's own domain,
- the sender offers standard one-click unsubscribe at an `https` address on
  that domain,
- and the mail wasn't judged spam or phishing.

Pressing it sends exactly one standard unsubscribe request from a separate,
locked-down service: no images, no other links, no redirects, and never to an
address inside your network. It never confirms your address any other way. If
the sender only offers an email address, the portal shows it so you can send
the email yourself.

## Opening it from other devices

```sh
./bridgekeep portal network on     # asks which of this machine's addresses to use
./bridgekeep portal network off    # back to this machine only
```

Network mode serves HTTPS only, with the portal's own certificate. Each
browser warns once that it doesn't know the certificate. Continue only if the
fingerprint in the warning matches the one `./bridgekeep portal` and
**Settings > Access** show.

To stop the warning, download the certificate from **Settings > Access** and
trust it:

- **macOS:** open it, then in Keychain Access double-click it and set "When
  using this certificate" to Always Trust.
- **Windows:** open it, Install Certificate > Current User > place it in
  "Trusted Root Certification Authorities".
- **iPhone and iPad:** open it in Safari, install the profile in Settings,
  then turn it on under Settings > General > About > Certificate Trust
  Settings.
- **Android:** Settings > Security > Encryption & credentials > Install a
  certificate > CA certificate.
- **Firefox** keeps its own list: Settings > Privacy & Security >
  Certificates > View Certificates > Authorities > Import.

In network mode, sign-ins time out after an hour idle instead of 12 hours.

**Don't forward the port on your router.** For access away from home, use a
VPN such as WireGuard or Tailscale, or an SSH tunnel to the machine:
`ssh -L 8443:127.0.0.1:8443 you@your-server`.

## Host commands

| Command | What it does |
|---|---|
| `./bridgekeep portal` | Where to open it, the certificate fingerprint, and a claim code if it isn't claimed yet |
| `./bridgekeep portal code` | A new claim code (before it's claimed) |
| `./bridgekeep portal reset-admin` | Forget the admin password and authenticator, sign everyone out, and print a new claim code |
| `./bridgekeep portal network on` / `off` | Open it to your home network over HTTPS, or back to this machine only |

A few things stay on the host on purpose, so that a stolen portal session
can't do them: installing a Bridge update (`./bridgekeep deploy-update`),
recovering the admin account, and turning network access on or off.

## How it's protected

- Its own container: a separate user, read-only filesystem, no capabilities,
  no Docker access, and no route to the internet. It never holds an IMAP
  password.
- Admin password hashed with argon2id, optional authenticator (TOTP) with
  replay protection, and back-off after failed sign-ins.
- Password again (step-up, at most every 5 minutes) for changes that matter:
  live mode, analyzer settings, lists, the AI vendor and keys, Discord, the
  Proton sign-in, older mail, unsubscribe, and the admin password and
  authenticator.
- Protection against DNS rebinding and cross-site requests, strict cookies,
  and a content security policy. Nothing loads from a CDN.

The portal's data (the password hash, the authenticator secret and the audit
log) holds no mail or Proton secrets. If you lose it,
`./bridgekeep portal reset-admin` and a new claim are all you need.

Developer details: [portal/README.md](../portal/README.md).
