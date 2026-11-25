# Bridgekeep

*Nothing crosses unchecked.*

> **Unofficial.** Bridgekeep is an independent project. It is not affiliated
> with, endorsed by, or supported by Proton AG. "Proton" and "Proton Mail
> Bridge" are trademarks of Proton AG, used here only to describe what this
> project runs.

Bridgekeep runs [Proton Mail Bridge](https://proton.me/mail/bridge) headless
on your own Linux server, keeps it updated safely, and can add an AI mail
analyzer that flags spam and phishing in your Proton inbox. You manage it from
a small self-hosted admin website and a single `./bridgekeep` command. There
is no cloud service: everything runs on your machine.

It runs on Linux hosts with amd64 (x86_64) or arm64 CPUs, including a
Raspberry Pi, and has guided installs for **Proxmox VE** and **TrueNAS SCALE**.

Proton does not support running Bridge in Docker. Bridgekeep runs Proton's
own, unmodified Bridge in its command-line mode. Running Bridge this way is
at your own risk with respect to Proton's terms of service.

## Contents

- [Features](#features)
- [What you need](#what-you-need)
- [Install](#install)
- [After setup](#after-setup)
- [The admin portal](#the-admin-portal)
- [The AI mail analyzer](#the-ai-mail-analyzer)
- [Updates](#updates)
- [Alerts](#alerts)
- [Command reference](#command-reference)
- [Security and privacy](#security-and-privacy)
- [Documentation](#documentation)
- [Development](#development)
- [License](#license)

## Features

**Proton Mail Bridge, headless and hardened**

- Proton's official Bridge, built from Proton's published source for the
  pinned release (or, on amd64, from Proton's signed `.deb`). Every release
  is checked against Proton's signing key, which is committed to this
  repository, and the source must match a pinned hash.
- Signed, ready-built images for amd64 and arm64 when your host can use
  them, with a local build from source as the automatic fallback.
- No GUI, no Qt, no self-updating launcher. Runs as a non-root user with a
  read-only filesystem, all Linux capabilities dropped, and memory limits.
- Private by default: Bridge publishes no ports. Only containers on its
  private mail network can reach IMAP.
- Sign-in to Proton (password, two-factor code, mailbox password) during
  setup or later from the portal. The password your mail clients use is
  saved without being shown on screen.

**Safe automatic updates**

- A nightly job looks for a new Bridge release, verifies it, builds it and
  smoke-tests it on a throwaway copy.
- Nothing goes live until you say so: `./bridgekeep deploy-update` swaps the
  tested version in and rolls back automatically if it isn't healthy.
- Rebuilds weekly anyway, so operating system security fixes are picked up.

**AI mail analyzer (optional)**

- Classifies new mail as legitimate, promotional, spam or phishing, using
  Claude Haiku by default, or OpenAI, Google Gemini, or a model on your own
  network.
- Starts in **log-only mode**: it records what it would do and moves nothing.
  When you're happy, switch to **live mode** in the portal, which moves
  flagged mail to `AI-Review` or `AI-Quarantine` folders. It never deletes
  mail and never moves it to Trash.
- Your own lists come first: senders you protect are never quarantined, and
  senders you block are flagged without asking the AI.
- Learns from your corrections ("not spam" / "spam") in the portal.
- Monthly spending cap (default $20), plus hourly and daily limits. At the
  cap it keeps working on your rules and lists alone until the 1st.
- Only mail that arrives after setup is analyzed. Older mail is analyzed
  only if you ask, after a cost estimate you confirm.
- Defends against prompt injection: hidden text is stripped, injection
  attempts are detected, and the AI can only ever lower what happens to a
  message, never override your lists or safety rules.

**Self-hosted admin portal (optional)**

- A web app for your browser, on this computer only or as an HTTPS website
  on your home network. Works on phones, in light and dark mode.
- Status of every service, storage use, mail synced and AI spend at a glance.
- Sign in to Proton (including two-factor), review flagged mail, browse the
  log, edit your lists, change analyzer settings, choose the AI vendor and
  key, set up Discord alerts, analyze older mail, and one-click unsubscribe
  where it's safe.
- Admin password with an optional authenticator app, and an audit log of
  every change.

**Alerts and health checks**

- A health check every 5 minutes: container health, a real IMAP sign-in
  every 30 minutes, and free disk space.
- Discord alerts when Bridge is signed out, an update is waiting, a service is
  unhealthy, the disk is nearly full, or the AI budget is reached.
- `./bridgekeep status` and the portal's Status page show it all, including
  where the portal is and whether it's up.

## What you need

- A Linux machine that stays on: a Raspberry Pi 4 or 5, a mini PC, a NAS or a
  server, with an amd64 or arm64 CPU. A Proxmox VE or TrueNAS SCALE host also
  works.
- About 2 GB of free memory and 10 GB of free disk. Building Bridge from
  source is the heaviest step; on a small board, add swap.
- Docker Engine with Compose and Buildx. Version 28 or later is recommended,
  because the portal's network isolation needs it; setup warns on older
  versions. On Debian or Ubuntu, setup offers to install a missing Compose or
  Buildx.
- A Proton account with a paid plan (Bridge requires one).
- For the AI analyzer: an API key from Anthropic, OpenAI or Google, or a
  local model server. The analyzer also runs on your lists and rules alone,
  with no key.
- Full-disk encryption on the host is strongly recommended. Bridgekeep's data
  holds the keys to your mailbox.

## Install

Choose the guide for your host. Each one runs the same setup, which walks
you through everything and ends with a PASS/FAIL table.

### Linux (Debian, Ubuntu, Raspberry Pi OS, and others)

```sh
git clone -b preview https://github.com/factorialandha/bridgekeep-proton.git bridgekeep
cd bridgekeep
./bridgekeep setup
```

Full guide: [docs/linux-host.md](docs/linux-host.md).

### Proxmox VE

In the Proxmox host's shell, as root (the web UI's node **Shell**, or SSH):

```sh
bash -c "$(curl -fsSL https://raw.githubusercontent.com/factorialandha/bridgekeep-proton/preview/deploy/proxmox/install.sh)"
```

It makes an unprivileged Debian container with Docker for Bridgekeep and runs
setup inside it. Nothing else is installed on the Proxmox host. Full guide:
[docs/proxmox.md](docs/proxmox.md).

### TrueNAS SCALE (24.10 and later)

Create an encrypted dataset with the **Generic** preset in the web UI, then in
**System > Shell**:

```sh
sudo -i
cd /mnt/tank/bridgekeep        # your dataset
git clone -b preview https://github.com/factorialandha/bridgekeep-proton.git repo
cd repo
./bridgekeep setup
```

Setup keeps your sign-in and secrets on the dataset, so snapshots and
encryption cover them. Full guide: [docs/truenas.md](docs/truenas.md).

### What setup does

`./bridgekeep setup` runs ten steps. If one fails it prints the fix; run it
again and it carries on where it stopped.

1. Checks the machine: Docker, Compose, Buildx, memory and disk.
2. Chooses where your data lives (Docker volumes, or your TrueNAS dataset).
3. Gets Bridge: downloads the signed image for your CPU if it can, or
   builds it from source (5 to 15 minutes). `--build` always builds.
4. Smoke-tests the image.
5. Signs you in to Proton. This is the only typing: your address, password
   and two-factor code.
6. Starts Bridge and proves the sign-in with a real IMAP login.
7. Offers the AI mail analyzer and asks which AI vendor to use. It starts in
   log-only mode.
8. Offers the admin portal, and whether to open it to your home network.
9. Schedules the nightly update check and the 5-minute health check, and
   offers Discord alerts.
10. Prints the final PASS/FAIL table, and where to open the portal.

The first sync of a large mailbox can take hours. `./bridgekeep status`
shows its progress.

## After setup

```sh
./bridgekeep status        # everything at a glance
./bridgekeep portal        # where to open the admin portal (and a claim code the first time)
./bridgekeep doctor        # rerun the checks and print a fix for anything wrong
```

Open the portal address in your browser, enter the claim code, and choose an
admin password. From then on you can do almost everything there.

To add a part you skipped, run `./bridgekeep setup --analyzer` or
`./bridgekeep setup --portal`.

## The admin portal

| Page | What it's for |
|---|---|
| **Status** | Bridge, mail synced, AI spend against your budget, disk free, and anything that needs you (sign in again, an update waiting). |
| **Review** | Mail the analyzer flagged. Answer "Spam or not?" and it learns. |
| **Log** | Every decision, with the reason. Open one to see the details, protect the sender, or unsubscribe. |
| **Lists** | Senders you always protect and senders you always block. |
| **Analyzer** | Log-only or live mode, how strict to be, monthly budget and limits, the AI vendor and its API key. |
| **Older mail** | Analyze mail from before setup, after a cost estimate you confirm. |
| **Proton account** | Sign Bridge in to Proton again, with two-factor and mailbox password. |
| **Settings** | Discord alerts, home-network access and certificate, admin password, authenticator app. |
| **Audit log** | Every sign-in and change, with time and address. |

Full guide: [docs/portal.md](docs/portal.md).

## The AI mail analyzer

Each new message goes through these steps:

1. Bridgekeep extracts the sender, subject, Proton's authentication result,
   link domains, attachment types and up to 3,000 characters of visible
   text. Hidden text is removed and attachments are never opened.
2. Your lists are checked first. A verified, protected sender is kept
   without asking the AI.
3. The AI vendor you chose classifies it, with your past corrections for
   that sender's domain as context.
4. Safety rules can only make the result gentler: a protected keyword in the
   subject (such as a password reset or a sign-in code) is never quarantined.
5. The decision is logged. In live mode, the message is moved.

Only those extracted fields are sent to the AI vendor, never the full
message or attachments. Check your vendor's data-use terms, and prefer a paid
plan with data sharing off or zero retention. A local model keeps everything
at home.

Full guide: [docs/analyzer.md](docs/analyzer.md).

## Updates

- **Bridge:** every night Bridgekeep checks for a new Proton release, then
  verifies, builds and tests it. The portal and `./bridgekeep status` show
  "update waiting", and Discord tells you. Run `./bridgekeep deploy-update`
  to install it. If the new version isn't healthy, it rolls back.
- **Bridgekeep itself:** `git pull && ./bridgekeep setup` (on Proxmox, run
  the install command again). Setup rebuilds only what changed and keeps your
  sign-in and settings.

Details: [docs/operations.md](docs/operations.md#updates).

## Alerts

Turn on Discord alerts in the portal (**Settings > Alerts**) or with
`./bridgekeep alerts on`. Paste a Discord webhook URL; Bridgekeep sends a test
message and saves it only if Discord accepted it. Only the host talks to
Discord. No container ever holds the webhook.

Details: [docs/alerts.md](docs/alerts.md).

## Command reference

| Command | What it does |
|---|---|
| `./bridgekeep setup` | Install, or bring everything up to date. `--analyzer`, `--portal`, `--build`, `--yes` |
| `./bridgekeep status` | Health, signed-in address, sync progress, storage, portal address, updates |
| `./bridgekeep doctor` | Rerun the checks and print a fix for each failure |
| `./bridgekeep credentials` | Show the IMAP/SMTP username and password once |
| `./bridgekeep relogin` | Sign in to Proton again after an expired session |
| `./bridgekeep logs` | Follow Bridge's log |
| `./bridgekeep update` | Check for, build and test a new Bridge now (doesn't install it) |
| `./bridgekeep deploy-update` | Install the tested update, with automatic rollback |
| `./bridgekeep portal` | Where to open the portal. Also `code`, `reset-admin`, `network on`, `network off` |
| `./bridgekeep alerts` | Discord alerts: `on`, `off`, `test` |
| `./bridgekeep watch` | Install the 5-minute health check if missing, and run one round |
| `./bridgekeep backfill` | Analyze older mail: `estimate`, `start ID`, `pause`, `resume`, `cancel`, `status` |
| `./bridgekeep analyzer shadow` | Switch the analyzer back to log-only, even with the portal down |
| `./bridgekeep feedback` | How the AI compares with your corrections |
| `./bridgekeep stop` / `start` | Stop or start everything (or just `bridge`) |
| `./bridgekeep shell` | Proxmox only: a root shell in Bridgekeep's container |

## Security and privacy

- **There is no Bridgekeep server.** Your mail stays on your machine, except
  the extracted fields of each new message (sender, subject, link domains and
  up to 3,000 characters of visible text) sent to the AI vendor you chose, or
  nothing at all with a local model or no AI. The connections that carry mail
  or secrets are Bridge to Proton, the analyzer to that one AI vendor (through
  a proxy that allows only that host), the unsubscribe service when you press
  the button, and the host to Discord if you turn alerts on.
- **Other outside connections carry no mail or secrets:** GitHub (release
  checks and Bridge's source), ghcr.io (image downloads), Proton's download
  server (the signed `.deb` used to verify each release), and Debian's and
  Docker's package mirrors during builds.
- **Least privilege everywhere.** Each part runs in its own container with
  its own user, a read-only filesystem and no capabilities. The analyzer never
  holds the Bridge password: it reads mail through a proxy that allows only a
  short list of read commands (and, in live mode, moves between the inbox and
  the two AI folders).
- **Secrets live outside the code folder**, in `/etc/bridgekeep/secrets` (or
  your TrueNAS dataset), readable only by root and the one container that
  needs each one.
- **The portal is local by default.** On your home network it uses HTTPS with
  its own certificate. Don't forward it on your router; use a VPN for access
  away from home.
- **Back up encrypted.** Anyone with a copy of Bridgekeep's data can read your
  mailbox. See [docs/operations.md](docs/operations.md#backup-and-restore).

## Documentation

Start with [docs/README.md](docs/README.md). The main guides:

- [docs/linux-host.md](docs/linux-host.md): install on Linux (amd64 or arm64)
- [docs/proxmox.md](docs/proxmox.md): install on Proxmox VE
- [docs/truenas.md](docs/truenas.md): install on TrueNAS SCALE
- [docs/portal.md](docs/portal.md): using the admin portal
- [docs/analyzer.md](docs/analyzer.md): the AI mail analyzer
- [docs/operations.md](docs/operations.md): updates, backups, sign-in, troubleshooting
- [docs/alerts.md](docs/alerts.md): Discord alerts and health checks

## Development

`make lint` (shellcheck and hadolint), `make test` (smoke test, no Proton
account needed), `make analyzer-test` and `make portal-test` run the checks
locally. CI runs on a self-hosted Outpost runner
([ci/pipeline.yml](ci/pipeline.yml)) for `preview` and `main`: it lints,
builds, smoke-tests and scans every image, rebuilds daily to pick up security
fixes, and warns when Proton releases a new Bridge. CI never deploys. See
[docs/testing.md](docs/testing.md) for end-to-end testing with a real
account.

## License

GPL-3.0-or-later ([LICENSE](LICENSE)), the same licence as
[Proton Mail Bridge](https://github.com/ProtonMail/proton-bridge), which this
project builds unmodified and ships inside its image. Each Bridge image
carries the licence and the exact upstream source it was built from in
`/usr/share/doc/proton-bridge/` and in its `io.bridgekeep.bridge-source` and
`io.bridgekeep.bridge-commit` labels.
