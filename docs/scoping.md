# Proton Mail Bridge Docker Image: Scoping Document

## 1. Purpose and Background

Proton publishes no container image and does not support Docker deployment of Bridge. It ships as a desktop application, so every containerised Bridge is a community repack. This document scopes building and maintaining our own headless image rather than trusting a third-party wrapper, with the goal of exposing Bridge's local IMAP and SMTP endpoints to other containers or hosts on the network.

## 2. Existing Options Surveyed

- **shenxn/protonmail-bridge**: the long-standing community image. Multi-arch builds from source (amd64, arm64, arm/v7, riscv64). Interactive init step, then run detached with a persisted volume. Exposes ports to the network by default, so a firewall is needed.
- **goran-kovac/proton-bridge-docker**: minimal image built directly from Proton's official signed .deb package instead of relying on a community wrapper. Closest in spirit to what we would build.
- **purplehat93/proton-bridge-docker**: compiles Proton's official source with the upstream make build-nogui target and copies only the headless binary into the runtime image.
- **excavador/proton-bridge**: headless, multi-arch, built from upstream source.
- **RndmJoker/proton-mail-bridge-docker**: repackaged official Bridge with environment-variable configuration and a one-time login through a temporary web page or the CLI.
- **VideoCurio/ProtonMailBridgeDocker**: aimed at letting other containers send mail via SMTP only; tested on TrueNAS Scale.
- **asyncura/proton-mail-bridge**: an always-up-to-date image of the Bridge CLI on Docker Hub.
- **aarnaud/docker-protonmail-bridge**: uses Bridge's native non-privileged ports 1143 and 1025.

## 3. Goals

- Run official Proton Bridge headless (CLI mode, no GUI) in a container.
- Reproducible build from a pinned upstream version, with signature or checksum verification.
- Persistent state in a single volume: Bridge config, vault, and keychain.
- Expose IMAP (1143) and SMTP (1025) to a chosen network scope, with optional forwarding for non-localhost access.
- Run as a non-root user with a minimal runtime image.
- Simple, documented first-run login flow, including two-factor.
- Automated rebuilds when Proton releases a new Bridge version.

## 4. Non-Goals

- Reimplementing or patching Bridge's protocol logic.
- Bypassing Proton's paid-plan requirement for Bridge.
- Providing a GUI or web admin interface in version one.
- Multi-tenant hosting of many Proton accounts for other people.

## 5. Key Technical Decisions

### 5.1 Build source: signed .deb versus building from source

The .deb route is faster and uses Proton's signed artifact, but is limited to the architectures Proton ships. Building from source with the make build-nogui target supports more architectures such as arm64 and gives full control, at the cost of build time and toolchain maintenance. Recommendation: start with the signed .deb for amd64, add a source build path if arm64 is needed.

### 5.2 Credential storage

Bridge needs a keychain to store credentials. In a container with no desktop session, the usual approach is the pass password store backed by a GPG key generated at first run. The pass store and GPG home must live in the persistent volume, and the volume must be treated as a secret.

### 5.3 Network exposure

Bridge binds to localhost inside the container, so other containers cannot reach it directly. Options are a socat forwarder from all interfaces to the Bridge ports, or an in-container proxy. The forwarder should bind only to the Docker network, never published to a public interface by default.

### 5.4 Login flow

Proton Bridge has no headless environment-variable login: credentials are entered once through the interactive CLI, after which the session is persisted to disk. Our image should provide a clearly documented init command that runs the Bridge CLI interactively, with the login and info commands, and then exits cleanly.

### 5.5 TLS certificates

Bridge uses a self-signed certificate, which mail clients will complain about. Plan to export the certificate and document how to trust it, rather than disabling verification.

## 6. Architecture

A multi-stage Dockerfile: a builder stage that downloads and verifies the Bridge package or compiles from source, and a slim runtime stage with only the Bridge binary, pass, gnupg, socat, and a small entrypoint script. A non-root user owns a single volume mounted at the home directory. The entrypoint handles first-run GPG and pass initialisation, starts the socat forwarders, and then launches Bridge in non-interactive CLI mode. A compose file defines the service, volume, restart policy, and a private network.

## 6A. AI Email Analyzer and Processor

A second container sits beside Bridge, reads new mail over local IMAP, asks an AI model to classify each message, and moves confirmed spam to Trash. Bridge stays untouched; the analyzer is just another IMAP client, so the two can be built, tested, and updated independently.

### 6A.1 Goals

- Classify every new inbox message as spam, phishing, promotional, or legitimate.
- Automatically move high-confidence spam and phishing to Trash, never permanently delete.
- Leave anything uncertain in the inbox, or move it to a review folder, for a human to check.
- Keep a searchable log of every decision with the reason, so mistakes can be found and fixed.
- Learn from corrections: mail you rescue from Trash becomes a signal against that sender or pattern.

### 6A.2 Processing pipeline

1. **Fetch**: connect to Bridge over IMAP on port 1143 using the Bridge-generated password, and watch the inbox with IMAP IDLE or a short polling interval.
2. **Pre-filter**: apply cheap rules before any AI call. Allowlisted senders and contacts skip analysis entirely; known-bad senders go straight to the decision step.
3. **Extract**: pull sender, reply-to, authentication results headers (SPF, DKIM, DMARC), subject, links, and a truncated plain-text body. Strip images and attachments, and never execute or open them.
4. **Classify**: send the extracted fields to an AI model with a fixed prompt and a structured JSON response: label, confidence from 0 to 1, and a one-sentence reason.
5. **Decide**: apply thresholds. At or above the trash threshold, move to Trash. In the middle band, move to a review folder. Below it, leave in place.
6. **Act and log**: perform the IMAP move, flag the message with a label such as AI-Trashed, and write the decision to a local database.

### 6A.3 Model choice

There are two realistic routes, and the choice is the biggest open decision in this section.

- **Hosted API (such as Claude)**: best accuracy and least setup, but message content leaves your network and goes to a third party. Sending only the extracted fields, not full bodies, reduces exposure.
- **Local model (such as one served through Ollama)**: mail never leaves your hardware, at the cost of needing a capable machine and usually lower accuracy on tricky phishing.

A sensible hybrid is a local or rule-based first pass for obvious cases, escalating only ambiguous mail to a hosted model. Recommendation: prototype with a hosted API to learn what accuracy is achievable, then decide whether a local model is good enough to replace it.

### 6A.4 Safeguards against trashing real mail

The worst failure is a legitimate message, such as a password reset, invoice, or job offer, landing in Trash unseen. The design assumes the model will sometimes be wrong and limits the damage.

- **Trash, never delete**: messages are moved, not expunged, and Proton keeps Trash for a retention period, so every mistake is recoverable.
- **Dry-run mode first**: run for at least two weeks only logging what it would do, then compare against your own judgment before enabling any moves.
- **Conservative thresholds**: start with a very high trash threshold and a wide review band, then tighten as the logged accuracy justifies it.
- **Protected senders and keywords**: a never-trash list covering contacts, your employer's domains, banks, and security-related subjects such as verification codes and password resets.
- **Authentication signals**: mail that fails SPF, DKIM, and DMARC is a stronger spam signal, but passing them does not prove legitimacy, so they feed the prompt rather than decide alone.
- **Daily digest**: a short summary email or log of everything trashed in the last 24 hours, so a wrongly trashed message is noticed quickly.
- **Kill switch**: a single environment variable or file flag that puts the analyzer back into log-only mode.

### 6A.4a Maintaining the never-trash list

The never-trash list is the safety net under the whole analyzer, so it must be easy to grow, hard to poison, and regularly pruned. The principle is that the list is built mostly from evidence in your own mailbox, and only you or deterministic code can change it, never the AI and never an email.

**Storage and format**

- **A plain, versioned file**: keep the list as a human-readable YAML or TOML file in its own small Git repository, mounted read-only into the analyzer container. Every change is a commit, so you get history, diffs, and one-command rollback.
- **Entry types**: exact sender address, whole domain, display-name-plus-domain pair, and subject keyword patterns for security mail such as verification codes and password resets.
- **Metadata on every entry**: reason, date added, source (manual, auto-learned, or imported), and an optional expiry date. Entries without a reason are rejected on load.
- **Hot reload**: the analyzer re-reads the file on change, so edits take effect without restarting the container.

**How entries get added**

- **Seed import**: on first run, import your address book and the senders you have replied to or starred, pulled from the Sent folder over IMAP.
- **Automatic learning from your behavior**: any sender you have sent mail to becomes protected. A message you rescue from Trash or the review folder adds that sender as a suggested entry.
- **Suggest, don't silently add**: automatic additions go into a pending queue and appear in the daily digest with a one-click approve or reject link. Only high-trust signals, such as a sender you have replied to several times, are added without approval.
- **Quick manual add**: a small command-line tool, with an optional web page later, to add or remove an entry with a reason in one step.
- **Category templates**: ready-made groups you can switch on, for example banks, government, your employer, travel, and shipping, each maintained as a separate file.

**Protecting the list from abuse**

- **Verify before trusting**: a sender is only matched if the message passes SPF and DKIM for that domain. Otherwise an attacker could spoof a protected address to slip past the filter, so a failed match goes to the review folder.
- **Prefer domains and exact addresses over display names**: display names are trivially forged and are never sufficient on their own.
- **No self-service from email**: nothing in an email body, and nothing the AI outputs, can add to or alter the list. Changes come only from your own actions and the deterministic learning rules above.
- **Wildcards need care**: broad entries such as large mail provider domains are blocked by a lint rule, since protecting a whole free mail domain would protect every spammer using it.

**Keeping it healthy over time**

- **Monthly review report**: a short summary listing entries added, entries that protected a message from the analyzer, and entries that never matched anything in 90 days.
- **Expiry and re-confirmation**: automatically learned entries expire after a set period unless you interact with that sender again, so the list does not grow forever or keep protecting abandoned senders.
- **Hit logging**: every time the list overrides a trash decision, log the sender and the model's verdict. This shows which entries earn their place and shows how often the model wanted to trash something important.
- **Backups and sync**: because the list lives in Git, push it to a private remote. Losing it should never mean losing your protections.

**Related blocklist**

The same mechanism can maintain a blocklist of confirmed spam senders, learned from messages you manually mark as junk. Blocklist matches skip the AI call and go straight to Trash, saving cost, but they follow the same rules: reasons, expiry, verification, and no changes from email content.

### 6A.5 Privacy and security considerations

- **Prompt injection**: spam and phishing emails can contain text aimed at the AI, such as instructions to classify the message as safe or to take an action. This is treated as the primary threat and has its own defenses in section 6A.5a.
- **Data exposure**: with a hosted model, message content is sent off your network. Redact long bodies, strip attachments, and review the provider's data retention terms before enabling.
- **Credential handling**: the Bridge IMAP password and any API key live in container secrets, never in the image or the log.
- **Least privilege**: the analyzer only needs IMAP access to Bridge. It gets no access to the Proton volume and runs on the private Docker network only.
- **Log hygiene**: the decision log stores sender, subject, label, and reason, but not full bodies.

### 6A.5a Defending against malicious email content and embedded AI instructions

The core rule is that the AI can only produce an opinion, never an action. An attacker who fully controls the email body, including hidden text, should at worst get one message misclassified, and never get code run, mail forwarded, links opened, or settings changed.

**Design principles**

- **The model has no tools**: the classifier call is a plain text-in, JSON-out request. It is given no function calling, no web browsing, no file access, no email sending, and no memory of other messages, so there is nothing for an injected instruction to invoke.
- **Code decides, model advises**: only deterministic code performs IMAP moves, and it can perform exactly one action, moving a single message to Trash or the review folder. Forward, reply, delete, send, and open-link actions do not exist in the analyzer's code.
- **Strict output schema**: the response must parse as JSON with an enum label, a number from 0 to 1, and a short reason string. Anything else, including extra fields, free-form instructions, or malformed output, is discarded and the message is left untouched in the inbox.
- **One message per call, no shared context**: every classification is an isolated request, so a poisoned email cannot influence how later emails are judged.
- **Fail safe**: any error, timeout, schema violation, or suspicious output means leave the message in place. The failure direction is always toward keeping mail.

**Handling the untrusted body**

- **Clear data boundaries**: the prompt states that everything between the delimiters is untrusted content from an unknown sender, to be analyzed and never obeyed. Delimiters use a fresh random token per request so an attacker cannot forge the closing marker.
- **Strip hidden content before the model sees it**: convert HTML to plain text, drop invisible elements such as zero-size or white-on-white text, HTML comments, and zero-width and other Unicode control characters, and ignore text hidden in attributes or metadata. Hidden instructions are the most common injection route.
- **Never process attachments or follow links**: no attachment content is parsed by the AI, no URL is fetched, and no image is rendered, so injections hidden in documents, images, or remote pages never reach the model. Links are only listed as text, with their domains, for the model to judge.
- **Truncate and normalize**: cap body length, collapse whitespace, and normalize Unicode so very long padding, encoded payloads, and lookalike characters cannot smuggle instructions.

**Treat injection attempts as a spam signal**

- **Pattern scan before the AI call**: a deterministic check flags phrases aimed at AI systems, such as references to ignoring previous instructions, system prompts, or claims that the message is pre-approved or safe. A match raises the spam score and is logged as an injection attempt.
- **Disagreement check**: if the model labels a message legitimate but the pre-scan found injection patterns or failed authentication, the message goes to the review folder rather than the inbox or Trash.
- **Never lower suspicion on the email's say-so**: the pre-filter allowlist is based only on your own contact list and verified headers, never on anything the email body claims about itself.

**Limits on what a successful attack could do**

- **Worst case is bounded**: the most an attacker can achieve is a wrong label on their own message. The never-trash list means protected senders and security-related mail can never be moved by the analyzer, whatever the model says.
- **No sensitive context in the prompt**: the prompt contains no API keys, passwords, other emails, or account details, so there is nothing to leak even if the model were fully manipulated.
- **Output is never executed or rendered**: the reason string is stored as inert text in the log and escaped anywhere it is displayed, so it cannot become a second-stage attack through the digest email or a log viewer.
- **Rate and size limits**: caps on messages per minute and per sender stop a flood of crafted emails from exhausting your API budget or the review queue.

**Testing**

- Build an adversarial test set of emails containing known injection styles: plain instructions in the body, hidden white-on-white text, instructions in HTML comments, instructions in other languages, instructions encoded in base64, text posing as a system message, and fake closing delimiters.
- Run the set before every prompt or model change. Success means no test email causes any action other than a normal classification, and none is ever labelled legitimate solely because it asked to be.
- Log every detected injection attempt so you can review new attack styles and add them to the test set.

### 6A.6 Additional work items

1. Build the IMAP client with reconnect handling, since Bridge restarts and sync periods will drop connections.
2. Define the classification prompt and JSON schema, and assemble a labeled test set of at least a few hundred of your own messages, spam and legitimate, to measure accuracy before going live.
3. Implement the pre-filter rules and the allowlist and blocklist storage.
4. Add the decision log database and a simple way to review and correct decisions.
5. Implement the feedback loop: detect mail moved out of Trash and add it to the allowlist or test set.
6. Add cost and rate limiting if using a hosted model, including a monthly budget cap.
7. Package as a second container in the same compose stack, with a healthcheck and the kill switch.

### 6A.7 Open questions for the analyzer

- Hosted model, local model, or the hybrid?
- Should it only trash spam, or also sort legitimate mail into folders such as receipts and newsletters?
- Is a daily digest enough, or do you want an immediate notification when something high-value is trashed?
- Which language should the analyzer be written in, and where should the decision log live?
- Does the process need to cover your sent mail and other folders, or the inbox only?

## 7. Work Breakdown

1. Prototype: get Bridge running headless in a throwaway container and complete a login.
2. Keychain: automate GPG and pass initialisation, verify the session survives a restart.
3. Networking: add socat forwarding and test from a second container.
4. Hardening: non-root user, read-only root filesystem where possible, dropped capabilities, healthcheck.
5. Build pipeline: pinned version argument, checksum or signature verification, multi-arch if required.
6. Automation: scheduled check for new upstream releases and automatic rebuild and tag.
7. Documentation: first-run guide, compose example, backup and restore of the volume, certificate trust steps.

## 8. Risks and Open Questions

- **Upstream drift**: Proton can change Bridge's CLI or keychain behaviour between releases, so pinning and testing each bump matters.
- **Session expiry**: if Proton invalidates the session, the container needs a manual re-login. We need a way to detect and alert on this.
- **Initial sync time**: first sync of a large mailbox can take a long time and use significant disk space in the volume.
- **Security of the volume**: it holds the keys to the mailbox, so backups must be encrypted.
- **Terms of service**: Bridge is intended for personal desktop use; confirm that running it headless on a server fits your use.
- **Open question**: single-arch amd64 only, or also arm64 for a Raspberry Pi or Apple Silicon host?
- **Open question**: IMAP and SMTP both, or SMTP-only for sending notifications?

## 9. Success Criteria

- A fresh clone builds an image with a single command.
- After one interactive login, the container survives restarts and host reboots without further input.
- A second container can send mail via SMTP and read mail via IMAP over the private network.
- The image runs as non-root and passes a basic vulnerability scan.
- A new upstream Bridge release produces a tested image within a day with no manual steps.
