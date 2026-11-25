# Signing in to Proton from the admin portal

The admin portal can sign Bridge in to your Proton account, or sign it out,
without you running anything on the host. It does this through a small
program inside the Bridge container, the **sign-in broker** (`broker/`).
The portal never sees Bridge's CLI or the password Bridge generates for mail
apps.

## How it works

- The broker is the process the container's entrypoint supervises. It starts
  Bridge, keeps it running, and exits if Bridge exits, so Docker's restart
  policy still applies.
- When you sign in from the portal, the broker stops Bridge, because Bridge's
  CLI and its background service can't open the vault at the same time. It
  then answers the CLI's prompts with what you typed: address, password, 2FA
  code, and mailbox password if your account has one. Afterwards it turns
  off Bridge's self-update and telemetry, reads the IMAP credentials Bridge
  shows, and starts Bridge again. **Mail is paused for the minute or so this
  takes.**
- The Bridge password goes to `/run/bridge-credential` (the
  `bridge-credential` volume). Only Bridge and `imap-proxy` mount that volume.
  The files are mode 0440 with group 10011. imap-proxy reads them again for
  every login, so a new sign-in needs no restart. `./bridgekeep status` and
  the 5-minute health check use them too.
- Signing in again with `./bridgekeep relogin` on the host removes the
  broker's copy, so the newest sign-in always wins.

## The socket

`/run/broker/broker.sock`, in the `broker-sock` volume, is mounted only by
Bridge and the portal. Requests are HTTP/1.1 with JSON bodies.

| Request | Body | |
|---|---|---|
| `GET /status` | | `{state, account, error, hv_url, step_expires}` |
| `POST /login` | `{username, password}` | |
| `POST /2fa` | `{code}`, 6 to 8 digits | |
| `POST /mailbox-password` | `{password}` | |
| `POST /human-verification` | `{}` after you've finished the page at `hv_url` | |
| `POST /logout`, `POST /cancel` | `{}` | |

`state` is one of `signed_out`, `signing_in`, `waiting_2fa`,
`waiting_mailbox_password`, `waiting_human`, `signed_in` or `error`. Every
POST answers with the same status object.

If Proton rejects a password or code, the reply is still 200: that sign-in
ends, the state goes back to `signed_out` (or `signed_in` if Bridge already had
an account) and `error` says why, so you sign in again. A waiting step expires
after 5 minutes the same way.

Error codes:

- 400: a field is missing, has the wrong type, or contains a control character.
- 403: the caller isn't the portal.
- 409: the request doesn't fit the current step.
- 413: the body is over 4 KiB.
- 429: too many attempts, with `Retry-After`.

## Safeguards

- The socket is mode 0660, with group 10010, which only Bridge and the portal
  have. Its folder is 2750 and the portal mounts it read-only, so the portal can connect but not replace the
  socket. The portal starts after Bridge, so Bridge creates that folder in the
  new volume.
- The broker reads the caller's UID from the kernel (`SO_PEERCRED`) and
  serves only UID 10003 (`BROKER_PEER_UIDS`).
- Fields go to the CLI's input, so control characters are refused. That
  stops a value from smuggling a second command in.
- The broker never returns, logs or stores your Proton password, the 2FA
  code, the mailbox password, the Bridge password, or anything the CLI
  prints. The CLI's output stays inside the broker. Only Bridge's own log
  lines reach `docker logs`.
- Limits: 5 sign-ins per 15 minutes, and 5 codes per sign-in.

Tests: `tests/broker.sh` (CI job `broker`) runs the broker against the same
stand-in for Bridge's CLI that `tests/signin.sh` uses.
