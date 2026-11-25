# Bridgekeep admin portal

A small web UI that runs next to Bridge and the analyzer, on your own host.
There is no hosted service: the portal is part of the app. By default it
listens on **this computer only** (`127.0.0.1:8443`); network mode makes it
an HTTPS website for your other devices at home.

**Using the portal?** Read [docs/portal.md](../docs/portal.md). This file is
the developer reference: how it's built, configured and protected.

Pages: Status, Review, Log, Lists, Analyzer (mode, vendor, thresholds,
spending), Older mail (backfill), Proton account (sign-in with 2FA),
Settings (access, admin password, authenticator, Discord alerts) and the
audit log. The web app is React with shadcn/ui, built into the image; the
server is Python.

## Start it

`./bridgekeep setup` asks whether to set up the portal (step 8), builds it,
and then asks whether to open it to your home network. At the end it prints
where to open it and a one-time claim code. Enter the code, then choose a
password. Adding an authenticator app is optional but recommended (you can
add it later in Settings); with one, every sign-in needs a code as well.

Without `./bridgekeep`:

```sh
make portal-build                         # or: docker compose build portal
docker compose --profile portal up -d portal
docker compose --profile portal exec portal python -P -m portal code
```

## Open it from other devices (network mode)

```sh
./bridgekeep portal network on     # asks which address; off undoes it
```

These live in `.env`; `network on` writes the address and names, then restarts the portal:

- `PORTAL_ADDRESS`: the one address of this computer that Compose publishes
  on, such as `192.168.1.20`. Never `0.0.0.0`: the portal refuses it.
- `PORTAL_PORT`: setup picks 8443, or the next free port if something on this
  host (or another container) already uses it, and keeps it from then on.
- `PORTAL_HOSTS`: the names you open it by, such as
  `nas.local,nas,192.168.1.20`. Anything else gets "421 Misdirected".

Any address but loopback also switches the portal to HTTPS only. On first
start it makes its own certificate (ECDSA P-256, valid 825 days, renewed by
itself 30 days before expiry or when `PORTAL_HOSTS` changes) and keeps it in
its data volume. `./bridgekeep portal` prints its SHA-256 fingerprint in four
lines of eight.

**The first visit.** Each browser warns once that it doesn't know the
certificate. Open the warning's certificate details and continue only if the
fingerprint matches the one `./bridgekeep portal` printed: that's how you know
you reached this computer and not something pretending to be it.

**Skip the warning from now on** by installing the certificate as trusted.
Download it from `https://<address>:8443/portal.crt` (or Settings > Access), then:

- **macOS:** open it, Keychain Access adds it; double-click it there and set
  "When using this certificate" to Always Trust.
- **Windows:** open it, Install Certificate > Current User > Place all
  certificates in "Trusted Root Certification Authorities".
- **iPhone/iPad:** open it in Safari, install the profile in Settings, then
  Settings > General > About > Certificate Trust Settings, turn it on.
- **Android:** Settings > Security > Encryption & credentials > Install a
  certificate > CA certificate.
- **Firefox** keeps its own list: Settings > Privacy & Security >
  Certificates > View Certificates > Authorities > Import.

While network mode is on, sign-ins idle out after an hour instead of 12, and
password-only accounts see a banner recommending an authenticator.

Don't forward the port on your router. For access away from home, use a VPN
such as Tailscale or WireGuard. An SSH tunnel to the default local-only
portal works too: `ssh -L 8443:127.0.0.1:8443 you@your-host`.

**Client addresses.** Failed sign-ins back off per client address, and the
audit log records it. A normal Docker install passes the real LAN address
through. Rootless Docker (and some NAS setups that proxy ports) make every
client look like one address; the overall limit still applies, but the audit
log then can't tell devices apart.

## Host commands

| Command | What it does |
| --- | --- |
| `./bridgekeep portal` | Where to open it, the certificate fingerprint, and a claim code if it isn't claimed yet. |
| `./bridgekeep portal code` | A new claim code (before the portal is claimed). Codes last an hour and work once. Printed to a terminal only. |
| `./bridgekeep portal reset-admin` | Forgets the admin password and authenticator, signs everyone out and prints a new claim code. |
| `./bridgekeep portal network on` / `off` | Opens it to your home network over HTTPS, or back to this computer only. |

## How it is protected

It follows the security review's portal requirements (P1 to P12):

- **Own container, least privilege (P1).** UID 10003, read-only root,
  all capabilities dropped, `no-new-privileges`, no Docker socket. It is
  alone on the `portal-web` network, which has no masquerade, so it has no
  route to the internet. It never joins `mail` and holds no IMAP credential.
- **This computer only by default (P5).** Compose publishes on
  `PORTAL_ADDRESS`, which defaults to `127.0.0.1`. Network mode uses one
  interface address you pick, never `0.0.0.0`.
- **HTTPS on the network (P9).** The same variable that publishes the port
  turns on HTTPS, so the portal can't be reachable from the network over
  plain HTTP. TLS 1.2+, HSTS, and the `__Host-` Secure cookie.
- **Claim code (P6).** `./bridgekeep` prints a fresh one to your terminal
  only (that also voids the one in the container log from first start). Only
  its hash is stored. It lasts an hour, is used up the moment it's accepted, and is rate-limited.
- **Admin sign-in (P7).** argon2id password. An authenticator (TOTP, with
  replay protection) is optional: without
  one the password needs 15+ characters, otherwise 12+, and it may not be
  one of the 10,000 most common passwords or contain "bridgekeep" or
  "proton". The Status page nudges password-only accounts to add one.
  Turning the authenticator off always asks for the password and a current
  code. Failed attempts back off exponentially per address and overall.
  Recovery only from the host.
- **Step-up (P8).** Changing the admin password or turning on the
  authenticator needs the password (and a fresh code, if enrolled) again. Later releases use the same check for the Proton
  sign-in, live mode, list edits and the API key.
- **Browser attacks (P10, P11).** A Host allowlist (loopback names, plus
  `PORTAL_HOSTS`) against DNS rebinding. GETs never change anything; every
  POST needs a same-origin `Origin` and a per-session token. Session cookies
  are HttpOnly and SameSite=Strict (`__Host-` and Secure over HTTPS), with a
  12-hour idle timeout (1 hour in network mode), a new id at every sign-in,
  and every other session ends when the password or authenticator changes. Templates escape
  everything, the CSP allows only the portal's own script and styles, and
  nothing loads from a CDN.
- **Audit log (P12).** Every sign-in and change, with time, action and
  address, shown under Settings. The table refuses updates and deletes.
  Request bodies and query strings are never logged.

Cookies are not separated by port: another service on `127.0.0.1` could
receive the portal's cookie. Set `PORTAL_HOSTS=bridgekeep.localhost` and open
<http://bridgekeep.localhost:8443> to give the portal its own cookie scope in
Chrome and Firefox.

## Back up

The `portal-data` volume holds the admin password hash, the authenticator
(TOTP) seed and the audit log. Back it up encrypted, like the Bridge volume.
If you lose it, `reset-admin` and a new claim are all you need: it holds no
mail or Proton secrets.

Docker Engine 28 or later is needed for `127.0.0.1` publishing to keep LAN
neighbours out; older engines could forward to loopback-published ports.

## Develop

```sh
make portal-test     # unit tests in a throwaway container
make portal-smoke    # the built image: read-only, claim code, healthz, Host check
```
