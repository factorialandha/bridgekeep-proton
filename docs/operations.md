# Running Bridgekeep day to day

Everything here is a `./bridgekeep` command on the host (on Proxmox, the
`bridgekeep` command on the Proxmox host) or a page in the
[admin portal](portal.md). Run the commands from the folder you cloned.

## Checking on it

```sh
./bridgekeep status    # health, signed-in address, sync progress, storage, portal, updates
./bridgekeep doctor    # rerun setup's checks and print a fix for each failure
./bridgekeep logs      # follow Bridge's log (Ctrl+C to stop)
```

The portal's **Status** page shows the same, and lists anything that needs
you. A health check runs every 5 minutes: container health, free disk space,
and every 30 minutes a real IMAP sign-in. With [alerts](alerts.md) on, it
tells your Discord channel when something goes wrong.

## Stopping and starting

```sh
./bridgekeep stop           # everything, including the portal
./bridgekeep stop bridge    # only Bridge (the analyzer can't read mail meanwhile)
./bridgekeep start          # start it all again (or: start bridge)
```

A stopped service stays stopped, even after a reboot, until you start it, and
the health check doesn't alert about it meanwhile.

## Updates

### Bridge

Every night Bridgekeep:

1. Looks up the latest stable Bridge release and accepts it only if Proton
   signed it with the key committed in `keys/`. If Proton ever changes its
   signing key, the update stops and tells you; nothing changes until a
   reviewed commit adds the new key.
2. Rebuilds when there's a new Bridge or Go release, when Bridgekeep's part of
   the image changed, or when the image is a week old (for operating system
   security fixes).
3. Smoke-tests the new image on a throwaway copy.
4. Stops there. The status, the portal and Discord say an update is waiting.

To install it:

```sh
./bridgekeep deploy-update
```

It swaps in the tested image, waits for Bridge to become healthy, and rolls
back to the previous image if it doesn't. Your sign-in and settings stay as
they are. To check for an update straight away, run `./bridgekeep update`
(it builds and tests, and still waits for `deploy-update`).

Bridge's own self-updater isn't in the image, so Bridge never updates itself.

### Bridgekeep itself

```sh
git pull && ./bridgekeep setup
```

On Proxmox, run the install command again instead (or the same two commands
in a git checkout). Setup rebuilds only the parts whose code changed and
skips everything that's already done. New Bridge releases still wait for
`deploy-update`.

## Signing in to Proton again

If Proton ends the session (a password change, a revoked session, a long
time offline), Bridge keeps running but stops syncing. The health check
notices within 30 minutes, the portal's Status page says so, and Discord
alerts you.

Sign in again on the portal's **Proton account** page, or on the host:

```sh
./bridgekeep relogin
```

Both ask for your Proton password, a two-factor code if you use one, and
your mailbox password if you have one.

## Using Bridge from your own containers

Bridge publishes no ports on the host. Other containers reach it on its
private `proton-bridge_mail` Docker network, at `bridge:1143` (IMAP with
STARTTLS). SMTP sending is off by default.

```sh
./bridgekeep credentials    # the IMAP username and password, shown once
```

To connect a container of your own, add it to that network in your own app's
Compose file:

```yaml
services:
  my-client:
    image: ...
    networks: [mail]
networks:
  mail:
    external: true
    name: proton-bridge_mail
```

### TLS certificate

Bridge uses a self-signed certificate. Setup saves it as `bridge-cert.pem` in
the Bridgekeep folder. Trust that file in your client rather than turning
verification off:

- **Python** (`imaplib`): `ssl.create_default_context(cafile="bridge-cert.pem")`,
  passed to `starttls()`. The certificate is issued for `127.0.0.1`, so set
  `check_hostname = False` while still verifying against this one certificate.
- **Debian or Ubuntu containers:** copy it to
  `/usr/local/share/ca-certificates/proton-bridge.crt` and run
  `update-ca-certificates`.

The certificate stays the same across restarts and updates.

## Backup and restore

Bridgekeep's data holds the keys to your mailbox. **Anyone with a copy can
read your mail**, so keep backups encrypted, and keep the backup passphrase in
a password manager, not next to the backup.

- **Proxmox:** back up Bridgekeep's container (Datacenter > Backup) to
  Proxmox Backup Server with client-side encryption, or to an encrypted disk.
  See [proxmox.md](proxmox.md#backups-and-encryption).
- **TrueNAS:** snapshot and replicate the dataset. See
  [truenas.md](truenas.md#5-backups).
- **Other Linux hosts:** back up Bridge's data volume as an encrypted file:

```sh
./bridgekeep stop bridge
docker run --rm -v proton-bridge_bridge-data:/data:ro debian:trixie-slim \
  tar -C /data -cf - . | gpg --symmetric --cipher-algo AES256 -o bridge-backup.tar.gpg
./bridgekeep start bridge
```

To restore it onto a new machine, before running setup there:

```sh
docker volume create proton-bridge_bridge-data
gpg -d bridge-backup.tar.gpg | docker run --rm -i -v proton-bridge_bridge-data:/data \
  debian:trixie-slim sh -c 'tar -C /data -xf - && chown -R 10001:10001 /data'
./bridgekeep setup
```

Setup finds the restored sign-in and doesn't ask for it again. API keys and
the Discord webhook aren't in that backup; enter them again in the portal.
The mail cache rebuilds itself with a fresh sync, but the keychain in the
volume can't be recreated: without a backup, you sign in again.

Use full-disk encryption on the host too, since Bridge must start
unattended and its key can't have a passphrase.

## Troubleshooting

Start with `./bridgekeep doctor`. It reruns setup's checks and prints a fix
for each problem.

- **Setup stopped at a step:** read the fix it printed, then run
  `./bridgekeep setup` again. It carries on from that step. Logs from each
  step are in `.bridgekeep/logs/`.
- **Bridge is "unhealthy" right after starting:** Bridge can take a couple of
  minutes to open its ports. Wait, then check `./bridgekeep status`.
- **Bridge stops with a keychain error:** the data volume is damaged or
  partly missing (for example a half-restored backup). Bridgekeep refuses to
  make a new keychain over existing data, so nothing is lost silently.
  Restore the backup again, or start fresh and sign in again.
- **The first sync is slow:** a large mailbox can take many hours. Status
  shows progress, and new mail arrives meanwhile.
- **The portal won't open from another device:** check
  `./bridgekeep portal`. It may be on this machine only
  (`./bridgekeep portal network on`), on a port other than 8443, or blocked by
  the host's firewall.
- **Forgot the portal password:** `./bridgekeep portal reset-admin`, then
  claim it again with the code it prints.
- **The analyzer isn't checking mail:** the portal's Status page says why.
  Usually Bridge needs signing in again, or the AI has no key or has reached
  its budget (it keeps working on rules and lists meanwhile).
