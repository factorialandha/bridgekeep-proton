# Alerts and health checks

Bridgekeep can post short alerts to a Discord channel. It's optional: with no
webhook set up, alerts are only logged.

| Alert | When |
|---|---|
| Bridge signed out | Bridge refuses the saved sign-in. Run `./bridgekeep relogin`. |
| Update waiting | The nightly job built and tested a new Bridge. Run `./bridgekeep deploy-update`. |
| Update stopped | The nightly job stopped, for example because of a new signing key. Nothing was changed. |
| Not healthy / healthy again | A container was unhealthy or stopped on two checks in a row, and when it recovers. |
| Disk nearly full | Free space on the disk with Bridgekeep's data is under 10% or 5 GiB. |
| Budget reached | The analyzer reached its monthly model budget. It keeps sorting with your rules and lists, without the model, until the 1st. |

## Turning it on

In Discord, open **Server Settings**, then **Integrations**, then
**Webhooks**, make a webhook for the channel you want, and copy its URL.
Then either:

- in the portal, open **Settings > Alerts**, paste the URL and choose **Turn
  on alerts**, or
- on the host, run `./bridgekeep alerts on` and paste it when asked.

Bridgekeep sends a test message first and saves the URL only if Discord
accepted it. It's kept in the host's secrets folder, readable only by root,
and no container ever holds it.

| Command | What it does |
|---|---|
| `./bridgekeep alerts` | Show whether alerts are on |
| `./bridgekeep alerts on` | Turn alerts on, or replace the webhook |
| `./bridgekeep alerts test` | Send a test message |
| `./bridgekeep alerts off` | Turn alerts off |
| `./bridgekeep watch` | Install the 5-minute health check if it's missing, and run one round now |

Setup installs the health check and offers alerts at step 9, so most hosts
need none of this.

## Health checks

Every 5 minutes the host checks each container's health and the free disk
space, and every 30 minutes it proves the Bridge sign-in with a real IMAP
login. The results feed the portal's Status page, `./bridgekeep status`, and
the alerts above.

- The same alert repeats at most every 6 hours (signed out, not healthy) or
  24 hours (others), and at most 10 alerts go out in an hour.
- Messages have fixed wording, with only a short detail (a version, a
  container name) filled in. Mentions are off, so an alert never pings anyone.
- The health check's log is `/var/log/bridgekeep/health-watch.log`.

## For developers

The rest of this page describes how alerts and status files work inside
Bridgekeep.

### How it works

- Only the host sends to Discord (`scripts/notify.sh`, with curl). No
  container gets the webhook or a route to discord.com, so no egress
  allowlist changes.
- `scripts/health-watch.sh` runs every 5 minutes as root. `./bridgekeep
  setup` installs it (or `./bridgekeep watch` on a host set up earlier):
  a fixed wrapper, `/usr/local/lib/bridgekeep/health-watch`, run by the
  `bridgekeep-watch.timer` systemd timer (or cron). On TrueNAS SCALE, where
  /usr is read-only and reset on upgrades, the same wrapper lives inside the
  "Bridgekeep health watch" cron job itself (TrueNAS's own config). On every run the wrapper checks that only root can change the
  checkout and skips the round if not. Log: `/var/log/bridgekeep/health-watch.log`. It sends alerts that containers left
  in their spool folder, checks container health, and every 30 minutes
  proves the Bridge sign-in with a real IMAP login.
- What the wrapper runs, in plain text:
  ```bash
  root=/path/to/checkout log=/var/log/bridgekeep/health-watch.log
  checkout_safe() { … }   # the same function as in ./bridgekeep
  exec 9>/run/bridgekeep-watch.lock; flock -n 9 || exit 0
  if ! checkout_safe 2>>"$log"; then echo "… skipped: $root is not root-only" >>"$log"; exit 1; fi
  cd "$root" || exit 1
  bash scripts/health-watch.sh >>"$log" 2>&1
  tail -n 2000 "$log" >"$log.tmp" && mv -f "$log.tmp" "$log"
  ```
  To read the installed copy: `cat /usr/local/lib/bridgekeep/health-watch`,
  or on TrueNAS
  `midclt call cronjob.query '[["description","=","Bridgekeep health watch"]]' | python3 -c 'import json,sys,base64; print(base64.b64decode(json.load(sys.stdin)[0]["command"].split()[1]).decode())'`.
- `scripts/auto-update.sh` sends "update waiting" and "update stopped" itself.
- Each message has fixed wording. Only a short detail (a version, a
  container name) is filled in. Details are cut to plain characters, with no
  `@`, quotes or backticks, and shown as inline code, so a URL in one is
  never a clickable link. Discord mentions are switched off, so nothing can
  ping anyone.
- The same alert repeats at most every 6 hours (signed out, not healthy) or
  24 hours (others), and at most 10 alerts go out in an hour (and at most 10
  from each container's folder).

### Sending an alert from a container

Containers can't reach Discord. They write a small file into their own
spool folder, and the host sends it within 5 minutes.

| Container | Folder in the container | Owner | May send |
|---|---|---|---|
| analyzer, imap-proxy | `/run/bridgekeep/alerts` | 10002 | `budget_cap`, `login_expired`, `health_failed`, `health_recovered`, `analyzer_mode_changed`, `move_cap`, `imap_refused` |
| admin portal | `/run/bridgekeep/alerts` | 10003 | `login_expired`, `update_waiting` |

One alert per file. Write it as `NAME.tmp`, then rename it to `NAME.alert`,
so the host never reads half a file:

```
event=budget_cap
detail=monthly budget 20 USD reached
```

- `event` is one of the events above. Anything else is dropped.
- `detail` is optional, one line, up to 200 characters, plain text.
- The file must be at most 1 KiB, a regular file (not a link), and owned by
  the folder's owner.
- The host deduplicates, so writing the same alert again is harmless. Write it
  when the state changes, not on every loop.
- If the folder is missing or not writable, carry on. Alerts are best effort.

Python, for example:

```python
import os, uuid
def alert(event, detail=""):
    d = "/run/bridgekeep/alerts"
    name = os.path.join(d, uuid.uuid4().hex)
    try:
        with open(name + ".tmp", "w") as f:
            f.write(f"event={event}\ndetail={detail[:200]}\n")
        os.rename(name + ".tmp", name + ".alert")
    except OSError:
        pass
```

On the host the folders are under `/var/lib/bridgekeep/notify/spool/`, or
`BRIDGEKEEP_NOTIFY_DIR` in `.env` (TrueNAS: on the dataset).
`scripts/notify.sh init` creates them with the right owners.

### Status files for the admin portal

Each round, `health-watch.sh` also writes three files to
`/var/lib/bridgekeep/status/` (or `BRIDGEKEEP_STATUS_DIR`). The folder is
0750 and the files are 0640, owned by root with group 10003 (the portal's
user), so only root and the portal can read them. Each file is written to a
temp file and renamed into place. The portal mounts the folder read-only, so it needs no Docker access.
Each line is one `key=value`, plain text, at most 200 characters.

- `storage.env`: the output of `scripts/storage.sh` (sizes, free space, `low`).
- `host.env`: `docker_version`, `ts`.
- `bridge.env`: `bridge_health` (healthy, starting, unhealthy or not running),
  `signed_in` (yes or no), `account`, `sign_in_error`, `messages` and
  `messages_ts` (from the last IMAP check, every 30 minutes),
  `messages_prev` and `messages_prev_ts` (the check before), `update_scheduled`,
  `update_when`, `update_waiting_version`, `last_update_line` and `ts`.

`account` is the Proton address, so `bridge.env` holds personal data. Show it
only to the portal's signed-in admin.
