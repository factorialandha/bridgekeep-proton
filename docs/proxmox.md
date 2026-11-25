# Installing on Proxmox VE

One command installs Bridgekeep on a Proxmox VE host, with no git needed. Run
it in the host's shell as root (the web UI's node **Shell**, or SSH).

```sh
bash -c "$(curl -fsSL https://raw.githubusercontent.com/factorialandha/bridgekeep-proton/preview/deploy/proxmox/install.sh)"
```

It downloads Bridgekeep from GitHub to `/root/bridgekeep`, adds a
`bridgekeep` command to the host, and runs setup. Setup options go at the
end: `bash -c "$(curl ...)" _ --ctid 120`.

By default the container gets 2 cores, 2 GB of memory and a 20 GB disk, so
the host needs that much to spare. Keep Proxmox itself up to date (see
[If something goes wrong](#if-something-goes-wrong)).

A git checkout works too: `git clone -b preview https://github.com/factorialandha/bridgekeep-proton.git bridgekeep && cd bridgekeep && ./bridgekeep setup`.
Clone it as root (see below).

**If curl says 404,** the repository isn't public to you (for example a
private copy), and GitHub serves it only with a token. Make a
[fine-grained token](https://github.com/settings/personal-access-tokens/new)
for the repository only, with *Contents: read-only*. Then:

```sh
read -rsp 'GitHub token: ' GITHUB_TOKEN && export GITHUB_TOKEN && echo
bash -c "$(curl -fsSL -K- <<<"header = \"Authorization: Bearer $GITHUB_TOKEN\"" https://raw.githubusercontent.com/factorialandha/bridgekeep-proton/preview/deploy/proxmox/install.sh)"; unset GITHUB_TOKEN
```

`read -s` keeps the token out of your shell history, and `-K-` keeps it off
curl's command line. The installer sends it only to GitHub and doesn't save it.

Nothing gets installed on the host itself besides that folder and command.
Instead, setup:

1. Makes a Debian container (LXC) for Bridgekeep and starts it. Setup shows
   the plan and asks once first. The container is unprivileged, with
   *nesting* and *keyctl* on (Docker needs both), and starts with the host.
   It's tagged `bridgekeep`. Defaults: 2 cores, 2 GB of memory plus 1 GB of
   swap, a 20 GB disk on `local-lvm` (or the first storage that holds
   containers), and DHCP on `vmbr0`.
2. Installs Docker's own packages in the container. Their key file must hold
   exactly one key, with Docker's published fingerprint, and only that key is
   trusted, then setup checks that
   Docker can start a container in there.
3. Copies Bridgekeep to `/opt/bridgekeep` in the container: exactly the
   downloaded files, or a git checkout's last commit (tracked files and
   history, with no remote URL, credentials or untracked files).
4. Runs `./bridgekeep setup` in the container: the usual steps, prompts and
   PASS/FAIL table. In a container, the portal question defaults to **yes**
   for network access, because otherwise only the container itself could open
   it. The portal's address is the container's address.

Works on amd64 and on arm64 Proxmox ports. On arm64, if Proxmox's template
list has no Debian, setup offers to download Debian 13 for arm64 from
linuxcontainers.org. It's checked against that build's SHA256SUMS, but
nothing signs it, so you're trusting that site's HTTPS alone. Setup asks
first, and with `--yes` it refuses. To avoid it, download a Debian arm64
template yourself and pass `--template STORAGE:vztmpl/NAME`.

Setup runs git on the host checkout as root, so it refuses a checkout (or a
folder above it) that anyone but root can change. Clone it as root.

## Day two

Anywhere on the Proxmox host, every command works as usual and runs in the
container (from a git checkout, use `./bridgekeep` in that folder):

```sh
bridgekeep status        # starts with the container's number and address
bridgekeep credentials
bridgekeep portal code
bridgekeep shell         # a root shell inside the container
```

To update Bridgekeep, run the install command again (from a git checkout:
`git pull && ./bridgekeep setup`). Setup reuses the container, copies the new
version in, and carries on. Bridge updates still wait for
`bridgekeep deploy-update`.

## Choosing other settings

Add these options to the first `./bridgekeep setup`. Any other option, such as
`--yes`, `--portal` or `--build`, goes on to setup in the container.

| Option | Default |
|---|---|
| `--ctid N` | the next free ID |
| `--hostname NAME` | `bridgekeep` |
| `--storage NAME` | `local-lvm`, else `local-zfs`, else the first that holds containers |
| `--bridge vmbrN` | `vmbr0` |
| `--ip 192.168.1.50/24 --gateway 192.168.1.1` | DHCP |
| `--disk GB` / `--memory MB` / `--cores N` | 20 / 2048 / 2 |
| `--template STORAGE:vztmpl/NAME` | the newest Debian 13 (or 12) template |

`--ctid` never takes over a container that isn't tagged `bridgekeep`. If a
host has several Bridgekeep containers, add `--ctid` to every command.

## Backups and encryption

The container holds your Proton sign-in and the password your mail apps use.
Proxmox backups of it (Datacenter > Backup) are the simplest way to back it
up. Keep them encrypted: use Proxmox Backup Server with client-side
encryption, or a backup storage on an encrypted disk.

## If something goes wrong

- **"Docker can't start containers inside container N."** This is usually an
  older Proxmox release. Update the host (`apt update && apt full-upgrade`),
  reboot, and run setup again. Nesting must be on: `pct set N --features nesting=1,keyctl=1`.
- **No network address after 90 seconds.** The bridge has no DHCP. Run setup
  again with `--ip` and `--gateway`, or fix the container's network in the web UI.
- **ZFS storage on Proxmox older than 8.1** makes Docker fall back to a slow,
  space-hungry storage driver. Use `local-lvm`, or update Proxmox.
- To install directly on the Proxmox host anyway (not recommended), run
  `BRIDGEKEEP_PROXMOX=off ./bridgekeep setup`.
