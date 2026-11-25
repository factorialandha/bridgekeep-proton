# Installing on Linux (amd64 or arm64)

This guide covers any Linux machine that runs Docker: Debian, Ubuntu,
Raspberry Pi OS and others, on amd64 (x86_64) or arm64 (aarch64), such as a
Raspberry Pi 4 or 5. For Proxmox VE see [proxmox.md](proxmox.md), and for
TrueNAS SCALE see [truenas.md](truenas.md).

## 1. Prepare the machine

- **Full-disk encryption** (LUKS) is strongly recommended. Bridgekeep's data
  holds the keys to your mailbox.
- **Docker Engine with Compose and Buildx,** version 28 or later
  recommended (the portal's network isolation needs it; setup warns on older
  versions). If you don't have
  Docker yet, install Docker's own packages (below). If Compose or Buildx is
  missing on Debian or Ubuntu, setup offers to install it for you.
- **git**, to download Bridgekeep: `sudo apt install git`.
- **Memory:** about 2 GB free if Bridge has to be built from source. On a
  small board, add swap. A downloaded image needs much less.
- **Disk:** at least 10 GB free for Docker. The mail cache grows with your
  mailbox.
- **Your user** must be allowed to use Docker (the `docker` group), or run
  setup with `sudo`. Setup asks for `sudo` when it saves secrets.

### Installing Docker's own packages

Debian's and Raspberry Pi OS's `docker.io` package is often too old. Docker's
own packages replace it without touching your existing volumes, images or
containers:

```sh
sudo apt-get remove -y docker.io docker-compose docker-buildx containerd runc
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
docker version --format '{{.Server.Version}}'   # 28 or newer
```

On Ubuntu, use `linux/ubuntu` in both URLs. Raspberry Pi OS uses the Debian
URLs.

## 2. Run setup

```sh
git clone -b preview https://github.com/factorialandha/bridgekeep-proton.git bridgekeep
cd bridgekeep
./bridgekeep setup
```

Setup asks a few yes/no questions and your Proton sign-in, and prints every
command you might need. The steps:

1. **Checking this machine.** Docker, Compose, Buildx, memory and disk.
2. **Where your data lives.** Docker volumes on this machine.
3. **Getting Bridge.** It downloads the signed image for your CPU when it
   can (about a minute) and checks its signature. Otherwise it builds Bridge
   from Proton's source here, which takes 5 to 15 minutes the first time.
   `./bridgekeep setup --build` always builds locally.
4. **Testing the image** with a smoke test on a throwaway volume.
5. **Signing in to Proton.** Your address, password, and two-factor code if
   you use one. Bridge's own password, which mail clients use, is saved
   without being shown.
6. **Starting Bridge and checking the sign-in** with a real IMAP login.
7. **AI mail analyzer (optional).** Asks whether to set it up and which AI
   vendor to use (Anthropic, OpenAI, Google Gemini, a local server, or none
   for rules and lists only). The key is typed hidden. It starts in log-only
   mode.
8. **Admin portal (optional).** Builds the portal and asks whether to open it
   to your other devices at home (HTTPS). If port 8443 is taken, it picks the
   next free port.
9. **Scheduling.** The nightly update check, the 5-minute health check, and,
   if you want them, Discord alerts.
10. **Final check.** A PASS/FAIL table, and where to open the portal.

If a step fails, setup prints why and the fix. Run `./bridgekeep setup`
again and it carries on from there. It's always safe to run it again.

## 3. Afterwards

```sh
./bridgekeep status    # health, sync progress, storage, portal, updates
./bridgekeep portal    # the portal's address, and a claim code the first time
```

Open the portal, enter the claim code, and choose an admin password. See
[portal.md](portal.md).

The first sync of a large mailbox can take hours (a very large one, most of a
day). The analyzer and portal work during the sync.

## Which CPUs are covered

| | arm64 (aarch64) | amd64 (x86_64) |
|---|---|---|
| Signed ready-built image | yes | yes |
| Build from Proton's source | yes | yes |
| Build from Proton's signed `.deb` | no (Proton ships none for arm64) | yes |

Every build, on either CPU, uses only a Bridge release Proton published as a
signed `.deb`, checked against the key committed in `keys/`. A source build
must also match the source hash pinned in `bridge-version.env`.

## Updating

- New Bridge releases are built and tested every night, then wait for
  `./bridgekeep deploy-update`. See [operations.md](operations.md#updates).
- To update Bridgekeep itself: `git pull && ./bridgekeep setup`.

## Moving from another machine

To move an existing sign-in instead of signing in again, restore an encrypted
backup ([operations.md](operations.md#backup-and-restore)) before running
setup. The data works on either CPU.
