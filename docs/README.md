# Bridgekeep documentation

New here? Start with the [main README](../README.md) for what Bridgekeep does,
then pick the install guide for your host.

## Install

| Host | Guide | Command |
|---|---|---|
| Linux, amd64 or arm64 (Debian, Ubuntu, Raspberry Pi OS…) | [linux-host.md](linux-host.md) | `git clone` then `./bridgekeep setup` |
| Proxmox VE | [proxmox.md](proxmox.md) | one `curl` command in the host's shell |
| TrueNAS SCALE 24.10+ | [truenas.md](truenas.md) | `git clone` onto a dataset, then `./bridgekeep setup` |

## Use

- [portal.md](portal.md): the admin portal, page by page, and opening it from
  other devices
- [analyzer.md](analyzer.md): the AI mail analyzer: shadow and live mode,
  lists, spending, older mail, AI vendors and privacy
- [operations.md](operations.md): status, updates, signing in again, using
  Bridge from your own containers, backups and troubleshooting
- [alerts.md](alerts.md): Discord alerts and health checks

## Reference (for developers)

- [images.md](images.md): the signed amd64/arm64 images, and how hosts verify
  and pull them
- [broker.md](broker.md): the sign-in broker the portal uses to sign Bridge in
- [testing.md](testing.md): end-to-end testing with a real account on Docker
  Desktop
- [scoping.md](scoping.md): the original design and security scoping
- [analyzer/README.md](../analyzer/README.md): analyzer internals, the
  offline evaluation tool and the portal's settings files
- [portal/README.md](../portal/README.md): portal internals and security
  requirements
