# Installing on TrueNAS SCALE

Bridgekeep runs on TrueNAS SCALE 24.10 ("Electric Eel") and later, where apps
run on Docker. It runs from the TrueNAS shell as an ordinary Docker Compose
project, with its data on a ZFS dataset you choose, so snapshots, replication
and dataset encryption cover your sign-in and secrets. TrueNAS SCALE 24.04
and earlier ran apps on Kubernetes and are not supported.

It isn't a TrueNAS "Custom App": the Apps screen can't build or safely swap
images the way Bridgekeep's tested updates do. So Bridgekeep doesn't appear on
the Apps screen. You manage it with `./bridgekeep` commands and the admin
portal, and Docker still restarts it after a reboot.

## 1. Before you start

- **Apps enabled.** Under **Apps**, choose a pool for applications. TrueNAS
  starts Docker only once a pool is set.
- **An admin account and a shell:** **System > Shell** in the web UI, or SSH.
  Setup runs as root (`sudo -i`).
- **Memory:** if Bridge has to be built from source, it needs about 2 GB free.
  On a NAS whose ZFS cache uses most of the memory, run setup at a quiet time.

## 2. Create the dataset

In **Datasets**, add a dataset, for example `tank/bridgekeep`:

- **Dataset preset: Generic.** The SMB preset uses NFSv4 ACLs, which Bridge's
  key store can't use. Setup checks this and refuses an NFSv4 dataset.
- **Encryption: on.** The dataset holds the keys to your mailbox. With a key
  that TrueNAS stores, it unlocks at boot. With a passphrase, Bridge doesn't
  start after a reboot until you unlock the dataset; then run
  `./bridgekeep start`.

## 3. Run setup

In the shell:

```sh
sudo -i
cd /mnt/tank/bridgekeep        # your dataset's folder
git clone -b preview https://github.com/factorialandha/bridgekeep-proton.git repo
cd repo
./bridgekeep setup
```

The checkout must be on a dataset under `/mnt/`, because TrueNAS upgrades can
reset the system drive. Setup refuses anywhere else.

At step 2 setup asks which dataset folder to use, and suggests the folder
above the checkout (`/mnt/tank/bridgekeep` here). It creates the data and
secrets folders there with the right owners and permissions, and remembers the
choice. Everything else is the same as on any Linux host
([linux-host.md](linux-host.md#2-run-setup)), including the portal and
analyzer questions.

On TrueNAS setup also adds two jobs under **System > Advanced Settings >
Cron Jobs**: "Bridgekeep auto-update" (nightly) and "Bridgekeep health watch"
(every 5 minutes). Jobs there survive TrueNAS upgrades. Leave them in place.

If `git` isn't available in your shell, copy the repository folder onto the
dataset over SMB and carry on from `cd repo`.

## 4. Afterwards

```sh
cd /mnt/tank/bridgekeep/repo
./bridgekeep status
./bridgekeep portal
```

Day-to-day use is the same as on any host: see [operations.md](operations.md)
and [portal.md](portal.md). To update Bridgekeep itself:
`git pull && ./bridgekeep setup`.

## 5. Backups

Add a **Data Protection > Periodic Snapshot Task** for `tank/bridgekeep`, and
replicate it if you have a second pool or NAS. Replicate it as a raw stream
(keep the destination encrypted with the source's key), so the copy stays
encrypted and the destination never gets the key.

Snapshots keep old copies of everything, including secrets. After you change
the Bridge password or an API key because of a suspected leak, delete the
older snapshots too, on both pools. A snapshot of running Bridge is
crash-consistent, which Bridge recovers from. For a clean copy, run
`./bridgekeep stop bridge` during the snapshot and `./bridgekeep start bridge`
afterwards.

## 6. Other apps on the NAS

Bridge publishes no ports. Don't add port mappings for it, here or in a
TrueNAS app: like all Docker port mappings, they bypass the host firewall. A
container that needs mail can join Bridgekeep's private mail network instead
([operations.md](operations.md#using-bridge-from-your-own-containers)).

## Troubleshooting

Run `./bridgekeep doctor` first: it prints a fix for each problem it finds.

- **"does not exist" at step 2, or Bridge won't start after a reboot:** the
  dataset is locked. Unlock it in **Datasets**, then `./bridgekeep start`.
- **"required variable BRIDGEKEEP_DATA is missing":** a command ran outside
  the repository folder, or setup's saved dataset choice is gone. `cd` into
  the repository and run `./bridgekeep setup` again; it asks for the dataset
  and carries on.
- **Setup says the dataset uses NFSv4 ACLs:** create a dataset with the
  Generic preset, move the repository there, and run setup again.
- **"This checkout is on the system drive":** clone it onto a dataset under
  `/mnt/` instead.
- **The mail network won't start (`Pool overlaps`):** another app already uses
  `172.31.253.0/24`, which Bridgekeep uses for its private mail network.
  Setup and the portal can't change that range yet, so please open an issue
  if you hit this.
