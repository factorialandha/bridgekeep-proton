# Published images

CI publishes the Bridge and analyzer images to GitHub's container registry
for amd64 and arm64, so a host can pull an image in about a minute instead of
spending 5 to 15 minutes building it. The images are **private** for now.
Building locally still works and is the fallback whenever a pull isn't
possible.

| | |
|---|---|
| Bridge | `ghcr.io/factorialandha/bridgekeep-bridge` |
| Analyzer | `ghcr.io/factorialandha/bridgekeep-analyzer` |
| Tags from `preview` | `preview`, `<bridge version>-preview` (Bridge only), `preview-<commit12>` |
| Tags from `main` | `latest`, `<bridge version>` (Bridge only), `main-<commit12>` |
| Signed with, from `preview` | `keys/cosign.pub` |
| Signed with, from `main` | `keys/cosign-main.pub` (main has its own key) |

**Main has its own key.** Changes can reach `preview` without the
maintainer's own review, so preview runs must never be able to sign an image
that a host on `main` accepts. Main's private key lives only in an Outpost
environment, `main-signing`, whose branch rule allows the `main` branch
alone. A preview run can't read it, even if a change to `ci/pipeline.yml`
asks for it. Hosts on `main` accept only `keys/cosign-main.pub`, so an image
signed with the preview key is refused there whatever its annotations say.
The `branch=` annotation still catches mistakes such as a retagged image.

The names and settings are in [images.env](../images.env).

## How an image gets there

The `publish-*-preview` and `publish-*-main` jobs in `ci/pipeline.yml` run
only on pushes, schedules and manual runs of their own branch. Those are
protected runs, and only protected runs get secrets and host Docker, so no
other branch or pull request can push. The publish job runs after the
image's build, smoke test and vulnerability scan have passed in the same run.
[scripts/publish-images.sh](../scripts/publish-images.sh) then does this:

1. It builds the multi-arch image from the same pins as a local build. Bridge
   is compiled from the hash-checked source, and arm64 is cross-compiled. It
   adds an SBOM and a build-provenance attestation.
2. It pushes by tag and reads back the index digest.
3. It signs that digest, and each platform's image under it, with cosign,
   using this branch's key. The signature records `repo=`, `branch=` and `commit=`. `repo=` is there
   because the same key may sign other projects' images.

Before it builds anything, the job checks that the key's public half (from
`cosign public-key`) matches this branch's public key, `keys/cosign-main.pub`
on `main` and `keys/cosign.pub` on `preview`. It also refuses to publish if
it was handed the other branch's key. If this branch's file isn't committed
yet, the job prints the public key, publishes nothing, and ends with a
warning. The private key and password are passed to cosign only by variable
name. They are never printed, written to a file or kept as an artifact.

No secret is a build argument or part of any layer. The build arguments are
the public pins in `bridge-version.env` and the commit. The registry login
lives in a throwaway folder for the length of the job.

## How a host uses it

`scripts/pull-image.sh bridge` (also `make pull` or `bash scripts/make.sh pull`):

1. It looks for the image built from exactly this checkout's commit
   (`preview-<commit12>` or `main-<commit12>`). If there isn't one, it uses
   this branch's channel (`preview` or `latest`).
2. It verifies the signature with cosign from the pinned image in
   `images.env`. The signature must be made with this branch's key
   (`keys/cosign-main.pub` on main, `keys/cosign.pub` otherwise) and must
   say `repo=factorialandha/bridgekeep-proton` and `branch=<this branch>` (main
   on main, preview otherwise). For the commit tag it must also say
   `commit=<this commit>`. So a preview image retagged as `latest` fails, and
   so does an image the same key signed for another project. An
   image with no signature or a wrong one is refused, and the script stops.
   It doesn't quietly build instead. On `main` that includes an image signed
   with the preview key, even one that says `branch=main`: that is what an
   attack from a preview change would look like.
3. It pulls the image by the signed digest, never by tag.
4. Bridge: the image's Bridge version and upstream source commit must match
   `bridge-version.env`. Analyzer: it must have been built from this
   checkout's commit, or from an identical `analyzer/` folder (the same git
   tree hash, in the `io.bridgekeep.analyzer-tree` label), because it is only
   republished when `analyzer/` changes. `--allow-other-commit` overrides that. Then it runs the
   smoke test on the image, and only after that tags it `:local`.

Exit code 4 means there is nothing to pull here, for example because the host
isn't signed in to the registry, nothing is published for this commit, or
there's no public key for this branch yet. The caller then builds locally. `./bridgekeep setup` does
exactly that.

## One-time setup (maintainer)

**1. Signing keys.** There are two cosign keys, and only the four
`publish-*` jobs use them. If a job's key isn't set, that job is skipped with
a reason and everything else stays green.

- **Preview** signs with the key already in Outpost, stored as the masked
  **secrets** `COSIGN_PRIVATE_KEY` and `COSIGN_PASSWORD` (not plain
  variables). Its public half is `keys/cosign.pub`.
- **Main** signs with its own key, whose public half is
  `keys/cosign-main.pub`. Its private half is never a shared secret. It lives
  only in an Outpost environment named `main-signing`:
  1. Make the key pair on a machine of your own with Docker, outside any
     checkout. It asks for a password twice:
     ```sh
     mkdir -p ~/bridgekeep-main-key && cd ~/bridgekeep-main-key
     docker run --rm -it --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD:/k" -w /k \
       ghcr.io/sigstore/cosign/cosign:v2.6.1@sha256:68839b7f13dac5a6744a5d8818e984dd39183374e37855c19e14d623d9bc9037 \
       generate-key-pair
     ```
     Use a long, random password, for example one your password manager
     generates. That writes `cosign.key` (private) and `cosign.pub` (public).
  2. In Outpost, open the repository's **Environments** settings and add an
     environment named `main-signing`. Set its branch rule to `main` only.
     Add two environment secrets: `COSIGN_MAIN_PRIVATE_KEY`, with the whole
     of `cosign.key` as its value, and `COSIGN_MAIN_PASSWORD`, with the
     password. Don't add them under the shared **Secrets and variables**,
     because preview runs can read those.
  3. Commit `cosign.pub` as `keys/cosign-main.pub`.
  4. Keep `cosign.key` and its password somewhere offline, such as a password
     manager, and delete the folder.
  5. Check that Outpost keeps the key from preview: start a manual run of
     `preview` (**Run pipeline**). Its `main-signing-canary` job names the
     environment and fails if it can read `COSIGN_MAIN_PRIVATE_KEY`. It passes
     if Outpost refuses or skips the job, or the secret arrives empty. If it
     fails, delete the environment's secrets at once and make a new main key:
     preview runs could read the old one, so treat it as exposed. Main then
     needs another way to sign. Don't promote main's key to `main` until this
     has passed and the result is recorded here.

     Result: not run yet.

**Switching main to its own key.** The images on `main` from before this
change are signed with the preview key, so hosts on `main` refuse them once
they have `keys/cosign-main.pub`. The promotion to `main` that adds that file
republishes both images with main's key. Until that run is green, setup on a
`main` host stops at the signature check, as it should. Wait for the run, or
use `./bridgekeep setup --build`.

On each run, the job checks that the key still matches its committed public
key. If the public file isn't committed yet, the first run prints it so it
can be.

To rotate a key, make a new pair the same way, replace the secrets, and
commit the new public half in the same change. Its push publishes again
with the new key. Until that run finishes, hosts that already have the new
public file refuse the older images and stop at the signature check. Run
`./bridgekeep setup` on them again once that publish run is green.

**2. Registry push.** ghcr.io refuses the run's own GitHub token (preview
run 1809: 403 on upload), so the jobs push with a classic token in the
Outpost secret `GHCR_TOKEN`, as the `factorialandha` account. Make one
[with only `write:packages`](https://github.com/settings/tokens/new?scopes=write:packages&description=bridgekeep-ci)
(it implies `read:packages`; fine-grained tokens can't push packages). Tick
nothing else: no `repo`, no `delete:packages`. Set an expiry of 90 days or
less and put a reminder in your calendar. Add it under **Secrets and
variables** as a masked secret, and never paste it anywhere else. Until it
exists, the publish jobs are skipped with a reason.

Such a token can push to every package on the account, not only these two.
Hosts still refuse any image that isn't signed with their branch's key, so a
stray push can't reach them, but that is why the expiry stays short.

To rotate it: make a new token the same way, replace the `GHCR_TOKEN` secret
in Outpost, then delete the old token on GitHub's tokens page.

**3. Each host pulling a private image** needs a read-only login once. Make a
[classic token with only `read:packages`](https://github.com/settings/tokens/new?scopes=read:packages).
Fine-grained tokens can't read packages. Then:

```sh
docker login ghcr.io -u factorialandha    # paste the token as the password
```

## Going public later

1. In GitHub, open **Packages**, then each package, then **Package settings**,
   and change the visibility to Public.
2. Set `COSIGN_TLOG=true` in `images.env`. New signatures are then also
   written to the public Rekor transparency log, and pulls require that
   entry. While the images are private it stays off, because a Rekor entry
   would publish the image names and digests.

Nothing else changes. Hosts can then skip `docker login`.

## Licence

Bridge is GPL-3.0-or-later, and so is this repository. Every Bridge image
carries the licence and the exact upstream source it was built from in
`/usr/share/doc/proton-bridge/`, and in the `io.bridgekeep.bridge-source` and
`io.bridgekeep.bridge-commit` labels.
