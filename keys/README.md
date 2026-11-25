# Proton Bridge signing key

`proton-bridge-signing-key.gpg` is Proton's public key for Bridge packages.
The image build verifies the `.deb` with this committed file only, and never
downloads a key. `BRIDGE_SIGNING_KEY` in `bridge-version.env` pins its full
40-digit fingerprint as well, so swapping the file alone cannot change what
is trusted. Short and long key IDs are not accepted.

The file is not committed yet. To add it, run
`scripts/update-bridge.sh --trust-key <fingerprint>` with a fingerprint you
confirmed on a Proton page. The script stops unless the key it downloads has
exactly that fingerprint. Run it without the flag first to see the
fingerprint it got.

After that, the script reuses the committed key and refuses `--trust-key`.
Rotating the key is a deliberate, reviewed commit: remove the file and clear
`BRIDGE_SIGNING_KEY`, then run the script again.

## Image signing keys

`cosign.pub` and `cosign-main.pub` are the public halves of the cosign keys
that sign the published images: `cosign.pub` for `preview`,
`cosign-main.pub` for `main`. Hosts on `main` trust only `cosign-main.pub`.
The private halves are never in this repository. See
[docs/images.md](../docs/images.md).
