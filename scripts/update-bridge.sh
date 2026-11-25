#!/usr/bin/env bash
# Pin a Proton Mail Bridge release in bridge-version.env.
#
#   scripts/update-bridge.sh                            # latest stable release
#   scripts/update-bridge.sh 3.x.y                      # a specific version
#   scripts/update-bridge.sh --trust-key <FPR> [3.x.y]  # first run only, see below
#   scripts/update-bridge.sh --check                    # latest vs pinned; exit 10 if newer
#
# Downloads the .deb, verifies its signature with the committed key in
# keys/proton-bridge-signing-key.gpg (pinned by BRIDGE_SIGNING_KEY), and
# rewrites bridge-version.env with the version and the sha256. A release
# counts only if Proton published a signed .deb for it.
#
# For the source build (amd64 and arm64) it also pins:
#   BRIDGE_SOURCE_H1      the release's source hash from the public Go checksum
#                         database (sum.golang.org). The build refuses source
#                         that doesn't match.
#   BRIDGE_SOURCE_COMMIT  the commit the release tag points at, cross-checked
#                         with GitHub when git can reach it.
#   GO_TOOLCHAIN          the newest patch release of the Go version the
#                         release's go.mod asks for, so Go security fixes are
#                         picked up. The go command verifies the download.
#
# First run (no committed key yet): the script does NOT trust a key just
# because it was downloaded from proton.me, the same host as the .deb. Look up
# the full 40-digit fingerprint of Proton's Bridge signing key on a Proton page
# you trust and pass it with --trust-key. The script fetches the key, stops
# unless it has exactly that fingerprint, then writes it to keys/ and pins it.
# Later runs use only the committed key; replacing it is a deliberate commit.
#
# Needs curl, jq, gpg/gpgv, ar (binutils) and GNU coreutils. If any is missing
# (Git Bash on Windows, macOS), or UPDATE_BRIDGE_USE_DOCKER=1 is set, the script
# re-runs itself inside a small Debian container, so only Docker is required.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
debian_image=debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

if [[ -z ${UPDATE_BRIDGE_IN_CONTAINER:-} ]]; then
  missing=()
  for t in curl jq gpg gpgv ar sha256sum sort sed git; do
    command -v "$t" >/dev/null 2>&1 || missing+=("$t")
  done
  if ((${#missing[@]})) || [[ ${UPDATE_BRIDGE_USE_DOCKER:-} == 1 ]]; then
    command -v docker >/dev/null 2>&1 \
      || { echo "update-bridge: missing ${missing[*]} and Docker is not available" >&2; exit 1; }
    src=$root
    command -v cygpath >/dev/null 2>&1 && src=$(cygpath -w "$root")   # Git Bash on Windows
    echo "update-bridge: ${missing[*]:-forced} not available here; running in a Debian container"
    # MSYS_NO_PATHCONV stops Git Bash rewriting /work into a Windows path.
    MSYS_NO_PATHCONV=1 exec docker run --rm -e UPDATE_BRIDGE_IN_CONTAINER=1 \
      -v "$src:/work" -w /work "$debian_image" bash -c '
        set -e
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends ca-certificates curl jq gnupg gpgv binutils git >/dev/null
        exec bash scripts/update-bridge.sh "$@"' update-bridge "$@"
  fi
fi

pins=$root/bridge-version.env
keyfile=$root/keys/proton-bridge-signing-key.gpg
base_url=${BRIDGE_BASE_URL:-https://proton.me/download/bridge}
pubkey_url=${BRIDGE_PUBKEY_URL:-https://proton.me/download/bridge/bridge_pubkey.gpg}
version_url=${BRIDGE_VERSION_URL:-https://proton.me/download/current_version_linux.json}
notes_url=${BRIDGE_NOTES_URL:-https://proton.me/download/bridge/stable_releases.html}
goproxy=${BRIDGE_GOPROXY:-https://proxy.golang.org}
sumdb=${BRIDGE_SUMDB:-https://sum.golang.org}
source_repo=${BRIDGE_SOURCE_REPO:-https://github.com/ProtonMail/proton-bridge}
module=github.com/ProtonMail/proton-bridge/v3
module_escaped='github.com/!proton!mail/proton-bridge/v3'   # proxy path: capitals as !lower
# Proton marked 3.25.0 (Jun 2026) as a must-have security release: never pin older.
min_version=3.25.0
curl_proto=${BRIDGE_CURL_PROTO:-=https}   # tests override this to use file:// fixtures

die() { echo "update-bridge: $1" >&2; exit "${2:-1}"; }
is_fpr() { [[ $1 =~ ^[0-9A-F]{40}$ ]]; }
upper() { tr -d ' ' <<<"$1" | tr '[:lower:]' '[:upper:]'; }
version_ge() { [[ $(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1) == "$2" ]]; }

# shellcheck source=/dev/null
source "$pins"
pinned=${BRIDGE_VERSION:-}
pinned_key=$(upper "${BRIDGE_SIGNING_KEY:-}")

latest_version() {
  # Proton's stable release notes page (GitHub Releases lags behind it). This
  # takes the highest 3.x.y mentioned anywhere on the page, so a version only
  # mentioned in prose would win. The script prints what it picked, and the
  # result goes through a reviewed PR.
  local v
  v=$(curl -fsSL --proto "$curl_proto" "$notes_url" 2>/dev/null \
      | grep -oE '[Vv]?3\.[0-9]+\.[0-9]+' | tr -d 'vV' | sort -uV | tail -n1) || true
  if [[ -n $v ]]; then echo "$v"; return; fi
  # Fallback: Proton's update manifest.
  curl -fsSL --proto "$curl_proto" "$version_url" | jq -r '
    ( [ .. | objects | select((.CategoryName? // .Category? // "" | ascii_downcase) == "stable") | .Version? ]
      + [ .. | objects | .Version? ] )
    | map(select(type == "string" and test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))) | first // empty'
}

# Primary-key fingerprints in a key file, one per line.
key_fprs() {
  gpg --batch --with-colons --import-options show-only --import "$1" 2>/dev/null \
    | awk -F: '$1=="pub"{p=1; next} $1=="fpr" && p {print $10; p=0}'
}

mode=pin
want=""
trust_key=""
while (($#)); do
  case $1 in
    --check) mode=check ;;
    --trust-key) shift; trust_key=$(upper "${1:-}") ;;
    -*) die "unknown option $1" 2 ;;
    *) want=$1 ;;
  esac
  shift
done

if [[ -z $want ]]; then
  want=$(latest_version) || true
  [[ -n $want ]] || die "could not read the latest version from $notes_url; pass a version" 2
fi
echo "target version: $want"

if [[ $mode == check ]]; then
  echo "pinned=${pinned:-none} latest=$want"
  [[ $want == "$pinned" ]] && exit 0
  exit 10
fi

[[ $want =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "bad version: $want" 2
version_ge "$want" "$min_version" || die "refusing $want: older than security floor $min_version" 2

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
export GNUPGHOME=$tmp/gnupg
mkdir -m 700 "$GNUPGHOME"

if [[ -s $keyfile ]]; then
  [[ -z $trust_key ]] || die "a signing key is already committed in keys/. --trust-key is for the first run only. To rotate the key, remove keys/proton-bridge-signing-key.gpg and clear BRIDGE_SIGNING_KEY in a reviewed commit first." 2
  is_fpr "$pinned_key" || die "BRIDGE_SIGNING_KEY must be a full 40-digit fingerprint (got '$pinned_key')" 2
  cp "$keyfile" "$tmp/pubkey.gpg"
  key=$pinned_key
else
  echo "no committed signing key: fetching $pubkey_url"
  curl -fsSL --proto "$curl_proto" -o "$tmp/pubkey.gpg" "$pubkey_url"
  found=$(key_fprs "$tmp/pubkey.gpg")
  if [[ -z $trust_key ]]; then
    {
      echo
      echo "The downloaded key file contains these fingerprints:"
      while read -r f; do echo "    $f"; done <<<"$found"
      echo
      echo "Not trusting it automatically: it came from the same host as the package."
      echo "Confirm the fingerprint on a Proton page you trust, then re-run:"
      echo "    scripts/update-bridge.sh --trust-key <40-digit fingerprint> $want"
    } >&2
    exit 3
  fi
  is_fpr "$trust_key" || die "--trust-key needs a full 40-digit fingerprint" 2
  grep -qx "$trust_key" <<<"$found" \
    || die "the downloaded key does not have fingerprint $trust_key (it has: $(tr '\n' ' ' <<<"$found")). Stopping."
  key=$trust_key
fi

deb=protonmail-bridge_${want}-1_amd64.deb
echo "downloading $deb"
curl -fsSL --proto "$curl_proto" -o "$tmp/$deb" "$base_url/$deb"
sha=$(sha256sum "$tmp/$deb" | cut -d' ' -f1)

bash "$root/docker/verify-deb.sh" "$tmp/$deb" "$sha" "$key" "$tmp/pubkey.gpg"

# Source pins for the source build. Proton's signed .deb above shows that this
# version is a real release; these say exactly which source to build it from.
echo "resolving source for v$want"
info=$(curl -fsSL --proto "$curl_proto" "$goproxy/$module_escaped/@v/v$want.info") \
  || die "the Go module proxy has no $module v$want yet; try again later"
commit=$(jq -r '.Origin.Hash // empty' <<<"$info")
ref=$(jq -r '.Origin.Ref // empty' <<<"$info")
[[ $commit =~ ^[0-9a-f]{40}$ && $ref == "refs/tags/v$want" ]] \
  || die "unexpected origin for $module v$want from the Go module proxy: $info"
h1=$(curl -fsSL --proto "$curl_proto" "$sumdb/lookup/$module_escaped@v$want" \
  | awk -v m="$module" -v v="v$want" '$1==m && $2==v {print $3}')
[[ $h1 =~ ^h1:[A-Za-z0-9+/]{43}=$ ]] || die "could not read the source hash of $module v$want from $sumdb"
if [[ $want == "$pinned" && -n ${BRIDGE_SOURCE_H1:-} && $BRIDGE_SOURCE_H1 != "$h1" ]]; then
  die "the source hash for the pinned v$want changed ($BRIDGE_SOURCE_H1 -> $h1). That should never happen. Stopping."
fi
if command -v git >/dev/null 2>&1; then
  # Annotated tags list the tag object and, as ^{}, the commit; prefer ^{}.
  gh=$(git ls-remote "$source_repo" "refs/tags/v$want" "refs/tags/v$want^{}" 2>/dev/null \
       | sort -k2 | awk 'END {print $1}') || true
  if [[ -z $gh ]]; then
    echo "warning: could not reach $source_repo to cross-check the tag; using the Go proxy's record" >&2
  elif [[ $gh != "$commit" ]]; then
    die "tag v$want points at $gh on GitHub but at $commit in the Go module proxy. Stopping."
  fi
fi
gomod=$(curl -fsSL --proto "$curl_proto" "$goproxy/$module_escaped/@v/v$want.mod")
need=$(awk '$1=="toolchain" {print $2}' <<<"$gomod")
[[ -n $need ]] || need=go$(awk '$1=="go" {print $2}' <<<"$gomod")
[[ $need =~ ^go([0-9]+)\.([0-9]+) ]] || die "cannot read the Go version from v$want's go.mod"
minor="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"
toolchains=$(curl -fsSL --proto "$curl_proto" "$goproxy/golang.org/toolchain/@v/list")
go_tc=""
while read -r c; do
  grep -qx "v0.0.1-$c.linux-arm64" <<<"$toolchains" && go_tc=$c   # both arches must exist
done < <(sed -nE "s/^v0\.0\.1-(go${minor//./\\.}(\.[0-9]+)?)\.linux-amd64$/\1/p" <<<"$toolchains" | sort -V)
[[ -n $go_tc ]] || die "no Go $minor release found in the Go module proxy"
version_ge "${go_tc#go}" "${need#go}" || die "newest Go $minor ($go_tc) is older than v$want needs ($need)"
echo "source: commit $commit, $h1; Go $go_tc (go.mod asks for $need)"

if [[ ! -s $keyfile ]]; then
  mkdir -p "$(dirname "$keyfile")"
  gpg --batch --quiet --import "$tmp/pubkey.gpg" 2>/dev/null
  gpg --batch --export "$key" >"$keyfile"
  echo "wrote $keyfile (key $key)"
fi

set_pin() { # NAME VALUE: replace the line, or append it
  if grep -q "^$1=" "$pins"; then
    sed -i "s|^$1=.*|$1=$2|" "$pins"
  else
    printf '%s=%s\n' "$1" "$2" >>"$pins"
  fi
}
sed -i -e '/^# Not filled in yet/,/^# Versions below/d' "$pins"
set_pin BRIDGE_VERSION "$want"
set_pin BRIDGE_DEB_SHA256 "$sha"
set_pin BRIDGE_SIGNING_KEY "$key"
set_pin BRIDGE_SOURCE_H1 "$h1"
set_pin BRIDGE_SOURCE_COMMIT "$commit"
set_pin GO_TOOLCHAIN "$go_tc"
echo "pinned Bridge $want (sha256 $sha, key $key; source $h1 at ${commit:0:10}; $go_tc) in bridge-version.env"
