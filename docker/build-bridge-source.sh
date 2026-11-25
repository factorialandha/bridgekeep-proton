#!/usr/bin/env bash
# Build the Proton Mail Bridge core from source for the pinned release.
# Runs inside the Dockerfile's `source` stage.
#
#   build-bridge-source.sh <version> <source-h1> <commit> <go-toolchain> <target-arch> <out>
#
# Integrity:
#   - Source: the release is fetched as a Go module through proxy.golang.org.
#     `go mod download` checks it against the public Go checksum database
#     (sum.golang.org, an append-only log), and this script also requires that
#     hash to equal the one pinned in bridge-version.env. A moved tag or a
#     changed archive fails here.
#   - Go: GOTOOLCHAIN pins an exact Go release, which the go command downloads
#     and checks against the same checksum database.
#   - Dependencies: Bridge's own go.sum, checked against the checksum database.
#
# Cross-compiling: when the target arch differs from this machine's (CI
# builds arm64 on amd64), the Dockerfile installs a cross C compiler and the
# target's libraries, and this script points cgo and pkg-config at them.
set -euo pipefail

die() { echo "build-bridge-source: $*" >&2; exit 1; }

version=${1:-} want_h1=${2:-} commit=${3:-} toolchain=${4:-} arch=${5:-} out=${6:-}
[[ -n $version && -n $want_h1 && -n $toolchain && -n $arch && -n $out ]] \
  || die "source pins missing (BRIDGE_VERSION, BRIDGE_SOURCE_H1, GO_TOOLCHAIN): run scripts/update-bridge.sh, or build with make build"
[[ $want_h1 == h1:* ]] || die "BRIDGE_SOURCE_H1 must look like h1:..., got '$want_h1'"
[[ $toolchain =~ ^go[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || die "GO_TOOLCHAIN must look like go1.26.11, got '$toolchain'"

build_arch=$(dpkg --print-architecture)
case $arch in
  amd64) goarch=amd64 triplet=x86_64-linux-gnu  elf=3e ;;
  arm64) goarch=arm64 triplet=aarch64-linux-gnu elf=b7 ;;
  *) die "unsupported target architecture '$arch' (amd64 and arm64 are supported)" ;;
esac

export GOTOOLCHAIN=$toolchain GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
export GOFLAGS=-modcacherw CGO_ENABLED=1 GOOS=linux GOARCH=$goarch
if [[ $arch != "$build_arch" ]]; then
  export CC=$triplet-gcc
  export PKG_CONFIG_LIBDIR=/usr/lib/$triplet/pkgconfig:/usr/share/pkgconfig
  echo "cross-compiling for $arch on $build_arch with $CC"
fi

got_go=$(go version)
[[ $got_go == *" $toolchain "* ]] || die "expected Go $toolchain, got: $got_go"
echo "using $got_go"

mod=github.com/ProtonMail/proton-bridge/v3@v$version
json=$(cd /tmp && GOFLAGS=-modcacherw go mod download -json "$mod") \
  || die "could not download $mod from the Go module proxy"
sum=$(jq -r '.Sum // empty' <<<"$json")
dir=$(jq -r '.Dir // empty' <<<"$json")
[[ $sum == "$want_h1" ]] || die "source hash mismatch for $mod: got $sum, pinned $want_h1. Stopping."
[[ -d $dir ]] || die "module directory missing after download"
echo "source $mod verified ($sum)"

src=/src/bridge
rm -rf "$src"
mkdir -p "$src"
cp -a "$dir"/. "$src"/
chmod -R u+w "$src"
# Module archives don't keep file modes; the Makefile runs these directly.
find "$src/utils" -name '*.sh' -exec chmod +x {} +

cd "$src"
grep -q '^build-nogui:' Makefile || die "Bridge's Makefile has no build-nogui target any more"
# Command-line variables override the Makefile's git-based ones (the module
# archive has no .git). BUILD_ENV is only the Sentry environment name, and
# Sentry is off without DSN_SENTRY.
make build-nogui \
  BRIDGE_APP_VERSION="$version" \
  REVISION="${commit:0:10}" \
  TAG="v$version" \
  BUILD_ENV= \
  BUILD_TIME="$(date -u +%FT%T%z)"

[[ -x $src/bridge ]] || { ls -la "$src" >&2; die "build-nogui did not produce ./bridge"; }
machine=$(od -An -tx1 -j18 -N1 "$src/bridge" | tr -d ' \n')
[[ $machine == "$elf" ]] || die "built binary is for the wrong CPU (ELF machine 0x$machine, wanted 0x$elf for $arch)"

mkdir -p "$(dirname "$out")"
cp "$src/bridge" "$out"
echo "built Bridge $version for $arch: $out"
