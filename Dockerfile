# syntax=docker/dockerfile:1.7
#
# Headless Proton Mail Bridge for amd64 and arm64. Build with `make build`
# (scripts/build.sh), which passes the pins from bridge-version.env.
#
# BRIDGE_BUILD=source (default, amd64 and arm64): Bridge's core built from
#   Proton's source for the pinned release. The source comes through the Go
#   module proxy and must match the pinned hash, which is also recorded in the
#   public Go checksum database. Go itself is an exact, checksum-verified
#   release (GO_TOOLCHAIN). See docker/build-bridge-source.sh.
# BRIDGE_BUILD=deb (amd64 only): the core from Proton's own signed .deb,
#   checked against the pinned sha256 and Proton's package signature.

ARG DEBIAN_IMAGE=debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
ARG BRIDGE_BUILD=source

############################
# Build from source (any arch)
############################
# Runs on the build machine's own platform and cross-compiles when the
# target differs (CI checks arm64 this way), so no CPU emulation is needed.
# hadolint ignore=DL3029
FROM --platform=$BUILDPLATFORM ${DEBIAN_IMAGE} AS source

ARG TARGETARCH
ARG BRIDGE_VERSION
ARG BRIDGE_SOURCE_H1
ARG BRIDGE_SOURCE_COMMIT
ARG GO_TOOLCHAIN

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# golang-go only bootstraps: GO_TOOLCHAIN selects the exact Go release used.
# libsecret and libfido2 are the C libraries Bridge links against (cgo).
# hadolint ignore=DL3008,SC2086
RUN set -e; \
    build=$(dpkg --print-architecture); arch=${TARGETARCH:-$build}; \
    libs="libsecret-1-dev libfido2-dev libcbor-dev libssl-dev"; \
    pkgs="ca-certificates golang-go gcc libc6-dev make jq pkgconf"; \
    if [ "$arch" != "$build" ]; then \
      case $arch in \
        arm64) cross=aarch64-linux-gnu ;; \
        amd64) cross=x86-64-linux-gnu ;; \
        *) echo "unsupported target architecture: $arch" >&2; exit 1 ;; \
      esac; \
      dpkg --add-architecture "$arch"; \
      pkgs="$pkgs gcc-$cross libc6-dev-$arch-cross"; \
      libs=$(for l in $libs; do printf '%s:%s ' "$l" "$arch"; done); \
    fi; \
    apt-get update; \
    apt-get install -y --no-install-recommends $pkgs $libs; \
    rm -rf /var/lib/apt/lists/*

COPY docker/build-bridge-source.sh /usr/local/bin/build-bridge-source
RUN --mount=type=cache,target=/root/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    [ "$(printf '3.25.0\n%s\n' "${BRIDGE_VERSION}" | sort -V | head -n1)" = 3.25.0 ] \
      || { echo "Bridge ${BRIDGE_VERSION} is below the 3.25.0 security floor" >&2; exit 1; }; \
    bash /usr/local/bin/build-bridge-source "${BRIDGE_VERSION}" "${BRIDGE_SOURCE_H1}" \
      "${BRIDGE_SOURCE_COMMIT}" "${GO_TOOLCHAIN}" "${TARGETARCH:-$(dpkg --print-architecture)}" /out/bridge

############################
# Proton's signed .deb (amd64 only)
############################
FROM ${DEBIAN_IMAGE} AS deb

ARG TARGETARCH

ARG BRIDGE_VERSION
ARG BRIDGE_DEB_SHA256
ARG BRIDGE_SIGNING_KEY
ARG BRIDGE_BASE_URL=https://proton.me/download/bridge

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gnupg gpgv binutils \
 && rm -rf /var/lib/apt/lists/*

COPY docker/verify-deb.sh /usr/local/bin/verify-deb
# Proton's Bridge signing key is committed to the repo (keys/), never fetched
# at build time. BRIDGE_SIGNING_KEY pins its fingerprint as well.
COPY keys/ /keys/

WORKDIR /work
RUN [ "${TARGETARCH:-amd64}" = amd64 ] \
      || { echo "BRIDGE_BUILD=deb is amd64 only (Proton ships no ${TARGETARCH} .deb); use BRIDGE_BUILD=source" >&2; exit 1; } \
 && test -n "${BRIDGE_VERSION}" -a -n "${BRIDGE_DEB_SHA256}" -a -n "${BRIDGE_SIGNING_KEY}" \
      || { echo "Pins missing: run scripts/update-bridge.sh, or build with make build" >&2; exit 1; } \
 && test -s /keys/proton-bridge-signing-key.gpg \
      || { echo "keys/proton-bridge-signing-key.gpg missing: run scripts/update-bridge.sh" >&2; exit 1; } \
 && [ "$(printf '3.25.0\n%s\n' "${BRIDGE_VERSION}" | sort -V | head -n1)" = 3.25.0 ] \
      || { echo "Bridge ${BRIDGE_VERSION} is below the 3.25.0 security floor" >&2; exit 1; } \
 && deb="protonmail-bridge_${BRIDGE_VERSION}-1_amd64.deb" \
 && curl -fsSL --proto '=https' --tlsv1.2 -o "$deb" "${BRIDGE_BASE_URL}/${deb}" \
 && verify-deb "$deb" "${BRIDGE_DEB_SHA256}" "${BRIDGE_SIGNING_KEY}" /keys/proton-bridge-signing-key.gpg \
 && dpkg-deb -x "$deb" /work/root \
 && test -d /work/root/usr/lib/protonmail/bridge

# Keep only what headless CLI mode needs: the core binary. In the .deb,
# `proton-bridge` is the self-updating launcher, which looks for a `bridge`
# executable next to it and runs that; `bridge` is the core. We ship the core
# alone (no launcher, no GUI, no bundled Qt runtime).
RUN set -e; \
    dir=/work/root/usr/lib/protonmail/bridge; \
    if [ ! -x "$dir/bridge" ]; then echo "no bridge core binary in package:" >&2; ls -la "$dir" >&2; exit 1; fi; \
    mkdir -p /out; \
    cp "$dir/bridge" /out/bridge

# Pick the binary for BRIDGE_BUILD. Only the selected stage is built.
FROM scratch AS bridge-source
COPY --from=source /out/bridge /bridge

FROM scratch AS bridge-deb
COPY --from=deb /out/bridge /bridge

# hadolint ignore=DL3006
FROM bridge-${BRIDGE_BUILD} AS bridge

############################
# Sign-in broker (any arch, Go standard library only)
############################
# hadolint ignore=DL3029
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm@sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0 AS broker
ARG TARGETARCH
WORKDIR /src
COPY broker/ ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} GOFLAGS=-trimpath GOTOOLCHAIN=local \
    go build -buildvcs=false -ldflags='-s -w' -o /out/bridgekeep-broker .

############################
# Runtime
############################
FROM ${DEBIAN_IMAGE} AS runtime

ARG BRIDGE_VERSION
ARG BRIDGE_BUILD
ARG BRIDGE_SOURCE_COMMIT
ARG IMAGE_REVISION=""
ARG BRIDGE_UID=10001
ARG BRIDGE_GID=10001
# Shared groups: 10010 lets the portal reach the broker's socket; 10011 lets
# imap-proxy read the Bridge password the broker saves. Compose adds them.
ARG BROKER_GID=10010
ARG CRED_GID=10011

LABEL org.opencontainers.image.title="proton-bridge" \
      org.opencontainers.image.description="Headless Proton Mail Bridge (CLI mode)" \
      io.bridgekeep.build="${BRIDGE_BUILD}" \
      org.opencontainers.image.version="${BRIDGE_VERSION}" \
      org.opencontainers.image.source="https://github.com/factorialandha/bridgekeep-proton" \
      org.opencontainers.image.revision="${IMAGE_REVISION}" \
      org.opencontainers.image.licenses="GPL-3.0-or-later" \
      io.bridgekeep.bridge-source="https://github.com/ProtonMail/proton-bridge/tree/v${BRIDGE_VERSION}" \
      io.bridgekeep.bridge-commit="${BRIDGE_SOURCE_COMMIT}"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# pass + gnupg: keychain backend. socat: forwarders. tini: PID 1.
# libsecret/libfido2: libraries the Bridge core may link against.
# Upgrade first: the pinned base image can lag Debian security updates.
# hadolint ignore=DL3005,DL3008
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get install -y --no-install-recommends \
      ca-certificates pass gnupg socat tini procps libsecret-1-0 libfido2-1 \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid "${BRIDGE_GID}" bridge \
 && useradd --uid "${BRIDGE_UID}" --gid bridge --home-dir /home/bridge --create-home --shell /usr/sbin/nologin bridge \
 && chmod 700 /home/bridge \
 && groupadd --gid "${BROKER_GID}" bridgekeep-broker \
 && groupadd --gid "${CRED_GID}" bridgekeep-cred \
 && usermod -aG bridgekeep-broker,bridgekeep-cred bridge \
 && install -d -m 2750 -o "${BRIDGE_UID}" -g "${BROKER_GID}" /run/broker \
 && install -d -m 2750 -o "${BRIDGE_UID}" -g "${CRED_GID}" /run/bridge-credential

COPY --from=bridge /bridge /usr/local/lib/proton-bridge/bridge
COPY --chmod=0755 docker/entrypoint.sh /usr/local/bin/entrypoint
COPY --from=broker --chmod=0755 /out/bridgekeep-broker /usr/local/bin/bridgekeep-broker
# Proton Mail Bridge is GPL-3.0-or-later (so is this repository): ship the
# licence and say exactly which source the binary was built from.
COPY --chmod=0644 LICENSE /usr/share/doc/proton-bridge/LICENSE
RUN printf '%s\n' \
      "Proton Mail Bridge ${BRIDGE_VERSION}, GPL-3.0-or-later (see LICENSE in this folder)." \
      "Built unmodified from https://github.com/ProtonMail/proton-bridge/tree/v${BRIDGE_VERSION}" \
      "commit ${BRIDGE_SOURCE_COMMIT:-unknown}, build: ${BRIDGE_BUILD}." \
      "Packaging: https://github.com/factorialandha/bridgekeep-proton" \
      > /usr/share/doc/proton-bridge/SOURCE

# Fail the build now, not at runtime, if a shared library is missing.
RUN if ldd /usr/local/lib/proton-bridge/bridge | grep -q 'not found'; then \
      ldd /usr/local/lib/proton-bridge/bridge >&2; exit 1; \
    fi \
 && ln -s /usr/local/lib/proton-bridge/bridge /usr/local/bin/proton-bridge

# Paths only, no secrets (hadolint flags the word "PASSWORD").
# hadolint ignore=DL3064
ENV HOME=/home/bridge \
    GNUPGHOME=/home/bridge/.gnupg \
    PASSWORD_STORE_DIR=/home/bridge/.password-store

USER ${BRIDGE_UID}:${BRIDGE_GID}
WORKDIR /home/bridge
VOLUME ["/home/bridge"]

# Container-side forwarder ports. Bridge itself listens on 127.0.0.1 only.
EXPOSE 1143 1025

HEALTHCHECK --interval=30s --timeout=5s --start-period=2m --retries=3 \
  CMD ["/usr/local/bin/entrypoint", "healthcheck"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint"]
CMD ["run"]
