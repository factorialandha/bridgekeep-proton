#!/usr/bin/env bash
# The everyday Makefile targets, for hosts without `make` (TrueNAS SCALE).
#
#   bash scripts/make.sh build        # same as: make build
#   bash scripts/make.sh init         # same as: make init
#
# Each target runs the same script or docker command as the Makefile, so the
# two never build or start things differently. Targets that only matter on a
# development machine (lint, scan, check-arm64, the analyzer test targets)
# stay Makefile-only.
set -euo pipefail
export MSYS_NO_PATHCONV=1   # Git Bash: do not rewrite /paths in docker arguments

cd "$(dirname "$0")/.."
# shellcheck source=/dev/null
source bridge-version.env
IMAGE=${IMAGE:-proton-bridge}
TAG=${TAG:-$BRIDGE_VERSION}
ANALYZER_IMAGE=${ANALYZER_IMAGE:-proton-analyzer}
export BRIDGE_BUILD=${BRIDGE_BUILD:-source}
# Compose reads .env itself; analyzer-init also needs the secrets folder.
if [[ -z ${BRIDGEKEEP_SECRETS:-} && -f .env ]]; then
  BRIDGEKEEP_SECRETS=$(sed -n 's/^BRIDGEKEEP_SECRETS=//p' .env | tail -n1)
fi
export BRIDGEKEEP_SECRETS

usage() {
  cat <<'EOF'
usage: bash scripts/make.sh TARGET

  preflight       check Docker and Compose
  build           build the Bridge image from the pins (bridge-version.env)
  pull            use the published, signed image instead of building
  test            smoke-test the built image (no Proton account needed)
  init            stop Bridge and open the one-time login CLI
  up | down       start or stop the stack
  logs            follow Bridge's log
  cert            write Bridge's TLS certificate to bridge-cert.pem
  update          pin the latest Bridge release (scripts/update-bridge.sh)
  check-upstream  only report whether a newer Bridge exists
  auto-update     check, rebuild and smoke-test; leaves the update waiting
  deploy-update   swap in the waiting update, roll back on failure
  analyzer-build  build the AI analyzer image
  analyzer-init   one-time analyzer setup (config/ and the secrets folder)
EOF
}

target=${1:-}
case $target in
  preflight)      bash scripts/preflight.sh ;;
  build)          bash scripts/preflight.sh build
                  bash scripts/build.sh -t "$IMAGE:$TAG" -t "$IMAGE:local" ;;
  pull)           bash scripts/pull-image.sh bridge ;;
  test)           IMAGE=$IMAGE:local bash tests/smoke.sh ;;
  init)           bash scripts/preflight.sh
                  docker compose stop bridge 2>/dev/null || true
                  docker compose run --rm bridge-init ;;
  up)             bash scripts/preflight.sh && docker compose up -d ;;
  down)           bash scripts/preflight.sh && docker compose down ;;
  logs)           docker compose logs -f bridge ;;
  cert)           bash scripts/export-cert.sh bridge-cert.pem ;;
  update)         bash scripts/update-bridge.sh ;;
  check-upstream) bash scripts/update-bridge.sh --check ;;
  auto-update)    bash scripts/auto-update.sh ;;
  deploy-update)  bash scripts/preflight.sh && bash scripts/auto-update.sh --deploy ;;
  analyzer-build) docker build -t "$ANALYZER_IMAGE:local" analyzer/ ;;
  analyzer-init)  ANALYZER_IMAGE=$ANALYZER_IMAGE bash scripts/analyzer-init.sh ;;
  ''|-h|--help|help) usage ;;
  *)              echo "make.sh: unknown target '$target'" >&2; usage >&2; exit 2 ;;
esac
