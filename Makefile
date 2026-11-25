include bridge-version.env
export BRIDGE_VERSION BRIDGE_DEB_SHA256 BRIDGE_SIGNING_KEY

IMAGE ?= proton-bridge
TAG   ?= $(BRIDGE_VERSION)

.PHONY: preflight build pull check-arm64 lint test scan init up down logs cert update check-upstream auto-update deploy-update test-signin test-notify test-broker live-check \
        analyzer-build analyzer-test analyzer-smoke analyzer-scan analyzer-init \
        portal-build portal-test portal-smoke portal-scan

## Check Docker and Compose before the targets that need them (WSL: also
## that this is Docker Desktop's engine, which Git Bash and auto-update use).
preflight:
	@bash scripts/preflight.sh

## Build the image (the one command you need). Bridge is built from the pinned
## source by default, on amd64 or arm64. BRIDGE_BUILD=deb uses Proton's signed
## .deb instead (amd64 only).
BRIDGE_BUILD ?= source
export BRIDGE_BUILD
build:
	@bash scripts/preflight.sh build
	bash scripts/build.sh -t $(IMAGE):$(TAG) -t $(IMAGE):local

## Use the published, signed image instead of building (private on ghcr.io;
## needs `docker login ghcr.io` once). Exit 4 means "nothing to pull: build".
pull:
	bash scripts/pull-image.sh bridge

## Cross-compile Bridge for arm64 on any machine and check the binary (no
## emulation; the arm64 image itself is built on the arm64 host).
check-arm64:
	BRIDGE_BUILD=source bash scripts/build.sh --platform linux/arm64 --target bridge-source \
	  -o type=local,dest=.build/arm64
	@m=$$(od -An -tx1 -j18 -N1 .build/arm64/bridge | tr -d ' \n'); \
	  if [ "$$m" = b7 ]; then echo "ok: .build/arm64/bridge is an arm64 (aarch64) binary"; \
	  else echo "FAIL: .build/arm64/bridge has ELF machine 0x$$m, not aarch64" >&2; exit 1; fi

lint:
	docker run --rm -v "$(CURDIR):/src:ro" -w /src koalaman/shellcheck@sha256:bb596a0d169b85ddd81d8b6d3a2ff6d5baf5fca10b97f575ebc647c3dff62b3d \
	  docker/entrypoint.sh docker/verify-deb.sh docker/build-bridge-source.sh scripts/*.sh tests/*.sh
	docker run --rm -i hadolint/hadolint@sha256:9a3944b7fddcb947d1ffd90829ac1a6e5c30479223358f249d8b96c7d0019e27 < Dockerfile

## Smoke test: keychain init, non-root, read-only root, forwarders on a private network.
test:
	IMAGE=$(IMAGE):local tests/smoke.sh

## Vulnerability scan. Debian packages (which we control) gate the build on
## HIGH/CRITICAL with a fix available. Findings inside Proton's Bridge binary
## (Go modules/stdlib, fixable only by a new Proton release) are reported on
## every run but do not fail it; see docs/operations.md.
TRIVY = docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb
scan:
	$(TRIVY) image --pkg-types os --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 $(IMAGE):local
	@echo "== Report only: dependencies compiled into Proton's Bridge binary =="
	$(TRIVY) image --pkg-types library --severity HIGH,CRITICAL --ignore-unfixed --exit-code 0 $(IMAGE):local

init: preflight
	docker compose stop bridge 2>/dev/null || true
	docker compose run --rm bridge-init

up: preflight
	docker compose up -d

down: preflight
	docker compose down

logs: preflight
	docker compose logs -f bridge

cert: preflight
	bash scripts/export-cert.sh $(if $(FORCE),--force) bridge-cert.pem

## Live check with your own account: IMAP (and SMTP with SMTP=1) from a second
## container on the mail network. Prompts for the Bridge username/password.
## Needs a logged-in, healthy bridge and bridge-cert.pem (make cert).
live-check: preflight
	docker run --rm -it --network proton-bridge_mail --read-only --cap-drop ALL \
	  --security-opt no-new-privileges:true --user "$$(id -u):$$(id -g)" \
	  -v "$(CURDIR):/w:ro" $(PYTHON_IMAGE) python /w/tests/live-check.py $(if $(SMTP),--smtp)

update:
	scripts/update-bridge.sh

check-upstream:
	scripts/update-bridge.sh --check

## Check for a new Bridge, rebuild and smoke-test it. It does not deploy: it
## leaves the tested image waiting (AUTO_DEPLOY=true deploys straight away).
auto-update:
	scripts/auto-update.sh

## Swap in the tested update that auto-update left waiting; rolls back if the
## new container doesn't become healthy.
deploy-update: preflight
	scripts/auto-update.sh --deploy

## Sign-in helper tests against a stand-in for Bridge's CLI (needs go).
test-signin:
	tests/signin.sh

test-notify:
	tests/notify.sh

test-broker:
	tests/broker.sh

## AI analyzer (shadow mode, offline in this release). See analyzer/README.md.
ANALYZER_IMAGE ?= proton-analyzer
PYTHON_IMAGE   ?= python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

analyzer-build:
	docker build -t $(ANALYZER_IMAGE):local analyzer/

## One-time setup: config/ and the secrets (outside the checkout) for `docker compose --profile analyzer up -d`.
analyzer-init:
	ANALYZER_IMAGE=$(ANALYZER_IMAGE) scripts/analyzer-init.sh

## Unit tests in a throwaway container (no local Python needed).
analyzer-test:
	docker run --rm --network bridge -v "$(CURDIR)/analyzer:/src:ro" -w /tmp $(PYTHON_IMAGE) sh -c \
	  'cp -r /src /tmp/a && cd /tmp/a && pip install -q --require-hashes --only-binary=:all: -r requirements-test.txt && python -m pytest -q'

## The built image runs offline, read-only and unprivileged on the fixtures.
## Runs as the caller's UID so it can read a checkout made with a strict umask.
analyzer-smoke:
	docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true --user "$$(id -u):$$(id -g)" \
	  -v "$(CURDIR)/analyzer/tests/fixtures:/mail:ro" $(ANALYZER_IMAGE):local check --no-model --db :memory: /mail
	docker run --rm --network none --read-only --cap-drop ALL $(ANALYZER_IMAGE):local config

## Known HIGH/CRITICAL CVEs with a fix fail the build. Vulnerabilities only:
## the secret scanner misreads example text in the Anthropic SDK as keys.
analyzer-scan:
	$(TRIVY) image --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 $(ANALYZER_IMAGE):local

## Admin portal (localhost only). See portal/README.md.
PORTAL_IMAGE ?= bridgekeep-portal

PORTAL_COMMIT ?= $(shell bash scripts/versions.sh 2>/dev/null | sed -n 's/^bridgekeep_commit=\([0-9a-f]*\)$$/\1/p')

portal-build:
	bash scripts/docker-build.sh -t $(PORTAL_IMAGE):local --build-arg BRIDGEKEEP_COMMIT=$(PORTAL_COMMIT) portal/

portal-test:
	docker run --rm --network bridge -v "$(CURDIR)/portal:/src:ro" -w /tmp $(PYTHON_IMAGE) sh -c \
	  'cp -r /src /tmp/p && cd /tmp/p && pip install -q --require-hashes --only-binary=:all: -r requirements-test.txt && python -m pytest -q'

## The built image starts read-only and unprivileged, prints a claim code and answers on /healthz.
portal-smoke:
	PORTAL_IMAGE=$(PORTAL_IMAGE):local PORTAL_COMMIT=$(PORTAL_COMMIT) tests/portal-smoke.sh

portal-scan:
	$(TRIVY) image --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 $(PORTAL_IMAGE):local
