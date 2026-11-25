# Bridgekeep admin portal. Localhost only by default; see portal/README.md.
#
#   docker build -t bridgekeep-portal:local portal/
#
# Multi-arch: every dependency has a binary wheel for amd64 and arm64.
ARG PYTHON_IMAGE=python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
ARG NODE_IMAGE=node:22-trixie-slim@sha256:f0960f8dc047f358e3fb428f36ccba21732194fa5f0cac849f401e63e62fb9e6

# The React frontend (portal/web). Its output is plain HTML, JS and CSS, the same
# on every architecture, so it builds on the build machine's own platform. Only
# the built files reach the final image: no node, no node_modules.
FROM --platform=$BUILDPLATFORM ${NODE_IMAGE} AS web
ENV npm_config_update_notifier=false npm_config_fund=false npm_config_audit=false
WORKDIR /w/web
COPY web/package.json web/package-lock.json web/check.mjs ./
# Every package from registry.npmjs.org with a sha512 hash, exact versions (checked
# here too, since ./bridgekeep setup builds this on the host); no install scripts run.
RUN node check.mjs --lock-only && npm ci --ignore-scripts
COPY web/ ./
RUN npm run build

FROM ${PYTHON_IMAGE} AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
COPY requirements.txt /tmp/requirements.txt
# Every dependency is pinned by version and hash.
RUN python -m venv /venv \
 && /venv/bin/pip install --require-hashes --only-binary=:all: -r /tmp/requirements.txt \
 && /venv/bin/pip uninstall --yes pip

FROM ${PYTHON_IMAGE}
# Debian security fixes newer than the base image; no pip or ensurepip at runtime.
# hadolint ignore=DL3005
RUN apt-get update --error-on=any \
 && apt-get upgrade --yes --no-install-recommends \
 && rm -rf /var/lib/apt/lists/* \
 && rm -rf /usr/local/lib/python3.13/site-packages/pip /usr/local/lib/python3.13/site-packages/pip-* \
           /usr/local/lib/python3.13/ensurepip /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.13
# Fixed non-root UID 10003 (Bridge is 10001, the analyzer 10002).
RUN groupadd --system --gid 10003 portal \
 && useradd --system --uid 10003 --gid portal --home-dir /data --no-create-home --shell /usr/sbin/nologin portal \
 && mkdir -p /data && chown portal:portal /data && chmod 0700 /data
COPY --from=build /venv /venv
COPY src/portal /app/portal
COPY --from=web /w/src/portal/web_dist /app/portal/web_dist
RUN chmod -R a+rX,go-w /app
# The Bridgekeep commit this image was built from (./bridgekeep setup passes it;
# empty for a plain docker build). The footer shows it. Last, so a new commit
# rebuilds only this layer.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ARG BRIDGEKEEP_COMMIT=""
RUN printf '%s' "$BRIDGEKEEP_COMMIT" | tr -cd '0-9a-f' | cut -c1-40 >/app/portal/BUILD_COMMIT \
 && chmod 0444 /app/portal/BUILD_COMMIT
ENV PATH=/venv/bin:$PATH PYTHONPATH=/app PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10003:10003
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8443
HEALTHCHECK --interval=60s --timeout=10s --start-period=20s CMD ["python", "-P", "-m", "portal", "health"]
ENTRYPOINT ["python", "-P", "-m", "portal"]
CMD ["serve"]
