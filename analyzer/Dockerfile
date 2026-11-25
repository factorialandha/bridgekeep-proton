# AI email analyzer. Offline, log-only in this release.
#
#   docker build -t proton-analyzer:local analyzer/
#   docker run --rm --network none -v "$PWD/mail:/mail:ro" proton-analyzer:local check --no-model /mail
ARG PYTHON_IMAGE=python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

FROM ${PYTHON_IMAGE} AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
COPY requirements.txt /tmp/requirements.txt
# Every dependency is pinned by version and hash.
RUN python -m venv /venv \
 && /venv/bin/pip install --require-hashes --only-binary=:all: -r /tmp/requirements.txt \
 && /venv/bin/pip uninstall --yes pip

FROM ${PYTHON_IMAGE}
ARG IMAGE_REVISION=""
# git's tree hash of analyzer/ (publish-images.sh): lets a host use an image
# built from identical analyzer code at another commit (pull-image.sh).
ARG ANALYZER_TREE=""
LABEL org.opencontainers.image.title="bridgekeep-analyzer" \
      io.bridgekeep.analyzer-tree="${ANALYZER_TREE}" \
      org.opencontainers.image.source="https://github.com/factorialandha/bridgekeep-proton" \
      org.opencontainers.image.revision="${IMAGE_REVISION}" \
      org.opencontainers.image.licenses="GPL-3.0-or-later"
# Take Debian security fixes newer than the base image, and drop pip and
# ensurepip: nothing installs packages at runtime, and pip's vendored copies
# of urllib3, msgpack and pkg_resources are what the scanner flags.
# hadolint ignore=DL3005
RUN apt-get update --error-on=any \
 && apt-get upgrade --yes --no-install-recommends \
 && rm -rf /var/lib/apt/lists/* \
 && rm -rf /usr/local/lib/python3.13/site-packages/pip /usr/local/lib/python3.13/site-packages/pip-* \
           /usr/local/lib/python3.13/ensurepip /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.13
# Fixed non-root UID (10002; Bridge uses its own).
RUN groupadd --system --gid 10002 analyzer \
 && useradd --system --uid 10002 --gid analyzer --home-dir /data --no-create-home --shell /usr/sbin/nologin analyzer \
 && mkdir -p /data /config/lists /state /proxy-state && chown analyzer:analyzer /data /proxy-state \
 && chown 10004:10002 /state && chmod 0700 /state /proxy-state
COPY --from=build /venv /venv
COPY src/analyzer /app/analyzer
# Readable by the runtime user whatever the checkout's umask was. A RUN, not
# COPY --chmod, so the build also works without BuildKit.
RUN chmod -R a+rX,go-w /app
ENV PATH=/venv/bin:$PATH PYTHONPATH=/app PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 ANALYZER_CONFIG=/config/analyzer.yaml
USER 10002:10002
WORKDIR /data
VOLUME ["/data"]
ENTRYPOINT ["python", "-P", "-m", "analyzer"]
CMD ["--help"]
