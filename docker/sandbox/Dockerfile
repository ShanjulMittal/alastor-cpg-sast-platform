# ALASTOR v5.1 Hardened Offline/Mediated-Egress Scanner Sandbox Image
# Build from repository root:
#   docker build -f docker/sandbox/Dockerfile --build-arg ALASTOR_IMAGE_VERSION=5.1.0 -t alastor-sandbox:local .

ARG BASE_IMAGE=python:3.12-slim

FROM ${BASE_IMAGE} AS ca
COPY docker/sandbox/ca/ /tmp/ca_in/
RUN set -eu; \
    mkdir -p /ca_out; \
    for f in /tmp/ca_in/*; do \
        [ -f "$f" ] || continue; \
        if grep -q "PRIVATE KEY" "$f"; then \
            echo "ERROR: Private key detected in docker/sandbox/ca/ ($f); aborting build." >&2; \
            exit 1; \
        fi; \
    done; \
    for f in /tmp/ca_in/*.crt /tmp/ca_in/*.pem; do \
        [ -f "$f" ] || continue; \
        if grep -q "BEGIN CERTIFICATE" "$f" && ! grep -q "PRIVATE KEY" "$f"; then \
            base="$(basename "$f")"; \
            case "$base" in \
                *.pem) cp "$f" "/ca_out/${base%.pem}.crt" ;; \
                *) cp "$f" "/ca_out/${base}" ;; \
            esac; \
        fi; \
    done

FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    HOME=/tmp \
    ALASTOR_VAULT_DIR=/tmp/.alastor_vault \
    GIT_CONFIG_COUNT=4 \
    GIT_CONFIG_KEY_0=core.fsmonitor \
    GIT_CONFIG_VALUE_0="" \
    GIT_CONFIG_KEY_1=core.hooksPath \
    GIT_CONFIG_VALUE_1=/dev/null \
    GIT_CONFIG_KEY_2=core.sshCommand \
    GIT_CONFIG_VALUE_2=false \
    GIT_CONFIG_KEY_3=credential.helper \
    GIT_CONFIG_VALUE_3=""

RUN apt-get update && \
    apt-get install -y --no-install-recommends git ca-certificates socat && \
    rm -rf /var/lib/apt/lists/*

COPY --from=ca /ca_out/ /usr/local/share/ca-certificates/
RUN update-ca-certificates && \
    git config --system --add safe.directory /workspace

WORKDIR /app
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY backend/ /app/
RUN printf '%s\n' \
        '#!/bin/sh' \
        'set -eu' \
        'if [ -n "${ALASTOR_EGRESS_SOCKET:-}" ]; then' \
        '    socat TCP-LISTEN:3128,bind=127.0.0.1,fork,reuseaddr UNIX-CONNECT:"$ALASTOR_EGRESS_SOCKET" &' \
        'fi' \
        'exec python -m alastor_cli "$@"' \
        > /usr/local/bin/alastor-sandbox-entrypoint.sh && \
    chmod 0755 /usr/local/bin/alastor-sandbox-entrypoint.sh && \
    chmod -R a+rX /app && \
    find / -xdev -perm /6000 -type f -exec chmod ug-s {} +

ARG ALASTOR_IMAGE_VERSION=5.1.0
ARG ALASTOR_IMAGE_GIT_SHA=unknown
LABEL org.alastor.version="${ALASTOR_IMAGE_VERSION}" \
      org.alastor.git_sha="${ALASTOR_IMAGE_GIT_SHA}" \
      org.alastor.role="scanner"

USER 65534:65534
ENTRYPOINT ["/usr/local/bin/alastor-sandbox-entrypoint.sh"]
