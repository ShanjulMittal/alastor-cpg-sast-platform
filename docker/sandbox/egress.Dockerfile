# ALASTOR v5.1 Hardened Squid + Socat Mediated-Egress Proxy Sidecar Image
# Build from repository root:
#   docker build -f docker/sandbox/egress.Dockerfile --build-arg ALASTOR_IMAGE_VERSION=5.1.0 -t alastor-egress:local .

ARG BASE_IMAGE=ubuntu:24.04
FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends squid socat && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /run/alastor-egress && \
    chown 65534:65534 /run/alastor-egress && \
    find / -xdev -perm /6000 -type f -exec chmod ug-s {} +

ARG ALASTOR_IMAGE_VERSION=5.1.0
ARG ALASTOR_IMAGE_GIT_SHA=unknown
LABEL org.alastor.version="${ALASTOR_IMAGE_VERSION}" \
      org.alastor.git_sha="${ALASTOR_IMAGE_GIT_SHA}" \
      org.alastor.role="egress-proxy"

USER 65534:65534
