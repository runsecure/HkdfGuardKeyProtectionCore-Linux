# Linux test/build environment for HKDFGuard.
#
# Includes everything the default (external-secret/ephemeral) and
# hardware-backed (tpm2 via swtpm, pkcs11 via SoftHSM2) providers need, so
# the whole provider chain -- including the two providers that cannot be
# built or tested on the macOS host this crate was originally written on --
# can be exercised for real. See docker/README.md for usage.

# Ubuntu 24.04 LTS: tpm2-tss 4.x (4.0.1) from distro packages, and glibc
# 2.39, so the release binaries built here run on Ubuntu 24.04+, Debian 13
# and RHEL 10. (Debian 12 only offers tpm2-tss 3.2.1, even in backports.)
#
# Pinned by digest so a rebuild never silently picks up a different base
# image. To take an update, re-resolve deliberately (and update
# docker/Dockerfile.swtpm to match):
#   docker pull ubuntu:24.04
#   docker inspect --format='{{index .RepoDigests 0}}' ubuntu:24.04
# apt package versions below are intentionally not pinned: the archive
# drops superseded versions as updates land, so exact `pkg=version` pins
# would make this build start failing on its own. The base digest bounds
# which package set apt resolves against; Cargo.lock pins the Rust
# dependencies.
FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3

ENV DEBIAN_FRONTEND=noninteractive \
    CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    PATH=/usr/local/cargo/bin:$PATH

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        curl \
        ca-certificates \
        git \
        libtss2-dev \
        tpm2-tools \
        swtpm \
        swtpm-tools \
        softhsm2 \
        opensc \
    && rm -rf /var/lib/apt/lists/*

# Toolchain version must match rust-toolchain.toml at the repo root.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- -y --profile minimal --default-toolchain 1.98.1 \
    && rustup component add clippy

# SoftHSM2 needs a writable config + token directory; the default
# /etc/softhsm/softhsm2.conf + /var/lib/softhsm/tokens are root-owned,
# which is fine since tests run as root in this throwaway container.
ENV SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf
RUN mkdir -p /var/lib/softhsm/tokens

WORKDIR /work
COPY . /work

RUN chmod +x docker/entrypoint-test.sh docker/entrypoint-build.sh

ENTRYPOINT ["docker/entrypoint-test.sh"]
