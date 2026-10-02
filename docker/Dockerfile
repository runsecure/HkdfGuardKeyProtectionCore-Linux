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

# The tests run as `ci`, an unprivileged user in the `tss` group (the
# group that owns /dev/tpmrm0 on a real host), not as root: as root every
# file a test creates is root-owned and every mode-000 file is readable,
# so the tests that prove root-only config and owner-only secrets are
# refused would have nothing to refuse. HKDFGUARD_TESTS_MUST_NOT_RUN_AS_ROOT
# makes those tests fail, rather than skip, if they ever run as root here.
#
# The container itself still starts as root: docker/entrypoint-test.sh
# installs root-owned configuration under /etc/hkdfguard, exactly as a
# deployment would, and runs everything else as `ci` (setpriv). `ci` owns
# the source tree, the cargo registry cache, and its own SoftHSM2 token
# store.
RUN groupadd --force tss \
    && useradd --create-home --groups tss ci \
    && chown -R ci:ci "$CARGO_HOME" \
    && install -d -o ci -g ci -m 0700 /home/ci/softhsm-tokens \
    && printf 'directories.tokendir = /home/ci/softhsm-tokens\nobjectstore.backend = file\n' > /etc/softhsm2-ci.conf \
    && chmod 0644 /etc/softhsm2-ci.conf
ENV SOFTHSM2_CONF=/etc/softhsm2-ci.conf \
    HKDFGUARD_TESTS_MUST_NOT_RUN_AS_ROOT=1

WORKDIR /work
COPY --chown=ci:ci . /work

RUN chmod +x docker/entrypoint-test.sh docker/entrypoint-build.sh

ENTRYPOINT ["docker/entrypoint-test.sh"]
