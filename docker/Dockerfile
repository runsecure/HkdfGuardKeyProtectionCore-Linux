# Linux test/build environment for HKDFGuard.
#
# Includes everything the default (software/external-secret/ephemeral) and
# hardware-backed (tpm2 via swtpm, pkcs11 via SoftHSM2) providers need, so
# the whole provider chain -- including the two providers that cannot be
# built or tested on the macOS host this crate was originally written on --
# can be exercised for real. See docker/README.md for usage.

FROM debian:bookworm-slim

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

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- -y --profile minimal --default-toolchain stable \
    && rustup component add clippy

# SoftHSM2 needs a writable config + token directory; the default
# /etc/softhsm/softhsm2.conf + /var/lib/softhsm/tokens are root-owned,
# which is fine since tests run as root in this throwaway container.
ENV SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf
RUN mkdir -p /var/lib/softhsm/tokens

WORKDIR /work
COPY . /work

RUN chmod +x docker/entrypoint-test.sh

ENTRYPOINT ["docker/entrypoint-test.sh"]
