#!/usr/bin/env bash
# Builds HKDFGuard (release profile, all features) for both linux/amd64 and
# linux/arm64, each inside its own container built from the same
# docker/Dockerfile docker/run-tests.sh uses, gating each on cargo test.
# Copies the resulting shared/static libraries, CLI binary, and public C
# header out of each container into dist/linux-<arch> on the host.
#
# Building the non-native platform runs under QEMU emulation (via Docker's
# buildx), which is noticeably slower than the host's native architecture
# but requires no extra setup on a normal Docker Desktop install. Verify
# your Docker install supports this first if in doubt:
#   docker run --rm --platform linux/amd64 alpine uname -m
#   docker run --rm --platform linux/arm64 alpine uname -m
#
# Usage: docker/build-dist.sh
set -euo pipefail
cd "$(dirname "$0")/.."

PLATFORMS=(linux/amd64 linux/arm64)

for platform in "${PLATFORMS[@]}"; do
    arch="${platform#linux/}"
    tag="hkdfguard-build-$arch"
    out_dir="dist/linux-$arch"

    echo
    echo "=== Building for $platform ==="
    docker build --platform "$platform" -t "$tag" -f docker/Dockerfile .

    mkdir -p "$out_dir"
    docker run --rm --platform "$platform" \
        -v "$(pwd)/$out_dir:/dist" \
        --entrypoint docker/entrypoint-build.sh \
        "$tag"
done

echo
echo "Distribution artifacts:"
find dist -maxdepth 2 -type f | sort
