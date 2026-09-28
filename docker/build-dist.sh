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
# The container is already ephemeral (`docker run --rm`); the trap below
# additionally removes every image built by this run on exit -- success or
# failure -- so nothing is left behind on the host beyond this run.
#
# Usage: docker/build-dist.sh
set -euo pipefail
cd "$(dirname "$0")/.."

PLATFORMS=(linux/amd64 linux/arm64)

BUILT_TAGS=()
cleanup() {
    for tag in "${BUILT_TAGS[@]}"; do
        docker rmi -f "$tag" >/dev/null 2>&1 || true
    done
}
trap cleanup EXIT

for platform in "${PLATFORMS[@]}"; do
    arch="${platform#linux/}"
    tag="hkdfguard-build-$arch"
    out_dir="dist/linux-$arch"

    echo
    echo "=== Building for $platform ==="
    docker build --platform "$platform" -t "$tag" -f docker/Dockerfile .
    BUILT_TAGS+=("$tag")

    mkdir -p "$out_dir"
    docker run --rm --platform "$platform" \
        -v "$(pwd)/$out_dir:/dist" \
        --entrypoint docker/entrypoint-build.sh \
        "$tag"
done

echo
echo "Distribution artifacts:"
find dist -maxdepth 2 -type f | sort
