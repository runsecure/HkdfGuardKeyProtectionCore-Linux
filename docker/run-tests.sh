#!/usr/bin/env bash
# Builds the HKDFGuard test image and runs the full test matrix in it:
#   cargo build/test (default features) -> real link against tpm2-tss and
#   PKCS#11 -> a swtpm-backed TPM2 hardware test -> a SoftHSM2-backed
#   PKCS#11 hardware test -> a C ABI round trip.
#
# The container is already ephemeral (`docker run --rm`); the trap below
# additionally removes the built image on exit -- success or failure --
# so nothing is left behind on the host beyond this run.
#
# Usage: docker/run-tests.sh
set -euo pipefail
cd "$(dirname "$0")/.."

TAG=hkdfguard-test
cleanup() { docker rmi -f "$TAG" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker build -t "$TAG" -f docker/Dockerfile .
docker run --rm --cap-add IPC_LOCK "$TAG"   # IPC_LOCK: lets the CLI take its mlockall path