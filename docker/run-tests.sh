#!/usr/bin/env bash
# Builds the HKDFGuard test image and runs the full test matrix in it:
#   cargo build/test (default features) -> real link against tpm2-tss and
#   PKCS#11 -> a swtpm-backed TPM2 hardware test -> a SoftHSM2-backed
#   PKCS#11 hardware test -> a C ABI round trip.
#
# Usage: docker/run-tests.sh
set -euo pipefail
cd "$(dirname "$0")/.."

docker build -t hkdfguard-test -f docker/Dockerfile .
docker run --rm hkdfguard-test
