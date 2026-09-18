#!/usr/bin/env bash
# Runs the full HKDFGuard test matrix inside the container built from
# docker/Dockerfile: default-feature unit tests, a real link against
# tpm2-tss + a swtpm-backed TPM2 hardware test, and a real link against
# SoftHSM2 + a PKCS#11 hardware test. See docker/README.md.
set -euo pipefail

section() { printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }

section "cargo build (default features: software, external-secret, ephemeral)"
cargo build

section "cargo test (default features)"
cargo test

section "cargo build --features tpm2,pkcs11 (real link against libtss2-esys + cryptoki)"
cargo build --features tpm2,pkcs11
echo "Linked successfully against real tpm2-tss and PKCS#11 (loader) libraries."

section "starting swtpm (software TPM2 simulator)"
TPM_STATE_DIR=$(mktemp -d)
swtpm socket \
    --tpmstate dir="$TPM_STATE_DIR" \
    --tpm2 \
    --server type=tcp,port=2321 \
    --ctrl type=tcp,port=2322 \
    --flags not-need-init &
SWTPM_PID=$!
trap 'kill "$SWTPM_PID" 2>/dev/null || true' EXIT
sleep 1

export TCTI="swtpm:host=127.0.0.1,port=2321"
export TPM2TOOLS_TCTI="$TCTI"
tpm2_startup -c -T "$TCTI"
echo "swtpm is up and started (TCTI=$TCTI)."

section "cargo test --features tpm2 -- --ignored (against swtpm)"
cargo test --features tpm2 -- --ignored --test-threads=1

section "initializing a SoftHSM2 token"
SOFTHSM_MODULE=$(find /usr/lib -iname "libsofthsm2.so" 2>/dev/null | head -n1)
if [ -z "$SOFTHSM_MODULE" ]; then
    echo "libsofthsm2.so not found" >&2
    exit 1
fi
softhsm2-util --init-token --free --label hkdfguard-test --pin 1234 --so-pin 5678
export HKDFGUARD_PKCS11_MODULE="$SOFTHSM_MODULE"
export HKDFGUARD_PKCS11_PIN=1234
echo "SoftHSM2 token ready (module=$HKDFGUARD_PKCS11_MODULE)."

section "cargo test --features pkcs11 -- --ignored (against SoftHSM2)"
cargo test --features pkcs11 -- --ignored --test-threads=1

section "C ABI round trip via examples/wrap_unwrap.c (default providers)"
unset HKDFGUARD_PKCS11_MODULE HKDFGUARD_PKCS11_PIN TCTI TPM2TOOLS_TCTI
cargo build --release
cc -I include examples/wrap_unwrap.c -L target/release -lhkdfguard -o /tmp/wrap_unwrap
LD_LIBRARY_PATH=target/release /tmp/wrap_unwrap

section "ALL CHECKS PASSED"
