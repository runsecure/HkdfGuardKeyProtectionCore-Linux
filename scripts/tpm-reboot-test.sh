#!/usr/bin/env bash
# Approximates TPM reboot/persistence testing for hkdfguard's TPM2
# provider: TPM2_CreatePrimary's determinism (see the design note in
# src/provider/tpm2.rs) means a primary key derived from a fixed template
# must reproduce identically even after the emulated TPM process itself
# is stopped and restarted, as long as its state directory (where swtpm
# persists the primary seed) survives.
#
# This is an approximation, not a literal invocation of hkdfguard's own
# Rust code: it drives tpm2-tools directly against a plain default ECC
# template rather than reimplementing src/provider/tpm2.rs's exact
# per-service SHA-256(service) `unique`-field derivation in shell. That
# per-service differentiation is already covered, in-process and without
# needing a real restart, by the `#[ignore]`d
# different_services_produce_different_public_keys /
# _names tests in src/provider/tpm2.rs. What only an actual restart can
# exercise -- and what this script is for -- is whether CreatePrimary's
# output for a *fixed* template survives that restart at all.
#
# Workflow:
#   1. Start swtpm with persistent state.
#   2. Capture a primary's public area + Name.
#   3. Stop swtpm.
#   4. Restart swtpm using the same state directory.
#   5. Capture again.
#   6. Assert both captures are identical.
#
# Requires `swtpm`/`swtpm-tools` and `tpm2-tools` on PATH (see
# docker/Dockerfile, or docker/docker-compose.yml's `swtpm` service for a
# containerized alternative). Exact tpm2-tools flag names/output can vary
# slightly by version; this was written against the tpm2-tools release in
# docker/Dockerfile (Debian bookworm) and not independently re-verified
# against every other version.
#
# Usage: scripts/tpm-reboot-test.sh
set -euo pipefail
cd "$(dirname "$0")/.."

command -v swtpm >/dev/null || { echo "swtpm not found on PATH" >&2; exit 1; }
command -v tpm2_startup >/dev/null || { echo "tpm2-tools not found on PATH" >&2; exit 1; }

STATE_DIR=$(mktemp -d)
WORK_DIR=$(mktemp -d)
TCTI="swtpm:host=127.0.0.1,port=2321"

SWTPM_PID=""
cleanup() {
    [ -n "$SWTPM_PID" ] && kill "$SWTPM_PID" 2>/dev/null || true
}
trap cleanup EXIT

start_swtpm() {
    swtpm socket \
        --tpmstate dir="$STATE_DIR" \
        --tpm2 \
        --server type=tcp,port=2321 \
        --ctrl type=tcp,port=2322 \
        --flags not-need-init &
    SWTPM_PID=$!
    for _ in $(seq 1 50); do
        if tpm2_startup -c -T "$TCTI" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
    done
    echo "swtpm did not come up in time" >&2
    exit 1
}

stop_swtpm() {
    kill "$SWTPM_PID" 2>/dev/null || true
    wait "$SWTPM_PID" 2>/dev/null || true
    SWTPM_PID=""
}

# Creates an ECC primary under a fixed, default template and writes its
# marshalled public area and TPM Name to $1/$2. Uses a plain default
# template (no custom `unique` field) deliberately -- see this script's
# header for why that's sufficient for what's being tested here.
capture() {
    local public_out="$1" name_out="$2"
    local ctx="$WORK_DIR/primary.ctx"
    tpm2_createprimary -T "$TCTI" -C o -g sha256 -G ecc -c "$ctx" >/dev/null
    tpm2_readpublic -T "$TCTI" -c "$ctx" -o "$public_out" -n "$name_out" >/dev/null
    tpm2_flushcontext -T "$TCTI" -t >/dev/null 2>&1 || true
}

echo "== Starting swtpm (round 1) =="
start_swtpm
capture "$WORK_DIR/public1.bin" "$WORK_DIR/name1.bin"
echo "== Stopping swtpm =="
stop_swtpm

echo "== Restarting swtpm against the same state directory =="
start_swtpm
capture "$WORK_DIR/public2.bin" "$WORK_DIR/name2.bin"
stop_swtpm

if cmp -s "$WORK_DIR/public1.bin" "$WORK_DIR/public2.bin" && cmp -s "$WORK_DIR/name1.bin" "$WORK_DIR/name2.bin"; then
    echo "PASS: public key and Name are identical across the swtpm restart"
    exit 0
else
    echo "FAIL: public key or Name changed across the swtpm restart" >&2
    exit 1
fi
