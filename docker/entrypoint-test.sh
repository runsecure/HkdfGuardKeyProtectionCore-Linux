#!/usr/bin/env bash
# Runs the full HKDFGuard test matrix inside the container built from
# docker/Dockerfile: default-feature unit tests, a real link against
# tpm2-tss + a swtpm-backed TPM2 hardware test, and a real link against
# SoftHSM2 + a PKCS#11 hardware test. See docker/README.md.
set -euo pipefail

section() { printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }

section "cargo build (default features: external-secret, ephemeral)"
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

# The TPM provider requires a derivation secret by default. Debug builds
# (the test suites below) take its path from this variable; tests that
# exercise running without one set tpm.require_derivation_secret = false
# in their own policy.
TPM_SECRET_DIR=$(mktemp -d)
( umask 077; head -c 32 /dev/urandom > "$TPM_SECRET_DIR/tpm.derivation-secret" )
export HKDFGUARD_TPM_DERIVATION_SECRET_FILE="$TPM_SECRET_DIR/tpm.derivation-secret"

# The tpm2 feature's non-hardware tests -- derivation-secret file
# handling, template attributes, client-side Name computation -- need the
# feature to compile but no TPM, and are therefore not #[ignore]d. They
# only ever get compiled and run on Linux, so run them explicitly here.
section "cargo test --features tpm2 (tpm2 unit tests: derivation secret, Name computation)"
cargo test --features tpm2

section "cargo test --features tpm2 -- --ignored (against swtpm)"
cargo test --features tpm2 -- --ignored --test-threads=1

section "initializing a SoftHSM2 token"
SOFTHSM_MODULE=$(find /usr/lib -iname "libsofthsm2.so" 2>/dev/null | head -n1)
if [ -z "$SOFTHSM_MODULE" ]; then
    echo "libsofthsm2.so not found" >&2
    exit 1
fi
# Same label and PINs as scripts/native-tpm-test.sh; the pkcs11 tests select
# this token by label (SOFTHSM_TEST_TOKEN_LABEL in src/provider/pkcs11.rs).
softhsm2-util --init-token --free --label hkdfguard-test --pin 1234 --so-pin 5678
export HKDFGUARD_PKCS11_MODULE="$SOFTHSM_MODULE"
# The PIN is read from an owner-only file, never an environment variable
# (see src/provider/pkcs11.rs); the module must be root-owned, which the
# apt-installed libsofthsm2.so is.
PIN_DIR=$(mktemp -d)
( umask 077; printf '1234\n' > "$PIN_DIR/pkcs11.pin" )
export HKDFGUARD_PKCS11_PIN_FILE="$PIN_DIR/pkcs11.pin"
echo "SoftHSM2 token ready (module=$HKDFGUARD_PKCS11_MODULE, PIN file=$HKDFGUARD_PKCS11_PIN_FILE)."

section "cargo test --features pkcs11 -- --ignored (against SoftHSM2)"
cargo test --features pkcs11 -- --ignored --test-threads=1

section "C ABI round trip via examples/wrap_unwrap.c (default providers)"
unset HKDFGUARD_PKCS11_MODULE HKDFGUARD_PKCS11_PIN_FILE TCTI TPM2TOOLS_TCTI
rm -rf "$PIN_DIR"
# With no policy file, Ephemeral is never used, so the example needs a
# real KEK: provision an external secret for its service, as a
# deployment platform would. Release builds ignore
# HKDFGUARD_EXTERNAL_SECRET_DIR, so it goes in a standard secret mount.
SECRET_MOUNT=/run/secrets/hkdfguard
mkdir -p "$SECRET_MOUNT"
( umask 077; head -c 32 /dev/urandom > "$SECRET_MOUNT/com.company.orders" ) # owner-only, as the provider requires of a KEK file
cargo build --release
cc -I include examples/wrap_unwrap.c -L target/release -lHkdfGuardKeyProtectionLinux -o /tmp/wrap_unwrap
LD_LIBRARY_PATH=target/release /tmp/wrap_unwrap

section "hkdfguard-v1-initialize CLI output unwraps via libHkdfGuardKeyProtectionLinux.so"
# The CLI links this crate's Rust code statically (an rlib), so this proves
# the wrapped payload it writes is genuinely consumer-independent -- a
# *different*, dynamically-linked consumer (this C program, against the
# release .so) can unwrap it too, not just the CLI's own process image.
#
# There is no software-backed provider on this platform, so the shared,
# cross-process-persistent KEK both processes need here comes from
# external-secret: a secret file is provisioned into a shared directory
# before either process runs, exactly as a real deployment platform
# (Vault Agent, a Kubernetes Secret, ...) would have already done.
CLISO_SERVICE=com.hkdfguard.dockertest.cliso
( umask 077; head -c 32 /dev/urandom > "$SECRET_MOUNT/$CLISO_SERVICE" ) # owner-only, as the provider requires of a KEK file

DEK_FILE=$(mktemp)
head -c 32 /dev/urandom > "$DEK_FILE"
WRAPPED_FILE=$(mktemp)

# `provision` is the only command that makes the (deliberately slow) setup
# calls. For external-secret the mounted file *is* the provisioning, so
# this reports "already provisioned" -- and must still exit 0.
target/release/hkdfguard-v1-initialize provision --service-name "$CLISO_SERVICE"

# The DEK goes in on stdin, never on the command line: argv is readable by
# any process of the same user through /proc/<pid>/cmdline. `printf` is a
# shell builtin, so the base64 never becomes a child process's argv either.
# This is also the invocation a real deployment pipeline should use.
DEK_B64=$(base64 -w0 < "$DEK_FILE")
printf '%s' "$DEK_B64" | target/release/hkdfguard-v1-initialize wrap \
    --key-file-path "$WRAPPED_FILE" \
    --service-name "$CLISO_SERVICE" \
    --dek-stdin \
    --force
unset DEK_B64

cc -I include examples/cli_unwrap_check.c -L target/release -lHkdfGuardKeyProtectionLinux -o /tmp/cli_unwrap_check
LD_LIBRARY_PATH=target/release /tmp/cli_unwrap_check "$WRAPPED_FILE" "$CLISO_SERVICE" "$DEK_FILE"

# And the --dek-file path, which is what a secret mount or a systemd
# credential provides. Mode 0600 or the CLI refuses it.
WRAPPED_FILE2=$(mktemp)
DEK_B64_FILE=$(mktemp)
( umask 077; base64 -w0 < "$DEK_FILE" > "$DEK_B64_FILE" )
target/release/hkdfguard-v1-initialize wrap \
    --key-file-path "$WRAPPED_FILE2" \
    --service-name "$CLISO_SERVICE" \
    --dek-file "$DEK_B64_FILE" \
    --force
LD_LIBRARY_PATH=target/release /tmp/cli_unwrap_check "$WRAPPED_FILE2" "$CLISO_SERVICE" "$DEK_FILE"

# The retired argv form must be refused outright, not silently accepted.
if printf '%s' "$(base64 -w0 < "$DEK_FILE")" | target/release/hkdfguard-v1-initialize wrap \
        --key-file-path "$(mktemp -u)" --service-name "$CLISO_SERVICE" --dek AAAA 2>/dev/null; then
    echo "FAIL: --dek was accepted; it must be rejected" >&2
    exit 1
fi

# `wrap` never provisions: with nothing mounted for this service it must
# fail and point at `provision`, rather than quietly creating a KEK.
UNPROVISIONED_OUT=$(mktemp -u)
if printf '%s' "$(base64 -w0 < "$DEK_FILE")" | target/release/hkdfguard-v1-initialize wrap \
        --key-file-path "$UNPROVISIONED_OUT" --service-name com.hkdfguard.dockertest.unprovisioned --dek-stdin 2>/tmp/unprov.err; then
    echo "FAIL: wrap succeeded for a service with no provisioned KEK" >&2
    exit 1
fi
grep -q 'provision --service-name com.hkdfguard.dockertest.unprovisioned' /tmp/unprov.err \
    || { echo "FAIL: wrap's error did not point at the provision command:" >&2; cat /tmp/unprov.err >&2; exit 1; }
[ ! -e "$UNPROVISIONED_OUT" ] || { echo "FAIL: a failed wrap wrote an output file" >&2; exit 1; }
echo "--dek correctly rejected; unprovisioned wrap correctly refused; stdin and --dek-file both round-tripped."

rm -f "$DEK_FILE" "$WRAPPED_FILE" "$WRAPPED_FILE2" "$DEK_B64_FILE"
rm -rf "$SECRET_MOUNT"

section "release builds take security settings only from root-owned config, not the environment"
# Debug builds (everything above) honor HKDFGUARD_POLICY_FILE, the TCTI
# variables and HKDFGUARD_TPM_DERIVATION_SECRET_FILE so tests can redirect
# them. Release builds must not. Install a real root policy that reaches
# swtpm through `tpm.tcti`, then set all three variables to values that
# would break anything that read them. The release binaries must ignore
# them and work; the debug CLI, as a control, must read the bad policy and
# fail -- proving this check would catch a release build that honored it.
cargo build --release --features tpm2,pkcs11
cargo build --features tpm2,pkcs11   # the debug CLI used as the control below
mkdir -p /etc/hkdfguard
( umask 077; head -c 32 /dev/urandom > /etc/hkdfguard/tpm.derivation-secret )  # required by default
cat > /etc/hkdfguard/policy.toml <<'TOML'
[selection]
mode = "require"
provider = "tpm2"

[tpm]
tcti = "swtpm:host=127.0.0.1,port=2321"
TOML
chmod 0644 /etc/hkdfguard/policy.toml

BAD_DIR=$(mktemp -d)
printf 'this is not = valid [toml' > "$BAD_DIR/policy.toml"
printf 'group-readable, so refused if read' > "$BAD_DIR/secret"; chmod 0640 "$BAD_DIR/secret"
export HKDFGUARD_POLICY_FILE="$BAD_DIR/policy.toml"
export TCTI="device:/dev/nonexistent-tpm" TPM2TOOLS_TCTI="device:/dev/nonexistent-tpm"
export HKDFGUARD_TPM_DERIVATION_SECRET_FILE="$BAD_DIR/secret"

LD_LIBRARY_PATH=target/release /tmp/wrap_unwrap
RELEASE_STDERR=$(target/release/hkdfguard-v1-initialize provision --service-name com.hkdfguard.dockertest.release 2>&1 >/dev/null) \
    || { echo "FAIL: release CLI did not ignore the debug-only overrides: $RELEASE_STDERR" >&2; exit 1; }
for var in HKDFGUARD_POLICY_FILE TPM2TOOLS_TCTI HKDFGUARD_TPM_DERIVATION_SECRET_FILE; do
    grep -q "$var is set but ignored" <<<"$RELEASE_STDERR" \
        || { echo "FAIL: release CLI did not warn that $var was ignored: $RELEASE_STDERR" >&2; exit 1; }
done
echo "release: wrap/unwrap on the TPM named by /etc/hkdfguard/policy.toml; all three overrides ignored, with warnings."

if target/debug/hkdfguard-v1-initialize provision --service-name com.hkdfguard.dockertest.release >/dev/null 2>&1; then
    echo "FAIL: control: the debug CLI should have read the malformed HKDFGUARD_POLICY_FILE and failed" >&2; exit 1
fi
echo "control: the debug CLI honored the malformed override and failed, as designed."

unset HKDFGUARD_POLICY_FILE TCTI TPM2TOOLS_TCTI HKDFGUARD_TPM_DERIVATION_SECRET_FILE

# External secret: the variable points nowhere; release must ignore it and
# find the KEK in the standard mount, while the debug control follows it
# and finds nothing.
cat > /etc/hkdfguard/policy.toml <<'TOML'
[selection]
mode = "require"
provider = "external-secret"
TOML
mkdir -p /run/secrets/hkdfguard
( umask 077; head -c 32 /dev/urandom > /run/secrets/hkdfguard/com.hkdfguard.dockertest.extsecret )
export HKDFGUARD_EXTERNAL_SECRET_DIR=/nonexistent-secret-mount
RELEASE_OUT=$(target/release/hkdfguard-v1-initialize provision --service-name com.hkdfguard.dockertest.extsecret 2>&1) \
    || { echo "FAIL: release CLI did not ignore HKDFGUARD_EXTERNAL_SECRET_DIR: $RELEASE_OUT" >&2; exit 1; }
grep -q 'already provisioned' <<<"$RELEASE_OUT" && grep -q 'HKDFGUARD_EXTERNAL_SECRET_DIR is set but ignored' <<<"$RELEASE_OUT" \
    || { echo "FAIL: release CLI should have used the standard mount and warned: $RELEASE_OUT" >&2; exit 1; }
if HKDFGUARD_POLICY_FILE=/etc/hkdfguard/policy.toml target/debug/hkdfguard-v1-initialize provision \
        --service-name com.hkdfguard.dockertest.extsecret >/dev/null 2>&1; then
    echo "FAIL: control: the debug CLI should have followed HKDFGUARD_EXTERNAL_SECRET_DIR and found nothing" >&2; exit 1
fi
echo "release: external-secret ignored HKDFGUARD_EXTERNAL_SECRET_DIR and used the standard mount; debug control followed it."
unset HKDFGUARD_EXTERNAL_SECRET_DIR
rm -rf /run/secrets/hkdfguard

# PKCS#11: SoftHSM2 is installed, with an initialized token and a valid PIN
# at the default PIN path, and the variables point at all of it -- but the
# policy names no module. Release must not use PKCS#11 at all (no default
# module search, variables ignored); the debug control uses it.
cat > /etc/hkdfguard/policy.toml <<'TOML'
[selection]
mode = "require"
provider = "pkcs11"
TOML
( umask 077; printf '1234\n' > /etc/hkdfguard/pkcs11.pin )
PIN_DIR=$(mktemp -d)
( umask 077; printf '1234\n' > "$PIN_DIR/pkcs11.pin" )
export HKDFGUARD_PKCS11_MODULE="$SOFTHSM_MODULE" HKDFGUARD_PKCS11_PIN_FILE="$PIN_DIR/pkcs11.pin" HKDFGUARD_PKCS11_SLOT=0
if RELEASE_OUT=$(target/release/hkdfguard-v1-initialize provision --service-name com.hkdfguard.dockertest.pkcs11 2>&1); then
    echo "FAIL: release CLI used PKCS#11 with no pkcs11.module in policy: $RELEASE_OUT" >&2; exit 1
fi
grep -q 'no KEK provider is available' <<<"$RELEASE_OUT" \
    || { echo "FAIL: release CLI should have found no provider: $RELEASE_OUT" >&2; exit 1; }
for var in HKDFGUARD_PKCS11_MODULE HKDFGUARD_PKCS11_PIN_FILE HKDFGUARD_PKCS11_SLOT; do
    grep -q "$var is set but ignored" <<<"$RELEASE_OUT" \
        || { echo "FAIL: release CLI did not warn that $var was ignored: $RELEASE_OUT" >&2; exit 1; }
done
HKDFGUARD_POLICY_FILE=/etc/hkdfguard/policy.toml target/debug/hkdfguard-v1-initialize provision \
    --service-name com.hkdfguard.dockertest.pkcs11 >/dev/null 2>&1 \
    || { echo "FAIL: control: the debug CLI should have reached SoftHSM2 through the variables" >&2; exit 1; }
echo "release: PKCS#11 unused without pkcs11.module (no SoftHSM2 search, variables ignored); debug control used it."
unset HKDFGUARD_PKCS11_MODULE HKDFGUARD_PKCS11_PIN_FILE HKDFGUARD_PKCS11_SLOT

rm -rf /etc/hkdfguard "$BAD_DIR" "$PIN_DIR"

section "hkdfguard-v1-initialize locks its memory when it can"
# docker/run-tests.sh and CI grant CAP_IPC_LOCK, so the CLI must take the
# mlockall path; it exits non-zero if that fails, so a clean exit with no
# skip warning means memory really was locked. Without the capability the
# skip path must warn instead.
CAP_EFF=$((16#$(awk '/^CapEff:/{print $2}' /proc/self/status)))
CLI_STDERR=$(target/release/hkdfguard-v1-initialize --help 2>&1 >/dev/null) \
    || { echo "FAIL: CLI exited non-zero at startup: $CLI_STDERR" >&2; exit 1; }
if (( (CAP_EFF >> 14) & 1 )); then
    if grep -q 'memory not locked' <<<"$CLI_STDERR"; then
        echo "FAIL: CAP_IPC_LOCK is present but the CLI skipped mlockall" >&2; exit 1
    fi
    echo "CAP_IPC_LOCK present: CLI locked its memory (mlockall succeeded)."
else
    grep -q 'memory not locked' <<<"$CLI_STDERR" \
        || { echo "FAIL: no CAP_IPC_LOCK, yet the CLI gave no skip warning" >&2; exit 1; }
    echo "no CAP_IPC_LOCK: CLI skipped mlockall and warned, as designed."
fi

section "ALL CHECKS PASSED"
