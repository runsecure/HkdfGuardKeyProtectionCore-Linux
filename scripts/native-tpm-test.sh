#!/usr/bin/env bash
# Full hkdfguard test matrix on a native Linux machine with a real TPM
# (Intel PTT, AMD fTPM, or a discrete chip) -- the same sections as
# docker/entrypoint-test.sh, but against the hardware you will deploy on
# instead of swtpm, plus the things only real hardware can prove.
#
#   scripts/native-tpm-test.sh                 full matrix (default)
#   scripts/native-tpm-test.sh reboot capture  wrap a DEK on the TPM, save state, then reboot the machine
#   scripts/native-tpm-test.sh reboot verify   after the reboot: the same KEK must re-derive and unwrap it
#
# What it does, in order:
#   1. Preflight (scripts/native-tpm-preflight.sh).
#   2. Build with --features tpm2 (and pkcs11 if SoftHSM2 is installed).
#   3. Unit tests for the tpm2 feature (no device needed).
#   4. The #[ignore]d conformance suite against the REAL TPM: CreatePrimary
#      determinism, per-service uniqueness, Name formula, acceptance of the
#      hashed per-payload ECDH points, salted/encrypted session correctness, auto-mode.
#   5. The same suite again with a TPM derivation secret provisioned, which
#      exercises the runtime "does this TPM honor the secret" self-test.
#   6. Learns the salt-key and service-key Names from the TPM (the operator
#      helpers in src/provider/tpm2.rs) and writes a policy that REQUIRES
#      encrypted sessions with both Names pinned.
#   7. C ABI round trip (examples/wrap_unwrap.c) against the release .so
#      with the KEK on the TPM -- once under `auto`, once under that
#      `required` + pinned policy.
#   8. CLI -> separate C consumer: hkdfguard-v1-initialize wraps via stdin,
#      cli_unwrap_check unwraps through the .so. Cross-process persistence
#      on the real TPM.
#   9. If SoftHSM2 is present: the pkcs11 conformance suite.
#
# Nothing under /etc/hkdfguard is read or written: every policy and secret
# file this script uses lives in a temp dir it removes on exit, and the
# TPM is only ever asked to derive transient primaries (flushed after
# use). It leaves no state on the TPM.
#
# Environment:
#   HKDFGUARD_TCTI               override the TCTI (default from preflight)
#   HKDFGUARD_NATIVE_TEST_STATE  where `reboot capture` saves its state
#                                (default: ${XDG_STATE_HOME:-~/.local/state}/hkdfguard-native-tpm-test)
#   HKDFGUARD_TPM_DERIVATION_SECRET_FILE
#                                if set, honored throughout (and required
#                                to be set identically for reboot verify)
set -euo pipefail
cd "$(dirname "$0")/.."

section() { printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }
note()    { printf '   \033[2m%s\033[0m\n' "$*"; }

MODE="${1:-full}"
PHASE="${2:-}"

# ---------------------------------------------------------------------
# Preflight, shared setup
# ---------------------------------------------------------------------
section "preflight"
# shellcheck source=scripts/native-tpm-preflight.sh
source scripts/native-tpm-preflight.sh
export TCTI="${HKDFGUARD_TCTI:-$HKDFGUARD_PREFLIGHT_TCTI}"
export TPM2TOOLS_TCTI="$TCTI"
MANUFACTURER="$HKDFGUARD_PREFLIGHT_MANUFACTURER"

case "$MANUFACTURER" in
    INTC|AMD|QCOM|MSFT|IBM|GOOG|VMW) NO_EXTERNAL_BUS=1 ;;
    *) NO_EXTERNAL_BUS=0 ;;
esac

FEATURES="tpm2"
HAVE_SOFTHSM=0
# Tested on the substitution's *output*, not its exit status: under
# pipefail, `head` closing the pipe early makes `find` report failure
# even when it found the module.
SOFTHSM_MODULE=$(find /usr/lib /usr/lib64 /usr/local/lib -iname 'libsofthsm2.so' 2>/dev/null | head -n1 || true)
if [ -n "$SOFTHSM_MODULE" ]; then
    FEATURES="tpm2,pkcs11"
    HAVE_SOFTHSM=1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
# Isolate from any real host configuration: no policy unless a section
# writes one, and no external-secret mount.
export HKDFGUARD_POLICY_FILE="$WORK/no-policy"
export HKDFGUARD_EXTERNAL_SECRET_DIR="$WORK/no-external-secret"

# Writes $1 as the active policy file (root-or-self owned, 0600 -- the
# library refuses anything looser).
use_policy() {
    ( umask 077; printf '%s' "$1" > "$WORK/policy.yaml" )
    export HKDFGUARD_POLICY_FILE="$WORK/policy.yaml"
}
no_policy() { export HKDFGUARD_POLICY_FILE="$WORK/no-policy"; }

# Runs one #[ignore]d operator-helper test and extracts a KEY=value line.
# `--exact` matches the *full* test path, so it is spelled out here.
learn() { # learn <test-name> <KEY>
    cargo test --features tpm2 --lib "provider::tpm2::tests::$1" -- --ignored --exact --nocapture 2>/dev/null \
        | awk -F= -v k="$2" '$1==k {print $2; exit}'
}

# Builds a C example against the release library.
build_c() { # build_c <source.c> <out>
    cc -I include "$1" -L target/release -lHkdfGuardKeyProtectionLinux -o "$2"
}

# ---------------------------------------------------------------------
# Reboot persistence: the one thing swtpm can only approximate
# ---------------------------------------------------------------------
if [ "$MODE" = "reboot" ]; then
    STATE="${HKDFGUARD_NATIVE_TEST_STATE:-${XDG_STATE_HOME:-$HOME/.local/state}/hkdfguard-native-tpm-test}"
    SERVICE="com.hkdfguard.nativetest.reboot"
    use_policy $'selection:\n  mode: require\n  provider: tpm2\n'

    section "build (release, --features tpm2)"
    cargo build --release --features tpm2
    build_c examples/cli_unwrap_check.c "$WORK/cli_unwrap_check"

    case "$PHASE" in
        capture)
            section "reboot capture -> $STATE"
            mkdir -p "$STATE"; chmod 700 "$STATE"
            ( umask 077; head -c 32 /dev/urandom > "$STATE/dek.bin" )
            HKDFGUARD_PIN_SERVICE="$SERVICE" learn print_service_key_name_for_pinning SERVICE_KEY_NAME > "$STATE/service-name.hex"
            [ -s "$STATE/service-name.hex" ] || { echo "could not learn the service key Name" >&2; exit 1; }
            # On a TPM the KEK is derived on demand, so `provision` reports
            # it as already present; it is still the one command that makes
            # the setup calls, so run it as a real deployment would.
            target/release/hkdfguard-v1-initialize provision --service-name "$SERVICE"
            base64 -w0 < "$STATE/dek.bin" | target/release/hkdfguard-v1-initialize wrap \
                --key-file-path "$STATE/wrapped.key" --service-name "$SERVICE" --dek-stdin --force
            note "service key Name: $(cat "$STATE/service-name.hex")"
            note "wrapped DEK saved. Now REBOOT this machine, then run: scripts/native-tpm-test.sh reboot verify"
            if [ -n "${HKDFGUARD_TPM_DERIVATION_SECRET_FILE:-}" ]; then
                note "a derivation secret was in use; export HKDFGUARD_TPM_DERIVATION_SECRET_FILE identically before verify"
            fi
            exit 0
            ;;
        verify)
            section "reboot verify <- $STATE"
            [ -f "$STATE/wrapped.key" ] || { echo "no captured state in $STATE; run 'reboot capture' first" >&2; exit 1; }
            before=$(cat "$STATE/service-name.hex")
            after=$(HKDFGUARD_PIN_SERVICE="$SERVICE" learn print_service_key_name_for_pinning SERVICE_KEY_NAME)
            if [ "$before" != "$after" ]; then
                echo "FAIL: service key Name changed across the reboot ($before -> $after): the TPM did not re-derive the same KEK" >&2
                exit 1
            fi
            note "service key Name identical across reboot: $after"
            LD_LIBRARY_PATH=target/release "$WORK/cli_unwrap_check" "$STATE/wrapped.key" "$SERVICE" "$STATE/dek.bin"
            echo "PASS: the DEK wrapped before the reboot unwraps under the re-derived TPM KEK"
            exit 0
            ;;
        *)
            echo "usage: $0 reboot capture|verify" >&2; exit 2
            ;;
    esac
fi

[ "$MODE" = "full" ] || { echo "usage: $0 [full | reboot capture|verify]" >&2; exit 2; }

# ---------------------------------------------------------------------
# 2-3. Build + unit tests
# ---------------------------------------------------------------------
section "cargo build --features $FEATURES (real link against libtss2-esys${HAVE_SOFTHSM:+ + cryptoki})"
cargo build --features "$FEATURES"

section "cargo test --features tpm2 (tpm2 unit tests: derivation secret, Name computation, manufacturer classification)"
cargo test --features tpm2

# ---------------------------------------------------------------------
# 4. Conformance suite against the real TPM
# ---------------------------------------------------------------------
SKIP=()
if [ "$NO_EXTERNAL_BUS" -eq 0 ]; then
    # This test asserts `auto` SKIPS encryption, which is only true on an
    # fTPM/vTPM. On a discrete chip `auto` correctly encrypts, so the
    # assertion would fail for the right reason. Skip it, not the mechanism:
    # encrypted_session_ecdh_yields_the_same_z_as_a_plain_session still runs.
    SKIP=(--skip auto_mode_skips_encryption_on_swtpm_and_required_forces_it)
    note "discrete TPM ($MANUFACTURER): skipping the fTPM-only auto-mode assertion"
fi
# The two operator helpers only print; keep them out of the pass/fail run.
SKIP+=(--skip print_session_salt_key_name_for_pinning --skip print_service_key_name_for_pinning)

section "cargo test --features tpm2 -- --ignored (conformance suite against the real TPM: $TCTI)"
cargo test --features tpm2 -- --ignored --test-threads=1 "${SKIP[@]}"

# ---------------------------------------------------------------------
# 5. Same suite with a derivation secret provisioned
# ---------------------------------------------------------------------
section "conformance suite again with a TPM derivation secret (exercises the runtime honor check)"
( umask 077; head -c 32 /dev/urandom > "$WORK/tpm.derivation-secret" )
HKDFGUARD_TPM_DERIVATION_SECRET_FILE="$WORK/tpm.derivation-secret" \
    cargo test --features tpm2 -- --ignored --test-threads=1 "${SKIP[@]}"
note "the derivation secret changed every service key; the suite still passed, so this TPM honors it"

# ---------------------------------------------------------------------
# 6. Learn pins from the TPM, write a `required` policy
# ---------------------------------------------------------------------
section "learning Names to pin (session salt key, and the example service key)"
SALT_NAME=$(learn print_session_salt_key_name_for_pinning SALT_KEY_NAME)
SVC_NAME=$(HKDFGUARD_PIN_SERVICE=com.company.orders learn print_service_key_name_for_pinning SERVICE_KEY_NAME)
[ -n "$SALT_NAME" ] && [ -n "$SVC_NAME" ] || { echo "could not learn the Names to pin" >&2; exit 1; }
note "salt key Name:      $SALT_NAME"
note "service key Name:   $SVC_NAME (com.company.orders)"
REQUIRED_POLICY=$(cat <<EOF
selection:
  mode: require
  provider: tpm2
tpm:
  session_encryption: required
  pinned_session_salt_key_name: "$SALT_NAME"
  pinned_names:
    com.company.orders: "$SVC_NAME"
EOF
)
note "this policy is what a hardened deployment on THIS machine would install at /etc/hkdfguard/policy.yaml"
printf '%s\n' "$REQUIRED_POLICY" > "$WORK/required-policy.example.yaml"

# ---------------------------------------------------------------------
# 7. C ABI round trip on the TPM, under both policies
# ---------------------------------------------------------------------
section "cargo build --release --features tpm2"
cargo build --release --features tpm2
build_c examples/wrap_unwrap.c "$WORK/wrap_unwrap"
build_c examples/cli_unwrap_check.c "$WORK/cli_unwrap_check"

section "C ABI round trip (examples/wrap_unwrap.c) -- KEK on the TPM, policy: require tpm2, session_encryption auto"
use_policy $'selection:\n  mode: require\n  provider: tpm2\n'
LD_LIBRARY_PATH=target/release "$WORK/wrap_unwrap"

section "C ABI round trip -- policy: session_encryption REQUIRED with both Names pinned"
use_policy "$REQUIRED_POLICY"
LD_LIBRARY_PATH=target/release "$WORK/wrap_unwrap"
note "every ECDH in that run went through a salted, AES-128-CFB-encrypted session against a pinned salt key"

# ---------------------------------------------------------------------
# 8. CLI -> separate C consumer, across processes, on the TPM
# ---------------------------------------------------------------------
section "hkdfguard-v1-initialize (stdin) -> cli_unwrap_check via the .so, KEK on the TPM"
CLI_SERVICE=com.hkdfguard.nativetest.cli
( umask 077; head -c 32 /dev/urandom > "$WORK/dek.bin" )
target/release/hkdfguard-v1-initialize provision --service-name "$CLI_SERVICE"
base64 -w0 < "$WORK/dek.bin" | target/release/hkdfguard-v1-initialize wrap \
    --key-file-path "$WORK/wrapped.key" --service-name "$CLI_SERVICE" --dek-stdin --force
LD_LIBRARY_PATH=target/release "$WORK/cli_unwrap_check" "$WORK/wrapped.key" "$CLI_SERVICE" "$WORK/dek.bin"
no_policy

# ---------------------------------------------------------------------
# 9. Optional PKCS#11
# ---------------------------------------------------------------------
if [ "$HAVE_SOFTHSM" -eq 1 ]; then
    section "SoftHSM2 token + cargo test --features pkcs11 -- --ignored"
    export SOFTHSM2_CONF="$WORK/softhsm2.conf"
    mkdir -p "$WORK/tokens"
    printf 'directories.tokendir = %s\nobjectstore.backend = file\n' "$WORK/tokens" > "$SOFTHSM2_CONF"
    softhsm2-util --init-token --free --label hkdfguard-native --pin 1234 --so-pin 5678 >/dev/null
    ( umask 077; printf '1234\n' > "$WORK/pkcs11.pin" )
    export HKDFGUARD_PKCS11_MODULE="$SOFTHSM_MODULE" HKDFGUARD_PKCS11_PIN_FILE="$WORK/pkcs11.pin"
    cargo test --features pkcs11 -- --ignored --test-threads=1
    unset HKDFGUARD_PKCS11_MODULE HKDFGUARD_PKCS11_PIN_FILE SOFTHSM2_CONF
else
    section "pkcs11 suite skipped (SoftHSM2 not installed)"
fi

section "ALL NATIVE CHECKS PASSED on $MANUFACTURER via $TCTI"
echo "To also prove persistence across a real reboot:"
echo "  scripts/native-tpm-test.sh reboot capture   # then reboot"
echo "  scripts/native-tpm-test.sh reboot verify"
