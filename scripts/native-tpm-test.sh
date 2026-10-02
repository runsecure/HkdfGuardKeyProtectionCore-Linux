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
#      hashed per-payload ECDH points, salted/encrypted session correctness,
#      auto-mode, and the runtime "does this TPM honor the derivation
#      secret" self-test. A derivation secret is required by default, so
#      the script provisions one (see Environment below).
#   5. The same suite again under a second, different derivation secret:
#      every service key changes, and everything must still pass.
#   6. Learns the salt-key and service-key Names from the TPM (the operator
#      helpers in src/provider/tpm2.rs) and writes a policy that REQUIRES
#      encrypted sessions with both Names pinned.
#   7. C ABI round trip (examples/wrap_unwrap.c) against the .so
#      with the KEK on the TPM -- once under `auto`, once under that
#      `required` + pinned policy.
#   8. CLI -> separate C consumer: hkdfguard-v1-initialize wraps via stdin,
#      cli_unwrap_check unwraps through the .so. Cross-process persistence
#      on the real TPM.
#   9. If SoftHSM2 is present: the pkcs11 conformance suite.
#
# Everything is configured the way production is -- by a policy file --
# except that the file lives in this script's temp dir. A library only reads
# a policy other than /etc/hkdfguard/policy.toml when built with
# `--cfg hkdfguard_test_paths`, so everything here (tests, the .so, and the
# CLI the C examples use) is built that way, into its own target directory
# (target/test-paths) so it never mixes with an ordinary build. Nothing that
# ships is ever built with that flag.
#
# Nothing under /etc/hkdfguard is read or written: every policy and secret
# file this script uses lives in a temp dir it removes on exit, and the
# TPM is only ever asked to derive transient primaries (flushed after
# use). It leaves no state on the TPM.
#
# Options (read by this script; the library reads none of them):
#   HKDFGUARD_TCTI               override the TCTI (default from preflight)
#   HKDFGUARD_NATIVE_TEST_STATE  where `reboot capture` saves its state
#                                (default: ${XDG_STATE_HOME:-~/.local/state}/hkdfguard-native-tpm-test)
#   HKDFGUARD_TPM_DERIVATION_SECRET_FILE
#                                the derivation secret to put in the policies.
#                                If unset, the script creates one: in its temp
#                                dir for a full run, and in the state dir for
#                                `reboot`, where capture and verify must share it.
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
TCTI="${HKDFGUARD_TCTI:-$HKDFGUARD_PREFLIGHT_TCTI}"
export TPM2TOOLS_TCTI="$TCTI" # for tpm2-tools only; the library takes its TCTI from policy
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

# Test builds only, in their own target dir; see the note at the top.
export RUSTFLAGS="--cfg hkdfguard_test_paths"
export CARGO_TARGET_DIR="$PWD/target/test-paths"
BIN="$CARGO_TARGET_DIR/debug"

# The TPM provider refuses to run without a derivation secret unless policy
# says otherwise. Provision a throwaway one for a full run; `reboot` keeps
# its own in the state dir (below) so it survives the reboot.
SECRET="${HKDFGUARD_TPM_DERIVATION_SECRET_FILE:-}"
if [ -z "$SECRET" ] && [ "$MODE" != "reboot" ]; then
    SECRET="$WORK/tpm.derivation-secret"
    ( umask 077; head -c 32 /dev/urandom > "$SECRET" )
fi

# SoftHSM2, if present: a throwaway token, named in every policy below so
# the pkcs11 tests can reach it. Same label and PINs as
# docker/entrypoint-test.sh; the tests select it by label
# (SOFTHSM_TEST_TOKEN_LABEL in src/provider/pkcs11.rs).
if [ "$HAVE_SOFTHSM" -eq 1 ]; then
    export SOFTHSM2_CONF="$WORK/softhsm2.conf"
    mkdir -p "$WORK/tokens"
    printf 'directories.tokendir = %s\nobjectstore.backend = file\n' "$WORK/tokens" > "$SOFTHSM2_CONF"
    softhsm2-util --init-token --free --label hkdfguard-test --pin 1234 --so-pin 5678 >/dev/null
    ( umask 077; printf '1234\n' > "$WORK/pkcs11.pin" )
fi

# Prints a complete policy: $1 (the [selection] table and anything else
# top-level), this machine's TPM settings plus any extra [tpm] keys in $2,
# the SoftHSM2 token if there is one, then any further tables in $3.
policy() { # policy <selection...> [extra [tpm] keys] [more tables]
    printf '%s\n\n[tpm]\ntcti = "%s"\nderivation_secret_file = "%s"\n%s\n' "$1" "$TCTI" "$SECRET" "${2:-}"
    if [ "$HAVE_SOFTHSM" -eq 1 ]; then
        printf '\n[pkcs11]\nmodule = "%s"\npin_file = "%s"\ntoken_label = "hkdfguard-test"\n' "$SOFTHSM_MODULE" "$WORK/pkcs11.pin"
    fi
    printf '%s\n' "${3:-}"
}

# Makes `policy "$@"` the policy file every test build reads (tests layer
# their own policies over it). Owner-only, as the library requires.
use_policy() {
    ( umask 077; policy "$@" > "$WORK/policy.toml" )
    export HKDFGUARD_POLICY_FILE="$WORK/policy.toml"
}
# Selects as having no policy file would: the default order, no Ephemeral.
use_base_policy() { use_policy $'[selection]\nmode = "prefer"'; }

# Runs one #[ignore]d operator-helper test and extracts a KEY=value line.
# `--exact` matches the *full* test path, so it is spelled out here.
learn() { # learn <test-name> <KEY>
    cargo test --features tpm2 --lib "provider::tpm2::tests::$1" -- --ignored --exact --nocapture 2>/dev/null \
        | awk -F= -v k="$2" '$1==k {print $2; exit}'
}

# Builds a C example against the library.
build_c() { # build_c <source.c> <out>
    cc -I include "$1" -L "$BIN" -lHkdfGuardKeyProtectionLinux -o "$2"
}

# ---------------------------------------------------------------------
# Reboot persistence: the one thing swtpm can only approximate
# ---------------------------------------------------------------------
if [ "$MODE" = "reboot" ]; then
    STATE="${HKDFGUARD_NATIVE_TEST_STATE:-${XDG_STATE_HOME:-$HOME/.local/state}/hkdfguard-native-tpm-test}"
    SERVICE="com.hkdfguard.nativetest.reboot"
    # The secret must be identical before and after the reboot, or the key
    # can't be re-derived: keep it with the rest of the captured state.
    SECRET="${SECRET:-$STATE/tpm.derivation-secret}"
    use_policy $'[selection]\nmode = "require"\nprovider = "tpm2"'

    section "build (--features tpm2)"
    cargo build --features tpm2
    build_c examples/cli_unwrap_check.c "$WORK/cli_unwrap_check"

    case "$PHASE" in
        capture)
            section "reboot capture -> $STATE"
            mkdir -p "$STATE"; chmod 700 "$STATE"
            [ -f "$SECRET" ] || ( umask 077; head -c 32 /dev/urandom > "$SECRET" )
            ( umask 077; head -c 32 /dev/urandom > "$STATE/dek.bin" )
            HKDFGUARD_PIN_SERVICE="$SERVICE" learn print_service_key_name_for_pinning SERVICE_KEY_NAME > "$STATE/service-name.hex"
            [ -s "$STATE/service-name.hex" ] || { echo "could not learn the service key Name" >&2; exit 1; }
            # On a TPM the KEK is derived on demand, so `provision` reports
            # it as already present; it is still the one command that makes
            # the setup calls, so run it as a real deployment would.
            "$BIN"/hkdfguard-v1-initialize provision --service-name "$SERVICE"
            base64 -w0 < "$STATE/dek.bin" | "$BIN"/hkdfguard-v1-initialize wrap \
                --key-file-path "$STATE/wrapped.key" --service-name "$SERVICE" --dek-stdin --force
            note "service key Name: $(cat "$STATE/service-name.hex")"
            note "wrapped DEK saved. Now REBOOT this machine, then run: scripts/native-tpm-test.sh reboot verify"
            note "derivation secret: $SECRET -- verify must use the same one"
            exit 0
            ;;
        verify)
            section "reboot verify <- $STATE"
            [ -f "$STATE/wrapped.key" ] || { echo "no captured state in $STATE; run 'reboot capture' first" >&2; exit 1; }
            [ -f "$SECRET" ] \
                || { echo "derivation secret $SECRET is missing; capture's secret is needed to re-derive the key" >&2; exit 1; }
            before=$(cat "$STATE/service-name.hex")
            after=$(HKDFGUARD_PIN_SERVICE="$SERVICE" learn print_service_key_name_for_pinning SERVICE_KEY_NAME)
            if [ "$before" != "$after" ]; then
                echo "FAIL: service key Name changed across the reboot ($before -> $after): the TPM did not re-derive the same KEK" >&2
                exit 1
            fi
            note "service key Name identical across reboot: $after"
            LD_LIBRARY_PATH="$BIN" "$WORK/cli_unwrap_check" "$STATE/wrapped.key" "$SERVICE" "$STATE/dek.bin"
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
use_base_policy

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
section "conformance suite again under a second, different derivation secret"
FIRST_SECRET="$SECRET"
SECRET="$WORK/tpm.derivation-secret.2"
( umask 077; head -c 32 /dev/urandom > "$SECRET" )
use_base_policy
cargo test --features tpm2 -- --ignored --test-threads=1 "${SKIP[@]}"
note "a different secret changed every service key; the suite still passed"
SECRET="$FIRST_SECRET"
use_base_policy

# ---------------------------------------------------------------------
# 6. Learn pins from the TPM, write a `required` policy
# ---------------------------------------------------------------------
section "learning Names to pin (session salt key, and the example service key)"
SALT_NAME=$(learn print_session_salt_key_name_for_pinning SALT_KEY_NAME)
SVC_NAME=$(HKDFGUARD_PIN_SERVICE=com.company.orders learn print_service_key_name_for_pinning SERVICE_KEY_NAME)
[ -n "$SALT_NAME" ] && [ -n "$SVC_NAME" ] || { echo "could not learn the Names to pin" >&2; exit 1; }
note "salt key Name:      $SALT_NAME"
note "service key Name:   $SVC_NAME (com.company.orders)"
REQUIRED_SELECTION=$'[selection]\nmode = "require"\nprovider = "tpm2"'
REQUIRED_TPM_KEYS="session_encryption = \"required\"
pinned_session_salt_key_name = \"$SALT_NAME\""
REQUIRED_PINS="[tpm.pinned_names]
\"com.company.orders\" = \"$SVC_NAME\""
note "with this machine's real derivation-secret path in place of the scratch one, this is what a"
note "hardened deployment on THIS machine would install at /etc/hkdfguard/policy.toml:"
policy "$REQUIRED_SELECTION" "$REQUIRED_TPM_KEYS" "$REQUIRED_PINS" | sed 's/^/     /'

# ---------------------------------------------------------------------
# 7. C ABI round trip on the TPM, under both policies
# ---------------------------------------------------------------------
section "cargo build --features tpm2 (the .so and CLI the C examples load)"
cargo build --features tpm2
build_c examples/wrap_unwrap.c "$WORK/wrap_unwrap"
build_c examples/cli_unwrap_check.c "$WORK/cli_unwrap_check"

section "C ABI round trip (examples/wrap_unwrap.c) -- KEK on the TPM, policy: require tpm2, session_encryption auto"
use_policy $'[selection]\nmode = "require"\nprovider = "tpm2"'
LD_LIBRARY_PATH="$BIN" "$WORK/wrap_unwrap"

section "C ABI round trip -- policy: session_encryption REQUIRED with both Names pinned"
use_policy "$REQUIRED_SELECTION" "$REQUIRED_TPM_KEYS" "$REQUIRED_PINS"
LD_LIBRARY_PATH="$BIN" "$WORK/wrap_unwrap"
note "every ECDH in that run went through a salted, AES-128-CFB-encrypted session against a pinned salt key"

# ---------------------------------------------------------------------
# 8. CLI -> separate C consumer, across processes, on the TPM
# ---------------------------------------------------------------------
section "hkdfguard-v1-initialize (stdin) -> cli_unwrap_check via the .so, KEK on the TPM"
CLI_SERVICE=com.hkdfguard.nativetest.cli
( umask 077; head -c 32 /dev/urandom > "$WORK/dek.bin" )
"$BIN"/hkdfguard-v1-initialize provision --service-name "$CLI_SERVICE"
base64 -w0 < "$WORK/dek.bin" | "$BIN"/hkdfguard-v1-initialize wrap \
    --key-file-path "$WORK/wrapped.key" --service-name "$CLI_SERVICE" --dek-stdin --force
LD_LIBRARY_PATH="$BIN" "$WORK/cli_unwrap_check" "$WORK/wrapped.key" "$CLI_SERVICE" "$WORK/dek.bin"
use_base_policy

# ---------------------------------------------------------------------
# 9. Optional PKCS#11
# ---------------------------------------------------------------------
if [ "$HAVE_SOFTHSM" -eq 1 ]; then
    section "cargo test --features pkcs11 -- --ignored (against the SoftHSM2 token in the policy)"
    cargo test --features pkcs11 -- --ignored --test-threads=1
else
    section "pkcs11 suite skipped (SoftHSM2 not installed)"
fi

section "ALL NATIVE CHECKS PASSED on $MANUFACTURER via $TCTI"
echo "To also prove persistence across a real reboot:"
echo "  scripts/native-tpm-test.sh reboot capture   # then reboot"
echo "  scripts/native-tpm-test.sh reboot verify"
