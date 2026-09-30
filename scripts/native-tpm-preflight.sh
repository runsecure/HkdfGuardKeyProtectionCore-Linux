#!/usr/bin/env bash
# Read-only environment check for testing hkdfguard's TPM2 provider on a
# native Linux machine with a real TPM (Intel PTT, AMD fTPM, or a discrete
# part). Reports what it finds, says what `tpm.session_encryption: auto`
# will decide on this hardware, and exits non-zero if a hard requirement
# is missing. Changes nothing.
#
# Usage: scripts/native-tpm-preflight.sh
#
# Environment:
#   HKDFGUARD_TCTI   override the TCTI to test with (default: the first of
#                    device:/dev/tpmrm0, device:/dev/tpm0 that exists)
set -euo pipefail

ok()   { printf '  \033[32mok\033[0m    %s\n' "$*"; }
warn() { printf '  \033[33mwarn\033[0m  %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAILED=1; }
FAILED=0

echo "== hkdfguard native TPM preflight =="

# ---- OS ----
if [ "$(uname -s)" != "Linux" ]; then
    fail "this must run on Linux ($(uname -s) detected); the tpm2 feature does not build elsewhere"
    exit 1
fi
ok "Linux $(uname -r)"

# ---- TPM device ----
TCTI="${HKDFGUARD_TCTI:-}"
if [ -z "$TCTI" ]; then
    if [ -e /dev/tpmrm0 ]; then
        TCTI="device:/dev/tpmrm0"
    elif [ -e /dev/tpm0 ]; then
        TCTI="device:/dev/tpm0"
        warn "/dev/tpmrm0 (kernel resource manager) not present; falling back to /dev/tpm0, which cannot be shared with other TPM users"
    fi
fi
if [ -z "$TCTI" ]; then
    fail "no TPM device found (/dev/tpmrm0 or /dev/tpm0). Enable the TPM/fTPM in firmware, and check 'dmesg | grep -i tpm'"
else
    ok "TCTI: $TCTI"
    dev="${TCTI#device:}"
    if [ "$dev" != "$TCTI" ] && [ -e "$dev" ]; then
        if [ -r "$dev" ] && [ -w "$dev" ]; then
            ok "$dev is readable and writable by $(id -un)"
        else
            fail "$dev is not accessible by $(id -un) (owner $(stat -c '%U:%G %a' "$dev")). Add this user to the 'tss' group (then log in again), or run as root"
        fi
    fi
fi

# ---- tss group membership ----
# The udev rules shipped by tpm2-tools/libtss2-dev typically grant rw on
# /dev/tpm* to group 'tss' rather than the world, so this is the intended
# way to reach the device without root. `usermod -aG` only takes effect on
# the next login, so a user just added to the group won't see it in their
# *current* session's group list yet -- check both to catch that case.
if getent group tss >/dev/null 2>&1; then
    if id -nG | tr ' ' '\n' | grep -qx tss; then
        ok "user $(id -un) is in the 'tss' group (active in this session)"
    elif getent group tss | cut -d: -f4 | tr ',' '\n' | grep -qx "$(id -un)"; then
        warn "$(id -un) is in the 'tss' group in /etc/group, but this session predates it; log out and back in (or run 'newgrp tss') for it to take effect"
    else
        warn "$(id -un) is not in the 'tss' group; if the TPM device isn't otherwise accessible, run 'sudo usermod -aG tss $(id -un)' and log in again"
    fi
else
    warn "no 'tss' group on this system; TPM device access will rely on other permissions (e.g. running as root)"
fi

# ---- tpm2-tools ----
if command -v tpm2_getcap >/dev/null 2>&1; then
    ok "tpm2-tools: $(tpm2_getcap --version 2>/dev/null | head -n1 || echo present)"
else
    fail "tpm2-tools not found (needed to identify the TPM; install 'tpm2-tools')"
fi

# ---- identify the TPM ----
MANUFACTURER=""
if [ -n "$TCTI" ] && command -v tpm2_getcap >/dev/null 2>&1 && [ "$FAILED" -eq 0 ]; then
    if props=$(tpm2_getcap -T "$TCTI" properties-fixed 2>/dev/null); then
        # Output is YAML; TPM2_PT_MANUFACTURER's `value:` is the 4-char vendor id.
        MANUFACTURER=$(printf '%s\n' "$props" | awk '/TPM2_PT_MANUFACTURER/{f=1} f && /value:/{gsub(/"/,"",$2); print $2; exit}')
        vendor=$(printf '%s\n' "$props" | awk '/TPM2_PT_VENDOR_STRING_[1-4]/{f=1} f && /value:/{gsub(/"/,"",$2); printf "%s", $2; f=0}')
        fw=$(printf '%s\n' "$props" | awk '/TPM2_PT_FIRMWARE_VERSION_1/{f=1} f && /raw:/{print $2; exit}')
        ok "TPM manufacturer: ${MANUFACTURER:-unknown}${vendor:+ ($vendor)}${fw:+, firmware $fw}"
        case "${MANUFACTURER}" in
            INTC|AMD|QCOM)
                ok "firmware TPM (inside the SoC): no external bus to probe -> 'tpm.session_encryption: auto' will SKIP parameter encryption here"
                ;;
            MSFT|IBM|GOOG|VMW)
                ok "virtual/software TPM: no external bus -> 'auto' will SKIP parameter encryption"
                ;;
            IFX|STM|NTC|ATML|NSM|NSG|SMSC)
                ok "discrete TPM chip: 'auto' will ENCRYPT ECDH sessions (salted HMAC, AES-128-CFB). Pin the salt key Name for full protection -- see README"
                warn "one conformance test assumes an fTPM and will be skipped by native-tpm-test.sh on this hardware"
                ;;
            "")
                warn "could not read the manufacturer; 'auto' treats unknown as discrete and encrypts"
                ;;
            *)
                warn "unrecognized manufacturer '$MANUFACTURER'; 'auto' treats unknown as discrete and encrypts"
                ;;
        esac
    else
        fail "tpm2_getcap could not talk to the TPM via $TCTI (device busy, no access, or TPM disabled)"
    fi
fi

# ---- build toolchain ----
if command -v cargo >/dev/null 2>&1; then
    ok "cargo $(cargo --version | awk '{print $2}')"
else
    fail "cargo not found (install Rust via rustup)"
fi
if command -v cc >/dev/null 2>&1; then
    ok "cc: $(cc --version 2>/dev/null | head -n1)"
else
    fail "no C compiler (needed for the C ABI examples; install gcc or clang)"
fi
if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists tss2-esys 2>/dev/null; then
    ok "libtss2-esys $(pkg-config --modversion tss2-esys) (tss-esapi-sys links against this)"
else
    fail "libtss2-esys development files not found (Debian/Ubuntu: libtss2-dev; Fedora: tpm2-tss-devel). The tpm2 feature cannot build without them"
    fail "if you have installed, please also verify the pkg-config package is installed (pkgconf)"
fi

# ---- optional: PKCS#11 ----
# Tested on output, not pipeline status: under pipefail an early-exiting
# consumer would make `find` look like it failed even on a hit.
if [ -n "$(find /usr/lib /usr/lib64 /usr/local/lib -iname 'libsofthsm2.so' 2>/dev/null | head -n1 || true)" ]; then
    ok "SoftHSM2 present: native-tpm-test.sh will also run the pkcs11 suite"
else
    warn "SoftHSM2 not present: the pkcs11 suite will be skipped (optional; install 'softhsm2' to include it)"
fi

echo
if [ "$FAILED" -ne 0 ]; then
    echo "Preflight FAILED: fix the items above, then run scripts/native-tpm-test.sh" >&2
    exit 1
fi
echo "Preflight passed. Run: scripts/native-tpm-test.sh"
# Exported for callers that source this script.
export HKDFGUARD_PREFLIGHT_TCTI="$TCTI"
export HKDFGUARD_PREFLIGHT_MANUFACTURER="$MANUFACTURER"
