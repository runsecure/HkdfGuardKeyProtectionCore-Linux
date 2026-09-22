#!/usr/bin/env bash
# Builds the release library and names its dynamic-library output
# HkdfGuard.Kms.Linux.v1 - matching the HkdfGuard.Kms.<platform>.v1 naming
# convention this project's Windows (CMake OUTPUT_NAME) and macOS (Xcode
# PRODUCT_NAME) builds apply natively as part of their own build systems.
#
# Cargo can't produce this name directly: crate names (and therefore [lib]
# name in Cargo.toml) can't contain dots, so `cargo build` always produces
# libHkdfGuardKeyProtectionLinux.{so,dylib,a} regardless. This script does
# the one thing those other two platforms' build systems do natively - a
# copy to the project's actual release name - right after the real build,
# so that name is a repeatable build output rather than a one-off manual
# command. Only the dynamic library is renamed; the static archive
# (libHkdfGuardKeyProtectionLinux.a) keeps its Cargo-derived name, since
# nothing in this project links against it by the HkdfGuard.Kms.* name.
#
# Usage: scripts/build-release.sh
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --release

# Only the *host-native* dynamic-library extension is renamed - never both.
# target/release can end up holding a stale artifact from an unrelated
# build (e.g. a real Linux .so left over from a container/CI run, sitting
# alongside a .dylib this same directory's macOS host just produced); a
# blind `for ext in so dylib` loop would happily rename that foreign, stale
# file too, silently handing out a HkdfGuard.Kms.Linux.v1.so that doesn't
# match the source this script just built. Renaming only the extension
# `cargo build` on *this* host could actually have just produced avoids
# that entirely.
case "$(uname -s)" in
    Linux)  ext=so ;;
    Darwin) ext=dylib ;;
    *) echo "error: unsupported host platform $(uname -s)" >&2; exit 1 ;;
esac

src="target/release/libHkdfGuardKeyProtectionLinux.$ext"
dst="target/release/HkdfGuard.Kms.Linux.v1.$ext"
if [ ! -f "$src" ]; then
    echo "error: expected build output missing: $src" >&2
    exit 1
fi
cp "$src" "$dst"
echo "-> $dst"
