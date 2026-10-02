#!/usr/bin/env bash
# Fails unless Cargo.toml, debian/changelog and the RPM spec (Version and
# newest %changelog entry) carry the same version -- and, given a release
# tag such as v0.1.0, unless the tag names it too.
#
# Releasing a new version means bumping all three together: `version` in
# Cargo.toml, a new top entry in debian/changelog, and Version plus a new
# %changelog entry in packaging/rpm/hkdfguard.spec.
#
# Usage: packaging/check-version.sh [tag]
set -euo pipefail
cd "$(dirname "$0")/.."

cargo_v=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
deb_v=$(sed -n '1s/^hkdfguard (\([^)-]*\)-[^)]*).*/\1/p' debian/changelog)
rpm_v=$(sed -n 's/^Version:[[:space:]]*//p' packaging/rpm/hkdfguard.spec)
rpm_log_v=$(sed -n '/^%changelog/,$ s/^\*.* - \([^-]*\)-[^-]*$/\1/p' packaging/rpm/hkdfguard.spec | head -n 1)

status=0
check() {
    if [ "$2" != "$cargo_v" ]; then
        echo "error: $1 has version '$2', Cargo.toml has '$cargo_v'" >&2
        status=1
    fi
}
check debian/changelog "$deb_v"
check "packaging/rpm/hkdfguard.spec Version" "$rpm_v"
check "packaging/rpm/hkdfguard.spec %changelog" "$rpm_log_v"
[ $# -eq 0 ] || check "tag $1" "${1#v}"
[ $status -eq 0 ] && echo "version $cargo_v is consistent"
exit $status
