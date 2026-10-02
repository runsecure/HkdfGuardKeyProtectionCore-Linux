#!/usr/bin/env bash
# Builds the .deb packages inside the image from packaging/Dockerfile.debian
# and copies them into /dist -- bind-mount a host directory there (see
# packaging/build-packages.sh, which does this).
#
# The container starts as root only to collect into /dist; fetching,
# building, testing and lintian run as the unprivileged `builder`.
set -euo pipefail

section() { printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }

[ "$(id -u)" -eq 0 ] || { echo "build-deb.sh starts as root and drops to builder itself" >&2; exit 1; }
as_builder() { setpriv --reuid=builder --regid=builder --init-groups env HOME=/home/builder USER=builder LOGNAME=builder "$@"; }

section "version consistency"
packaging/check-version.sh

section "cargo fetch (the package build itself runs offline)"
as_builder cargo fetch --locked

section "dpkg-buildpackage (build, test, package)"
as_builder dpkg-buildpackage --build=binary --no-sign

section "lintian"
as_builder lintian --fail-on error --info --display-info ../hkdfguard_*.changes

section "collecting packages into /dist"
mkdir -p /dist
cp ../*.deb ../*.buildinfo ../*.changes /dist/
ls -la /dist
