#!/usr/bin/env bash
# Builds the .rpm packages inside the image from packaging/Dockerfile.el10
# and copies them into /dist -- bind-mount a host directory there (see
# packaging/build-packages.sh, which does this).
#
# The container starts as root only to collect into /dist; fetching,
# building and testing run as the unprivileged `builder`.
#
# Only binary RPMs are produced. A source RPM would not rebuild on its own:
# the build runs offline against crates fetched here, not ones it carries.
set -euo pipefail

section() { printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }

[ "$(id -u)" -eq 0 ] || { echo "build-rpm.sh starts as root and drops to builder itself" >&2; exit 1; }
as_builder() { setpriv --reuid=builder --regid=builder --init-groups env HOME=/home/builder USER=builder LOGNAME=builder "$@"; }

section "version consistency"
packaging/check-version.sh
version=$(sed -n 's/^Version:[[:space:]]*//p' packaging/rpm/hkdfguard.spec)

section "cargo fetch (the package build itself runs offline)"
as_builder cargo fetch --locked

section "source tarball"
as_builder mkdir -p /home/builder/rpmbuild/SOURCES
as_builder tar -C /build --exclude=hkdfguard/target \
    --transform "s,^hkdfguard,hkdfguard-$version," \
    -czf "/home/builder/rpmbuild/SOURCES/hkdfguard-$version.tar.gz" hkdfguard

section "rpmbuild (build, test, package)"
as_builder rpmbuild -bb packaging/rpm/hkdfguard.spec

section "collecting packages into /dist"
mkdir -p /dist
cp /home/builder/rpmbuild/RPMS/*/*.rpm /dist/
ls -la /dist
