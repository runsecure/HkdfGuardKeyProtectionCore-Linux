#!/usr/bin/env bash
# Builds the .deb (Debian 13) and .rpm (EL10: RHEL, AlmaLinux, Rocky)
# packages for linux/amd64 and linux/arm64, each in its own container, then
# installs each set into a clean container of its distribution and runs
# packaging/smoke-test.sh against it. Packages land in
# dist/packages/<distro>-<arch>/.
#
# Each package build runs the default and all-features test suites
# (dh_auto_test / %check) on its own distribution; the hardware-backed
# matrix (swtpm, SoftHSM2) stays in docker/run-tests.sh.
#
# The non-native architecture builds under QEMU emulation, as in
# docker/build-dist.sh, and is much slower. To build a subset:
#   DISTROS=debian ARCHES=amd64 packaging/build-packages.sh
#
# Usage: packaging/build-packages.sh
set -euo pipefail
cd "$(dirname "$0")/.."

DISTROS=${DISTROS:-"debian el10"}
ARCHES=${ARCHES:-"amd64 arm64"}

packaging/check-version.sh

BUILT_TAGS=()
cleanup() {
    for tag in "${BUILT_TAGS[@]}"; do
        docker rmi -f "$tag" >/dev/null 2>&1 || true
    done
}
trap cleanup EXIT

for distro in $DISTROS; do
    dockerfile="packaging/Dockerfile.$distro"
    [ -f "$dockerfile" ] || { echo "error: no $dockerfile" >&2; exit 1; }
    # The smoke test runs on the build image's own (digest-pinned) base.
    base_image=$(sed -n 's/^FROM[[:space:]]\{1,\}//p' "$dockerfile" | head -n 1)

    for arch in $ARCHES; do
        platform="linux/$arch"
        tag="hkdfguard-pkg-$distro-$arch"
        out_dir="dist/packages/$distro-$arch"

        echo
        echo "=== Building $distro packages for $platform ==="
        docker build --platform "$platform" -t "$tag" -f "$dockerfile" .
        BUILT_TAGS+=("$tag")

        rm -rf "$out_dir"
        mkdir -p "$out_dir"
        docker run --rm --platform "$platform" -v "$(pwd)/$out_dir:/dist" "$tag"

        echo
        echo "=== Smoke-testing $distro packages for $platform in a clean $base_image ==="
        docker run --rm --platform "$platform" \
            -v "$(pwd)/$out_dir:/packages:ro" \
            -v "$(pwd)/examples:/examples:ro" \
            -v "$(pwd)/packaging/smoke-test.sh:/smoke-test.sh:ro" \
            "$base_image" bash /smoke-test.sh /packages /examples
    done
done

echo
echo "Packages:"
find dist/packages -maxdepth 2 -type f \( -name '*.deb' -o -name '*.rpm' \) | sort
