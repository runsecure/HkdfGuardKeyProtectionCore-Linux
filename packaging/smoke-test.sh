#!/usr/bin/env bash
# Installs the built packages into a clean Debian 13 or EL10 container --
# the plain base image, not the build image, so a missing runtime
# dependency can't be masked by build tools -- and uses them as a consumer
# would: dynamic and static linking through pkg-config, dlopen by the
# HkdfGuard.Kms.Linux.v1 name, and the CLI's provision/wrap output
# unwrapped through the installed library.
#
# There is no TPM or PKCS#11 module in the container, so with no policy
# file the external-secret provider serves every call, as it does in
# docker/entrypoint-test.sh.
#
# Usage (as root, in the clean container; packaging/build-packages.sh
# runs it):
#   smoke-test.sh <package-dir> <examples-dir>
set -euo pipefail

section() { printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }

[ $# -eq 2 ] || { echo "usage: $0 <package-dir> <examples-dir>" >&2; exit 2; }
pkgs=$1
examples=$2
work=$(mktemp -d)

section "installing packages"
if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends gcc libc6-dev pkgconf \
        "$pkgs"/hkdfguard_*.deb "$pkgs"/libhkdfguard1_*.deb "$pkgs"/libhkdfguard-dev_*.deb
elif command -v dnf >/dev/null; then
    dnf -y install dnf-plugins-core
    dnf config-manager --set-enabled crb
    dnf -y install gcc pkgconf-pkg-config \
        $(find "$pkgs" -name '*.rpm' ! -name '*-debuginfo-*' ! -name '*-debugsource-*')
else
    echo "neither apt-get nor dnf found" >&2
    exit 1
fi

section "installed layout"
[ "$(stat -c '%U:%G %a' /etc/hkdfguard)" = "root:root 755" ] \
    || { echo "/etc/hkdfguard must be root:root 0755" >&2; exit 1; }
[ ! -e /etc/hkdfguard/policy.toml ] || { echo "packages must not install a policy" >&2; exit 1; }
libdir=$(pkg-config --variable=libdir hkdfguard)
ls -l "$libdir"/libhkdfguard* "$libdir"/HkdfGuard.Kms.Linux.v1.so
hkdfguard-v1-initialize --help

section "external secrets for the test services (root's mount, as a platform's would be)"
install -d -m 0755 /run/secrets/hkdfguard
for service in com.company.orders com.company.cli; do
    install -m 0600 /dev/null "/run/secrets/hkdfguard/$service"
    head -c 32 /dev/urandom > "/run/secrets/hkdfguard/$service"
done

section "dynamic link via pkg-config"
# shellcheck disable=SC2046 # pkg-config output is a list of flags
cc -o "$work/wrap_unwrap" "$examples/wrap_unwrap.c" $(pkg-config --cflags --libs hkdfguard)
ldd "$work/wrap_unwrap" | grep -F "libhkdfguard.so.1 => $libdir/libhkdfguard.so.1"
"$work/wrap_unwrap"

section "static link via pkg-config --static"
# shellcheck disable=SC2046
cc -o "$work/wrap_unwrap_static" "$examples/wrap_unwrap.c" $(pkg-config --cflags hkdfguard) \
    "$libdir/libhkdfguard.a" $(pkg-config --static --libs hkdfguard | sed 's/-lhkdfguard\b//')
if ldd "$work/wrap_unwrap_static" | grep -F libhkdfguard; then
    echo "static build still depends on the shared library" >&2
    exit 1
fi
"$work/wrap_unwrap_static"

section "dlopen(\"HkdfGuard.Kms.Linux.v1.so\")"
cat > "$work/dlopen_check.c" <<'C'
#include <dlfcn.h>
#include <stdio.h>
int main(void) {
    void* lib = dlopen("HkdfGuard.Kms.Linux.v1.so", RTLD_NOW);
    if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    if (!dlsym(lib, "hkdfguard_wrap_dek")) { fprintf(stderr, "dlsym: %s\n", dlerror()); return 1; }
    puts("HkdfGuard.Kms.Linux.v1.so loads and exports hkdfguard_wrap_dek");
    return 0;
}
C
cc -o "$work/dlopen_check" "$work/dlopen_check.c" -ldl
"$work/dlopen_check"

section "CLI provision + wrap, unwrapped through the installed library"
# shellcheck disable=SC2046
cc -o "$work/cli_unwrap_check" "$examples/cli_unwrap_check.c" $(pkg-config --cflags --libs hkdfguard)
install -m 0600 /dev/null "$work/dek.bin"
head -c 32 /dev/urandom > "$work/dek.bin"
hkdfguard-v1-initialize provision -sn com.company.cli
# base64 reads the DEK from stdin and writes it to a pipe: it never
# reaches an argument list.
base64 -w0 < "$work/dek.bin" | hkdfguard-v1-initialize wrap -kf "$work/wrapped.key" -sn com.company.cli --dek-stdin
"$work/cli_unwrap_check" "$work/wrapped.key" com.company.cli "$work/dek.bin"

section "SMOKE TEST PASSED"
