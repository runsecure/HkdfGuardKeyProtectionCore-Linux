// Gives the Linux shared library an ELF SONAME, so programs linked against
// it record `libhkdfguard.so.1` as their dependency rather than whatever
// file name they happened to link (Cargo's libHkdfGuardKeyProtectionLinux.so).
// The packages install the library under exactly that name, and dpkg/rpm
// derive the library's dependency metadata from it.
//
// The `.1` is the C ABI's major version (include/hkdfguard.h): bump it, and
// the packages' library names (debian/control, packaging/rpm/hkdfguard.spec),
// only for an incompatible ABI change -- a removed or changed function,
// status code, or payload format. Additions don't bump it.
//
// A program linked against target/release directly therefore needs a
// `libhkdfguard.so.1` next to the .so at run time; scripts/build-release.sh
// and the test scripts create that symlink.

const SONAME: &str = "libhkdfguard.so.1";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,{SONAME}");
    }
}
