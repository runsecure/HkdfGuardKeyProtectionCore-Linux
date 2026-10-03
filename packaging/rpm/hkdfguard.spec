# Built by packaging/build-rpm.sh inside packaging/Dockerfile.el10, with
# the rustup toolchain pinned in rust-toolchain.toml on PATH (EL10's own
# rust is older) and dependency sources fetched beforehand with
# `cargo fetch --locked`, so the build itself runs offline.

# The library and CLI link Rust crates statically. Their notices ship in
# THIRD-PARTY-LICENSES.txt; `packaging/third-party-licenses.py --licenses`
# lists their license expressions, which this must cover.
%global linked_licenses Apache-2.0 AND BSD-3-Clause AND ISC AND MIT AND (Apache-2.0 OR MIT) AND (MIT OR Unlicense)

Name:           hkdfguard
Version:        0.1.0
Release:        1%{?dist}
Summary:        DEK wrapping under a TPM2, PKCS#11 or external-secret KEK (CLI)
License:        %{linked_licenses}
URL:            https://github.com/torinblair/KeyProtectionCore-Linux
Source0:        %{name}-%{version}.tar.gz

# tss-esapi-sys ships pregenerated bindings for these Linux targets only.
ExclusiveArch:  x86_64 aarch64

BuildRequires:  gcc
BuildRequires:  python3
BuildRequires:  pkgconfig(tss2-esys) >= 4.0
BuildRequires:  pkgconfig(tss2-mu)
BuildRequires:  pkgconfig(tss2-sys)
BuildRequires:  pkgconfig(tss2-tctildr)

# The CLI links the library code statically, but reads the same policy:
# keep the two at the same version.
Requires:       %{name}-libs%{?_isa} = %{version}-%{release}

%global common_description %{expand:
HKDFGuard wraps 32-byte Data Encryption Keys (DEKs) under a persistent,
per-service Key Encryption Key (KEK) held by the strongest provider the
host offers: a TPM 2.0, a PKCS#11 token, or an administrator-provisioned
secret file. Wrapping is ECDH (P-256) against a per-payload point,
HKDF-SHA512 and AES-256-GCM.}

%description %{common_description}

This package contains hkdfguard-v1-initialize, which provisions a
service's KEK and wraps DEKs under it at deployment time.

%package libs
Summary:        DEK wrapping under a TPM2, PKCS#11 or external-secret KEK
License:        %{linked_licenses}

%description libs %{common_description}

Provider selection is controlled by the root-owned policy file
/etc/hkdfguard/policy.toml, which this package does not create.

This package contains the shared library.

%package devel
Summary:        Development files for HKDFGuard
License:        Apache-2.0
Requires:       %{name}-libs%{?_isa} = %{version}-%{release}
# hkdfguard.pc's Requires.private names the tss2 modules.
Requires:       tpm2-tss-devel%{?_isa}

%description devel %{common_description}

This package contains the C header and the pkg-config file.

%package static
Summary:        Static library for HKDFGuard
License:        %{linked_licenses}
Requires:       %{name}-devel%{?_isa} = %{version}-%{release}

%description static %{common_description}

This package contains the static library.

%prep
%autosetup

%build
# Keep debug info for the -debuginfo packages; Cargo.toml's release
# profile strips it, which suits the tarball release.
export CARGO_PROFILE_RELEASE_STRIP=false
export CARGO_PROFILE_RELEASE_DEBUG=line-tables-only
cargo build --locked --offline --release --all-features
python3 packaging/third-party-licenses.py target/THIRD-PARTY-LICENSES.txt

%install
# The library goes in under its SONAME (see build.rs), not Cargo's name.
install -D -m 0755 target/release/libhkdfguard_v1.so %{buildroot}%{_libdir}/libhkdfguard.so.1
ln -s libhkdfguard.so.1 %{buildroot}%{_libdir}/libhkdfguard.so
# HkdfGuard.Kms.<platform>.v1 is the library's name on every platform;
# consumers that load it by that name at run time need it here.
ln -s libhkdfguard.so.1 %{buildroot}%{_libdir}/HkdfGuard.Kms.Linux.v1.so
install -D -m 0644 target/release/libhkdfguard_v1.a %{buildroot}%{_libdir}/libhkdfguard.a
install -D -m 0644 include/hkdfguard.h %{buildroot}%{_includedir}/hkdfguard.h
install -d %{buildroot}%{_libdir}/pkgconfig
sed -e 's|@LIBDIR@|%{_libdir}|' -e 's|@VERSION@|%{version}|' \
    packaging/hkdfguard.pc.in > %{buildroot}%{_libdir}/pkgconfig/hkdfguard.pc
install -D -m 0755 target/release/hkdfguard-v1-initialize %{buildroot}%{_bindir}/hkdfguard-v1-initialize
install -D -m 0644 packaging/hkdfguard-v1-initialize.1 %{buildroot}%{_mandir}/man1/hkdfguard-v1-initialize.1
install -d -m 0755 %{buildroot}%{_sysconfdir}/hkdfguard

%check
cargo test --locked --offline
cargo test --locked --offline --all-features

%files
%license LICENSE
%{_bindir}/hkdfguard-v1-initialize
%{_mandir}/man1/hkdfguard-v1-initialize.1*

%files libs
%license LICENSE target/THIRD-PARTY-LICENSES.txt
%doc README.md
%{_libdir}/libhkdfguard.so.1
%{_libdir}/HkdfGuard.Kms.Linux.v1.so
%dir %{_sysconfdir}/hkdfguard

%files devel
%{_includedir}/hkdfguard.h
%{_libdir}/libhkdfguard.so
%{_libdir}/pkgconfig/hkdfguard.pc

%files static
%{_libdir}/libhkdfguard.a

%changelog
* Fri Oct 02 2026 runsecure <torin@torinblair.com> - 0.1.0-1
- Initial packaging.
