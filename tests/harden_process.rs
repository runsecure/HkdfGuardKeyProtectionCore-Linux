//! `hkdfguard_harden_process` changes process-wide state (core limit,
//! dumpable flag), so it gets its own test binary -- its own process --
//! rather than running inside the shared unit-test process.

use hkdfguard_v1::{hkdfguard_harden_process, status};

// Only this user can write to it, whatever the umask: the library refuses
// to trust a policy or secret mount in a group-writable directory.
#[cfg(hkdfguard_test_paths)]
fn private_tempdir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new().permissions(std::fs::Permissions::from_mode(0o700)).tempdir().unwrap()
}

#[test]
fn hardening_takes_effect_and_the_library_still_works_afterwards() {
    assert_eq!(hkdfguard_harden_process(), status::OK);
    assert_eq!(hkdfguard_harden_process(), status::OK, "must be idempotent");

    let mut limit = libc::rlimit { rlim_cur: 1, rlim_max: 1 };
    // SAFETY: getrlimit writes into a valid rlimit.
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
    assert_eq!((limit.rlim_cur, limit.rlim_max), (0, 0), "core dumps must be disabled, hard limit included");

    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_GET_DUMPABLE takes no further arguments.
        let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
        assert_eq!(dumpable, 0, "the process must be non-dumpable");
    }

    // The rest needs this process's library to read the test's own policy,
    // which only a `--cfg hkdfguard_test_paths` build does (the test scripts
    // set it); a plain `cargo test` checks the hardening above only.
    #[cfg(hkdfguard_test_paths)]
    {
        use std::ffi::CString;
        use std::os::raw::c_int;
        use std::os::unix::fs::PermissionsExt;
        use hkdfguard_v1::{hkdfguard_unwrap_dek, hkdfguard_wrap_dek};

        // A non-dumpable process loses some /proc/<pid> access. The
        // external-secret provider re-checks an opened descriptor through
        // /proc/self/fd, so prove a full wrap/unwrap through it still works.
        let mount = private_tempdir();
        let service = "com.company.hardened";
        let key_path = mount.path().join(service);
        std::fs::write(&key_path, p256::SecretKey::random(&mut rand_core::OsRng).to_bytes()).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let policy_dir = private_tempdir();
        let policy = policy_dir.path().join("policy.toml");
        std::fs::write(
            &policy,
            format!(
                "[selection]\nmode = \"require\"\nprovider = \"external-secret\"\n[external_secret]\ndir = \"{}\"\n",
                mount.path().display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::env::set_var("HKDFGUARD_POLICY_FILE", &policy);

        let c_service = CString::new(service).unwrap();
        let dek = [0x5Au8; 32];
        let mut wrapped = [0u8; 512];
        let mut wrapped_len = wrapped.len() as c_int;
        assert_eq!(
            hkdfguard_wrap_dek(c_service.as_ptr(), dek.as_ptr(), 32, wrapped.as_mut_ptr(), &mut wrapped_len),
            status::OK
        );
        let mut out = [0u8; 32];
        let mut out_len = out.len() as c_int;
        assert_eq!(
            hkdfguard_unwrap_dek(c_service.as_ptr(), wrapped.as_ptr(), wrapped_len, out.as_mut_ptr(), &mut out_len),
            status::OK
        );
        assert_eq!(out, dek);
    }
}
