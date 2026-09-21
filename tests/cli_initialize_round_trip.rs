//! Integration test for the `hkdfguard-v1-initialize` CLI tool
//! (`src/bin/hkdfguard-v1-initialize.rs`): runs it as a real, separate
//! process to wrap a DEK to a file, then loads this crate as a library (in
//! *this* process) and confirms `hkdfguard_unwrap_dek` recovers exactly the
//! DEK that was fed in on the command line. Deliberately spans two
//! processes -- the CLI's wrap and this test's unwrap -- rather than
//! calling the library twice in one process, so it also exercises the
//! software provider's on-disk KEK persistence, not just its in-memory
//! behavior within a single run.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serial_test::serial;
use std::ffi::CString;
use std::fs;
use std::os::raw::c_int;
use std::process::Command;
use tempfile::tempdir;
use HkdfGuardKeyProtectionLinux::{hkdfguard_unwrap_dek, status};

// Points the software provider at a fresh temp directory and disables the
// external-secret provider, matching the isolation pattern this crate's own
// FFI tests use -- deterministic, and doesn't touch any real host KEK
// storage. Critically, this also keeps the wrap from silently falling back
// to the Ephemeral provider (in-memory only, scoped to a single process),
// which would make a cross-process round trip like this one fail even
// though the CLI itself worked correctly.
fn with_isolated_software_provider<F: FnOnce()>(f: F) {
    let dir = tempdir().unwrap();
    std::env::set_var("HKDFGUARD_SOFTWARE_DIR", dir.path());
    std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", "/nonexistent-for-tests");
    f();
    std::env::remove_var("HKDFGUARD_SOFTWARE_DIR");
    std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
}

#[test]
#[serial]
fn cli_wrapped_dek_unwraps_to_original_input() {
    with_isolated_software_provider(|| {
        let original_dek: [u8; 32] = core::array::from_fn(|i| i as u8);
        let dek_b64 = STANDARD.encode(original_dek);

        let out_dir = tempdir().unwrap();
        let key_path = out_dir.path().join("wrapped.key");

        let output = Command::new(env!("CARGO_BIN_EXE_hkdfguard-v1-initialize"))
            .arg(&key_path)
            .args(["--material-identifier", "5"])
            .args(["--service-name", "com.example.orders"])
            .args(["--dek", &dek_b64])
            .output()
            .expect("failed to run hkdfguard-v1-initialize");

        assert!(
            output.status.success(),
            "CLI failed (status {:?}): stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let wrapped = fs::read(&key_path).expect("wrapped key file should exist");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o640, "wrapped key file must be written with mode 0640");
        }

        // Exactly the composition rule the CLI applies internally:
        // <service-name>.<material-identifier>.
        let service = CString::new("com.example.orders.5").unwrap();
        let mut recovered = [0u8; 32];
        let mut recovered_len: c_int = recovered.len() as c_int;
        let rc = hkdfguard_unwrap_dek(
            service.as_ptr(),
            wrapped.as_ptr(),
            wrapped.len() as c_int,
            recovered.as_mut_ptr(),
            &mut recovered_len,
        );

        assert_eq!(rc, status::OK, "hkdfguard_unwrap_dek failed with status {rc}");
        assert_eq!(recovered_len, 32);
        assert_eq!(recovered, original_dek, "unwrapped DEK must match the original --dek input");
    });
}

#[test]
#[serial]
fn cli_force_overwrite_secure_deletes_then_rewraps() {
    with_isolated_software_provider(|| {
        let out_dir = tempdir().unwrap();
        let key_path = out_dir.path().join("wrapped.key");

        let first_dek: [u8; 32] = core::array::from_fn(|i| i as u8);
        let run_cli = |dek: [u8; 32], extra_args: &[&str]| {
            let dek_b64 = STANDARD.encode(dek);
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_hkdfguard-v1-initialize"));
            cmd.arg(&key_path)
                .args(["--material-identifier", "9"])
                .args(["--service-name", "com.example.rotation"])
                .args(["--dek", &dek_b64])
                .args(extra_args);
            cmd.output().expect("failed to run hkdfguard-v1-initialize")
        };

        let first = run_cli(first_dek, &[]);
        assert!(first.status.success(), "initial write should succeed");

        let second_dek: [u8; 32] = core::array::from_fn(|i| 255 - i as u8);
        let second = run_cli(second_dek, &["--force"]);
        assert!(
            second.status.success(),
            "forced overwrite should succeed: stderr={}",
            String::from_utf8_lossy(&second.stderr)
        );

        // The file on disk must now unwrap to the *second* DEK, not the first.
        // (Whether the overwrite actually delete-and-recreated the file
        // rather than truncating it in place is covered separately by the
        // secure_delete unit tests in src/bin/hkdfguard-v1-initialize.rs --
        // inode number isn't a reliable signal for that here, since some
        // filesystems immediately reuse a just-freed inode for a new file.)
        let wrapped = fs::read(&key_path).unwrap();
        let service = CString::new("com.example.rotation.9").unwrap();
        let mut recovered = [0u8; 32];
        let mut recovered_len: c_int = recovered.len() as c_int;
        let rc = hkdfguard_unwrap_dek(
            service.as_ptr(),
            wrapped.as_ptr(),
            wrapped.len() as c_int,
            recovered.as_mut_ptr(),
            &mut recovered_len,
        );
        assert_eq!(rc, status::OK);
        assert_eq!(recovered, second_dek, "file must contain the second wrap, not the first");
    });
}

#[test]
#[serial]
fn cli_rejects_pre_existing_file_without_force() {
    with_isolated_software_provider(|| {
        let dek_b64 = STANDARD.encode([0x42u8; 32]);
        let out_dir = tempdir().unwrap();
        let key_path = out_dir.path().join("wrapped.key");
        fs::write(&key_path, b"pre-existing content").unwrap();

        let output = Command::new(env!("CARGO_BIN_EXE_hkdfguard-v1-initialize"))
            .arg(&key_path)
            .args(["--material-identifier", "1"])
            .args(["--service-name", "com.example.billing"])
            .args(["--dek", &dek_b64])
            .output()
            .expect("failed to run hkdfguard-v1-initialize");

        assert!(!output.status.success(), "CLI should refuse to overwrite an existing file");
        assert_eq!(
            fs::read(&key_path).unwrap(),
            b"pre-existing content",
            "existing file must be left untouched without --force"
        );
    });
}
