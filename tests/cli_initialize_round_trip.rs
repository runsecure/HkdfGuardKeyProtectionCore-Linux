//! Integration test for the `hkdfguard-v1-initialize` CLI tool
//! (`src/bin/hkdfguard-v1-initialize.rs`): runs it as a real, separate
//! process to wrap a DEK to a file, then loads this crate as a library (in
//! *this* process) and confirms `hkdfguard_unwrap_dek` recovers exactly the
//! DEK that was fed to it. The DEK goes in on stdin (or via `--dek-file`),
//! never on the command line -- argv is readable by any process of the
//! same user via `/proc/<pid>/cmdline`. Deliberately spans two
//! processes -- the CLI's wrap and this test's unwrap -- rather than
//! calling the library twice in one process, so it also exercises a
//! genuinely persistent (not per-process, in-memory) KEK, not just
//! in-memory behavior within a single run.
//!
//! There is no software-backed (locally-generated, filesystem-encrypted-
//! at-rest) provider on this platform, so the persistent provider used
//! here is external-secret: each test pre-provisions its own service's
//! secret file into an isolated temp directory before invoking the CLI,
//! mimicking how a real deployment platform (Vault Agent, a Kubernetes
//! Secret, ...) would have already dropped the file before the app starts
//! -- external-secret never creates one itself.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use p256::SecretKey;
use rand_core::OsRng;
use serial_test::serial;
use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::os::raw::c_int;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use tempfile::tempdir;
use HkdfGuardKeyProtectionLinux::{hkdfguard_unwrap_dek, status};

// Points the external-secret provider at a fresh temp directory, isolated
// from any real host KEK storage, and pre-provisions a secret file for
// `service` inside it -- external-secret never creates one itself, so the
// CLI's own `hkdfguard_create_kek` call only succeeds because this is
// already here.
fn with_provisioned_external_secret<F: FnOnce()>(service: &str, f: F) {
    let dir = tempdir().unwrap();
    std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", dir.path());
    let secret_key = SecretKey::random(&mut OsRng);
    fs::write(dir.path().join(service), secret_key.to_bytes()).unwrap();
    f();
    std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
}

// Runs the CLI as a real subprocess with the base64 DEK written to its
// stdin, which is how a deployment pipeline is expected to supply it.
fn run_cli_stdin(
    key_path: &std::path::Path,
    service: &str,
    dek: &[u8; 32],
    extra_args: &[&str],
) -> std::process::Output {
    let dek_b64 = STANDARD.encode(dek);
    let mut child = Command::new(env!("CARGO_BIN_EXE_hkdfguard-v1-initialize"))
        .arg(key_path)
        .args(["--service-name", service])
        .arg("--dek-stdin")
        .args(extra_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn hkdfguard-v1-initialize");
    child
        .stdin
        .as_mut()
        .expect("stdin was piped")
        .write_all(dek_b64.as_bytes())
        .expect("failed to write the DEK to the CLI's stdin");
    drop(child.stdin.take()); // close stdin so the child sees EOF
    child
        .wait_with_output()
        .expect("failed to run hkdfguard-v1-initialize")
}

#[test]
#[serial]
fn cli_wrapped_dek_unwraps_to_original_input() {
    with_provisioned_external_secret("com.example.orders", || {
        let original_dek: [u8; 32] = core::array::from_fn(|i| i as u8);

        let out_dir = tempdir().unwrap();
        let key_path = out_dir.path().join("wrapped.key");

        let output = run_cli_stdin(&key_path, "com.example.orders", &original_dek, &[]);

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

        let service = CString::new("com.example.orders").unwrap();
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
        assert_eq!(recovered, original_dek, "unwrapped DEK must match the DEK fed in on stdin");
    });
}

#[test]
#[serial]
fn cli_force_overwrite_secure_deletes_then_rewraps() {
    with_provisioned_external_secret("com.example.rotation", || {
        let out_dir = tempdir().unwrap();
        let key_path = out_dir.path().join("wrapped.key");

        let first_dek: [u8; 32] = core::array::from_fn(|i| i as u8);
        let run_cli = |dek: [u8; 32], extra_args: &[&str]| {
            run_cli_stdin(&key_path, "com.example.rotation", &dek, extra_args)
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
        let service = CString::new("com.example.rotation").unwrap();
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
    // This scenario never reaches the KEK provider at all -- the CLI's
    // own pre-check refuses an existing output file before touching
    // create_kek/wrap -- so no external secret needs to be provisioned.
    let dir = tempdir().unwrap();
    std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", dir.path());

    let out_dir = tempdir().unwrap();
    let key_path = out_dir.path().join("wrapped.key");
    fs::write(&key_path, b"pre-existing content").unwrap();

    let output = run_cli_stdin(&key_path, "com.example.billing", &[0x42u8; 32], &[]);

    assert!(!output.status.success(), "CLI should refuse to overwrite an existing file");
    assert_eq!(
        fs::read(&key_path).unwrap(),
        b"pre-existing content",
        "existing file must be left untouched without --force"
    );

    std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
}

#[test]
#[serial]
fn cli_accepts_the_dek_from_a_file_and_refuses_it_on_the_command_line() {
    with_provisioned_external_secret("com.example.fileinput", || {
        let original_dek = [0x7Bu8; 32];
        let out_dir = tempdir().unwrap();
        let key_path = out_dir.path().join("wrapped.key");

        // A root-or-owner-only file, as a secret mount or a systemd
        // credential would provide. A trailing newline is tolerated, since
        // that is what `printf '%s\n'` and most editors produce.
        let dek_path = out_dir.path().join("dek.b64");
        fs::write(&dek_path, format!("{}\n", STANDARD.encode(original_dek))).unwrap();
        fs::set_permissions(&dek_path, fs::Permissions::from_mode(0o600)).unwrap();

        let output = Command::new(env!("CARGO_BIN_EXE_hkdfguard-v1-initialize"))
            .arg(&key_path)
            .args(["--service-name", "com.example.fileinput"])
            .args(["--dek-file", dek_path.to_str().unwrap()])
            .output()
            .expect("failed to run hkdfguard-v1-initialize");
        assert!(
            output.status.success(),
            "--dek-file should succeed (status {:?}): stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );

        // Round-trips through the library, exactly as the stdin path does.
        let wrapped = fs::read(&key_path).expect("wrapped key file should exist");
        let service = CString::new("com.example.fileinput").unwrap();
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
        assert_eq!(recovered, original_dek);

        // A group-readable DEK file is refused rather than used.
        let loose_path = out_dir.path().join("loose.b64");
        fs::write(&loose_path, STANDARD.encode(original_dek)).unwrap();
        fs::set_permissions(&loose_path, fs::Permissions::from_mode(0o644)).unwrap();
        let loose_key_path = out_dir.path().join("loose.key");
        let output = Command::new(env!("CARGO_BIN_EXE_hkdfguard-v1-initialize"))
            .arg(&loose_key_path)
            .args(["--service-name", "com.example.fileinput"])
            .args(["--dek-file", loose_path.to_str().unwrap()])
            .output()
            .expect("failed to run hkdfguard-v1-initialize");
        assert!(!output.status.success(), "a group-readable DEK file must be refused");
        assert!(!loose_key_path.exists(), "nothing should have been written");

        // And the retired argv form is rejected outright, with an error
        // that says why -- this is the whole point of the change.
        let argv_key_path = out_dir.path().join("argv.key");
        let output = Command::new(env!("CARGO_BIN_EXE_hkdfguard-v1-initialize"))
            .arg(&argv_key_path)
            .args(["--service-name", "com.example.fileinput"])
            .args(["--dek", &STANDARD.encode(original_dek)])
            .output()
            .expect("failed to run hkdfguard-v1-initialize");
        assert!(!output.status.success(), "--dek must no longer be accepted");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("cmdline"), "error should explain the exposure: {stderr}");
        assert!(!argv_key_path.exists(), "nothing should have been written");
    });
}
