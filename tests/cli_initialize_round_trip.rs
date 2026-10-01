//! Integration test for the `hkdfguard-v1-initialize` CLI tool
//! (`src/bin/hkdfguard-v1-initialize.rs`): runs it as a real, separate
//! process -- `provision` and then `wrap` -- then loads this crate as a
//! library (in *this* process) and confirms `hkdfguard_unwrap_dek`
//! recovers exactly the DEK that was fed to it. The DEK goes in on stdin
//! (or via `--dek-file`), never on the command line -- argv is readable by
//! any process of the same user via `/proc/<pid>/cmdline`. Deliberately
//! spans two processes -- the CLI's wrap and this test's unwrap -- rather
//! than calling the library twice in one process, so it also exercises a
//! genuinely persistent (not per-process, in-memory) KEK.
//!
//! There is no software-backed (locally-generated, filesystem-encrypted-
//! at-rest) provider on this platform, so the persistent provider used
//! here is external-secret: each test pre-provisions its own service's
//! secret file into an isolated temp directory before invoking the CLI,
//! mimicking how a real deployment platform (Vault Agent, a Kubernetes
//! Secret, ...) would have already dropped the file before the app starts
//! -- external-secret never creates one itself. For that provider,
//! `provision` therefore always reports "already provisioned": the mounted
//! file *is* the provisioning. The create path is covered in-process by
//! the binary's own unit tests against the ephemeral provider.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use p256::SecretKey;
use rand_core::OsRng;
use serial_test::serial;
use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::os::raw::c_int;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
// Only this user can write to it, whatever the umask: the library refuses
// to trust a policy or secret mount in a group-writable directory, and
// `tempfile::tempdir()` creates `0777 & !umask`.
fn tempdir() -> std::io::Result<tempfile::TempDir> {
    tempfile::Builder::new().permissions(fs::Permissions::from_mode(0o700)).tempdir()
}
use HkdfGuardKeyProtectionLinux::{hkdfguard_unwrap_dek, status};

// Points the external-secret provider at a fresh temp directory, isolated
// from any real host KEK storage, and pre-provisions a secret file for
// `service` inside it -- external-secret never creates one itself, so
// `wrap` only finds a KEK because this is already here.
fn with_provisioned_external_secret<F: FnOnce()>(service: &str, f: F) {
    let dir = tempdir().unwrap();
    std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", dir.path());
    let secret_key = SecretKey::random(&mut OsRng);
    let secret_path = dir.path().join(service);
    fs::write(&secret_path, secret_key.to_bytes()).unwrap();
    fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600)).unwrap(); // owner-only, as the provider requires of a KEK file
    f();
    std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
}

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hkdfguard-v1-initialize"))
}

// `hkdfguard-v1-initialize provision --service-name <service>`
fn run_provision(service: &str) -> Output {
    cli()
        .arg("provision")
        .args(["--service-name", service])
        .output()
        .expect("failed to run hkdfguard-v1-initialize provision")
}

// `hkdfguard-v1-initialize wrap --key-file-path <path> --service-name
// <service> --dek-stdin [extra]`, with the base64 DEK written to the
// subprocess's stdin -- how a deployment pipeline is expected to supply it.
fn run_wrap_stdin(key_path: &Path, service: &str, dek: &[u8; 32], extra_args: &[&str]) -> Output {
    let dek_b64 = STANDARD.encode(dek);
    let mut child = cli()
        .arg("wrap")
        .args(["--key-file-path", key_path.to_str().unwrap()])
        .args(["--service-name", service])
        .arg("--dek-stdin")
        .args(extra_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn hkdfguard-v1-initialize wrap");
    child
        .stdin
        .as_mut()
        .expect("stdin was piped")
        .write_all(dek_b64.as_bytes())
        .expect("failed to write the DEK to the CLI's stdin");
    drop(child.stdin.take()); // close stdin so the child sees EOF
    child.wait_with_output().expect("failed to run hkdfguard-v1-initialize wrap")
}

fn unwrap_via_library(service: &str, wrapped: &[u8]) -> (c_int, [u8; 32]) {
    let service = CString::new(service).unwrap();
    let mut recovered = [0u8; 32];
    let mut recovered_len: c_int = recovered.len() as c_int;
    let rc = hkdfguard_unwrap_dek(
        service.as_ptr(),
        wrapped.as_ptr(),
        wrapped.len() as c_int,
        recovered.as_mut_ptr(),
        &mut recovered_len,
    );
    (rc, recovered)
}

fn stderr_of(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
#[serial]
fn cli_provision_then_wrap_unwraps_to_original_input() {
    with_provisioned_external_secret("com.example.orders", || {
        let original_dek: [u8; 32] = core::array::from_fn(|i| i as u8);
        let out_dir = tempdir().unwrap();
        let key_path = out_dir.path().join("wrapped.key");

        // provision: for external-secret the mounted file is the
        // provisioning, so this reports "already" and exits 0.
        let provisioned = run_provision("com.example.orders");
        assert!(provisioned.status.success(), "provision failed: {}", stderr_of(&provisioned));
        assert!(
            String::from_utf8_lossy(&provisioned.stdout).contains("already provisioned"),
            "external-secret must report the mounted file as already provisioned"
        );

        let output = run_wrap_stdin(&key_path, "com.example.orders", &original_dek, &[]);
        assert!(
            output.status.success(),
            "wrap failed (status {:?}): stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            stderr_of(&output)
        );

        let wrapped = fs::read(&key_path).expect("wrapped key file should exist");
        let mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "wrapped key file must be written with mode 0640");

        let (rc, recovered) = unwrap_via_library("com.example.orders", &wrapped);
        assert_eq!(rc, status::OK, "hkdfguard_unwrap_dek failed with status {rc}");
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
        let first = run_wrap_stdin(&key_path, "com.example.rotation", &first_dek, &[]);
        assert!(first.status.success(), "initial write should succeed: {}", stderr_of(&first));

        let second_dek: [u8; 32] = core::array::from_fn(|i| 255 - i as u8);
        let second = run_wrap_stdin(&key_path, "com.example.rotation", &second_dek, &["--force"]);
        assert!(second.status.success(), "forced overwrite should succeed: {}", stderr_of(&second));

        // The file on disk must now unwrap to the *second* DEK, not the first.
        // (Whether the overwrite actually delete-and-recreated the file
        // rather than truncating it in place is covered separately by the
        // secure_delete unit tests in src/bin/hkdfguard-v1-initialize.rs --
        // inode number isn't a reliable signal for that here, since some
        // filesystems immediately reuse a just-freed inode for a new file.)
        let wrapped = fs::read(&key_path).unwrap();
        let (rc, recovered) = unwrap_via_library("com.example.rotation", &wrapped);
        assert_eq!(rc, status::OK);
        assert_eq!(recovered, second_dek, "file must contain the second wrap, not the first");
    });
}

#[test]
#[serial]
fn cli_rejects_pre_existing_file_without_force() {
    // This scenario never reaches the KEK provider at all -- `wrap`'s own
    // pre-check refuses an existing output file before reading the DEK or
    // touching the library -- so no external secret needs to be provisioned.
    let dir = tempdir().unwrap();
    std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", dir.path());

    let out_dir = tempdir().unwrap();
    let key_path = out_dir.path().join("wrapped.key");
    fs::write(&key_path, b"pre-existing content").unwrap();

    let output = run_wrap_stdin(&key_path, "com.example.billing", &[0x42u8; 32], &[]);

    assert!(!output.status.success(), "wrap should refuse to overwrite an existing file");
    assert_eq!(
        fs::read(&key_path).unwrap(),
        b"pre-existing content",
        "existing file must be left untouched without --force"
    );

    std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
}

#[test]
#[serial]
fn cli_wrap_without_a_provisioned_kek_fails_and_preserves_the_existing_file() {
    // An external-secret mount that exists but holds nothing for this
    // service, and a policy that pins the chain to external-secret. The
    // pin matters: with `tpm2` compiled in and a TPM reachable (the Docker
    // harness runs this against swtpm), the TPM provider derives every
    // service's KEK on demand and would legitimately serve this one --
    // which is correct behavior, but not the scenario under test.
    // Relying on "no provider happens to be available" would make this
    // test track the host's hardware instead of the CLI's behavior.
    let empty_mount = tempdir().unwrap();
    std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", empty_mount.path());
    let policy_dir = tempdir().unwrap();
    let policy = policy_dir.path().join("policy.toml");
    fs::write(&policy, "[selection]\nmode = \"require\"\nprovider = \"external-secret\"\n").unwrap();
    fs::set_permissions(&policy, fs::Permissions::from_mode(0o644)).unwrap(); // not the umask: some distros default to 002 (group-writable), which the policy loader correctly refuses
    std::env::set_var("HKDFGUARD_POLICY_FILE", &policy);

    let out_dir = tempdir().unwrap();
    let key_path = out_dir.path().join("wrapped.key");
    fs::write(&key_path, b"the key file that was already here").unwrap();

    // `wrap` never provisions: it must fail, name the fix, and -- even
    // with --force -- leave the existing key file exactly as it was,
    // because the wrap fails before the old file is ever touched.
    let output = run_wrap_stdin(&key_path, "com.example.unprovisioned", &[0x42u8; 32], &["--force"]);
    assert!(!output.status.success(), "wrap must fail without a provisioned KEK");
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("provision --service-name com.example.unprovisioned"),
        "error must point at the provision command: {stderr}"
    );
    assert_eq!(
        fs::read(&key_path).unwrap(),
        b"the key file that was already here",
        "a failed wrap must never destroy the existing key file, even with --force"
    );

    // And `provision` for that service fails too: external-secret cannot
    // create a KEK, and nothing else is allowed to.
    let provisioned = run_provision("com.example.unprovisioned");
    assert!(!provisioned.status.success(), "provision must fail when no provider can create a KEK");

    std::env::remove_var("HKDFGUARD_POLICY_FILE");
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

        let output = cli()
            .arg("wrap")
            .args(["--key-file-path", key_path.to_str().unwrap()])
            .args(["--service-name", "com.example.fileinput"])
            .args(["--dek-file", dek_path.to_str().unwrap()])
            .output()
            .expect("failed to run hkdfguard-v1-initialize");
        assert!(output.status.success(), "--dek-file should succeed: {}", stderr_of(&output));

        // Round-trips through the library, exactly as the stdin path does.
        let wrapped = fs::read(&key_path).expect("wrapped key file should exist");
        let (rc, recovered) = unwrap_via_library("com.example.fileinput", &wrapped);
        assert_eq!(rc, status::OK);
        assert_eq!(recovered, original_dek);

        // A group-readable DEK file is refused rather than used.
        let loose_path = out_dir.path().join("loose.b64");
        fs::write(&loose_path, STANDARD.encode(original_dek)).unwrap();
        fs::set_permissions(&loose_path, fs::Permissions::from_mode(0o644)).unwrap();
        let loose_key_path = out_dir.path().join("loose.key");
        let output = cli()
            .arg("wrap")
            .args(["--key-file-path", loose_key_path.to_str().unwrap()])
            .args(["--service-name", "com.example.fileinput"])
            .args(["--dek-file", loose_path.to_str().unwrap()])
            .output()
            .expect("failed to run hkdfguard-v1-initialize");
        assert!(!output.status.success(), "a group-readable DEK file must be refused");
        assert!(!loose_key_path.exists(), "nothing should have been written");

        // The retired argv form is rejected outright, with an error that
        // says why.
        let argv_key_path = out_dir.path().join("argv.key");
        let output = cli()
            .arg("wrap")
            .args(["--key-file-path", argv_key_path.to_str().unwrap()])
            .args(["--service-name", "com.example.fileinput"])
            .args(["--dek", &STANDARD.encode(original_dek)])
            .output()
            .expect("failed to run hkdfguard-v1-initialize");
        assert!(!output.status.success(), "--dek must no longer be accepted");
        assert!(stderr_of(&output).contains("cmdline"), "error should explain the exposure");
        assert!(!argv_key_path.exists(), "nothing should have been written");

        // And the pre-subcommand positional form fails with a pointer to
        // --key-file-path, rather than being misread as a subcommand.
        let output = cli()
            .arg(key_path.to_str().unwrap())
            .args(["--service-name", "com.example.fileinput", "--dek-stdin"])
            .output()
            .expect("failed to run hkdfguard-v1-initialize");
        assert!(!output.status.success());
        assert!(stderr_of(&output).contains("--key-file-path"), "must point at the new flag");
    });
}
