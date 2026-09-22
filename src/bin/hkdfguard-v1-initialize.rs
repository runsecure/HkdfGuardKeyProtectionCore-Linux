//! CLI tool: wraps a caller-supplied Data Encryption Key (DEK) under a
//! persistent KEK and writes the wrapped payload to a file.
//!
//! Calls into the `hkdfguard` library through its stable C ABI
//! (`hkdfguard_wrap_dek`), the same interface any other-language caller
//! uses -- this tool takes no shortcut through the library's internal
//! Rust types.
//!
//! The KEK's `service` identity is `<service-name>.<material-identifier>`:
//! the material identifier lets one logical service own up to 256 distinct
//! KEKs (e.g. for key rotation), each addressed by its own `service` string
//! under the hood.
//!
//! Usage:
//! ```text
//! hkdfguard-v1-initialize <key-file-path> \
//!     --material-identifier|-mi <1-256> \
//!     --service-name|-sn <name> \
//!     --dek|-d <base64> \
//!     [--force|-f]
//! ```
//!
//! Note: `--dek` on the command line is visible to other processes on the
//! same host via `/proc/<pid>/cmdline` for the life of this process, like
//! any command-line argument. That's a general Linux limitation, not
//! specific to this tool.
//!
//! When `--force` overwrites an existing file at `<key-file-path>`, the old
//! contents are securely overwritten in place before the file is removed
//! (see [`secure_delete`]) rather than just truncated/replaced. Note this
//! is a best-effort measure against a plain read of the disk: it cannot
//! guarantee erasure on copy-on-write or log-structured filesystems (e.g.
//! btrfs, ZFS), or on flash storage doing wear-leveling remaps, where the
//! original blocks may still exist elsewhere on the device.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand_core::{OsRng, RngCore};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::raw::c_int;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::ExitCode;
use zeroize::Zeroizing;
use HkdfGuardKeyProtectionLinux::{hkdfguard_wrap_dek, status};

// rw-r-----: readable by the owning deployment user and its group, writable
// only by the owner, inaccessible to everyone else.
const KEY_FILE_MODE: u32 = 0o640;

// Number of (all-zero pass, random pass) rounds `secure_delete` runs before
// removing the file -- 2 passes per round, so this yields 8 total
// overwrites as specified.
const SECURE_DELETE_ROUNDS: usize = 4;

const PROGRAM_NAME: &str = "hkdfguard-v1-initialize";
const MATERIAL_IDENTIFIER_MIN: u32 = 1;
const MATERIAL_IDENTIFIER_MAX: u32 = 256;
const DEK_LEN: usize = 32;
// Generous starting capacity for the wrapped payload -- see
// hkdfguard_wrap_dek's own doc comment ("at most a few hundred bytes").
// Retried once at the library-reported size on BUFFER_TOO_SMALL, so this
// only needs to be a reasonable common case, not an absolute upper bound.
const INITIAL_WRAPPED_CAPACITY: usize = 512;

struct Args {
    key_file_path: String,
    material_identifier: u32,
    service_name: String,
    dek_base64: String,
    force: bool,
}

enum ParseOutcome {
    Run(Args),
    Help,
}

fn print_usage() {
    eprintln!(
        "Usage: {PROGRAM_NAME} <key-file-path> --material-identifier|-mi <{MATERIAL_IDENTIFIER_MIN}-{MATERIAL_IDENTIFIER_MAX}> --service-name|-sn <name> --dek|-d <base64> [--force|-f]"
    );
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<ParseOutcome, String> {
    let mut key_file_path: Option<String> = None;
    let mut material_identifier: Option<u32> = None;
    let mut service_name: Option<String> = None;
    let mut dek_base64: Option<String> = None;
    let mut force = false;

    let mut args = args.skip(1); // skip argv[0]
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => return Ok(ParseOutcome::Help),
            "--force" | "-f" => force = true,
            "--material-identifier" | "-mi" => {
                let value = args.next().ok_or_else(|| format!("{arg} requires a value"))?;
                let parsed: u32 = value
                    .parse()
                    .map_err(|_| format!("--material-identifier must be an integer, got \"{value}\""))?;
                if !(MATERIAL_IDENTIFIER_MIN..=MATERIAL_IDENTIFIER_MAX).contains(&parsed) {
                    return Err(format!(
                        "--material-identifier must be between {MATERIAL_IDENTIFIER_MIN} and {MATERIAL_IDENTIFIER_MAX}, got {parsed}"
                    ));
                }
                material_identifier = Some(parsed);
            }
            "--service-name" | "-sn" => {
                let value = args.next().ok_or_else(|| format!("{arg} requires a value"))?;
                if value.is_empty() {
                    return Err("--service-name must not be empty".to_string());
                }
                service_name = Some(value);
            }
            "--dek" | "-d" => {
                dek_base64 = Some(args.next().ok_or_else(|| format!("{arg} requires a value"))?);
            }
            other if key_file_path.is_none() && !other.starts_with('-') => {
                key_file_path = Some(other.to_string());
            }
            other => return Err(format!("unrecognized argument: {other}")),
        }
    }

    let key_file_path = key_file_path.ok_or("missing required <key-file-path>")?;
    let material_identifier =
        material_identifier.ok_or("missing required --material-identifier|-mi")?;
    let service_name = service_name.ok_or("missing required --service-name|-sn")?;
    let dek_base64 = dek_base64.ok_or("missing required --dek|-d")?;

    Ok(ParseOutcome::Run(Args {
        key_file_path,
        material_identifier,
        service_name,
        dek_base64,
        force,
    }))
}

// Maps a hkdfguard_wrap_dek status code to a human-readable description,
// for a clearer error message than a bare integer.
fn describe_status(code: c_int) -> String {
    match code {
        status::INVALID_ARGUMENT => "invalid argument (bad service name or DEK length)".to_string(),
        status::PROVIDER_UNAVAILABLE => "no KEK provider is available on this host".to_string(),
        status::PROVIDER_ERROR => "the selected KEK provider failed".to_string(),
        status::CRYPTO_ERROR => "a cryptographic operation failed".to_string(),
        status::INTERNAL_ERROR => "an internal error occurred in the hkdfguard library".to_string(),
        status::INVALID_UTF8 => "the service name is not valid UTF-8".to_string(),
        status::MISSING_SERVICE_NAME => "the service name is missing or empty".to_string(),
        other => format!("unknown status code {other}"),
    }
}

fn wrap_dek(service: &CString, dek: &[u8]) -> Result<Vec<u8>, String> {
    let mut wrapped = vec![0u8; INITIAL_WRAPPED_CAPACITY];
    let mut wrapped_len: c_int = wrapped.len() as c_int;

    let mut rc = hkdfguard_wrap_dek(
        service.as_ptr(),
        dek.as_ptr(),
        dek.len() as c_int,
        wrapped.as_mut_ptr(),
        &mut wrapped_len,
    );

    if rc == status::BUFFER_TOO_SMALL {
        // `wrapped_len` now holds the size the library actually needs; retry once at that size.
        wrapped = vec![0u8; wrapped_len as usize];
        rc = hkdfguard_wrap_dek(
            service.as_ptr(),
            dek.as_ptr(),
            dek.len() as c_int,
            wrapped.as_mut_ptr(),
            &mut wrapped_len,
        );
    }

    if rc != status::OK {
        return Err(format!("hkdfguard_wrap_dek failed: {}", describe_status(rc)));
    }

    wrapped.truncate(wrapped_len as usize);
    Ok(wrapped)
}

// Enforces that `<service-name>.<material-identifier>` -- the string
// actually used as the KEK's identity -- contains only ASCII alphanumeric
// characters or '.'. The material identifier is already digits-only (see
// its parse in `parse_args`), so in practice this only constrains
// `--service-name`, but it's checked on the combined string to match
// exactly what gets passed to `hkdfguard_wrap_dek`.
fn validate_service_charset(service: &str) -> Result<(), String> {
    if service.chars().all(|c| c.is_ascii_alphanumeric() || c == '.') {
        Ok(())
    } else {
        Err(format!(
            "combined service name \"{service}\" must contain only alphanumeric characters or '.'"
        ))
    }
}

// Overwrites `path`'s existing content in place for `SECURE_DELETE_ROUNDS`
// rounds -- each round first an all-zero-bit pass, then a pass of fresh
// random bits, fsync'd after every pass -- before unlinking it. Called only
// when `--force` is about to replace a file that already exists.
//
// If the file can't be opened for writing (EACCES/EPERM -- this tool
// doesn't own it), the overwrite passes are skipped entirely and this falls
// back to a plain `remove_file`, per explicit product direction: destroying
// the old bytes first is worth attempting, but not worth failing the whole
// command over when this process isn't even allowed to write to the file
// it's about to replace -- matches this project's macOS/Windows tools.
fn secure_delete(path: &Path) -> Result<(), String> {
    let len = fs::metadata(path)
        .map_err(|e| format!("failed to stat {}: {e}", path.display()))?
        .len() as usize;

    let mut file = match OpenOptions::new().write(true).open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return fs::remove_file(path).map_err(|e| {
                format!("failed to remove {} after permission-denied secure delete: {e}", path.display())
            });
        }
        Err(e) => return Err(format!("failed to open {} for secure delete: {e}", path.display())),
    };

    let mut buf = vec![0u8; len];
    for _ in 0..SECURE_DELETE_ROUNDS {
        buf.iter_mut().for_each(|b| *b = 0); // pass: overwrite with bit 0 throughout
        overwrite_pass(&mut file, path, &buf)?;

        OsRng.fill_bytes(&mut buf); // pass: overwrite with a fresh random bit pattern
        overwrite_pass(&mut file, path, &buf)?;
    }

    drop(file);
    fs::remove_file(path).map_err(|e| format!("failed to remove {} after secure delete: {e}", path.display()))
}

// Rewinds to the start of `file` and writes `buf` (the same length as the
// file, per `secure_delete`), fsync'ing before returning so this pass is
// durable on disk before the next one begins.
fn overwrite_pass(file: &mut File, path: &Path, buf: &[u8]) -> Result<(), String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|e| format!("secure delete: failed to seek {}: {e}", path.display()))?;
    file.write_all(buf)
        .map_err(|e| format!("secure delete: failed to write {}: {e}", path.display()))?;
    file.sync_all()
        .map_err(|e| format!("secure delete: failed to sync {}: {e}", path.display()))
}

fn run(args: &mut Args) -> Result<(), String> {
    // Fast, friendly pre-check: fail before ever touching the KEK provider
    // if the output path obviously already exists and --force wasn't
    // passed. The final `create_new` open below is the actual correctness
    // guarantee against the exists-then-create race; this is purely a
    // fail-fast convenience on top of it.
    let path = Path::new(&args.key_file_path);
    if path.exists() {
        if !args.force {
            return Err(format!(
                "{} already exists; pass --force|-f to overwrite",
                args.key_file_path
            ));
        }
        secure_delete(path)?;
    }

    // `service` is not secret -- it's a logical identifier, not key
    // material -- so it's computed and validated before the DEK's own
    // tightly-scoped block, so that block can end the instant the DEK is no
    // longer needed without `service` needing to be reconstructed
    // afterward.
    let service = format!("{}.{}", args.service_name, args.material_identifier);
    validate_service_charset(&service)?;
    let service_c = CString::new(service.clone())
        .map_err(|_| "the combined service name must not contain a NUL byte".to_string())?;

    let wrapped = {
        // Both the base64 *text* (`args.dek_base64`) and the decoded
        // plaintext DEK *bytes* (`dek`) are secret, and both are scoped as
        // tightly as possible around exactly the statements that need
        // them: decode, clear the text immediately (it has now served its
        // one purpose), validate the byte length, wrap, then `dek` is
        // zeroed by `Zeroizing`'s `Drop` the instant this block ends --
        // immediately after wrap_dek is done with it, not at the end of
        // run() (which would otherwise leave it sitting in memory, unused
        // but unwiped, through the final file write below).
        let dek = Zeroizing::new(
            STANDARD
                .decode(&args.dek_base64)
                .map_err(|e| format!("--dek is not valid base64: {e}"))?,
        );

        // The base64 text has now served its only purpose: clear this
        // process's one owned copy of it right here, rather than leaving
        // it sitting in `args` for the rest of this function. `String`'s
        // `clear` drops its heap buffer's contents via dealloc, not a
        // guaranteed zero-fill; a `Zeroizing<String>` would offer that
        // guarantee but isn't used for `args.dek_base64` itself since
        // `parse_args` populates it as a plain `String` (a user-facing CLI
        // argument, not a library-internal secret buffer) -- this does not
        // erase the original command-line argument the OS still holds
        // elsewhere -- see this file's header comment on that inherent,
        // unavoidable argv-visibility limitation.
        args.dek_base64.clear();
        args.dek_base64.shrink_to_fit();

        if dek.len() != DEK_LEN {
            return Err(format!(
                "--dek must decode to exactly {DEK_LEN} bytes, got {}",
                dek.len()
            ));
        }

        wrap_dek(&service_c, &dek)?
        // `dek`'s `Zeroizing` wrapper zeroes it here, as this block ends --
        // immediately after wrap_dek returns the wrapped (encrypted, no
        // longer secret) form, which is the only thing that survives past
        // this point.
    };

    // `create_new` makes "does this file already exist" and "create it"
    // one indivisible kernel operation (the actual correctness guarantee
    // against the exists-then-create race -- the `path.exists()` check
    // above is purely a fail-fast convenience, not this guarantee), and
    // `.mode(KEY_FILE_MODE)` sets the permissions at the moment of
    // creation so there's no window where the file briefly exists with
    // broader (umask-derived) permissions before being locked down after
    // the fact. By the time this runs, `path` is always either brand new
    // or was just deleted by `secure_delete` above, so `set_permissions`
    // below is defense-in-depth against the umask, not strictly required.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(KEY_FILE_MODE)
        .open(&args.key_file_path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                format!("{} already exists; pass --force|-f to overwrite", args.key_file_path)
            } else {
                format!("failed to open {}: {e}", args.key_file_path)
            }
        })?;
    file.write_all(&wrapped)
        .map_err(|e| format!("failed to write {}: {e}", args.key_file_path))?;
    file.set_permissions(fs::Permissions::from_mode(KEY_FILE_MODE))
        .map_err(|e| format!("failed to set permissions on {}: {e}", args.key_file_path))?;

    println!(
        "wrapped key written to {} ({} bytes, service \"{service}\")",
        args.key_file_path,
        wrapped.len()
    );
    Ok(())
}

fn main() -> ExitCode {
    match parse_args(std::env::args()) {
        Ok(ParseOutcome::Help) => {
            print_usage();
            ExitCode::SUCCESS
        }
        Ok(ParseOutcome::Run(mut args)) => match run(&mut args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
        Err(e) => {
            eprintln!("error: {e}");
            print_usage();
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    // `secure_delete`'s multi-pass overwrite content isn't observable from
    // outside the function by the time it returns (the file is gone by
    // then) -- what's directly testable here is its documented end state:
    // the file no longer exists. (An inode-number check was tried as a
    // stronger signal in this crate's CLI integration tests, but dropped:
    // some filesystems reuse a just-freed inode immediately for a new
    // file, which made that check flaky rather than meaningful.)
    #[test]
    fn secure_delete_removes_the_file() {
        let file = NamedTempFile::new().unwrap();
        fs::write(file.path(), b"sensitive content to be wiped").unwrap();
        assert!(file.path().exists());

        secure_delete(file.path()).unwrap();

        assert!(!file.path().exists());
    }

    #[test]
    fn secure_delete_handles_an_empty_file() {
        let file = NamedTempFile::new().unwrap(); // created empty
        secure_delete(file.path()).unwrap();
        assert!(!file.path().exists());
    }

    #[test]
    fn secure_delete_fails_cleanly_on_a_missing_file() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_path_buf();
        drop(file);
        fs::remove_file(&path).ok();
        assert!(secure_delete(&path).is_err());
    }

    #[test]
    fn validate_service_charset_accepts_alphanumerics_and_dots() {
        assert!(validate_service_charset("com.example.orders.5").is_ok());
        assert!(validate_service_charset("Service123.42").is_ok());
    }

    #[test]
    fn validate_service_charset_rejects_other_characters() {
        for bad in ["com_example.5", "com example.5", "com-example.5", "com/example.5"] {
            assert!(validate_service_charset(bad).is_err(), "should reject \"{bad}\"");
        }
    }

    #[test]
    fn parse_args_rejects_material_identifier_out_of_range() {
        let argv = ["prog", "key.bin", "-mi", "0", "-sn", "svc", "-d", "AAAA"]
            .into_iter()
            .map(String::from);
        assert!(parse_args(argv).is_err());

        let argv = ["prog", "key.bin", "-mi", "257", "-sn", "svc", "-d", "AAAA"]
            .into_iter()
            .map(String::from);
        assert!(parse_args(argv).is_err());
    }

    #[test]
    fn parse_args_accepts_boundary_material_identifiers() {
        for value in ["1", "256"] {
            let argv = ["prog", "key.bin", "-mi", value, "-sn", "svc", "-d", "AAAA"]
                .into_iter()
                .map(String::from);
            assert!(matches!(parse_args(argv), Ok(ParseOutcome::Run(_))), "should accept {value}");
        }
    }
}
