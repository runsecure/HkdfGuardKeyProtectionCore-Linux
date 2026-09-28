//! CLI tool: wraps a caller-supplied Data Encryption Key (DEK) under a
//! persistent KEK and writes the wrapped payload to a file.
//!
//! Calls into the `hkdfguard` library through its stable C ABI
//! (`hkdfguard_create_kek`, then `hkdfguard_wrap_dek`), the same interface
//! any other-language caller uses -- this tool takes no shortcut through
//! the library's internal Rust types. As of the KEK-provisioning split,
//! `hkdfguard_wrap_dek` never creates a KEK itself, so this tool -- being
//! the one that initializes a service's very first wrapped key -- always
//! provisions the KEK explicitly first; `hkdfguard_create_kek` is
//! idempotent, so this is safe even if the KEK already existed.
//!
//! The KEK's `service` identity is exactly the caller-supplied
//! `--service-name`; there is no further structure to it.
//!
//! Usage:
//! ```text
//! hkdfguard-v1-initialize <key-file-path> \
//!     --service-name|-sn <name> \
//!     (--dek-stdin | --dek-file <path>) \
//!     [--force|-f]
//! ```
//!
//! ## Supplying the DEK
//!
//! The DEK is base64 (of exactly 32 raw bytes) and is read either from
//! standard input or from a file. It is deliberately **not** accepted as a
//! command-line argument: argv is world-readable through
//! `/proc/<pid>/cmdline` for the life of the process, so every DEK ever
//! deployed would be exposed to any process running as the same user. It
//! is deliberately not read from an environment variable either, for the
//! same reason applied to `/proc/<pid>/environ` -- which is additionally
//! inherited by every child process (this matches the reasoning already
//! applied to the PKCS#11 PIN; see `src/provider/pkcs11.rs`).
//!
//! ```text
//! # stdin -- printf is a shell builtin, so nothing reaches argv
//! printf '%s' "$DEK_B64" | hkdfguard-v1-initialize key.bin -sn svc --dek-stdin
//!
//! # file -- e.g. a Kubernetes/Vault secret mount or a systemd credential
//! hkdfguard-v1-initialize key.bin -sn svc --dek-file "$CREDENTIALS_DIRECTORY/dek"
//! ```
//!
//! A `--dek-file` must be a regular file, must not be a symlink, must be
//! owned by root or by this process's user, and must grant no access to
//! group or others (e.g. mode `0400`/`0600`). A single trailing newline
//! (optionally CRLF) is ignored on both paths.
//!
//! What this tool cannot fix: if the *caller* puts the DEK in an
//! environment variable, or pipes it with a non-builtin `echo` (argv
//! again), the exposure moves upstream. Whatever drives this tool has to
//! avoid both.
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
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::raw::c_int;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::ExitCode;
use zeroize::{Zeroize, Zeroizing};
use HkdfGuardKeyProtectionLinux::{hkdfguard_create_kek, hkdfguard_wrap_dek, status};

// rw-r-----: readable by the owning deployment user and its group, writable
// only by the owner, inaccessible to everyone else.
const KEY_FILE_MODE: u32 = 0o640;

// Number of (all-zero pass, random pass) rounds `secure_delete` runs before
// removing the file -- 2 passes per round, so this yields 8 total
// overwrites as specified.
const SECURE_DELETE_ROUNDS: usize = 4;

const PROGRAM_NAME: &str = "hkdfguard-v1-initialize";
const DEK_LEN: usize = 32;
// Mirrors the library's own cap (see cstr_to_service in src/lib.rs) so this
// tool can give a specific, immediate error instead of relying on the
// library's generic INVALID_ARGUMENT.
const MAX_SERVICE_LEN: usize = 128;
// Generous starting capacity for the wrapped payload -- see
// hkdfguard_wrap_dek's own doc comment ("at most a few hundred bytes").
// Retried once at the library-reported size on BUFFER_TOO_SMALL, so this
// only needs to be a reasonable common case, not an absolute upper bound.
const INITIAL_WRAPPED_CAPACITY: usize = 512;
// Upper bound on the DEK input read from stdin or a file. Base64 of 32
// bytes is 44 characters; this leaves room for a trailing newline (or
// CRLF) and nothing more, so a wrong file fails fast instead of being
// slurped into memory.
const MAX_DEK_INPUT_LEN: usize = 64;
// Mode bits that must be clear on a --dek-file: no access at all for
// group or others.
const FORBID_GROUP_OTHER_ACCESS: u32 = 0o077;

// Where the base64 DEK is read from. Never argv, never the environment --
// see this file's header comment.
#[derive(Debug, PartialEq, Eq)]
enum DekSource {
    Stdin,
    File(String),
}

struct Args {
    key_file_path: String,
    service_name: String,
    dek_source: DekSource,
    force: bool,
}

enum ParseOutcome {
    Run(Args),
    Help,
}

fn print_usage() {
    eprintln!(
        "Usage: {PROGRAM_NAME} <key-file-path> --service-name|-sn <name> (--dek-stdin | --dek-file <path>) [--force|-f]\n\
         \n\
         The DEK is base64 of exactly 32 bytes, read from stdin or a file -- never\n\
         from a command-line argument or an environment variable, both of which are\n\
         readable by other processes of the same user.\n\
         \n\
         Examples:\n\
           printf '%s' \"$DEK_B64\" | {PROGRAM_NAME} key.bin -sn svc --dek-stdin\n\
           {PROGRAM_NAME} key.bin -sn svc --dek-file \"$CREDENTIALS_DIRECTORY/dek\""
    );
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<ParseOutcome, String> {
    let mut key_file_path: Option<String> = None;
    let mut service_name: Option<String> = None;
    let mut dek_source: Option<DekSource> = None;
    let mut force = false;

    // Rejects a second DEK source rather than letting the last one win:
    // silently ignoring one of two explicitly-requested inputs is exactly
    // the kind of ambiguity that leads to wrapping the wrong key.
    fn set_source(slot: &mut Option<DekSource>, source: DekSource) -> Result<(), String> {
        if slot.is_some() {
            return Err("give exactly one of --dek-stdin or --dek-file".to_string());
        }
        *slot = Some(source);
        Ok(())
    }

    let mut args = args.skip(1); // skip argv[0]
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => return Ok(ParseOutcome::Help),
            "--force" | "-f" => force = true,
            "--service-name" | "-sn" => {
                let value = args.next().ok_or_else(|| format!("{arg} requires a value"))?;
                if value.is_empty() {
                    return Err("--service-name must not be empty".to_string());
                }
                service_name = Some(value);
            }
            "--dek-stdin" => set_source(&mut dek_source, DekSource::Stdin)?,
            "--dek-file" => {
                let value = args.next().ok_or_else(|| format!("{arg} requires a value"))?;
                if value.is_empty() {
                    return Err("--dek-file must not be empty".to_string());
                }
                set_source(&mut dek_source, DekSource::File(value))?;
            }
            // Removed rather than deprecated: accepting the DEK on argv
            // exposes it via /proc/<pid>/cmdline, so leaving it in place
            // "for compatibility" would just preserve the vulnerability.
            // A clear error beats a silent "unrecognized argument".
            "--dek" | "-d" => {
                return Err(
                    "--dek is no longer supported: the DEK would be visible to other processes \
                     via /proc/<pid>/cmdline. Use --dek-stdin or --dek-file instead."
                        .to_string(),
                )
            }
            other if key_file_path.is_none() && !other.starts_with('-') => {
                key_file_path = Some(other.to_string());
            }
            other => return Err(format!("unrecognized argument: {other}")),
        }
    }

    let key_file_path = key_file_path.ok_or("missing required <key-file-path>")?;
    let service_name = service_name.ok_or("missing required --service-name|-sn")?;
    let dek_source = dek_source.ok_or("missing required --dek-stdin or --dek-file <path>")?;

    Ok(ParseOutcome::Run(Args {
        key_file_path,
        service_name,
        dek_source,
        force,
    }))
}

// Reads at most `MAX_DEK_INPUT_LEN` bytes from `src` into a single
// pre-sized, self-zeroing buffer.
//
// The buffer is allocated at full size up front and never grown, because
// `read_to_end` reallocates as it goes and leaves the intermediate copies
// un-wiped in freed memory -- the same reasoning the library applies to
// its own secret-file reads. Input longer than the limit is rejected
// rather than truncated, so a wrong file can't silently decode to a
// plausible-looking key.
fn read_bounded(src: &mut dyn Read, what: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut buf = Zeroizing::new(vec![0u8; MAX_DEK_INPUT_LEN + 1]);
    let mut filled = 0;
    while filled < buf.len() {
        match src.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("failed to read {what}: {e}")),
        }
    }
    if filled > MAX_DEK_INPUT_LEN {
        return Err(format!(
            "{what} is longer than {MAX_DEK_INPUT_LEN} bytes; expected base64 of a {DEK_LEN}-byte DEK"
        ));
    }
    buf.truncate(filled); // shrinks the length only; the full allocation is still zeroed on drop
    Ok(buf)
}

// Opens a --dek-file with the same hardening the library applies to its
// own secret files: O_NOFOLLOW so a symlink fails the open outright, and
// ownership/permission checks made against the *opened descriptor* rather
// than the path, so nothing can be swapped between the check and the read.
fn read_dek_file(path: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                format!("--dek-file {path} is a symlink; refusing to follow it")
            } else {
                format!("failed to open --dek-file {path}: {e}")
            }
        })?;

    let meta = file
        .metadata()
        .map_err(|e| format!("failed to stat --dek-file {path}: {e}"))?;
    if !meta.file_type().is_file() {
        // A FIFO here would block the read indefinitely; a directory or
        // device makes no sense as a key source.
        return Err(format!("--dek-file {path} is not a regular file"));
    }
    // SAFETY: geteuid takes no arguments and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != 0 && meta.uid() != euid {
        return Err(format!(
            "--dek-file {path} is owned by uid {}, which is neither root nor this process's user",
            meta.uid()
        ));
    }
    let offending = meta.mode() & FORBID_GROUP_OTHER_ACCESS;
    if offending != 0 {
        return Err(format!(
            "--dek-file {path} permissions are too broad (mode {:o}; bits {offending:o} must be clear)",
            meta.mode() & 0o7777
        ));
    }

    read_bounded(&mut file, "--dek-file")
}

// Decodes the base64 DEK text, tolerating exactly one trailing newline
// (optionally CRLF) so a file written by `printf '%s\n'` or an editor
// still works. Only base64 is accepted: raw 32-byte input fails to decode
// with a clear error rather than being silently misinterpreted.
fn decode_dek(text: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let trimmed = match text.strip_suffix(b"\n") {
        Some(t) => t.strip_suffix(b"\r").unwrap_or(t),
        None => text,
    };
    if trimmed.is_empty() {
        return Err("the DEK input is empty".to_string());
    }

    let dek = Zeroizing::new(
        STANDARD
            .decode(trimmed)
            .map_err(|e| format!("the DEK input is not valid base64: {e}"))?,
    );
    if dek.len() != DEK_LEN {
        return Err(format!(
            "the DEK must decode to exactly {DEK_LEN} bytes, got {}",
            dek.len()
        ));
    }
    Ok(dek)
}

// Reads and decodes the DEK from wherever the caller pointed us.
fn load_dek(source: &DekSource) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut text = match source {
        DekSource::Stdin => {
            let stdin = std::io::stdin();
            let mut locked = stdin.lock();
            read_bounded(&mut locked, "the DEK on stdin")?
        }
        DekSource::File(path) => read_dek_file(path)?,
    };
    let dek = decode_dek(&text);
    text.zeroize(); // the base64 text has served its only purpose; don't wait for scope exit
    dek
}

// Maps a hkdfguard_wrap_dek status code to a human-readable description,
// for a clearer error message than a bare integer.
fn describe_status(code: c_int) -> String {
    match code {
        status::INVALID_ARGUMENT => "invalid argument (bad DEK length, etc.)".to_string(),
        status::PROVIDER_UNAVAILABLE => "no KEK provider is available on this host".to_string(),
        status::PROVIDER_ERROR => "the selected KEK provider failed".to_string(),
        status::CRYPTO_ERROR => "a cryptographic operation failed".to_string(),
        status::INTERNAL_ERROR => "an internal error occurred in the hkdfguard library".to_string(),
        status::INVALID_SERVICE_NAME => "the service name is missing, empty, too long, or contains an invalid character".to_string(),
        status::KEK_NOT_FOUND => "no KEK exists yet for this service".to_string(),
        status::FINGERPRINT_MISMATCH => {
            "the wrapped payload's KEK fingerprint does not match the current KEK for this service".to_string()
        }
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

// Enforces that `--service-name` -- the string actually used as the KEK's
// identity -- contains only ASCII alphanumeric characters or '.', doesn't
// start with '.', and has no two consecutive dots: the same rules the
// library itself applies (see cstr_to_service in src/lib.rs), checked here
// too so the tool can give a specific message instead of a bare status code.
fn validate_service_charset(service: &str) -> Result<(), String> {
    if !service.chars().all(|c| c.is_ascii_alphanumeric() || c == '.') {
        return Err(format!(
            "service name \"{service}\" must contain only alphanumeric characters or '.'"
        ));
    }
    if service.starts_with('.') {
        return Err(format!("service name \"{service}\" must not start with '.'"));
    }
    if service.contains("..") {
        return Err(format!("service name \"{service}\" must not contain consecutive dots"));
    }
    Ok(())
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

    // `args.service_name` is not secret -- it's a logical identifier, not
    // key material -- so no special scoping is needed for it. Validated
    // before the DEK's own tightly-scoped block below. Lowercased to match
    // the library's own normalization (hkdfguard_wrap_dek/_unwrap_dek treat
    // the service name case-insensitively), so what's printed and recorded
    // here always reflects the actual KEK identity that gets used.
    if args.service_name.len() > MAX_SERVICE_LEN {
        return Err(format!(
            "--service-name must be at most {MAX_SERVICE_LEN} bytes, got {}",
            args.service_name.len()
        ));
    }
    validate_service_charset(&args.service_name)?;
    args.service_name.make_ascii_lowercase();
    let service_c = CString::new(args.service_name.clone())
        .map_err(|_| "the service name must not contain a NUL byte".to_string())?;

    // Provision the KEK before ever touching the secret DEK bytes below --
    // hkdfguard_wrap_dek no longer creates one itself, and this tool is the
    // one that initializes a service's very first key, so it's the right
    // place to do so. Idempotent: harmless if this service already has one.
    let rc = hkdfguard_create_kek(service_c.as_ptr());
    if rc != status::OK {
        return Err(format!("hkdfguard_create_kek failed: {}", describe_status(rc)));
    }

    let wrapped = {
        // The plaintext DEK is scoped as tightly as possible: read and
        // decode it, wrap it, and let `Zeroizing`'s `Drop` scrub it the
        // instant this block ends -- immediately after wrap_dek is done
        // with it, rather than at the end of run(), which would leave it
        // sitting in memory, unused but unwiped, through the final file
        // write below. `load_dek` wipes the base64 text it read on the way
        // out, so no copy of that survives this line either.
        let dek = load_dek(&args.dek_source)?;
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
        "wrapped key written to {} ({} bytes, service \"{}\")",
        args.key_file_path,
        wrapped.len(),
        args.service_name
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
        assert!(validate_service_charset("com.example.orders").is_ok());
        assert!(validate_service_charset("Service123.42").is_ok());
    }

    #[test]
    fn validate_service_charset_rejects_other_characters() {
        for bad in ["com_example", "com example", "com-example", "com/example"] {
            assert!(validate_service_charset(bad).is_err(), "should reject \"{bad}\"");
        }
    }

    #[test]
    fn validate_service_charset_rejects_leading_and_consecutive_dots() {
        for bad in [".", "..", "...", ".hidden", "..parent", "com..example", "com.example..", "a...b"] {
            assert!(validate_service_charset(bad).is_err(), "should reject \"{bad}\"");
        }
    }

    #[test]
    fn parse_args_requires_service_name() {
        let argv = ["prog", "key.bin", "--dek-stdin"].into_iter().map(String::from);
        assert!(parse_args(argv).is_err());
    }

    #[test]
    fn parse_args_accepts_stdin_and_file_sources() {
        let argv = ["prog", "key.bin", "-sn", "svc", "--dek-stdin"].into_iter().map(String::from);
        match parse_args(argv) {
            Ok(ParseOutcome::Run(args)) => assert_eq!(args.dek_source, DekSource::Stdin),
            _ => panic!("expected Run"),
        }

        let argv = ["prog", "key.bin", "-sn", "svc", "--dek-file", "/run/secrets/dek"]
            .into_iter()
            .map(String::from);
        match parse_args(argv) {
            Ok(ParseOutcome::Run(args)) => {
                assert_eq!(args.dek_source, DekSource::File("/run/secrets/dek".to_string()));
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn parse_args_requires_exactly_one_dek_source() {
        // None.
        let argv = ["prog", "key.bin", "-sn", "svc"].into_iter().map(String::from);
        assert!(parse_args(argv).is_err(), "a DEK source is mandatory");

        // Two -- rejected rather than last-one-wins, so an ambiguous
        // invocation can't quietly wrap the wrong key.
        let argv = ["prog", "key.bin", "-sn", "svc", "--dek-stdin", "--dek-file", "/x"]
            .into_iter()
            .map(String::from);
        assert!(parse_args(argv).is_err());

        let argv = ["prog", "key.bin", "-sn", "svc", "--dek-file", "/x", "--dek-file", "/y"]
            .into_iter()
            .map(String::from);
        assert!(parse_args(argv).is_err());
    }

    // `ParseOutcome` has no `Debug` impl (and `Args` deliberately doesn't
    // grow one), so pull the error out by matching rather than unwrap_err.
    fn expect_parse_err(args: impl Iterator<Item = String>) -> String {
        match parse_args(args) {
            Err(e) => e,
            Ok(_) => panic!("expected a parse error"),
        }
    }

    #[test]
    fn parse_args_rejects_the_removed_dek_flag_with_an_explanation() {
        for flag in ["--dek", "-d"] {
            let argv = ["prog", "key.bin", "-sn", "svc", flag, "AAAA"].into_iter().map(String::from);
            let err = expect_parse_err(argv);
            assert!(
                err.contains("cmdline") && err.contains("--dek-stdin"),
                "the error must explain why and point at the replacement, got: {err}"
            );
        }
    }

    // ---- DEK decoding ----

    fn valid_b64() -> String {
        STANDARD.encode([0x5au8; DEK_LEN])
    }

    #[test]
    fn decode_dek_accepts_base64_with_an_optional_trailing_newline() {
        let b64 = valid_b64();
        assert_eq!(*decode_dek(b64.as_bytes()).unwrap(), vec![0x5au8; DEK_LEN]);
        assert_eq!(*decode_dek(format!("{b64}\n").as_bytes()).unwrap(), vec![0x5au8; DEK_LEN]);
        assert_eq!(*decode_dek(format!("{b64}\r\n").as_bytes()).unwrap(), vec![0x5au8; DEK_LEN]);
    }

    #[test]
    fn decode_dek_rejects_bad_input() {
        assert!(decode_dek(b"").is_err(), "empty");
        assert!(decode_dek(b"\n").is_err(), "newline only");
        assert!(decode_dek(b"not base64!!").is_err(), "not base64");
        // Only one trailing newline is tolerated; a second is not base64.
        assert!(decode_dek(format!("{}\n\n", valid_b64()).as_bytes()).is_err());
        // Right encoding, wrong length.
        assert!(decode_dek(STANDARD.encode([0u8; 16]).as_bytes()).is_err(), "16 bytes");
        assert!(decode_dek(STANDARD.encode([0u8; 33]).as_bytes()).is_err(), "33 bytes");
        // Raw 32 bytes is not accepted as a silent alternative encoding.
        assert!(decode_dek(&[0x5au8; DEK_LEN]).is_err(), "raw bytes must not decode");
    }

    #[test]
    fn read_bounded_rejects_input_over_the_limit() {
        let too_long = vec![b'A'; MAX_DEK_INPUT_LEN + 1];
        assert!(read_bounded(&mut too_long.as_slice(), "test").is_err());

        let at_limit = vec![b'A'; MAX_DEK_INPUT_LEN];
        assert_eq!(read_bounded(&mut at_limit.as_slice(), "test").unwrap().len(), MAX_DEK_INPUT_LEN);
    }

    // ---- --dek-file hardening ----

    fn write_mode(dir: &Path, name: &str, contents: &[u8], mode: u32) -> std::path::PathBuf {
        let path = dir.join(name);
        fs::write(&path, contents).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn dek_file_accepts_an_owner_only_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_mode(dir.path(), "dek", valid_b64().as_bytes(), 0o600);
        let text = read_dek_file(path.to_str().unwrap()).unwrap();
        assert_eq!(*decode_dek(&text).unwrap(), vec![0x5au8; DEK_LEN]);
    }

    #[test]
    fn dek_file_rejects_group_or_world_accessible_permissions() {
        let dir = tempfile::tempdir().unwrap();
        for mode in [0o640, 0o604, 0o644, 0o660] {
            let path = write_mode(dir.path(), &format!("dek{mode:o}"), valid_b64().as_bytes(), mode);
            assert!(
                read_dek_file(path.to_str().unwrap()).is_err(),
                "mode {mode:o} must be rejected"
            );
        }
    }

    #[test]
    fn dek_file_rejects_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = write_mode(dir.path(), "real-dek", valid_b64().as_bytes(), 0o600);
        let link = dir.path().join("link-dek");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = read_dek_file(link.to_str().unwrap()).unwrap_err();
        assert!(err.contains("symlink"), "got: {err}");
    }

    #[test]
    fn dek_file_rejects_a_directory_and_a_missing_path() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_dek_file(dir.path().to_str().unwrap()).is_err());
        assert!(read_dek_file("/nonexistent-hkdfguard-dek-for-tests").is_err());
    }

    #[test]
    fn dek_file_rejects_an_oversized_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_mode(dir.path(), "big", &[b'A'; MAX_DEK_INPUT_LEN + 1], 0o600);
        assert!(read_dek_file(path.to_str().unwrap()).is_err());
    }

    #[test]
    fn load_dek_reads_from_a_file_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_mode(dir.path(), "dek", format!("{}\n", valid_b64()).as_bytes(), 0o400);
        let dek = load_dek(&DekSource::File(path.to_str().unwrap().to_string())).unwrap();
        assert_eq!(*dek, vec![0x5au8; DEK_LEN]);
    }
}
