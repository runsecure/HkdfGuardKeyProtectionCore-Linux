//! CLI tool for setting up a service's persistent KEK and wrapping DEKs
//! under it. Two subcommands, deliberately separate:
//!
//! - `provision` -- ensure a KEK exists for a service. This is the *only*
//!   place the setup calls (`hkdfguard_kek_exists`, `hkdfguard_create_kek`)
//!   are made. They are deliberately slow (see the library's setup-call
//!   latency floor) and meant to run once, at deployment time.
//! - `wrap` -- wrap a caller-supplied Data Encryption Key (DEK) under the
//!   service's KEK and write the wrapped payload to a file. It never
//!   creates a KEK: if none is provisioned, it fails and says to run
//!   `provision`. That keeps the fast, repeatable operation free of the
//!   setup calls, and makes "the KEK is missing" a loud, specific error
//!   instead of something quietly fixed on the fly.
//!
//! Both call into the `hkdfguard` library through its stable C ABI, the
//! same interface any other-language caller uses -- this tool takes no
//! shortcut through the library's internal Rust types.
//!
//! The KEK's `service` identity is exactly the caller-supplied
//! `--service-name`; there is no further structure to it.
//!
//! Usage:
//! ```text
//! hkdfguard-v1-initialize provision --service-name|-sn <name>
//!
//! hkdfguard-v1-initialize wrap \
//!     --key-file-path|-kf <path> \
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
//! printf '%s' "$DEK_B64" | hkdfguard-v1-initialize wrap -kf key.bin -sn svc --dek-stdin
//!
//! # file -- e.g. a Kubernetes/Vault secret mount or a systemd credential
//! hkdfguard-v1-initialize wrap -kf key.bin -sn svc --dek-file "$CREDENTIALS_DIRECTORY/dek"
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
//! ## Overwriting
//!
//! When `--force` replaces an existing file at `--key-file-path`, the wrap
//! is completed in memory *first*, and only then is the old file securely
//! overwritten in place and removed (see [`secure_delete`]). A wrap that
//! fails -- no KEK provisioned, provider unavailable, bad DEK input --
//! therefore never destroys the key file that was already there. The
//! secure overwrite is a best-effort measure against a plain read of the
//! disk: it cannot guarantee erasure on copy-on-write or log-structured
//! filesystems (e.g. btrfs, ZFS), or on flash storage doing wear-leveling
//! remaps, where the original blocks may still exist elsewhere.

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
use HkdfGuardKeyProtectionLinux::{
    hkdfguard_create_kek, hkdfguard_harden_process, hkdfguard_kek_exists, hkdfguard_wrap_dek, status,
};

// rw-------: the owning deployment user only. The payload is ciphertext,
// but anyone who can both read it and reach the provider (a `tss` group
// member, on a TPM host) can unwrap it, so group read is not the default.
// A deployment that wants a group to read it grants that deliberately.
const KEY_FILE_MODE: u32 = 0o600;

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

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Provision {
        service_name: String,
    },
    Wrap {
        key_file_path: String,
        service_name: String,
        dek_source: DekSource,
        force: bool,
    },
}

enum ParseOutcome {
    Run(Command),
    Help,
}

fn print_usage() {
    eprintln!(
        "Usage:\n\
         \x20 {PROGRAM_NAME} provision --service-name|-sn <name>\n\
         \x20 {PROGRAM_NAME} wrap --key-file-path|-kf <path> --service-name|-sn <name> (--dek-stdin | --dek-file <path>) [--force|-f]\n\
         \n\
         provision  ensures a KEK exists for the service. Run once, at deployment time;\n\
         \x20          this is the only command that makes the (deliberately slow) setup calls.\n\
         wrap       wraps a DEK under the service's existing KEK and writes the payload to\n\
         \x20          --key-file-path. Fails if the KEK has not been provisioned.\n\
         \n\
         The DEK is base64 of exactly 32 bytes, read from stdin or a file -- never\n\
         from a command-line argument or an environment variable, both of which are\n\
         readable by other processes of the same user.\n\
         \n\
         Examples:\n\
         \x20 {PROGRAM_NAME} provision -sn svc\n\
         \x20 printf '%s' \"$DEK_B64\" | {PROGRAM_NAME} wrap -kf key.bin -sn svc --dek-stdin\n\
         \x20 {PROGRAM_NAME} wrap -kf key.bin -sn svc --dek-file \"$CREDENTIALS_DIRECTORY/dek\""
    );
}

// Parses `--service-name|-sn <value>` when `arg` is that flag; the shared
// piece of both subcommands' argument loops.
fn take_service_name(arg: &str, args: &mut impl Iterator<Item = String>) -> Result<String, String> {
    let value = args.next().ok_or_else(|| format!("{arg} requires a value"))?;
    if value.is_empty() {
        return Err("--service-name must not be empty".to_string());
    }
    Ok(value)
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<ParseOutcome, String> {
    let mut args = args.skip(1); // skip argv[0]

    let subcommand = match args.next() {
        None => return Err("missing subcommand: expected `provision` or `wrap`".to_string()),
        Some(s) if s == "--help" || s == "-h" || s == "help" => return Ok(ParseOutcome::Help),
        Some(s) => s,
    };

    match subcommand.as_str() {
        "provision" => parse_provision(&mut args),
        "wrap" => parse_wrap(&mut args),
        other if !other.starts_with('-') && (other.contains('/') || other.ends_with(".key") || other.ends_with(".bin")) => Err(format!(
            "unknown subcommand {other:?}. The key file path is no longer positional: use `wrap --key-file-path|-kf {other}`"
        )),
        other => Err(format!("unknown subcommand {other:?}: expected `provision` or `wrap`")),
    }
}

fn parse_provision(args: &mut impl Iterator<Item = String>) -> Result<ParseOutcome, String> {
    let mut service_name: Option<String> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => return Ok(ParseOutcome::Help),
            "--service-name" | "-sn" => service_name = Some(take_service_name(&arg, args)?),
            "--key-file-path" | "-kf" | "--dek-stdin" | "--dek-file" | "--dek" | "-d" | "--force" | "-f" => {
                return Err(format!("{arg} is not valid for `provision`; it belongs to `wrap`"))
            }
            other => return Err(format!("unrecognized argument for `provision`: {other}")),
        }
    }

    let service_name = service_name.ok_or("provision: missing required --service-name|-sn")?;
    Ok(ParseOutcome::Run(Command::Provision { service_name }))
}

fn parse_wrap(args: &mut impl Iterator<Item = String>) -> Result<ParseOutcome, String> {
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

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => return Ok(ParseOutcome::Help),
            "--force" | "-f" => force = true,
            "--service-name" | "-sn" => service_name = Some(take_service_name(&arg, args)?),
            "--key-file-path" | "-kf" => {
                let value = args.next().ok_or_else(|| format!("{arg} requires a value"))?;
                if value.is_empty() {
                    return Err("--key-file-path must not be empty".to_string());
                }
                key_file_path = Some(value);
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
            other if !other.starts_with('-') => {
                return Err(format!(
                    "unexpected positional argument {other:?}: the key file path is given as --key-file-path|-kf"
                ))
            }
            other => return Err(format!("unrecognized argument for `wrap`: {other}")),
        }
    }

    let key_file_path = key_file_path.ok_or("wrap: missing required --key-file-path|-kf")?;
    let service_name = service_name.ok_or("wrap: missing required --service-name|-sn")?;
    let dek_source = dek_source.ok_or("wrap: missing required --dek-stdin or --dek-file <path>")?;

    Ok(ParseOutcome::Run(Command::Wrap {
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
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY) // a FIFO must fail the regular-file check below, not block the open
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

// Maps a library status code to a human-readable description, for a
// clearer error message than a bare integer.
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
        status::PROCESS_HARDENING_FAILED => {
            "could not disable core dumps / ptrace access for this process".to_string()
        }
        other => format!("unknown status code {other}"),
    }
}

// Wraps `dek` under `service`'s *existing* KEK. Never provisions one: a
// missing KEK is reported with the exact command that fixes it.
fn wrap_dek(service: &CString, service_display: &str, dek: &[u8]) -> Result<Vec<u8>, String> {
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

    if rc == status::KEK_NOT_FOUND {
        return Err(format!(
            "no KEK is provisioned for service \"{service_display}\"; run \
             `{PROGRAM_NAME} provision --service-name {service_display}` first"
        ));
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

// Validates and normalizes `--service-name` in place, returning it as the
// C string both subcommands hand to the library. Lowercased to match the
// library's own normalization (the ABI treats the name case-insensitively),
// so what's printed here always reflects the actual KEK identity used. Not
// secret -- a logical identifier, not key material.
fn prepare_service(service_name: &mut str) -> Result<CString, String> {
    if service_name.len() > MAX_SERVICE_LEN {
        return Err(format!(
            "--service-name must be at most {MAX_SERVICE_LEN} bytes, got {}",
            service_name.len()
        ));
    }
    validate_service_charset(service_name)?;
    service_name.make_ascii_lowercase();
    CString::new(&*service_name).map_err(|_| "the service name must not contain a NUL byte".to_string())
}

// Whether anything at all occupies `path` -- including a dangling symlink,
// which `Path::exists` (it follows links) reports as absent, and which the
// `create_new` below would then fail on with a misleading "already exists".
fn path_is_taken(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

// Largest existing file `--force` will overwrite. A wrapped key is a few
// hundred bytes; something far bigger at the key path isn't one, and
// overwriting it would also mean allocating and writing that much eight
// times over.
const MAX_REPLACEABLE_KEY_FILE_LEN: u64 = 64 * 1024;

// Overwrites `path`'s existing content in place for `SECURE_DELETE_ROUNDS`
// rounds -- each round first an all-zero-bit pass, then a pass of fresh
// random bits, fsync'd after every pass -- before unlinking it. Called only
// when `--force` is about to replace a file that already exists.
//
// Only ever a regular file, and only the one at `path` itself: a symlink
// there is refused rather than followed (following it would overwrite
// whatever it points at -- any file this user can write), as are a FIFO
// (which would block the open forever), a directory, and a device. The
// descriptor is opened `O_NOFOLLOW|O_NONBLOCK` and re-checked against what
// was examined, so nothing swapped in between gets overwritten either.
//
// If the file can't be opened for writing (EACCES/EPERM -- this tool
// doesn't own it), the overwrite passes are skipped entirely and this falls
// back to a plain `remove_file`, per explicit product direction: destroying
// the old bytes first is worth attempting, but not worth failing the whole
// command over when this process isn't even allowed to write to the file
// it's about to replace -- matches this project's macOS/Windows tools.
fn secure_delete(path: &Path) -> Result<(), String> {
    let refuse = |why: &str| format!("{} {why}; refusing to overwrite it", path.display());
    let check = |meta: &fs::Metadata| -> Result<usize, String> {
        if !meta.file_type().is_file() {
            return Err(refuse("is not a regular file (a symlink, directory, FIFO, or device)"));
        }
        if meta.len() > MAX_REPLACEABLE_KEY_FILE_LEN {
            return Err(refuse(&format!("is {} bytes, far larger than any wrapped key", meta.len())));
        }
        Ok(meta.len() as usize)
    };

    let examined = fs::symlink_metadata(path).map_err(|e| format!("failed to stat {}: {e}", path.display()))?;
    check(&examined)?;

    let mut file = match OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return fs::remove_file(path).map_err(|e| {
                format!("failed to remove {} after permission-denied secure delete: {e}", path.display())
            });
        }
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Err(refuse("changed to a symlink")),
        Err(e) => return Err(format!("failed to open {} for secure delete: {e}", path.display())),
    };
    let opened = file.metadata().map_err(|e| format!("failed to stat {}: {e}", path.display()))?;
    if (opened.dev(), opened.ino()) != (examined.dev(), examined.ino()) {
        return Err(refuse("was replaced while it was being examined"));
    }
    let len = check(&opened)?;

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

// `provision`: the only place the setup calls are made. Checks first so
// the outcome can be reported precisely -- "already provisioned" versus
// "provisioned now" -- and so an existing KEK is never touched.
fn run_provision(mut service_name: String) -> Result<(), String> {
    let service_c = prepare_service(&mut service_name)?;

    let mut exists: c_int = 0;
    let rc = hkdfguard_kek_exists(service_c.as_ptr(), &mut exists);
    if rc != status::OK {
        return Err(format!("hkdfguard_kek_exists failed: {}", describe_status(rc)));
    }
    if exists == 1 {
        println!("KEK already provisioned for service \"{service_name}\"; nothing to do");
        return Ok(());
    }

    let rc = hkdfguard_create_kek(service_c.as_ptr());
    if rc != status::OK {
        return Err(format!(
            "hkdfguard_create_kek failed: {} (see the messages above for the provider's reason)",
            describe_status(rc)
        ));
    }
    println!("KEK provisioned for service \"{service_name}\"");
    Ok(())
}

// `wrap`: no setup calls. The wrap is completed in memory before the
// existing key file (if any) is touched, so a failure -- most likely "no
// KEK provisioned" -- never costs the caller the key file they had.
fn run_wrap(key_file_path: String, mut service_name: String, dek_source: DekSource, force: bool) -> Result<(), String> {
    let path = Path::new(&key_file_path);

    // Fast, friendly pre-check: fail before reading the DEK or touching
    // the provider if the output path obviously already exists and --force
    // wasn't passed. The final `create_new` open below is the actual
    // correctness guarantee against the exists-then-create race; this is
    // purely a fail-fast convenience on top of it.
    if path_is_taken(path) && !force {
        return Err(format!("{key_file_path} already exists; pass --force|-f to overwrite"));
    }

    let service_c = prepare_service(&mut service_name)?;

    let wrapped = {
        // The plaintext DEK is scoped as tightly as possible: read and
        // decode it, wrap it, and let `Zeroizing`'s `Drop` scrub it the
        // instant this block ends -- immediately after wrap_dek is done
        // with it, rather than at the end of this function, which would
        // leave it sitting in memory, unused but unwiped, through the file
        // write below. `load_dek` wipes the base64 text it read on the way
        // out, so no copy of that survives this line either.
        let dek = load_dek(&dek_source)?;
        wrap_dek(&service_c, &service_name, &dek)?
        // `dek`'s `Zeroizing` wrapper zeroes it here, as this block ends --
        // immediately after wrap_dek returns the wrapped (encrypted, no
        // longer secret) form, which is the only thing that survives past
        // this point.
    };

    // Only now, with a complete wrapped payload in hand, replace the old
    // file. Re-evaluated here rather than trusting the pre-check above, in
    // case the file appeared in the meantime.
    if path_is_taken(path) {
        if !force {
            return Err(format!("{key_file_path} already exists; pass --force|-f to overwrite"));
        }
        secure_delete(path)?;
    }

    // `create_new` makes "does this file already exist" and "create it"
    // one indivisible kernel operation (the actual correctness guarantee
    // against the exists-then-create race), and `.mode(KEY_FILE_MODE)`
    // sets the permissions at the moment of creation so there's no window
    // where the file briefly exists with broader (umask-derived)
    // permissions before being locked down after the fact. By the time
    // this runs, `path` is always either brand new or was just deleted by
    // `secure_delete` above, so `set_permissions` below is defense-in-depth
    // against the umask, not strictly required.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(KEY_FILE_MODE)
        .open(&key_file_path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                format!("{key_file_path} already exists; pass --force|-f to overwrite")
            } else {
                format!("failed to open {key_file_path}: {e}")
            }
        })?;
    file.write_all(&wrapped)
        .map_err(|e| format!("failed to write {key_file_path}: {e}"))?;
    file.set_permissions(fs::Permissions::from_mode(KEY_FILE_MODE))
        .map_err(|e| format!("failed to set permissions on {key_file_path}: {e}"))?;

    println!(
        "wrapped key written to {key_file_path} ({} bytes, service \"{service_name}\")",
        wrapped.len()
    );
    Ok(())
}

fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Provision { service_name } => run_provision(service_name),
        Command::Wrap {
            key_file_path,
            service_name,
            dek_source,
            force,
        } => run_wrap(key_file_path, service_name, dek_source, force),
    }
}

// `CAP_IPC_LOCK`'s bit in the capability sets of /proc/self/status.
#[cfg(any(target_os = "linux", test))]
const CAP_IPC_LOCK: u32 = 14;

// Whether `mlockall(MCL_CURRENT | MCL_FUTURE)` is safe to apply: only when
// no RLIMIT_MEMLOCK can ever be hit. With a finite limit the kernel either
// refuses MCL_CURRENT outright (virtual size over the limit -- harmless,
// nothing is applied) or accepts it, after which MCL_FUTURE makes any
// allocation that would cross the limit fail and the process abort
// mid-operation. CAP_IPC_LOCK bypasses the limit; so does an unlimited one.
#[cfg(any(target_os = "linux", test))]
fn memory_lock_is_unbounded(cap_eff: Option<u64>, memlock_soft: u64, memlock_hard: u64, infinity: u64) -> bool {
    let has_ipc_lock = cap_eff.is_some_and(|caps| caps & (1u64 << CAP_IPC_LOCK) != 0);
    has_ipc_lock || (memlock_soft == infinity && memlock_hard == infinity)
}

// The effective capability set, from the `CapEff:` line of a
// /proc/<pid>/status document. `None` if absent or malformed.
#[cfg(any(target_os = "linux", test))]
fn parse_cap_eff(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
}

// Keeps this process's memory -- the plaintext DEK included -- out of swap.
// Applied only when it can't later abort an allocation (see
// `memory_lock_is_unbounded`); otherwise skipped with a warning, since
// default limits for unprivileged users would make it fail or, worse,
// succeed and then kill the process. If it should work and doesn't, that
// is an error.
#[cfg(target_os = "linux")]
fn lock_memory() -> Result<(), String> {
    let cap_eff = fs::read_to_string("/proc/self/status").ok().as_deref().and_then(parse_cap_eff);
    let mut memlock = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: getrlimit writes into a valid rlimit.
    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut memlock) } != 0 {
        return Err(format!("could not read RLIMIT_MEMLOCK: {}", std::io::Error::last_os_error()));
    }

    if !memory_lock_is_unbounded(cap_eff, memlock.rlim_cur, memlock.rlim_max, libc::RLIM_INFINITY) {
        eprintln!(
            "warning: memory not locked: needs CAP_IPC_LOCK or an unlimited RLIMIT_MEMLOCK \
             (e.g. run as root, or LimitMEMLOCK=infinity for a systemd unit); key material in \
             this process could be written to swap"
        );
        return Ok(());
    }

    // SAFETY: mlockall takes only flags.
    if unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) } != 0 {
        return Err(format!(
            "could not lock memory (mlockall): {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn lock_memory() -> Result<(), String> {
    Ok(())
}

// Prints the library's warnings and errors to stderr. The library reports
// through the `log` facade and is silent without a logger installed, which
// would hide exactly the messages an operator running this tool needs --
// e.g. the TPM Name to pin when `provision` is refused under
// `tpm.require_pinned_names`, or why a PIN file or secret was rejected.
struct StderrLogger;

impl log::Log for StderrLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Warn
    }
    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            eprintln!("{}: {}", record.level().as_str().to_ascii_lowercase(), record.args());
        }
    }
    fn flush(&self) {}
}

static LOGGER: StderrLogger = StderrLogger;

fn main() -> ExitCode {
    if log::set_logger(&LOGGER).is_ok() {
        log::set_max_level(log::LevelFilter::Warn);
    }
    // Before anything is read: this process holds a plaintext DEK, so it
    // must not be dumpable or debuggable by other processes of the same
    // user. Refuse to run rather than handle a DEK unprotected.
    let rc = hkdfguard_harden_process();
    if rc != status::OK {
        eprintln!("error: {}; refusing to handle key material", describe_status(rc));
        return ExitCode::FAILURE;
    }
    if let Err(e) = lock_memory() {
        eprintln!("error: {e}; refusing to handle key material");
        return ExitCode::FAILURE;
    }
    match parse_args(std::env::args()) {
        Ok(ParseOutcome::Help) => {
            print_usage();
            ExitCode::SUCCESS
        }
        Ok(ParseOutcome::Run(command)) => match run(command) {
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
    use serial_test::serial;
    use tempfile::NamedTempFile;

    // Only this user can write to it, whatever the umask: the library refuses
    // to trust a policy or secret mount in a group-writable directory.
    fn private_tempdir() -> tempfile::TempDir {
        tempfile::Builder::new().permissions(fs::Permissions::from_mode(0o700)).tempdir().unwrap()
    }

    fn argv(parts: &[&str]) -> impl Iterator<Item = String> {
        parts.iter().map(|s| s.to_string()).collect::<Vec<_>>().into_iter()
    }

    // `ParseOutcome` has no `Debug` impl, so pull results out by matching.
    fn expect_run(args: impl Iterator<Item = String>) -> Command {
        match parse_args(args) {
            Ok(ParseOutcome::Run(c)) => c,
            Ok(ParseOutcome::Help) => panic!("expected Run, got Help"),
            Err(e) => panic!("expected Run, got error: {e}"),
        }
    }
    fn expect_parse_err(args: impl Iterator<Item = String>) -> String {
        match parse_args(args) {
            Err(e) => e,
            Ok(_) => panic!("expected a parse error"),
        }
    }

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
    fn secure_delete_refuses_a_symlink_and_leaves_its_target_alone() {
        let dir = private_tempdir();
        let victim = dir.path().join("some-other-file");
        fs::write(&victim, b"not a wrapped key").unwrap();
        let link = dir.path().join("wrapped.key");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        let err = secure_delete(&link).unwrap_err();
        assert!(err.contains("not a regular file"), "unexpected: {err}");
        assert_eq!(fs::read(&victim).unwrap(), b"not a wrapped key", "the link's target must be untouched");
        assert!(path_is_taken(&link), "and the link itself is left for the operator to look at");
    }

    #[test]
    fn secure_delete_refuses_a_fifo_without_blocking() {
        let dir = private_tempdir();
        let fifo = dir.path().join("wrapped.key");
        let c = CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: c is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);

        let (tx, rx) = std::sync::mpsc::channel();
        let path = fifo.clone();
        std::thread::spawn(move || tx.send(secure_delete(&path)).unwrap());
        let result = rx.recv_timeout(std::time::Duration::from_secs(5)).expect("secure_delete blocked on a FIFO");
        assert!(result.unwrap_err().contains("not a regular file"));
    }

    #[test]
    fn secure_delete_refuses_a_file_far_larger_than_a_wrapped_key() {
        let dir = private_tempdir();
        let big = dir.path().join("wrapped.key");
        let f = File::create(&big).unwrap();
        f.set_len(MAX_REPLACEABLE_KEY_FILE_LEN + 1).unwrap(); // sparse: no real disk use
        let err = secure_delete(&big).unwrap_err();
        assert!(err.contains("far larger"), "unexpected: {err}");
        assert!(big.exists());
    }

    #[test]
    fn a_dangling_symlink_counts_as_taken() {
        let dir = private_tempdir();
        let link = dir.path().join("wrapped.key");
        std::os::unix::fs::symlink(dir.path().join("nowhere"), &link).unwrap();
        assert!(!link.exists(), "Path::exists follows the link");
        assert!(path_is_taken(&link));
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

    // ---- subcommand parsing ----

    #[test]
    fn parse_requires_a_subcommand() {
        let err = expect_parse_err(argv(&["prog"]));
        assert!(err.contains("provision") && err.contains("wrap"), "{err}");

        let err = expect_parse_err(argv(&["prog", "frobnicate", "-sn", "svc"]));
        assert!(err.contains("unknown subcommand"), "{err}");
    }

    #[test]
    fn parse_help_in_every_position() {
        for args in [
            vec!["prog", "--help"],
            vec!["prog", "-h"],
            vec!["prog", "help"],
            vec!["prog", "provision", "--help"],
            vec!["prog", "wrap", "-kf", "k", "-h"],
        ] {
            assert!(matches!(parse_args(argv(&args)), Ok(ParseOutcome::Help)), "{args:?}");
        }
    }

    #[test]
    fn old_positional_key_file_form_is_rejected_with_a_pointer_to_the_new_flag() {
        // The pre-subcommand invocation put the key file first. It must
        // fail -- and say what to do instead -- rather than being read as
        // a subcommand name.
        let err = expect_parse_err(argv(&["prog", "key.bin", "-sn", "svc", "--dek-stdin"]));
        assert!(err.contains("--key-file-path"), "{err}");

        let err = expect_parse_err(argv(&["prog", "/var/lib/app/wrapped", "-sn", "svc", "--dek-stdin"]));
        assert!(err.contains("--key-file-path"), "{err}");

        // And a stray positional inside `wrap` is refused the same way.
        let err = expect_parse_err(argv(&["prog", "wrap", "key.bin", "-sn", "svc", "--dek-stdin"]));
        assert!(err.contains("--key-file-path"), "{err}");
    }

    #[test]
    fn parse_provision() {
        assert_eq!(
            expect_run(argv(&["prog", "provision", "--service-name", "svc"])),
            Command::Provision { service_name: "svc".to_string() }
        );
        assert_eq!(
            expect_run(argv(&["prog", "provision", "-sn", "svc"])),
            Command::Provision { service_name: "svc".to_string() }
        );

        let err = expect_parse_err(argv(&["prog", "provision"]));
        assert!(err.contains("--service-name"), "{err}");
        let err = expect_parse_err(argv(&["prog", "provision", "-sn", ""]));
        assert!(err.contains("empty"), "{err}");
    }

    #[test]
    fn provision_refuses_wrap_only_flags() {
        for flag in [
            vec!["--key-file-path", "k"],
            vec!["-kf", "k"],
            vec!["--dek-stdin"],
            vec!["--dek-file", "/x"],
            vec!["--force"],
        ] {
            let mut a = vec!["prog", "provision", "-sn", "svc"];
            a.extend(flag.iter());
            let err = expect_parse_err(argv(&a));
            assert!(err.contains("belongs to `wrap`"), "{flag:?}: {err}");
        }
    }

    #[test]
    fn parse_wrap_accepts_stdin_and_file_sources() {
        match expect_run(argv(&["prog", "wrap", "-kf", "key.bin", "-sn", "svc", "--dek-stdin"])) {
            Command::Wrap { key_file_path, service_name, dek_source, force } => {
                assert_eq!(key_file_path, "key.bin");
                assert_eq!(service_name, "svc");
                assert_eq!(dek_source, DekSource::Stdin);
                assert!(!force);
            }
            other => panic!("expected Wrap, got {other:?}"),
        }

        match expect_run(argv(&[
            "prog", "wrap", "--key-file-path", "key.bin", "--service-name", "svc", "--dek-file", "/run/secrets/dek", "--force",
        ])) {
            Command::Wrap { dek_source, force, .. } => {
                assert_eq!(dek_source, DekSource::File("/run/secrets/dek".to_string()));
                assert!(force);
            }
            other => panic!("expected Wrap, got {other:?}"),
        }
    }

    #[test]
    fn parse_wrap_requires_key_file_service_and_exactly_one_dek_source() {
        let err = expect_parse_err(argv(&["prog", "wrap", "-sn", "svc", "--dek-stdin"]));
        assert!(err.contains("--key-file-path"), "{err}");

        let err = expect_parse_err(argv(&["prog", "wrap", "-kf", "k", "--dek-stdin"]));
        assert!(err.contains("--service-name"), "{err}");

        let err = expect_parse_err(argv(&["prog", "wrap", "-kf", "k", "-sn", "svc"]));
        assert!(err.contains("--dek-stdin"), "a DEK source is mandatory: {err}");

        // Two sources -- rejected rather than last-one-wins, so an
        // ambiguous invocation can't quietly wrap the wrong key.
        assert!(parse_args(argv(&["prog", "wrap", "-kf", "k", "-sn", "svc", "--dek-stdin", "--dek-file", "/x"])).is_err());
        assert!(parse_args(argv(&["prog", "wrap", "-kf", "k", "-sn", "svc", "--dek-file", "/x", "--dek-file", "/y"])).is_err());
    }

    #[test]
    fn parse_wrap_rejects_the_removed_dek_flag_with_an_explanation() {
        for flag in ["--dek", "-d"] {
            let err = expect_parse_err(argv(&["prog", "wrap", "-kf", "k", "-sn", "svc", flag, "AAAA"]));
            assert!(
                err.contains("cmdline") && err.contains("--dek-stdin"),
                "the error must explain why and point at the replacement, got: {err}"
            );
        }
    }

    // ---- provision / wrap against the real library, in-process ----

    // Points the library at a policy that names Ephemeral (the only
    // provider that can *create* a KEK without external state) and at no
    // external-secret mount. Ephemeral keys are per-process, which is
    // exactly right for an in-process test of the provision flow.
    fn with_ephemeral_policy<F: FnOnce()>(f: F) {
        let dir = private_tempdir();
        let policy = dir.path().join("policy.toml");
        fs::write(&policy, "preferred_order = [\"external-secret\", \"ephemeral\"]\n[selection]\nmode = \"prefer\"\n").unwrap();
        fs::set_permissions(&policy, fs::Permissions::from_mode(0o644)).unwrap(); // not the umask: some distros default to 002 (group-writable), which the policy loader correctly refuses
        std::env::set_var("HKDFGUARD_POLICY_FILE", &policy);
        f();
        std::env::remove_var("HKDFGUARD_POLICY_FILE");
    }

    #[test]
    #[serial]
    #[cfg_attr(not(hkdfguard_test_paths), ignore = "needs a library that reads its own policy: RUSTFLAGS=\"--cfg hkdfguard_test_paths\" (the test scripts set it)")]
    fn provision_creates_then_reports_already_provisioned() {
        // Pays the library's real setup-call floor (this binary links the
        // library without cfg(test)): kek_exists + create_kek, then
        // kek_exists again -- a few seconds, once.
        with_ephemeral_policy(|| {
            let service = "com.hkdfguard.clitest.provision".to_string();
            run_provision(service.clone()).expect("first provision must create the KEK");
            run_provision(service).expect("second provision must be a no-op success");
        });
    }

    #[test]
    #[serial]
    #[cfg_attr(not(hkdfguard_test_paths), ignore = "needs a library that reads its own policy: RUSTFLAGS=\"--cfg hkdfguard_test_paths\" (the test scripts set it)")]
    fn wrap_without_a_provisioned_kek_fails_with_the_provision_hint_and_touches_nothing() {
        with_ephemeral_policy(|| {
            let dir = private_tempdir();
            let key_path = dir.path().join("wrapped.key");
            fs::write(&key_path, b"the key file that was already here").unwrap();

            let dek_path = dir.path().join("dek.b64");
            fs::write(&dek_path, STANDARD.encode([0x5au8; DEK_LEN])).unwrap();
            fs::set_permissions(&dek_path, fs::Permissions::from_mode(0o600)).unwrap();

            // --force is given, and the KEK is missing: the old file must
            // survive, because the wrap fails before it is ever touched.
            let err = run_wrap(
                key_path.to_str().unwrap().to_string(),
                "com.hkdfguard.clitest.neverprovisioned".to_string(),
                DekSource::File(dek_path.to_str().unwrap().to_string()),
                true,
            )
            .unwrap_err();
            assert!(err.contains("provision --service-name"), "must point at the fix: {err}");
            assert_eq!(fs::read(&key_path).unwrap(), b"the key file that was already here");
        });
    }

    #[test]
    #[serial]
    #[cfg_attr(not(hkdfguard_test_paths), ignore = "needs a library that reads its own policy: RUSTFLAGS=\"--cfg hkdfguard_test_paths\" (the test scripts set it)")]
    fn provision_then_wrap_round_trip_in_process() {
        with_ephemeral_policy(|| {
            let service = "com.hkdfguard.clitest.roundtrip".to_string();
            run_provision(service.clone()).unwrap();

            let dir = private_tempdir();
            let key_path = dir.path().join("wrapped.key");
            let dek_path = dir.path().join("dek.b64");
            fs::write(&dek_path, STANDARD.encode([0x5au8; DEK_LEN])).unwrap();
            fs::set_permissions(&dek_path, fs::Permissions::from_mode(0o600)).unwrap();

            run_wrap(
                key_path.to_str().unwrap().to_string(),
                service,
                DekSource::File(dek_path.to_str().unwrap().to_string()),
                false,
            )
            .unwrap();
            assert!(key_path.exists());
            assert_eq!(fs::metadata(&key_path).unwrap().permissions().mode() & 0o777, KEY_FILE_MODE);
        });
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

    // ---- memory locking decision ----

    const INF: u64 = u64::MAX;

    #[test]
    fn cap_eff_is_parsed_from_proc_status() {
        let status = "Name:\tx\nCapInh:\t0000000000000000\nCapEff:\t000001ffffffffff\nCapBnd:\t0\n";
        assert_eq!(parse_cap_eff(status), Some(0x1ff_ffff_ffff));
        assert_eq!(parse_cap_eff("Name:\tx\n"), None);
        assert_eq!(parse_cap_eff("CapEff:\tnothex\n"), None);
    }

    #[test]
    fn memory_is_locked_only_when_no_limit_can_be_hit() {
        let ipc_lock = Some(1u64 << CAP_IPC_LOCK);
        let other_caps = Some(!(1u64 << CAP_IPC_LOCK));

        assert!(memory_lock_is_unbounded(ipc_lock, 65536, 65536, INF), "CAP_IPC_LOCK bypasses any limit");
        assert!(memory_lock_is_unbounded(Some(0), INF, INF, INF), "an unlimited RLIMIT_MEMLOCK is safe");
        assert!(memory_lock_is_unbounded(None, INF, INF, INF), "unlimited is safe even if caps are unreadable");

        // A finite limit without the capability: MCL_FUTURE could abort a
        // later allocation, so skip.
        assert!(!memory_lock_is_unbounded(other_caps, 8 << 20, 8 << 20, INF));
        assert!(!memory_lock_is_unbounded(Some(0), 1 << 30, INF, INF), "a finite soft limit still binds");
        assert!(!memory_lock_is_unbounded(None, 65536, 65536, INF));
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
        let dir = private_tempdir();
        let path = write_mode(dir.path(), "dek", valid_b64().as_bytes(), 0o600);
        let text = read_dek_file(path.to_str().unwrap()).unwrap();
        assert_eq!(*decode_dek(&text).unwrap(), vec![0x5au8; DEK_LEN]);
    }

    #[test]
    fn dek_file_rejects_group_or_world_accessible_permissions() {
        let dir = private_tempdir();
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
        let dir = private_tempdir();
        let target = write_mode(dir.path(), "real-dek", valid_b64().as_bytes(), 0o600);
        let link = dir.path().join("link-dek");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = read_dek_file(link.to_str().unwrap()).unwrap_err();
        assert!(err.contains("symlink"), "got: {err}");
    }

    #[test]
    fn dek_file_rejects_a_directory_and_a_missing_path() {
        let dir = private_tempdir();
        assert!(read_dek_file(dir.path().to_str().unwrap()).is_err());
        assert!(read_dek_file("/nonexistent-hkdfguard-dek-for-tests").is_err());
    }

    #[test]
    fn dek_file_rejects_an_oversized_file() {
        let dir = private_tempdir();
        let path = write_mode(dir.path(), "big", &[b'A'; MAX_DEK_INPUT_LEN + 1], 0o600);
        assert!(read_dek_file(path.to_str().unwrap()).is_err());
    }

    #[test]
    fn load_dek_reads_from_a_file_end_to_end() {
        let dir = private_tempdir();
        let path = write_mode(dir.path(), "dek", format!("{}\n", valid_b64()).as_bytes(), 0o400);
        let dek = load_dek(&DekSource::File(path.to_str().unwrap().to_string())).unwrap();
        assert_eq!(*dek, vec![0x5au8; DEK_LEN]);
    }
}
