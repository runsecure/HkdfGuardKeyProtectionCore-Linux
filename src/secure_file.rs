//! Hardened reads of security-sensitive files (the administrative policy,
//! the PKCS#11 PIN, externally provisioned KEK material) and a buffer type
//! that guarantees what was read is wiped once it's no longer needed.
//!
//! Two properties every caller relies on:
//!
//! - **Checks are made on the opened descriptor, not the path.** Ownership,
//!   permission bits, and "is this a regular file" come from `fstat` on the
//!   file that was actually opened, so nothing can swap the path between a
//!   check and the read.
//! - **Secret bytes are never left behind in freed memory.** [`SecretBuffer`]
//!   reads into a single, fixed-size allocation made up front -- it never
//!   grows, so there are no intermediate buffers freed un-wiped the way
//!   `Read::read_to_end` leaves them -- and zeroes that whole allocation
//!   (including unused capacity) on [`SecretBuffer::wipe`] and on drop.

use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

/// Who a checked file must be owned by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    /// uid 0 only.
    Root,
    /// uid 0, or this process's effective uid.
    RootOrCurrentUser,
}

/// Who must own configuration this process reads but must not be able to
/// change: the policy file, the PKCS#11 PIN file, the TPM derivation
/// secret, and the directories they live in.
///
/// Every build that ships requires root. Accepting the service's own uid would let
/// any process running as that uid rewrite them -- and under Yama
/// `ptrace_scope >= 1` or in a container without `CAP_SYS_PTRACE`, such a
/// process can rewrite the service's files without being able to read its
/// memory. Rewriting the policy redirects every future wrap to a KEK the
/// writer controls; rewriting the PIN locks the HSM user out; rewriting the
/// derivation secret changes every TPM KEK. Test builds (`cfg(test)`, or
/// the harnesses' `--cfg hkdfguard_test_paths`) also accept this process's
/// own uid, so tests can use temp files; no ordinary build setting --
/// debug profile included -- relaxes it.
pub const fn config_owner() -> Owner {
    if cfg!(any(test, hkdfguard_test_paths)) {
        Owner::RootOrCurrentUser
    } else {
        Owner::Root
    }
}

/// Permission bits that must be clear: nobody but the owner may write.
pub const FORBID_GROUP_OTHER_WRITE: u32 = 0o022;
/// Permission bits that must be clear: nobody but the owner may read, write, or execute.
pub const FORBID_GROUP_OTHER_ACCESS: u32 = 0o077;

const GROUP_READ: u32 = 0o040;
const STICKY: u32 = 0o1000;

/// What a file must satisfy before its contents are trusted.
#[derive(Debug, Clone, Copy)]
pub struct FileRequirements {
    /// `None` skips the ownership check.
    pub owner: Option<Owner>,
    /// Any of these mode bits being set rejects the file.
    pub forbidden_mode_bits: u32,
    /// `false` opens with `O_NOFOLLOW`: a symlink as the final path
    /// component fails the open (ELOOP) instead of being followed.
    pub follow_symlinks: bool,
    /// Exempts group read from `forbidden_mode_bits` when the file is owned
    /// by root. `root:<service-group> 0440` is how a root-owned secret is
    /// made readable by a non-root service; on a file the service owns
    /// itself, group read would only leak it to other group members.
    pub allow_group_read_if_root_owned: bool,
}

/// Opens `path` read-only and validates it against `req` using the opened
/// descriptor's own metadata. Only ever returns `ErrorKind::NotFound` when
/// the file genuinely doesn't exist; a file that exists but fails a check
/// is reported as `PermissionDenied` or `InvalidData`, so callers can tell
/// "absent" apart from "present but untrustworthy".
pub fn open_checked(path: &Path, req: &FileRequirements) -> io::Result<File> {
    // O_NONBLOCK: opening a FIFO with no writer would otherwise block in
    // open(2) itself -- before the descriptor could be checked -- hanging
    // the caller (and, for a setup call, everything queued behind it). With
    // it, the open returns at once and the regular-file check below refuses
    // it. It has no effect on reading a regular file. O_NOCTTY: a terminal
    // device must not become this process's controlling terminal.
    let mut flags = libc::O_NONBLOCK | libc::O_NOCTTY;
    if !req.follow_symlinks {
        flags |= libc::O_NOFOLLOW;
    }
    let mut opts = OpenOptions::new();
    opts.read(true).custom_flags(flags);
    let file = opts.open(path)?;
    let meta = file.metadata()?;
    let mut forbidden = req.forbidden_mode_bits;
    if req.allow_group_read_if_root_owned && meta.uid() == 0 {
        forbidden &= !GROUP_READ;
    }
    check_metadata(&meta, req.owner, forbidden)?;
    Ok(file)
}

/// Checks that nobody `owner` doesn't cover can rename, replace, or delete
/// anything beneath `dir`: `dir` and every ancestor up to `/` must be a
/// directory owned per `owner`. `dir` itself must not be writable by group
/// or others. An ancestor may be, if it is sticky (`/tmp`-style): the
/// kernel then lets only an entry's owner or the directory's owner rename
/// or remove it, and the entry beneath was itself just checked. Write bits
/// are ignored on a read-only mount (e.g. a Kubernetes Secret or ConfigMap
/// volume, which is `1777` but mounted read-only).
///
/// With the target file's own ownership also checked, this means nobody
/// untrusted can swap the path between this check and a later open or
/// `dlopen` of it by path.
///
/// `dir` must be canonical (no symlinks). Every failure, including one
/// from a directory vanishing mid-walk, is `PermissionDenied` -- never
/// `NotFound`, which callers reserve for "the file isn't there".
pub fn check_dir_chain(dir: &Path, owner: Owner) -> io::Result<()> {
    for (i, d) in dir.ancestors().enumerate() {
        let fail = |what: String| io::Error::new(io::ErrorKind::PermissionDenied, format!("directory {}: {what}", d.display()));
        let meta = std::fs::metadata(d).map_err(|e| fail(e.to_string()))?;
        if !meta.is_dir() {
            return Err(fail("not a directory".to_string()));
        }
        check_owner_and_mode(&meta, Some(owner), 0).map_err(|e| fail(e.to_string()))?;

        let mode = meta.mode();
        let writable = mode & FORBID_GROUP_OTHER_WRITE != 0;
        let protected_by_sticky = i > 0 && mode & STICKY != 0;
        if writable && !protected_by_sticky && !on_read_only_mount(d) {
            return Err(fail(format!(
                "writable by group or others (mode {:o}), so its entries can be replaced",
                mode & 0o7777
            )));
        }
    }
    Ok(())
}

fn on_read_only_mount(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: c_path is a valid NUL-terminated string; `st` is a properly
    // sized out-parameter that statvfs fully initializes on success.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut st) } != 0 {
        return false;
    }
    st.f_flag & libc::ST_RDONLY != 0
}

/// Checks that nobody `owner` doesn't cover can delete, rename, or replace
/// `path` or make it resolve elsewhere: the directory `path` is named in
/// (or, while that doesn't exist, its nearest existing ancestor), and the
/// directory of whatever `path` currently resolves to, must each pass
/// [`check_dir_chain`].
///
/// Checking where a file *would* be, not just where it is, matters for
/// files whose absence is meaningful: a missing policy means "no policy",
/// so if an untrusted user could delete it, they could switch policy off.
pub fn check_location(path: &Path, owner: Owner) -> io::Result<()> {
    let denied = |what: String| io::Error::new(io::ErrorKind::PermissionDenied, what);

    let named_in = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let existing = named_in
        .ancestors()
        .find(|d| !d.as_os_str().is_empty() && d.exists())
        .unwrap_or(Path::new("."));
    let existing = std::fs::canonicalize(existing).map_err(|e| denied(format!("{}: {e}", existing.display())))?;
    check_dir_chain(&existing, owner)?;

    match std::fs::canonicalize(path) {
        Ok(target) => match target.parent() {
            Some(target_dir) if target_dir != existing => check_dir_chain(target_dir, owner),
            _ => Ok(()),
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()), // absent, or a dangling link: the open reports it
        Err(e) => Err(denied(format!("{}: {e}", path.display()))),
    }
}

/// Validates already-obtained metadata: must be a regular file (never a
/// directory, FIFO, device, or socket), owned per `owner`, with none of
/// `forbidden_mode_bits` set.
pub fn check_metadata(meta: &Metadata, owner: Option<Owner>, forbidden_mode_bits: u32) -> io::Result<()> {
    if !meta.file_type().is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not a regular file"));
    }
    check_owner_and_mode(meta, owner, forbidden_mode_bits)
}

/// Ownership + permission-bit check alone, for callers validating
/// something other than a regular file (e.g. a directory).
pub fn check_owner_and_mode(meta: &Metadata, owner: Option<Owner>, forbidden_mode_bits: u32) -> io::Result<()> {
    if let Some(owner) = owner {
        let uid = meta.uid();
        // SAFETY: geteuid takes no arguments and cannot fail.
        let euid = unsafe { libc::geteuid() };
        let ok = match owner {
            Owner::Root => uid == 0,
            Owner::RootOrCurrentUser => uid == 0 || uid == euid,
        };
        if !ok {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("owned by uid {uid}, which is not an allowed owner"),
            ));
        }
    }
    let offending = meta.mode() & forbidden_mode_bits;
    if offending != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("permissions too broad (mode {:o}; bits {offending:o} must be clear)", meta.mode() & 0o7777),
        ));
    }
    Ok(())
}

/// A byte buffer for secret file contents that is guaranteed to be zeroed
/// once it's no longer needed: explicitly via [`SecretBuffer::wipe`] as
/// soon as the caller is done with it, and unconditionally on drop -- so
/// every early-return or error path clears it too.
pub struct SecretBuffer {
    bytes: Zeroizing<Vec<u8>>,
}

impl SecretBuffer {
    /// Reads all of `file` into one allocation of exactly `max_len + 1`
    /// bytes made before the first read. The allocation never grows, so no
    /// partially-filled intermediate buffer is ever freed with secret bytes
    /// still in it. A file longer than `max_len` is rejected (and the
    /// partial read wiped) rather than truncated.
    pub fn read_from(file: &mut File, max_len: usize) -> io::Result<Self> {
        let mut bytes = Zeroizing::new(vec![0u8; max_len + 1]);
        let mut filled = 0;
        while filled < bytes.len() {
            match file.read(&mut bytes[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e), // `bytes` is zeroed as it drops here
            }
        }
        if filled > max_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("file exceeds the {max_len}-byte limit"),
            ));
        }
        bytes.truncate(filled); // shrinks the length only; the allocation (and its zeroing on drop) is unchanged
        Ok(SecretBuffer { bytes })
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Zeroes the entire underlying allocation -- contents and spare
    /// capacity -- immediately, rather than waiting for drop. Afterward the
    /// buffer is empty. Safe to call more than once.
    pub fn wipe(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for SecretBuffer {
    fn drop(&mut self) {
        self.wipe(); // belt and braces: `Zeroizing` would also do this, but make the guarantee explicit here
    }
}

/// Test-only: writes `contents` to `path` and pins its mode to `0o644`,
/// rather than trusting the umask to leave it non-group/other-writable.
/// A permissive umask (some distros default to `002`) would otherwise
/// produce a `664` file that `check_owner_and_mode`'s
/// `FORBID_GROUP_OTHER_WRITE` correctly refuses -- breaking every fixture
/// that writes a policy/config file it expects to load successfully.
#[cfg(test)]
pub(crate) fn write_world_readable_for_tests(path: &std::path::Path, contents: impl AsRef<[u8]>) {
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o644)).unwrap();
}

/// Test-only: a temp directory nobody but this user can write to, whatever
/// the umask. `tempfile::tempdir()` creates `0777 & !umask`, which under a
/// `002` umask is group-writable -- a directory [`check_dir_chain`] rightly
/// refuses to trust a policy or secret in.
#[cfg(test)]
pub(crate) fn private_tempdir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    fn temp_file_with(contents: &[u8], mode: u32) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(contents).unwrap();
        f.flush().unwrap();
        std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        f
    }

    const OWNER_ONLY: FileRequirements = FileRequirements {
        owner: Some(Owner::RootOrCurrentUser),
        forbidden_mode_bits: FORBID_GROUP_OTHER_ACCESS,
        follow_symlinks: true,
        allow_group_read_if_root_owned: false,
    };

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn is_root() -> bool {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() == 0 }
    }

    #[test]
    fn group_read_is_allowed_only_on_a_root_owned_file_when_requested() {
        let f = temp_file_with(b"x", 0o640);
        let req = FileRequirements { allow_group_read_if_root_owned: true, ..OWNER_ONLY };
        let result = open_checked(f.path(), &req);
        if is_root() {
            result.unwrap(); // root:<group> 0640 is the supported layout for a non-root service
        } else {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied, "a self-owned secret must stay owner-only");
        }
        // Never group write, and never anything for others, root-owned or not.
        for mode in [0o660, 0o644] {
            chmod(f.path(), mode);
            assert_eq!(open_checked(f.path(), &req).unwrap_err().kind(), io::ErrorKind::PermissionDenied, "mode {mode:o}");
        }
    }

    #[test]
    fn dir_chain_accepts_a_private_dir_and_refuses_a_shared_writable_one() {
        let base = crate::secure_file::private_tempdir();
        let dir = std::fs::canonicalize(base.path()).unwrap();
        check_dir_chain(&dir, Owner::RootOrCurrentUser).unwrap();

        for mode in [0o770, 0o707, 0o1777] {
            chmod(&dir, mode);
            let err = check_dir_chain(&dir, Owner::RootOrCurrentUser).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "mode {mode:o}");
        }
        chmod(&dir, 0o700);
    }

    #[test]
    fn dir_chain_allows_a_sticky_ancestor_but_not_a_plain_writable_one() {
        let base = crate::secure_file::private_tempdir();
        let outer = std::fs::canonicalize(base.path()).unwrap();
        let inner = outer.join("inner");
        std::fs::create_dir(&inner).unwrap();
        chmod(&inner, 0o700);

        chmod(&outer, 0o1777);
        check_dir_chain(&inner, Owner::RootOrCurrentUser).expect("sticky: nobody else can rename `inner`");

        chmod(&outer, 0o777);
        assert!(check_dir_chain(&inner, Owner::RootOrCurrentUser).is_err(), "anyone could rename `inner` away");
        chmod(&outer, 0o700);
    }

    #[test]
    fn dir_chain_with_root_owner_refuses_a_user_owned_dir() {
        if is_root() {
            return;
        }
        let base = crate::secure_file::private_tempdir();
        let err = check_dir_chain(&std::fs::canonicalize(base.path()).unwrap(), Owner::Root).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn location_is_checked_even_when_the_file_is_absent() {
        let base = crate::secure_file::private_tempdir();
        let missing = base.path().join("not-yet").join("policy.toml");
        check_location(&missing, Owner::RootOrCurrentUser).unwrap();

        chmod(base.path(), 0o777);
        let err = check_location(&missing, Owner::RootOrCurrentUser).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "its absence must not be trusted either");
        chmod(base.path(), 0o700);
    }

    #[test]
    fn location_checks_where_a_symlink_points_too() {
        let trusted = crate::secure_file::private_tempdir();
        let shared = crate::secure_file::private_tempdir();
        let target = shared.path().join("policy.toml");
        std::fs::write(&target, b"x").unwrap();
        let link = trusted.path().join("policy.toml");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        check_location(&link, Owner::RootOrCurrentUser).unwrap();

        chmod(shared.path(), 0o777);
        assert!(check_location(&link, Owner::RootOrCurrentUser).is_err(), "the target's directory is writable by others");
        chmod(shared.path(), 0o700);
    }

    #[test]
    fn reads_contents_within_limit() {
        let f = temp_file_with(b"hello", 0o600);
        let mut file = open_checked(f.path(), &OWNER_ONLY).unwrap();
        let buf = SecretBuffer::read_from(&mut file, 16).unwrap();
        assert_eq!(buf.as_slice(), b"hello");
        assert_eq!(buf.as_slice().len(), 5);
    }

    #[test]
    fn exact_limit_is_accepted_and_one_over_is_rejected() {
        let f = temp_file_with(&[7u8; 8], 0o600);
        let mut file = File::open(f.path()).unwrap();
        assert_eq!(SecretBuffer::read_from(&mut file, 8).unwrap().as_slice().len(), 8);

        let mut file = File::open(f.path()).unwrap();
        let err = SecretBuffer::read_from(&mut file, 7).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn wipe_empties_the_buffer_and_is_idempotent() {
        let f = temp_file_with(b"secret-material", 0o600);
        let mut file = File::open(f.path()).unwrap();
        let mut buf = SecretBuffer::read_from(&mut file, 64).unwrap();
        buf.wipe();
        assert!(buf.as_slice().is_empty());
        assert_eq!(buf.as_slice(), b"");
        buf.wipe(); // second wipe must be harmless
        assert!(buf.as_slice().is_empty());
    }

    #[test]
    fn rejects_group_or_world_accessible_file() {
        let f = temp_file_with(b"x", 0o640);
        let err = open_checked(f.path(), &OWNER_ONLY).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn write_only_restriction_allows_world_readable() {
        let f = temp_file_with(b"x", 0o644);
        let req = FileRequirements { forbidden_mode_bits: FORBID_GROUP_OTHER_WRITE, ..OWNER_ONLY };
        open_checked(f.path(), &req).unwrap();

        std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(open_checked(f.path(), &req).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn root_only_owner_rejects_non_root_file() {
        if is_root() {
            return; // running as root, so any temp file is root-owned; nothing to reject
        }
        let f = temp_file_with(b"x", 0o600);
        let req = FileRequirements { owner: Some(Owner::Root), ..OWNER_ONLY };
        assert_eq!(open_checked(f.path(), &req).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn rejects_directories() {
        let dir = crate::secure_file::private_tempdir();
        let req = FileRequirements { owner: None, forbidden_mode_bits: 0, ..OWNER_ONLY };
        assert_eq!(open_checked(dir.path(), &req).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_fifo_is_refused_without_blocking_the_open() {
        let dir = private_tempdir();
        let fifo = dir.path().join("policy.toml");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: c is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || tx.send(open_checked(&fifo, &OWNER_ONLY).map(|_| ())).unwrap());
        let result = rx.recv_timeout(std::time::Duration::from_secs(5)).expect("open_checked blocked on a FIFO");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn missing_file_is_reported_as_not_found() {
        let err = open_checked(Path::new("/nonexistent-hkdfguard-secure-file-test"), &OWNER_ONLY).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn no_follow_rejects_symlink_but_follow_accepts_it() {
        let target = temp_file_with(b"x", 0o600);
        let dir = crate::secure_file::private_tempdir();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(target.path(), &link).unwrap();

        open_checked(&link, &OWNER_ONLY).unwrap(); // follow_symlinks: true

        let no_follow = FileRequirements { follow_symlinks: false, ..OWNER_ONLY };
        let err = open_checked(&link, &no_follow).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ELOOP));
    }
}
