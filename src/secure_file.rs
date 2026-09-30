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
    #[cfg_attr(not(feature = "pkcs11"), allow(dead_code))] // only the PKCS#11 module-path check requires strictly-root ownership today
    Root,
    /// uid 0, or this process's effective uid (a process can't meaningfully
    /// protect a file from its own uid anyway).
    RootOrCurrentUser,
}

/// Permission bits that must be clear: nobody but the owner may write.
pub const FORBID_GROUP_OTHER_WRITE: u32 = 0o022;
/// Permission bits that must be clear: nobody but the owner may read, write, or execute.
#[cfg_attr(not(feature = "pkcs11"), allow(dead_code))] // only the PKCS#11 PIN file needs owner-only access today (also used by this module's tests)
pub const FORBID_GROUP_OTHER_ACCESS: u32 = 0o077;

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
}

/// Opens `path` read-only and validates it against `req` using the opened
/// descriptor's own metadata. Only ever returns `ErrorKind::NotFound` when
/// the file genuinely doesn't exist; a file that exists but fails a check
/// is reported as `PermissionDenied` or `InvalidData`, so callers can tell
/// "absent" apart from "present but untrustworthy".
pub fn open_checked(path: &Path, req: &FileRequirements) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    if !req.follow_symlinks {
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let file = opts.open(path)?;
    check_metadata(&file.metadata()?, req.owner, req.forbidden_mode_bits)?;
    Ok(file)
}

/// Validates already-obtained metadata: must be a regular file (never a
/// directory, FIFO, device, or socket -- a FIFO would otherwise block a
/// read forever), owned per `owner`, with none of `forbidden_mode_bits` set.
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
    };

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
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return; // running as root, so any temp file is root-owned; nothing to reject
        }
        let f = temp_file_with(b"x", 0o600);
        let req = FileRequirements { owner: Some(Owner::Root), ..OWNER_ONLY };
        assert_eq!(open_checked(f.path(), &req).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn rejects_directories() {
        let dir = tempfile::tempdir().unwrap();
        let req = FileRequirements { owner: None, forbidden_mode_bits: 0, follow_symlinks: true };
        assert_eq!(open_checked(dir.path(), &req).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn missing_file_is_reported_as_not_found() {
        let err = open_checked(Path::new("/nonexistent-hkdfguard-secure-file-test"), &OWNER_ONLY).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn no_follow_rejects_symlink_but_follow_accepts_it() {
        let target = temp_file_with(b"x", 0o600);
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(target.path(), &link).unwrap();

        open_checked(&link, &OWNER_ONLY).unwrap(); // follow_symlinks: true

        let no_follow = FileRequirements { follow_symlinks: false, ..OWNER_ONLY };
        let err = open_checked(&link, &no_follow).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ELOOP));
    }
}
