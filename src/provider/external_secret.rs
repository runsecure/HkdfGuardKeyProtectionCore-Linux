//! Provider 3: External Secret Provider.
//!
//! Used when TPM2 and PKCS#11 are both unavailable. Reads a persistent P-256
//! KEK that has been provisioned *outside* this process by the deployment
//! platform -- a Kubernetes Secret, a Docker secret, a Vault Agent
//! sink, a CSI Secret Store volume, a systemd credential, or any other
//! mounted-file secret mechanism -- rather than generating one itself.
//!
//! Lookup pattern: `<base>/hkdfguard/<service>`, where `<base>` is the first
//! of a list of conventional secret mount points that exists (overridable
//! wholesale with `HKDFGUARD_EXTERNAL_SECRET_DIR`, which should point
//! directly at the `hkdfguard` directory).
//!
//! The secret file's contents must be either a PKCS#8 DER-encoded P-256
//! private key, or exactly 32 raw big-endian scalar bytes.
//!
//! This provider never creates or writes a secret: if no file exists for a
//! given service it declines with [`Error::KeyNotProvisioned`].
//!
//! ## What the file must satisfy
//!
//! For this provider the file *is* the KEK private key -- not a PIN or a
//! defensive input -- so it is held to the same standard as every other
//! secret this crate reads from disk:
//!
//! - **Owned by root or by this process's user**, with **no group or
//!   other access** (`0400`/`0600`). A group- or world-readable private
//!   key is refused, and refused loudly: it is reported as an error, never
//!   as "not provisioned", so a misconfigured mount can't silently fall
//!   through to a weaker provider.
//! - **A regular file.** Not a directory, device, or FIFO (which would
//!   block the read forever).
//! - **Resolves to a path inside the mount.** Symlinks are followed --
//!   Kubernetes Secret volumes materialize every key as a symlink into a
//!   `..data/` directory, and refusing that would refuse the most common
//!   delivery mechanism outright -- but only while the resolution stays
//!   within the mount directory. A link that leads anywhere else is
//!   refused. That keeps the property the old blanket symlink ban was
//!   after (nothing in the mount can redirect a read to an arbitrary host
//!   path) without breaking the platform that needs symlinks.
//!
//! All checks are made on the opened descriptor, and the resolved path is
//! opened with `O_NOFOLLOW` so no link can be swapped in between
//! resolution and open -- see [`open_secret_within_mount`].
//!
//! Every common mechanism can meet the mode requirement with one setting:
//! Kubernetes `defaultMode: 0400`, Vault Agent `perms = "0400"`, Docker
//! Swarm `mode: 0400`; systemd `LoadCredential=` is already `0400`.

use crate::error::{Error, Result}; // this crate's error type + `Result` alias
use crate::provider::{KekHandle, KekProvider, ProviderType, SharedSecret}; // traits/types this module implements
use crate::secure_file::{open_checked, FileRequirements, Owner, SecretBuffer, FORBID_GROUP_OTHER_ACCESS}; // descriptor-based trust checks and a self-wiping read buffer
use elliptic_curve::pkcs8::DecodePrivateKey; // lets `SecretKey` parse from PKCS#8 DER
use p256::{PublicKey, SecretKey}; // P-256 key types
use std::fs::File;
use std::path::{Path, PathBuf}; // filesystem path types

// Conventional mount points used by common secret-injection mechanisms,
// checked in order until one actually exists on disk.
const CANDIDATE_MOUNTS: &[&str] = &[
    "/var/run/secrets/hkdfguard",   // generic / Kubernetes-style secret mount
    "/run/secrets/hkdfguard",       // Docker Swarm secrets
    "/vault/secrets/hkdfguard",     // HashiCorp Vault Agent sink
    "/mnt/secrets-store/hkdfguard", // CSI Secret Store driver
];

// Holds the resolved secret directory, or `None` if no mount was found at
// construction time (in which case this provider is simply unavailable).
pub struct ExternalSecretProvider {
    dir: Option<PathBuf>,
}

impl ExternalSecretProvider {
    pub fn new() -> Self {
        ExternalSecretProvider { dir: resolve_dir() } // resolve once at construction
    }
}

// Whether `service` is safe to use directly as a single file name inside
// the mount directory: non-empty, no path separator, and never able to
// name "." (the mount itself), ".." (its parent), or a hidden dot-file --
// so no leading '.' and no consecutive dots. The C ABI already rejects
// such names before they get here (see cstr_to_service in src/lib.rs);
// this is the same rule enforced again at the point where the name
// actually becomes a path, so an in-crate caller that bypasses the ABI
// can't use it to escape the mount either. (The containment check in
// `open_secret_within_mount` would catch an escape anyway; this just
// refuses the name before touching the filesystem at all.)
fn is_safe_file_name(service: &str) -> bool {
    !service.is_empty() && !service.contains('/') && !service.starts_with('.') && !service.contains("..")
}

impl Default for ExternalSecretProvider {
    fn default() -> Self {
        Self::new()
    }
}

// Handle type returned from `load_kek`; holds the key parsed from the
// mounted secret file.
struct ExternalSecretHandle {
    key_id: Vec<u8>,       // diagnostic-only tag embedded in the wrapped payload
    secret_key: SecretKey, // the key loaded from the externally provisioned file
}

impl KekHandle for ExternalSecretHandle {
    fn key_id(&self) -> &[u8] {
        &self.key_id
    }

    fn ecdh(&self, peer_public_key: &PublicKey) -> Result<SharedSecret> {
        let shared = p256::ecdh::diffie_hellman(
            self.secret_key.to_nonzero_scalar(), // our private scalar
            peer_public_key.as_affine(),         // the protocol's fixed point H (see crypto.rs)
        );
        let mut out = [0u8; 32];
        out.copy_from_slice(shared.raw_secret_bytes().as_slice()); // copy the shared secret's raw bytes
        Ok(SharedSecret::new(out)) // wrap in the zeroizing alias
    }

    fn public_key(&self) -> Result<PublicKey> {
        Ok(self.secret_key.public_key()) // trivial: the public half is always derivable from the private key we already hold
    }
}

impl KekProvider for ExternalSecretProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::ExternalSecret
    }

    fn probe(&self) -> bool {
        self.dir.is_some() // "available" means we at least found a mount directory (not that any given service has a file in it)
    }

    // Reads nothing: resolves and opens the file exactly as `load_kek`
    // would, so "exists" means "exists *and* would be accepted". A file
    // that is present but fails a trust check is an error here, not
    // `false` -- reporting it as absent would let the chain move on to a
    // weaker provider and hide the misconfiguration.
    fn kek_exists(&self, service: &str) -> Result<bool> {
        if !is_safe_file_name(service) {
            return Ok(false); // can never name a provisioned secret file
        }
        let Some(dir) = self.dir.as_ref() else {
            return Ok(false); // no mount at all
        };
        match open_secret_within_mount(dir, service) {
            Ok(_file) => Ok(true), // opened and passed every check; the descriptor is dropped unread
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Error::Provider(format!(
                "external secret for this service is present but not trusted: {e}"
            ))),
        }
    }

    // `create_if_missing` is deliberately ignored: this provider never
    // creates or writes a secret (see the module-level doc comment) --
    // whether the caller wanted to create one or only load an existing
    // one, the answer when nothing is provisioned is the same
    // `KeyNotProvisioned` decline either way.
    fn load_kek(&self, service: &str, _create_if_missing: bool) -> Result<Box<dyn KekHandle>> {
        if !is_safe_file_name(service) {
            return Err(Error::Provider(format!(
                "service name {service:?} cannot be used as an external secret file name"
            )));
        }
        let dir = self
            .dir
            .as_ref()
            .ok_or(Error::KeyNotProvisioned("no external secret mount found"))?; // no mount at all -> decline immediately

        let mut file = match open_secret_within_mount(dir, service) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // mount exists, but nothing has been provisioned for this specific service yet
                return Err(Error::KeyNotProvisioned(
                    "no secret file provisioned for this service",
                ));
            }
            Err(e) => {
                // present but untrusted (escapes the mount, wrong owner, too
                // broad a mode, not a regular file) or unreadable: a real
                // failure, never "not provisioned"
                return Err(Error::Provider(format!(
                    "external secret for this service rejected: {e}"
                )));
            }
        };

        // Raw KEK private-key material (a PKCS#8 DER key or a raw scalar)
        // read straight off disk into a `SecretBuffer`: one fixed
        // allocation, never grown, zeroed on every exit path below.
        let mut bytes = SecretBuffer::read_from(&mut file, MAX_SECRET_FILE_LEN)
            .map_err(|e| Error::Provider(format!("failed to read external secret: {e}")))?;

        let parsed = parse_secret_key(bytes.as_slice()); // accept either raw-scalar or PKCS#8 DER
        bytes.wipe(); // the raw bytes have served their only purpose -- clear them now, on success *and* failure, before propagating anything
        let secret_key = parsed?;
        let key_id = format!("external:{service}").into_bytes();

        Ok(Box::new(ExternalSecretHandle {
            key_id,
            secret_key,
        }))
    }
}

// Largest secret file accepted. A PKCS#8 DER P-256 key is ~138 bytes and
// a raw scalar is 32; this leaves generous headroom (e.g. for a PKCS#8
// encoding that also embeds optional attributes) while bounding the one
// up-front allocation `SecretBuffer` makes.
const MAX_SECRET_FILE_LEN: usize = 4096;

/// What a mounted KEK file must satisfy -- identical to the PKCS#11 PIN
/// and the TPM derivation secret, because it is at least as sensitive.
const SECRET_FILE_REQUIREMENTS: FileRequirements = FileRequirements {
    owner: Some(Owner::RootOrCurrentUser),
    forbidden_mode_bits: FORBID_GROUP_OTHER_ACCESS,
    follow_symlinks: false, // applied to the already-resolved path; see below
};

/// Resolves `<mount>/<service>` to the real file it names, refuses the
/// result unless it lies inside the mount, and opens it under
/// [`SECRET_FILE_REQUIREMENTS`].
///
/// Symlinks are followed during resolution -- that is what makes a
/// Kubernetes Secret volume (`<key>` → `..data/<key>` → `..<ts>/<key>`)
/// work -- but the fully resolved target must still start with the fully
/// resolved mount, so a link out of the mount is refused. Both sides are
/// canonicalized because the mount itself is often reached through a
/// symlink (`/var/run` → `/run` on most distributions).
///
/// The resolved path contains no symlinks, so opening *it* with
/// `O_NOFOLLOW` closes the race between resolution and open: a link
/// swapped in for the final component in that window fails with `ELOOP`
/// instead of being followed. On Linux the descriptor's own path is then
/// read back from `/proc/self/fd` and re-checked against the mount, which
/// also covers an intermediate directory being swapped. (Doing that
/// requires write access to a root-owned mount directory -- i.e. root --
/// but the check is one `readlink`, and it turns a race into a detection.)
///
/// Only `NotFound` means "nothing provisioned"; every other failure means
/// "something is there and it is not acceptable".
fn open_secret_within_mount(mount: &Path, service: &str) -> std::io::Result<File> {
    use std::io::{Error as IoError, ErrorKind};

    let mount_real = std::fs::canonicalize(mount)?;
    let target_real = std::fs::canonicalize(mount.join(service))?; // NotFound if nothing is provisioned; follows a symlink chain

    if !target_real.starts_with(&mount_real) {
        // Component-wise comparison, so `<mount>-evil/x` does not pass for `<mount>`.
        return Err(IoError::new(
            ErrorKind::PermissionDenied,
            format!("resolves to {}, outside the secret mount", target_real.display()),
        ));
    }

    let file = open_checked(&target_real, &SECRET_FILE_REQUIREMENTS).map_err(|e| {
        if e.raw_os_error() == Some(libc::ELOOP) {
            IoError::new(ErrorKind::PermissionDenied, "changed to a symlink between resolution and open")
        } else {
            e
        }
    })?;

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let opened = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
        if !opened.starts_with(&mount_real) {
            return Err(IoError::new(
                ErrorKind::PermissionDenied,
                format!("opened descriptor refers to {}, outside the secret mount", opened.display()),
            ));
        }
    }

    Ok(file)
}

// Accepts either a 32-byte raw scalar or a PKCS#8 DER-encoded key, since
// different provisioning tools produce different formats.
fn parse_secret_key(bytes: &[u8]) -> Result<SecretKey> {
    if bytes.len() == 32 {
        // exactly 32 bytes: treat as a raw big-endian P-256 private scalar
        return SecretKey::from_slice(bytes)
            .map_err(|e| Error::Provider(format!("invalid raw external KEK scalar: {e}")));
    }
    // anything else: try to parse it as a standard PKCS#8 DER private key
    SecretKey::from_pkcs8_der(bytes)
        .map_err(|e| Error::Provider(format!("external secret is not a valid P-256 key: {e}")))
}

// Picks the secret mount directory: an explicit override first, otherwise
// the first conventional mount point that actually exists.
fn resolve_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("HKDFGUARD_EXTERNAL_SECRET_DIR") {
        let path = PathBuf::from(dir);
        return if path.is_dir() { Some(path) } else { None }; // override must actually exist, or we report "unavailable"
    }

    CANDIDATE_MOUNTS
        .iter()
        .map(Path::new) // turn each &str into a &Path
        .find(|p| p.is_dir()) // first one that actually exists on this host
        .map(Path::to_path_buf) // convert the borrowed Path into an owned PathBuf to return
}

#[cfg(test)]
mod tests {
    use super::*; // bring `ExternalSecretProvider` etc. into scope
    use elliptic_curve::pkcs8::EncodePrivateKey; // lets the test encode a key to PKCS#8 DER for the "provisioned" fixture
    use rand_core::OsRng; // used to generate test keys
    use serial_test::serial; // these tests mutate a shared env var, so they must not run concurrently
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir; // throwaway directory for each test

    // Runs `f` against a provider pointed at a fresh temp directory acting
    // as the "mounted secret" location.
    fn with_dir<F: FnOnce(&ExternalSecretProvider, &Path)>(f: F) {
        let dir = tempdir().unwrap();
        std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", dir.path()); // redirect this provider at the temp dir
        let provider = ExternalSecretProvider::new();
        f(&provider, dir.path());
        std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR"); // don't leak the override into other tests
    }

    // Writes a secret file the way a correctly configured platform would:
    // owner-only. `std::fs::write` alone inherits the umask (usually
    // 0644), which the provider now refuses.
    fn provision(dir: &Path, name: &str, bytes: impl AsRef<[u8]>) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes.as_ref()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    #[test]
    #[serial]
    fn declines_when_no_secret_provisioned() {
        with_dir(|provider, _dir| {
            // no file has been written into the temp dir, so this must decline, not error or succeed
            match provider.load_kek("com.company.orders", true) {
                Err(Error::KeyNotProvisioned(_)) => {}
                Err(other) => panic!("expected KeyNotProvisioned, got {other:?}"),
                Ok(_) => panic!("expected KeyNotProvisioned, got Ok"),
            }
        });
    }

    #[test]
    #[serial]
    fn kek_exists_reflects_the_mounted_file_and_create_if_missing_is_ignored() {
        with_dir(|provider, dir| {
            assert!(!provider.kek_exists("com.company.orders").unwrap());
            // Even with create_if_missing = true, this provider never
            // creates one -- it can only ever load what's already mounted.
            assert!(matches!(
                provider.load_kek("com.company.orders", true),
                Err(Error::KeyNotProvisioned(_))
            ));

            let secret_key = SecretKey::random(&mut OsRng);
            provision(dir, "com.company.orders", secret_key.to_bytes()); // simulate an operator provisioning it externally

            assert!(provider.kek_exists("com.company.orders").unwrap());
            provider.load_kek("com.company.orders", false).unwrap(); // now loads fine
        });
    }

    #[test]
    #[serial]
    fn refuses_dot_names_even_when_a_file_exists_there() {
        with_dir(|provider, dir| {
            // A real, valid key sitting at a hidden-file name in the
            // mount: reachable as a path, but the provider must still
            // refuse the name rather than load it.
            let secret_key = SecretKey::random(&mut OsRng);
            provision(dir, ".hidden", secret_key.to_bytes());

            for bad in [".hidden", ".", "..", "...", "com..orders", ""] {
                assert!(!provider.kek_exists(bad).unwrap(), "kek_exists must be false for {bad:?}");
                match provider.load_kek(bad, false) {
                    Err(Error::Provider(msg)) => assert!(msg.contains("cannot be used"), "{bad:?}: {msg}"),
                    Err(other) => panic!("{bad:?}: expected Provider error, got {other:?}"),
                    Ok(_) => panic!("{bad:?}: must not load"),
                }
            }
        });
    }

    #[test]
    #[serial]
    fn follows_kubernetes_style_symlinks_within_the_mount() {
        // A Kubernetes Secret volume lays out every key as
        //   <mount>/<key>  ->  ..data/<key>
        //   <mount>/..data ->  ..<timestamp>/        (a real directory)
        // so that updates can swap `..data` atomically. Both hops stay
        // inside the mount, so they must be followed. (On macOS the temp
        // dir itself lives under a symlink, /var -> /private/var, which
        // also exercises the mount-side canonicalization.)
        with_dir(|provider, dir| {
            let versioned = dir.join("..2026_09_28_00_00_00.000000000");
            std::fs::create_dir(&versioned).unwrap();
            let key = SecretKey::random(&mut OsRng);
            provision(&versioned, "com.company.orders", key.to_bytes());
            std::os::unix::fs::symlink(&versioned, dir.join("..data")).unwrap();
            std::os::unix::fs::symlink(
                Path::new("..data").join("com.company.orders"),
                dir.join("com.company.orders"),
            )
            .unwrap();

            assert!(provider.kek_exists("com.company.orders").unwrap());
            let handle = provider.load_kek("com.company.orders", false).unwrap();
            assert_eq!(handle.public_key().unwrap(), key.public_key());
        });
    }

    #[test]
    #[serial]
    fn refuses_a_symlink_that_escapes_the_mount() {
        with_dir(|provider, dir| {
            // A real, correctly-permissioned key file living *outside* the
            // mount directory: it would pass every per-file check, so the
            // containment rule is the only thing standing between a
            // planted link and an attacker-chosen KEK.
            let outside = tempdir().unwrap();
            let secret_key = SecretKey::random(&mut OsRng);
            let real_path = provision(outside.path(), "real-secret", secret_key.to_bytes());
            std::os::unix::fs::symlink(&real_path, dir.join("com.company.orders")).unwrap();

            match provider.load_kek("com.company.orders", true) {
                Err(Error::Provider(msg)) => assert!(msg.contains("outside"), "unexpected message: {msg}"),
                Err(other) => panic!("expected Provider(..outside..), got {other:?}"),
                Ok(_) => panic!("must not load a key from outside the mount"),
            }
            // And kek_exists reports the misconfiguration, not "absent".
            assert!(provider.kek_exists("com.company.orders").is_err());
        });
    }

    #[test]
    #[serial]
    fn refuses_group_or_world_accessible_files_as_errors_not_absence() {
        with_dir(|provider, dir| {
            let secret_key = SecretKey::random(&mut OsRng);
            let path = provision(dir, "com.company.orders", secret_key.to_bytes());

            for mode in [0o644u32, 0o640, 0o604, 0o660, 0o444] {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
                match provider.load_kek("com.company.orders", true) {
                    Err(Error::Provider(msg)) => assert!(msg.contains("permissions"), "mode {mode:o}: {msg}"),
                    Err(other) => panic!("mode {mode:o}: expected Provider(..permissions..), got {other:?}"),
                    Ok(_) => panic!("mode {mode:o}: a group/world-accessible KEK must be refused"),
                }
                assert!(
                    provider.kek_exists("com.company.orders").is_err(),
                    "mode {mode:o}: kek_exists must surface the misconfiguration, not report absence"
                );
            }

            // Owner-only modes are accepted.
            for mode in [0o600u32, 0o400] {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
                assert!(provider.kek_exists("com.company.orders").unwrap(), "mode {mode:o}");
                provider.load_kek("com.company.orders", true).unwrap();
            }
        });
    }

    #[test]
    #[serial]
    fn refuses_a_directory_at_the_service_name() {
        with_dir(|provider, dir| {
            std::fs::create_dir(dir.join("com.company.orders")).unwrap();
            assert!(provider.kek_exists("com.company.orders").is_err());
            assert!(matches!(provider.load_kek("com.company.orders", true), Err(Error::Provider(_))));
        });
    }

    #[test]
    #[serial]
    fn different_provisioned_keys_produce_different_public_keys() {
        with_dir(|provider, dir| {
            let key_a = SecretKey::random(&mut OsRng);
            let key_b = SecretKey::random(&mut OsRng);
            provision(dir, "com.company.orders", key_a.to_bytes());
            provision(dir, "com.company.billing", key_b.to_bytes());

            let handle_a = provider.load_kek("com.company.orders", true).unwrap();
            let handle_b = provider.load_kek("com.company.billing", true).unwrap();

            let public_a = handle_a.public_key().unwrap();
            let public_b = handle_b.public_key().unwrap();

            // Each handle's reported public key must match its own
            // provisioned secret, not just differ from the other one --
            // guards against a regression where public_key() returns a
            // stale, cached, or otherwise-mismatched value.
            assert_eq!(public_a, key_a.public_key());
            assert_eq!(public_b, key_b.public_key());
            assert_ne!(public_a, public_b, "different provisioned keys must produce different public keys");
        });
    }

    #[test]
    #[serial]
    fn loads_provisioned_pkcs8_secret() {
        with_dir(|provider, dir| {
            let secret_key = SecretKey::random(&mut OsRng); // simulate an operator-provisioned key
            let der = secret_key.to_pkcs8_der().unwrap();
            provision(dir, "com.company.orders", der.as_bytes()); // "provision" it as a mounted file

            let handle = provider.load_kek("com.company.orders", true).unwrap();
            let eph = SecretKey::random(&mut OsRng); // stand-in peer key
            let expected = p256::ecdh::diffie_hellman(
                secret_key.to_nonzero_scalar(),
                eph.public_key().as_affine(),
            ); // compute the expected shared secret directly, independent of the provider
            let actual = handle.ecdh(&eph.public_key()).unwrap();
            assert_eq!(actual.as_slice(), expected.raw_secret_bytes().as_slice()); // provider's result must match
        });
    }

    #[test]
    #[serial]
    fn loads_provisioned_raw_scalar_secret() {
        with_dir(|provider, dir| {
            let secret_key = SecretKey::random(&mut OsRng);
            provision(dir, "com.company.orders", secret_key.to_bytes()); // provision as raw 32-byte scalar this time

            let handle = provider.load_kek("com.company.orders", true).unwrap();
            let eph = SecretKey::random(&mut OsRng);
            let expected = p256::ecdh::diffie_hellman(
                secret_key.to_nonzero_scalar(),
                eph.public_key().as_affine(),
            );
            let actual = handle.ecdh(&eph.public_key()).unwrap();
            assert_eq!(actual.as_slice(), expected.raw_secret_bytes().as_slice());
            // Since we provisioned the file ourselves, we independently
            // know the exact key -- `public_key()` must report that same
            // key, not some other/derived value.
            assert_eq!(handle.public_key().unwrap(), secret_key.public_key());
        });
    }

    #[test]
    #[serial]
    fn probe_and_provider_type() {
        with_dir(|provider, _dir| {
            assert!(provider.probe());
            assert_eq!(provider.provider_type(), ProviderType::ExternalSecret);
        });

        std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", "/nonexistent-dir-12345");
        let provider = ExternalSecretProvider::new();
        assert!(!provider.probe());
        std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
    }

    #[test]
    #[serial]
    fn key_id_format() {
        with_dir(|provider, dir| {
            let secret_key = SecretKey::random(&mut OsRng);
            provision(dir, "com.company.orders", secret_key.to_bytes());

            let handle = provider.load_kek("com.company.orders", true).unwrap();
            assert_eq!(handle.key_id(), b"external:com.company.orders");
        });
    }

    #[test]
    #[serial]
    fn rejects_corrupted_secret_file() {
        with_dir(|provider, dir| {
            // A corrupt 32-byte scalar (all zeros is not a valid P-256 scalar).
            provision(dir, "com.company.orders", [0u8; 32]);
            let res = provider.load_kek("com.company.orders", true);
            assert!(matches!(res, Err(Error::Provider(_))));

            // Garbage of a non-32 length, which fails PKCS#8 parsing.
            provision(dir, "com.company.billing", b"invalid-pkcs8-data");
            let res2 = provider.load_kek("com.company.billing", true);
            assert!(matches!(res2, Err(Error::Provider(_))));
        });
    }
}
