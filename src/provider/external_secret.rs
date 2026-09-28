//! Provider 3: External Secret Provider.
//!
//! Used when TPM2 and PKCS#11 are both unavailable. Reads a persistent P-256
//! KEK that has been provisioned *outside* this process by the deployment
//! platform -- a Kubernetes Secret, a Docker secret, a Vault Agent
//! sink, a CSI Secret Store volume, or any other mounted-file secret
//! mechanism -- rather than generating one itself.
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
//! given service it declines with [`Error::KeyNotProvisioned`], and the
//! selection chain falls through to the Ephemeral provider.
//!
//! The secret file must be a *regular* file, not a symlink: the mount
//! directory is populated by the deployment platform, not this process,
//! so a symlink there (accidental or planted by something else with write
//! access to the mount) could otherwise redirect a read to an arbitrary
//! path on the host. Enforced by opening with `O_NOFOLLOW` -- which fails
//! atomically if the final path component is a symlink -- rather than a
//! separate "is this a symlink" check before the read, which would leave
//! a TOCTOU window open to a swap in between.

use crate::error::{Error, Result}; // this crate's error type + `Result` alias
use crate::provider::{KekHandle, KekProvider, ProviderType, SharedSecret}; // traits/types this module implements
use elliptic_curve::pkcs8::DecodePrivateKey; // lets `SecretKey` parse from PKCS#8 DER
use p256::{PublicKey, SecretKey}; // P-256 key types
use crate::secure_file::{open_checked, FileRequirements, SecretBuffer}; // O_NOFOLLOW + regular-file checks on the opened fd, and a self-wiping read buffer
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

    // Full path to the secret file for one service, if a base directory
    // was found at all.
    fn secret_path(&self, service: &str) -> Option<PathBuf> {
        self.dir.as_ref().map(|d| d.join(service)) // e.g. <dir>/com.company.orders
    }
}

// Whether `service` is safe to use directly as a single file name inside
// the mount directory: non-empty, no path separator, and never able to
// name "." (the mount itself), ".." (its parent), or a hidden dot-file --
// so no leading '.' and no consecutive dots. The C ABI already rejects
// such names before they get here (see cstr_to_service in src/lib.rs);
// this is the same rule enforced again at the point where the name
// actually becomes a path, so an in-crate caller that bypasses the ABI
// can't use it to escape the mount either.
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

    fn ecdh(&self, ephemeral_public_key: &PublicKey) -> Result<SharedSecret> {
        let shared = p256::ecdh::diffie_hellman(
            self.secret_key.to_nonzero_scalar(), // our private scalar
            ephemeral_public_key.as_affine(),     // the caller's ephemeral public point
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

    // Side-effect-free: just checks whether a secret file exists for this
    // service, without reading or parsing it. Uses `symlink_metadata` (not
    // `Path::is_file`, which follows symlinks) so a symlink here reports
    // as "doesn't exist" -- matching `load_kek`'s own refusal to follow
    // one -- rather than falsely reporting success.
    fn kek_exists(&self, service: &str) -> Result<bool> {
        if !is_safe_file_name(service) {
            return Ok(false); // can never name a provisioned secret file
        }
        Ok(self.secret_path(service).is_some_and(|p| {
            std::fs::symlink_metadata(&p)
                .map(|m| m.file_type().is_file())
                .unwrap_or(false)
        }))
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
        let path = self
            .secret_path(service)
            .ok_or(Error::KeyNotProvisioned("no external secret mount found"))?; // no mount at all -> decline immediately

        // Raw KEK private-key material (a PKCS#8 DER key or a raw scalar)
        // read straight off disk into a `SecretBuffer`: one fixed
        // allocation, never grown, zeroed on every exit path below.
        let mut bytes = match read_regular_file_no_symlink(&path) {
            Ok(b) => b, // file exists, is a regular file (not a symlink), and was read successfully
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // mount exists, but nothing has been provisioned for this specific service yet
                return Err(Error::KeyNotProvisioned(
                    "no secret file provisioned for this service",
                ))
            }
            Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
                // O_NOFOLLOW rejected the open because the final path
                // component is a symlink -- treated as a hard failure,
                // not "not provisioned": there IS something at this path,
                // it's just not something we'll read.
                return Err(Error::Provider(format!(
                    "external secret {} is a symlink; refusing to follow it",
                    path.display()
                )))
            }
            Err(e) => {
                // any other I/O error (permissions, etc.) is a real failure, not "not provisioned"
                return Err(Error::Provider(format!(
                    "failed to read external secret {}: {e}",
                    path.display()
                )))
            }
        };

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

// Opens `path` with O_NOFOLLOW and reads its full contents into a
// self-wiping `SecretBuffer`. O_NOFOLLOW makes the kernel fail the open
// (ELOOP) if the final path component is a symlink, atomically -- there's
// no separate "check, then open" step for something else with write
// access to the mount directory to win a race against. The opened file
// must also be a regular file (checked on the descriptor, so a FIFO can't
// block the read forever).
fn read_regular_file_no_symlink(path: &Path) -> std::io::Result<SecretBuffer> {
    let requirements = FileRequirements {
        owner: None,
        forbidden_mode_bits: 0,
        follow_symlinks: false,
    };
    let mut file = open_checked(path, &requirements)?;
    SecretBuffer::read_from(&mut file, MAX_SECRET_FILE_LEN)
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
            std::fs::write(dir.join("com.company.orders"), secret_key.to_bytes()).unwrap(); // simulate an operator provisioning it externally

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
            std::fs::write(dir.join(".hidden"), secret_key.to_bytes()).unwrap();

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
    fn rejects_symlink_secret_file() {
        with_dir(|provider, dir| {
            // A real key file living outside the mount directory.
            let outside = tempdir().unwrap();
            let secret_key = SecretKey::random(&mut OsRng);
            let real_path = outside.path().join("real-secret");
            std::fs::write(&real_path, secret_key.to_bytes()).unwrap();

            // A symlink inside the mount directory pointing at it --
            // simulates something else with write access to the mount
            // (or an operator mistake) redirecting the read elsewhere.
            std::os::unix::fs::symlink(&real_path, dir.join("com.company.orders")).unwrap();

            // kek_exists must not report a symlink as an existing KEK,
            // matching load_kek's own refusal to follow it.
            assert!(!provider.kek_exists("com.company.orders").unwrap());

            match provider.load_kek("com.company.orders", true) {
                Err(Error::Provider(msg)) => {
                    assert!(msg.contains("symlink"), "unexpected message: {msg}")
                }
                Err(other) => panic!("expected Provider(..symlink..), got {other:?}"),
                Ok(_) => panic!("expected Provider(..symlink..), got Ok"),
            }
        });
    }

    #[test]
    #[serial]
    fn different_provisioned_keys_produce_different_public_keys() {
        with_dir(|provider, dir| {
            let key_a = SecretKey::random(&mut OsRng);
            let key_b = SecretKey::random(&mut OsRng);
            std::fs::write(dir.join("com.company.orders"), key_a.to_bytes()).unwrap();
            std::fs::write(dir.join("com.company.billing"), key_b.to_bytes()).unwrap();

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
            std::fs::write(dir.join("com.company.orders"), der.as_bytes()).unwrap(); // "provision" it as a mounted file

            let handle = provider.load_kek("com.company.orders", true).unwrap();
            let eph = SecretKey::random(&mut OsRng); // stand-in for the wrapper's ephemeral key
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
            std::fs::write(dir.join("com.company.orders"), secret_key.to_bytes()).unwrap(); // provision as raw 32-byte scalar this time

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
            std::fs::write(dir.join("com.company.orders"), secret_key.to_bytes()).unwrap();

            let handle = provider.load_kek("com.company.orders", true).unwrap();
            assert_eq!(handle.key_id(), b"external:com.company.orders");
        });
    }

    #[test]
    #[serial]
    fn rejects_corrupted_secret_file() {
        with_dir(|provider, dir| {
            // Write a corrupt 32-byte scalar (e.g. all 0s or all 0xFF which is invalid for P-256 scalar)
            std::fs::write(dir.join("com.company.orders"), [0u8; 32]).unwrap();
            let res = provider.load_kek("com.company.orders", true);
            assert!(matches!(res, Err(Error::Provider(_))));

            // Write random garbage of arbitrary non-32 length (which fails PKCS8 parsing)
            std::fs::write(dir.join("com.company.billing"), b"invalid-pkcs8-data").unwrap();
            let res2 = provider.load_kek("com.company.billing", true);
            assert!(matches!(res2, Err(Error::Provider(_))));
        });
    }
}
