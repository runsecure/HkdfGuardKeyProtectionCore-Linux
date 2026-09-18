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
//! selection chain falls through to the Software provider.

use crate::error::{Error, Result}; // this crate's error type + `Result` alias
use crate::provider::{KekHandle, KekProvider, ProviderType, SharedSecret}; // traits/types this module implements
use elliptic_curve::pkcs8::DecodePrivateKey; // lets `SecretKey` parse from PKCS#8 DER
use p256::{PublicKey, SecretKey}; // P-256 key types
use std::path::{Path, PathBuf}; // filesystem path types
use zeroize::Zeroizing; // scrubs the raw secret-file bytes as soon as they've been parsed

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

impl Default for ExternalSecretProvider {
    fn default() -> Self {
        Self::new()
    }
}

// Handle type returned from `get_or_create_kek`; holds the key parsed from
// the mounted secret file.
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
}

impl KekProvider for ExternalSecretProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::ExternalSecret
    }

    fn probe(&self) -> bool {
        self.dir.is_some() // "available" means we at least found a mount directory (not that any given service has a file in it)
    }

    fn get_or_create_kek(&self, service: &str) -> Result<Box<dyn KekHandle>> {
        let path = self
            .secret_path(service)
            .ok_or(Error::KeyNotProvisioned("no external secret mount found"))?; // no mount at all -> decline immediately

        let bytes = match std::fs::read(&path) {
            // Wrap immediately: this is the raw KEK private-key material
            // (a PKCS#8 DER key or a raw scalar) read straight off disk,
            // and must not be dropped un-scrubbed once `parse_secret_key`
            // is done with it.
            Ok(b) => Zeroizing::new(b), // file exists and was read successfully
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // mount exists, but nothing has been provisioned for this specific service yet
                return Err(Error::KeyNotProvisioned(
                    "no secret file provisioned for this service",
                ))
            }
            Err(e) => {
                // any other I/O error (permissions, etc.) is a real failure, not "not provisioned"
                return Err(Error::Provider(format!(
                    "failed to read external secret {}: {e}",
                    path.display()
                )))
            }
        };

        let secret_key = parse_secret_key(&bytes)?; // accept either raw-scalar or PKCS#8 DER
        let key_id = format!("external:{service}").into_bytes();

        Ok(Box::new(ExternalSecretHandle {
            key_id,
            secret_key,
        }))
    }
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
            match provider.get_or_create_kek("com.company.orders") {
                Err(Error::KeyNotProvisioned(_)) => {}
                Err(other) => panic!("expected KeyNotProvisioned, got {other:?}"),
                Ok(_) => panic!("expected KeyNotProvisioned, got Ok"),
            }
        });
    }

    #[test]
    #[serial]
    fn loads_provisioned_pkcs8_secret() {
        with_dir(|provider, dir| {
            let secret_key = SecretKey::random(&mut OsRng); // simulate an operator-provisioned key
            let der = secret_key.to_pkcs8_der().unwrap();
            std::fs::write(dir.join("com.company.orders"), der.as_bytes()).unwrap(); // "provision" it as a mounted file

            let handle = provider.get_or_create_kek("com.company.orders").unwrap();
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

            let handle = provider.get_or_create_kek("com.company.orders").unwrap();
            let eph = SecretKey::random(&mut OsRng);
            let expected = p256::ecdh::diffie_hellman(
                secret_key.to_nonzero_scalar(),
                eph.public_key().as_affine(),
            );
            let actual = handle.ecdh(&eph.public_key()).unwrap();
            assert_eq!(actual.as_slice(), expected.raw_secret_bytes().as_slice());
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

            let handle = provider.get_or_create_kek("com.company.orders").unwrap();
            assert_eq!(handle.key_id(), b"external:com.company.orders");
        });
    }

    #[test]
    #[serial]
    fn rejects_corrupted_secret_file() {
        with_dir(|provider, dir| {
            // Write a corrupt 32-byte scalar (e.g. all 0s or all 0xFF which is invalid for P-256 scalar)
            std::fs::write(dir.join("com.company.orders"), [0u8; 32]).unwrap();
            let res = provider.get_or_create_kek("com.company.orders");
            assert!(matches!(res, Err(Error::Provider(_))));

            // Write random garbage of arbitrary non-32 length (which fails PKCS8 parsing)
            std::fs::write(dir.join("com.company.billing"), b"invalid-pkcs8-data").unwrap();
            let res2 = provider.get_or_create_kek("com.company.billing");
            assert!(matches!(res2, Err(Error::Provider(_))));
        });
    }
}
