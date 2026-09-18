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

use crate::error::{Error, Result};
use crate::provider::{KekHandle, KekProvider, ProviderType, SharedSecret};
use elliptic_curve::pkcs8::DecodePrivateKey;
use p256::{PublicKey, SecretKey};
use std::path::{Path, PathBuf};

const CANDIDATE_MOUNTS: &[&str] = &[
    "/var/run/secrets/hkdfguard",
    "/run/secrets/hkdfguard",
    "/vault/secrets/hkdfguard",
    "/mnt/secrets-store/hkdfguard",
];

pub struct ExternalSecretProvider {
    dir: Option<PathBuf>,
}

impl ExternalSecretProvider {
    pub fn new() -> Self {
        ExternalSecretProvider { dir: resolve_dir() }
    }

    fn secret_path(&self, service: &str) -> Option<PathBuf> {
        self.dir.as_ref().map(|d| d.join(service))
    }
}

impl Default for ExternalSecretProvider {
    fn default() -> Self {
        Self::new()
    }
}

struct ExternalSecretHandle {
    key_id: Vec<u8>,
    secret_key: SecretKey,
}

impl KekHandle for ExternalSecretHandle {
    fn key_id(&self) -> &[u8] {
        &self.key_id
    }

    fn ecdh(&self, ephemeral_public_key: &PublicKey) -> Result<SharedSecret> {
        let shared = p256::ecdh::diffie_hellman(
            self.secret_key.to_nonzero_scalar(),
            ephemeral_public_key.as_affine(),
        );
        let mut out = [0u8; 32];
        out.copy_from_slice(shared.raw_secret_bytes().as_slice());
        Ok(SharedSecret::new(out))
    }
}

impl KekProvider for ExternalSecretProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::ExternalSecret
    }

    fn probe(&self) -> bool {
        self.dir.is_some()
    }

    fn get_or_create_kek(&self, service: &str) -> Result<Box<dyn KekHandle>> {
        let path = self
            .secret_path(service)
            .ok_or(Error::KeyNotProvisioned("no external secret mount found"))?;

        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::KeyNotProvisioned(
                    "no secret file provisioned for this service",
                ))
            }
            Err(e) => {
                return Err(Error::Provider(format!(
                    "failed to read external secret {}: {e}",
                    path.display()
                )))
            }
        };

        let secret_key = parse_secret_key(&bytes)?;
        let key_id = format!("external:{service}").into_bytes();

        Ok(Box::new(ExternalSecretHandle {
            key_id,
            secret_key,
        }))
    }
}

fn parse_secret_key(bytes: &[u8]) -> Result<SecretKey> {
    if bytes.len() == 32 {
        return SecretKey::from_slice(bytes)
            .map_err(|e| Error::Provider(format!("invalid raw external KEK scalar: {e}")));
    }
    SecretKey::from_pkcs8_der(bytes)
        .map_err(|e| Error::Provider(format!("external secret is not a valid P-256 key: {e}")))
}

fn resolve_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("HKDFGUARD_EXTERNAL_SECRET_DIR") {
        let path = PathBuf::from(dir);
        return if path.is_dir() { Some(path) } else { None };
    }

    CANDIDATE_MOUNTS
        .iter()
        .map(Path::new)
        .find(|p| p.is_dir())
        .map(Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use elliptic_curve::pkcs8::EncodePrivateKey;
    use rand_core::OsRng;
    use serial_test::serial;
    use tempfile::tempdir;

    fn with_dir<F: FnOnce(&ExternalSecretProvider, &Path)>(f: F) {
        let dir = tempdir().unwrap();
        std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", dir.path());
        let provider = ExternalSecretProvider::new();
        f(&provider, dir.path());
        std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
    }

    #[test]
    #[serial]
    fn declines_when_no_secret_provisioned() {
        with_dir(|provider, _dir| {
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
            let secret_key = SecretKey::random(&mut OsRng);
            let der = secret_key.to_pkcs8_der().unwrap();
            std::fs::write(dir.join("com.company.orders"), der.as_bytes()).unwrap();

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
    fn loads_provisioned_raw_scalar_secret() {
        with_dir(|provider, dir| {
            let secret_key = SecretKey::random(&mut OsRng);
            std::fs::write(dir.join("com.company.orders"), secret_key.to_bytes()).unwrap();

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
}
