//! Provider 4: Software-Backed KEK.
//!
//! Used when no hardware-backed provider (TPM2, PKCS#11) and no externally
//! provisioned secret is available. Generates one persistent P-256 KEK per
//! service and stores it PKCS#8-DER-encoded, encrypted at rest with
//! AES-256-GCM under a locally-held "vault key", in a directory with `0700`
//! permissions and `0600` permissions on every file.
//!
//! Threat model note: the vault key lives on the same filesystem as the
//! encrypted private keys, so this protects against casual disclosure
//! (accidental backup/copy, non-privileged reads) but *not* against an
//! attacker with the same filesystem access as the process -- which is
//! exactly why this provider is priority 4, below every hardware-backed
//! option. Deployments that need real protection should enable `tpm2` or
//! `pkcs11`, or provision a KEK via the external-secret provider.

use crate::error::{Error, Result};
use crate::provider::{KekHandle, KekProvider, ProviderType, SharedSecret};
use aes_gcm::aead::{Aead, KeyInit, Payload as AeadPayload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use elliptic_curve::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use p256::{PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const VAULT_KEY_FILE: &str = "vault.key";
const VAULT_KEY_LEN: usize = 32;
const FILE_NONCE_LEN: usize = 12;

pub struct SoftwareProvider {
    dir: PathBuf,
}

impl SoftwareProvider {
    pub fn new() -> Self {
        SoftwareProvider { dir: resolve_dir() }
    }

    fn key_path(&self, service: &str) -> PathBuf {
        self.dir.join(format!("{}.key", service_fingerprint(service)))
    }

    fn vault_key_path(&self) -> PathBuf {
        self.dir.join(VAULT_KEY_FILE)
    }

    fn load_or_create_vault_key(&self) -> Result<Zeroizing<[u8; VAULT_KEY_LEN]>> {
        ensure_private_dir(&self.dir)?;
        let path = self.vault_key_path();

        match fs::read(&path) {
            Ok(bytes) => {
                if bytes.len() != VAULT_KEY_LEN {
                    return Err(Error::Provider(format!(
                        "vault key file {} has unexpected length",
                        path.display()
                    )));
                }
                let mut key = Zeroizing::new([0u8; VAULT_KEY_LEN]);
                key.copy_from_slice(&bytes);
                Ok(key)
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                let mut key = Zeroizing::new([0u8; VAULT_KEY_LEN]);
                OsRng.fill_bytes(&mut *key);
                write_private_file_atomic(&path, &*key)?;
                Ok(key)
            }
            Err(e) => Err(Error::Provider(format!(
                "failed to read vault key {}: {e}",
                path.display()
            ))),
        }
    }
}

impl Default for SoftwareProvider {
    fn default() -> Self {
        Self::new()
    }
}

struct SoftwareHandle {
    key_id: Vec<u8>,
    secret_key: SecretKey,
}

impl KekHandle for SoftwareHandle {
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

impl KekProvider for SoftwareProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Software
    }

    fn probe(&self) -> bool {
        ensure_private_dir(&self.dir).is_ok()
    }

    fn get_or_create_kek(&self, service: &str) -> Result<Box<dyn KekHandle>> {
        ensure_private_dir(&self.dir)?;
        let vault_key = self.load_or_create_vault_key()?;
        let path = self.key_path(service);
        let key_id = service_fingerprint(service).into_bytes();

        let secret_key = match fs::read(&path) {
            Ok(stored) => decrypt_private_key(&vault_key, &stored)?,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                let secret_key = SecretKey::random(&mut OsRng);
                let encrypted = encrypt_private_key(&vault_key, &secret_key)?;
                write_private_file_atomic(&path, &encrypted)?;
                secret_key
            }
            Err(e) => {
                return Err(Error::Provider(format!(
                    "failed to read KEK file {}: {e}",
                    path.display()
                )))
            }
        };

        Ok(Box::new(SoftwareHandle {
            key_id,
            secret_key,
        }))
    }
}

fn encrypt_private_key(vault_key: &[u8; VAULT_KEY_LEN], secret_key: &SecretKey) -> Result<Vec<u8>> {
    let der = secret_key
        .to_pkcs8_der()
        .map_err(|e| Error::Provider(format!("failed to encode KEK as PKCS#8: {e}")))?;

    let mut nonce_bytes = [0u8; FILE_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(vault_key));
    let ciphertext = cipher
        .encrypt(
            nonce,
            AeadPayload {
                msg: der.as_bytes(),
                aad: b"hkdfguard-software-kek-v1",
            },
        )
        .map_err(|_| Error::Provider("failed to encrypt KEK for storage".into()))?;

    let mut out = Vec::with_capacity(FILE_NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn decrypt_private_key(vault_key: &[u8; VAULT_KEY_LEN], stored: &[u8]) -> Result<SecretKey> {
    if stored.len() < FILE_NONCE_LEN {
        return Err(Error::Provider("stored KEK file is truncated".into()));
    }
    let (nonce_bytes, ciphertext) = stored.split_at(FILE_NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(vault_key));
    let der: Zeroizing<Vec<u8>> = Zeroizing::new(
        cipher
            .decrypt(
                nonce,
                AeadPayload {
                    msg: ciphertext,
                    aad: b"hkdfguard-software-kek-v1",
                },
            )
            .map_err(|_| Error::Provider("failed to decrypt stored KEK (corrupt or tampered)".into()))?,
    );

    SecretKey::from_pkcs8_der(&der)
        .map_err(|e| Error::Provider(format!("stored KEK is not valid PKCS#8: {e}")))
}

/// Deterministic, filesystem-safe, non-reversible tag for `service`, used
/// as the on-disk filename. Not a KEK derivation -- it only addresses
/// where a randomly generated KEK is stored, exactly like macOS
/// `kSecAttrService` or a Windows CNG key name.
fn service_fingerprint(service: &str) -> String {
    let digest = Sha256::digest(service.as_bytes());
    hex_encode(&digest)
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn resolve_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("HKDFGUARD_SOFTWARE_DIR") {
        return PathBuf::from(dir);
    }

    #[cfg(unix)]
    {
        // Root / system services: a shared system-wide location.
        if unsafe { libc::geteuid() } == 0 {
            return PathBuf::from("/var/lib/hkdfguard");
        }
    }

    dirs::config_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("hkdfguard")
}

fn ensure_private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)
        .map_err(|e| Error::Provider(format!("failed to create {}: {e}", dir.display())))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| Error::Provider(format!("failed to chmod {}: {e}", dir.display())))?;
    }
    Ok(())
}

fn write_private_file_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, contents)
        .map_err(|e| Error::Provider(format!("failed to write {}: {e}", tmp_path.display())))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::Provider(format!("failed to chmod {}: {e}", tmp_path.display())))?;
    }

    fs::rename(&tmp_path, path)
        .map_err(|e| Error::Provider(format!("failed to finalize {}: {e}", path.display())))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use tempfile::tempdir;

    fn with_dir<F: FnOnce(&SoftwareProvider)>(f: F) {
        let dir = tempdir().unwrap();
        std::env::set_var("HKDFGUARD_SOFTWARE_DIR", dir.path());
        let provider = SoftwareProvider::new();
        f(&provider);
        std::env::remove_var("HKDFGUARD_SOFTWARE_DIR");
    }

    #[test]
    #[serial]
    fn creates_and_reloads_same_key() {
        with_dir(|provider| {
            let h1 = provider.get_or_create_kek("com.company.orders").unwrap();
            let h2 = provider.get_or_create_kek("com.company.orders").unwrap();

            let eph = SecretKey::random(&mut OsRng);
            let eph_pub = eph.public_key();

            assert_eq!(*h1.ecdh(&eph_pub).unwrap(), *h2.ecdh(&eph_pub).unwrap());
        });
    }

    #[test]
    #[serial]
    fn private_key_file_is_not_plaintext_pkcs8() {
        with_dir(|provider| {
            provider.get_or_create_kek("com.company.orders").unwrap();
            let path = provider.key_path("com.company.orders");
            let stored = fs::read(path).unwrap();
            // A plaintext PKCS#8 P-256 key starts with a recognizable DER
            // SEQUENCE tag; ciphertext should not parse as one.
            assert!(SecretKey::from_pkcs8_der(&stored).is_err());
        });
    }

    #[test]
    #[serial]
    fn file_permissions_are_0600() {
        with_dir(|provider| {
            provider.get_or_create_kek("com.company.orders").unwrap();
            let path = provider.key_path("com.company.orders");
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        });
    }
}
