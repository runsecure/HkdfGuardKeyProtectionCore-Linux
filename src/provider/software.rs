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

use crate::error::{Error, Result}; // this crate's error type + `Result` alias
use crate::provider::{KekHandle, KekProvider, ProviderType, SharedSecret}; // traits/types this module implements
use aes_gcm::{AeadInPlace, Aes256Gcm, Key, KeyInit, Nonce, Tag}; // in-place AEAD trait, concrete cipher, and its key/nonce/tag types (all fixed-size, stack-resident)
use elliptic_curve::pkcs8::{DecodePrivateKey, EncodePrivateKey}; // lets `SecretKey` serialize to/from PKCS#8 DER
use p256::{PublicKey, SecretKey}; // P-256 key types
use rand_core::{OsRng, RngCore}; // OS RNG + the trait providing `fill_bytes`
use sha2::{Digest, Sha256}; // used to fingerprint service names into filenames
use std::fs; // filesystem read/write/rename/permissions
use std::io::ErrorKind; // used to distinguish "file missing" from other I/O errors
use std::path::{Path, PathBuf}; // filesystem path types
use zeroize::{Zeroize, Zeroizing}; // `Zeroize` for explicit scrubbing of stack/heap buffers, `Zeroizing` for auto-scrub-on-drop wrappers

const VAULT_KEY_FILE: &str = "vault.key"; // filename of the shared AES key that encrypts every service's KEK file
const VAULT_KEY_LEN: usize = 32; // AES-256 key size in bytes
const FILE_NONCE_LEN: usize = 12; // AES-GCM's standard 96-bit nonce size, stored as a prefix on each encrypted file
const TAG_LEN: usize = 16; // AES-GCM's standard 128-bit authentication tag size
// PKCS#8 DER encoding of a P-256 `SecretKey` (via `EncodePrivateKey`, which
// includes the public key point) is a fixed size for a fixed curve --
// empirically confirmed at 138 bytes across many freshly generated keys.
// Pinning this lets us decrypt directly into a stack buffer instead of a
// heap `Vec<u8>`; `encrypt_private_key`/`decrypt_private_key` both verify
// the actual length matches before trusting it, so a future dependency
// change that altered this would fail loudly instead of corrupting data.
const PKCS8_DER_LEN: usize = 138;

// Holds only the storage directory; every actual key is read from/written
// to disk on demand rather than cached in memory.
pub struct SoftwareProvider {
    dir: PathBuf, // where vault.key and every per-service *.key file live
}

impl SoftwareProvider {
    pub fn new() -> Self {
        SoftwareProvider { dir: resolve_dir() } // figure out the storage directory once, at construction time
    }

    // Path to the (encrypted) private-key file for one service.
    fn key_path(&self, service: &str) -> PathBuf {
        self.dir.join(format!("{}.key", service_fingerprint(service))) // filename is a hash of the service name, not the raw name
    }

    // Path to the shared vault key that encrypts every service's key file.
    fn vault_key_path(&self) -> PathBuf {
        self.dir.join(VAULT_KEY_FILE)
    }

    // Reads the vault key from disk, generating and persisting a new
    // random one on first use.
    fn load_or_create_vault_key(&self) -> Result<Zeroizing<[u8; VAULT_KEY_LEN]>> {
        ensure_private_dir(&self.dir)?; // make sure the storage directory exists with tight permissions
        let path = self.vault_key_path();

        match fs::read(&path) {
            Ok(bytes) => {
                // Wrap immediately: `bytes` holds the raw vault key
                // plaintext read from disk, and must not be dropped
                // un-scrubbed even on the early-return error path below.
                let bytes = Zeroizing::new(bytes);
                if bytes.len() != VAULT_KEY_LEN {
                    // the file exists but isn't a 32-byte key -- treat as corruption, don't silently truncate/pad
                    return Err(Error::Provider(format!(
                        "vault key file {} has unexpected length",
                        path.display()
                    )));
                }
                let mut key = Zeroizing::new([0u8; VAULT_KEY_LEN]); // zeroizing buffer to hold the loaded key
                key.copy_from_slice(&bytes);
                Ok(key)
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                // first run: no vault key yet, so generate and persist one
                let mut key = Zeroizing::new([0u8; VAULT_KEY_LEN]);
                OsRng.fill_bytes(&mut *key); // fill with cryptographically random bytes
                write_private_file_atomic(&path, &*key)?; // persist it with 0600 permissions
                Ok(key)
            }
            Err(e) => Err(Error::Provider(format!(
                // any other I/O error (permissions, disk error, ...) is a hard failure
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

// The handle type returned from `get_or_create_kek`; holds the decrypted
// (in-memory only) private key long enough to perform one ECDH.
struct SoftwareHandle {
    key_id: Vec<u8>,       // diagnostic-only tag embedded in the wrapped payload
    secret_key: SecretKey, // the service's private key, decrypted from disk
}

impl KekHandle for SoftwareHandle {
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

impl KekProvider for SoftwareProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Software
    }

    fn probe(&self) -> bool {
        ensure_private_dir(&self.dir).is_ok() // "available" simply means we can create/access the storage directory
    }

    fn get_or_create_kek(&self, service: &str) -> Result<Box<dyn KekHandle>> {
        ensure_private_dir(&self.dir)?; // make sure the directory exists before touching any files in it
        let vault_key = self.load_or_create_vault_key()?; // the AES key that protects every service's file
        let path = self.key_path(service); // this service's specific key file
        let key_id = service_fingerprint(service).into_bytes(); // non-secret diagnostic tag for the payload

        let secret_key = match fs::read(&path) {
            Ok(stored) => decrypt_private_key(&vault_key, &stored)?, // file exists: decrypt and reuse it
            Err(e) if e.kind() == ErrorKind::NotFound => {
                // first time this service is requested: generate, encrypt, and persist a new key
                let secret_key = SecretKey::random(&mut OsRng);
                let encrypted = encrypt_private_key(&vault_key, &secret_key)?;
                write_private_file_atomic(&path, &encrypted)?;
                secret_key
            }
            Err(e) => {
                return Err(Error::Provider(format!(
                    // any other I/O error is a hard failure, not "key doesn't exist yet"
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

// Serializes `secret_key` to PKCS#8 DER, then encrypts that DER blob with
// AES-256-GCM under `vault_key`, returning `nonce || ciphertext || tag`
// ready to write to disk. The plaintext DER never touches a heap
// allocation: it's encrypted in place inside a stack-allocated buffer
// (`der::SecretDocument`, which `to_pkcs8_der()` returns, already
// zeroizes its own heap storage on drop -- but encrypting via the
// in-place/detached API additionally avoids `aes_gcm`'s convenience
// `encrypt()` making a *second*, separate heap copy of the plaintext).
fn encrypt_private_key(vault_key: &[u8; VAULT_KEY_LEN], secret_key: &SecretKey) -> Result<Vec<u8>> {
    let der = secret_key
        .to_pkcs8_der() // standard, portable private-key encoding
        .map_err(|e| Error::Provider(format!("failed to encode KEK as PKCS#8: {e}")))?;
    let der_bytes = der.as_bytes();
    if der_bytes.len() != PKCS8_DER_LEN {
        // defensive: if a future dependency bump ever changes this
        // encoding's size, fail loudly rather than truncate/corrupt it
        return Err(Error::Provider(format!(
            "unexpected PKCS#8 DER length {} (expected {PKCS8_DER_LEN})",
            der_bytes.len()
        )));
    }

    let mut nonce_bytes = [0u8; FILE_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes); // fresh random nonce for this one encryption
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(vault_key)); // set up AES-256-GCM with the vault key

    // Copy the DER-encoded private key onto the stack and encrypt it in
    // place: `buf` starts as plaintext and ends as ciphertext, entirely
    // within this stack frame.
    let mut buf = [0u8; PKCS8_DER_LEN];
    buf.copy_from_slice(der_bytes);
    let tag: Tag = cipher
        .encrypt_in_place_detached(nonce, b"hkdfguard-software-kek-v1", &mut buf)
        .map_err(|_| Error::Provider("failed to encrypt KEK for storage".into()))?;
    // `buf` now holds ciphertext, not plaintext -- safe to copy into the
    // (necessarily heap-backed, variable-content) file buffer below.

    let mut out = Vec::with_capacity(FILE_NONCE_LEN + PKCS8_DER_LEN + TAG_LEN);
    out.extend_from_slice(&nonce_bytes); // nonce goes first so decryption knows where to find it
    out.extend_from_slice(&buf); // then the ciphertext
    out.extend_from_slice(&tag); // then the GCM tag
    Ok(out)
}

// Reverses `encrypt_private_key`: splits off the nonce and tag, decrypts
// and authenticates the ciphertext in place in a stack buffer, then
// parses the recovered DER back into a key. The decrypted private-key
// DER never touches a heap allocation.
fn decrypt_private_key(vault_key: &[u8; VAULT_KEY_LEN], stored: &[u8]) -> Result<SecretKey> {
    if stored.len() != FILE_NONCE_LEN + PKCS8_DER_LEN + TAG_LEN {
        return Err(Error::Provider("stored KEK file has unexpected length".into())); // wrong size to be one of our files at all
    }
    let (nonce_bytes, rest) = stored.split_at(FILE_NONCE_LEN); // first 12 bytes are the nonce
    let (ciphertext, tag_bytes) = rest.split_at(PKCS8_DER_LEN); // then the ciphertext, then the trailing tag
    let nonce = Nonce::from_slice(nonce_bytes);
    let tag = Tag::from_slice(tag_bytes);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(vault_key));

    // Decrypt in place into a stack buffer: `buf` starts as ciphertext
    // (not secret) and, only on successful authentication, ends as the
    // plaintext private-key DER.
    let mut buf = [0u8; PKCS8_DER_LEN];
    buf.copy_from_slice(ciphertext);
    let auth_result =
        cipher.decrypt_in_place_detached(nonce, b"hkdfguard-software-kek-v1", &mut buf, tag);

    if auth_result.is_err() {
        // Authentication failed: `buf` may now hold unauthenticated
        // (attacker-influenced or garbage) bytes -- scrub before erroring.
        buf.zeroize();
        return Err(Error::Provider(
            "failed to decrypt stored KEK (corrupt or tampered)".into(),
        ));
    }

    let secret_key = SecretKey::from_pkcs8_der(&buf) // parse the recovered DER back into a usable key
        .map_err(|e| Error::Provider(format!("stored KEK is not valid PKCS#8: {e}")));
    buf.zeroize(); // our stack copy of the plaintext DER is no longer needed once parsed into `SecretKey` (which zeroizes itself on drop)
    secret_key
}

/// Deterministic, filesystem-safe, non-reversible tag for `service`, used
/// as the on-disk filename. Not a KEK derivation -- it only addresses
/// where a randomly generated KEK is stored, exactly like macOS
/// `kSecAttrService` or a Windows CNG key name.
fn service_fingerprint(service: &str) -> String {
    let digest = Sha256::digest(service.as_bytes()); // hash the service name so it's filename-safe regardless of content
    hex_encode(&digest) // render as a hex string for use in a path
}

// Minimal, dependency-free hex encoder (avoids pulling in a `hex` crate for
// this one small use).
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write; // brings the `write!` macro's target trait into scope for `String`
    let mut s = String::with_capacity(bytes.len() * 2); // each byte becomes exactly 2 hex characters
    for b in bytes {
        let _ = write!(s, "{b:02x}"); // append this byte as two lowercase hex digits
    }
    s
}

// Decides where on disk this provider stores its files, honoring an
// explicit override, then falling back to a root-appropriate system
// directory, then a per-user config directory.
fn resolve_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("HKDFGUARD_SOFTWARE_DIR") {
        return PathBuf::from(dir); // explicit operator override always wins
    }

    #[cfg(unix)]
    {
        // Root / system services: a shared system-wide location.
        if unsafe { libc::geteuid() } == 0 {
            // SAFETY: `geteuid()` takes no arguments and has no preconditions; it's a pure syscall wrapper.
            return PathBuf::from("/var/lib/hkdfguard");
        }
    }

    dirs::config_dir() // platform-appropriate per-user config directory (e.g. $XDG_CONFIG_HOME)
        .unwrap_or_else(std::env::temp_dir) // last-resort fallback if even that can't be determined
        .join("hkdfguard")
}

// Creates the storage directory if needed and locks its permissions down
// to owner-only (0700) on Unix.
fn ensure_private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir) // no-op if it already exists; creates parents too
        .map_err(|e| Error::Provider(format!("failed to create {}: {e}", dir.display())))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt; // brings `from_mode`/`.mode()` into scope
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)) // owner read/write/execute only
            .map_err(|e| Error::Provider(format!("failed to chmod {}: {e}", dir.display())))?;
    }
    Ok(())
}

// Writes `contents` to `path` without ever leaving a partially-written or
// wrong-permission file visible: write to a temp file, chmod it, then
// atomically rename it into place.
fn write_private_file_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let tmp_path = path.with_extension("tmp"); // scratch file in the same directory (same filesystem, so rename is atomic)
    fs::write(&tmp_path, contents)
        .map_err(|e| Error::Provider(format!("failed to write {}: {e}", tmp_path.display())))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600)) // owner read/write only, before it's visible under its real name
            .map_err(|e| Error::Provider(format!("failed to chmod {}: {e}", tmp_path.display())))?;
    }

    fs::rename(&tmp_path, path) // atomic on the same filesystem: no window where `path` is partially written
        .map_err(|e| Error::Provider(format!("failed to finalize {}: {e}", path.display())))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*; // bring `SoftwareProvider` etc. into scope
    use serial_test::serial; // ensures these tests (which mutate a shared env var) never run concurrently
    use tempfile::tempdir; // throwaway directory, deleted when it goes out of scope

    // Runs `f` against a `SoftwareProvider` pointed at a fresh temp
    // directory, then cleans up the environment variable override.
    fn with_dir<F: FnOnce(&SoftwareProvider)>(f: F) {
        let dir = tempdir().unwrap();
        std::env::set_var("HKDFGUARD_SOFTWARE_DIR", dir.path()); // redirect this provider's storage to the temp dir
        let provider = SoftwareProvider::new();
        f(&provider);
        std::env::remove_var("HKDFGUARD_SOFTWARE_DIR"); // don't leak the override into other tests
    }

    #[test]
    #[serial]
    fn creates_and_reloads_same_key() {
        with_dir(|provider| {
            let h1 = provider.get_or_create_kek("com.company.orders").unwrap(); // creates the key file
            let h2 = provider.get_or_create_kek("com.company.orders").unwrap(); // must load the same key back

            let eph = SecretKey::random(&mut OsRng);
            let eph_pub = eph.public_key();

            assert_eq!(*h1.ecdh(&eph_pub).unwrap(), *h2.ecdh(&eph_pub).unwrap()); // same key -> same shared secret
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
            use std::os::unix::fs::PermissionsExt; // brings `.mode()` into scope
            let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777; // mask off the non-permission bits
            assert_eq!(mode, 0o600);
        });
    }
}
