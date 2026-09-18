//! The provider-agnostic wrap/unwrap protocol:
//! `ECDH(P-256) -> HKDF-SHA256 -> AES-256-GCM`.
//!
//! Every provider (TPM2, PKCS#11, external secret, software, ephemeral)
//! implements the same [`crate::provider::KekHandle::ecdh`] contract, so
//! this module is the *only* place the actual wrap/unwrap algorithm is
//! implemented -- providers never see plaintext DEKs or derived keys.

use crate::error::{Error, Result};
use crate::payload::{Payload, NONCE_LEN, UNCOMPRESSED_POINT_LEN};
use crate::provider;
use aes_gcm::aead::{Aead, KeyInit, Payload as AeadPayload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use elliptic_curve::sec1::ToEncodedPoint;
use hkdf::Hkdf;
use p256::{PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

const HKDF_INFO_PREFIX: &[u8] = b"hkdfguard-wrap-v1:";
const AAD: &[u8] = b"hkdfguard-dek-v1";

pub const DEK_LEN: usize = 32;

pub fn wrap(service: &str, dek: &[u8; DEK_LEN]) -> Result<Vec<u8>> {
    let (provider, handle) = provider::select_for_wrap(service)?;

    let ephemeral_secret = SecretKey::random(&mut OsRng);
    let ephemeral_public = ephemeral_secret.public_key();

    let mut shared_secret = handle.ecdh(&ephemeral_public)?;
    let mut wrapping_key = derive_wrapping_key(&shared_secret, service)?;
    shared_secret.zeroize_in_place();

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*wrapping_key));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            AeadPayload {
                msg: dek.as_slice(),
                aad: AAD,
            },
        )
        .map_err(|_| Error::Crypto("AES-256-GCM encryption failed"));
    wrapping_key.zeroize_in_place();
    let ciphertext = ciphertext?;

    let ephemeral_public_key: [u8; UNCOMPRESSED_POINT_LEN] = ephemeral_public
        .to_encoded_point(false)
        .as_bytes()
        .try_into()
        .map_err(|_| Error::Crypto("unexpected ephemeral public key encoding length"))?;

    let payload = Payload {
        provider_type: provider.provider_type(),
        key_id: handle.key_id().to_vec(),
        ephemeral_public_key,
        nonce: nonce_bytes,
        ciphertext,
    };

    Ok(payload.to_bytes())
}

pub fn unwrap(service: &str, wrapped: &[u8]) -> Result<[u8; DEK_LEN]> {
    let payload = Payload::from_bytes(wrapped)?;

    let provider = provider::get_by_type(payload.provider_type)?;
    let handle = provider.get_or_create_kek(service)?;

    let ephemeral_public = PublicKey::from_sec1_bytes(&payload.ephemeral_public_key)
        .map_err(|_| Error::Crypto("malformed ephemeral public key in wrapped payload"))?;

    let mut shared_secret = handle.ecdh(&ephemeral_public)?;
    let mut wrapping_key = derive_wrapping_key(&shared_secret, service)?;
    shared_secret.zeroize_in_place();

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*wrapping_key));
    let plaintext = cipher.decrypt(
        Nonce::from_slice(&payload.nonce),
        AeadPayload {
            msg: &payload.ciphertext,
            aad: AAD,
        },
    );
    wrapping_key.zeroize_in_place();

    let plaintext = plaintext.map_err(|_| {
        Error::Crypto("AES-256-GCM authentication failed (tampered, wrong service, or wrong KEK)")
    })?;
    let mut plaintext = Zeroizing::new(plaintext);

    if plaintext.len() != DEK_LEN {
        plaintext.zeroize_in_place();
        return Err(Error::Crypto("decrypted DEK has unexpected length"));
    }

    let mut dek = [0u8; DEK_LEN];
    dek.copy_from_slice(&plaintext);
    Ok(dek)
}

fn derive_wrapping_key(
    shared_secret: &[u8; 32],
    service: &str,
) -> Result<Zeroizing<[u8; 32]>> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut info = Vec::with_capacity(HKDF_INFO_PREFIX.len() + service.len());
    info.extend_from_slice(HKDF_INFO_PREFIX);
    info.extend_from_slice(service.as_bytes());

    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(&info, &mut *out)
        .map_err(|_| Error::Crypto("HKDF-SHA256 expand failed"))?;
    Ok(out)
}

/// Small local extension so `Zeroizing<[u8; 32]>` values can be explicitly
/// zeroized *before* they go out of scope (e.g. immediately after the AEAD
/// call, rather than waiting for the end of the function), matching the
/// spec's "shortest possible lifetime" requirement.
trait ZeroizeInPlace {
    fn zeroize_in_place(&mut self);
}

impl ZeroizeInPlace for Zeroizing<[u8; 32]> {
    fn zeroize_in_place(&mut self) {
        use zeroize::Zeroize;
        self.as_mut().zeroize();
    }
}

impl ZeroizeInPlace for Zeroizing<Vec<u8>> {
    fn zeroize_in_place(&mut self) {
        use zeroize::Zeroize;
        self.as_mut_slice().zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use tempfile::tempdir;

    fn with_isolated_software_provider<F: FnOnce()>(f: F) {
        let dir = tempdir().unwrap();
        std::env::set_var("HKDFGUARD_SOFTWARE_DIR", dir.path());
        std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", "/nonexistent-for-tests");
        f();
        std::env::remove_var("HKDFGUARD_SOFTWARE_DIR");
        std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
    }

    #[test]
    #[serial]
    fn round_trips_through_software_provider() {
        with_isolated_software_provider(|| {
            let dek = [0x42u8; DEK_LEN];
            let wrapped = wrap("com.company.orders", &dek).unwrap();
            let recovered = unwrap("com.company.orders", &wrapped).unwrap();
            assert_eq!(dek, recovered);
        });
    }

    #[test]
    #[serial]
    fn wrong_service_fails_to_unwrap() {
        with_isolated_software_provider(|| {
            let dek = [0x11u8; DEK_LEN];
            let wrapped = wrap("com.company.orders", &dek).unwrap();
            let err = unwrap("com.company.billing", &wrapped).unwrap_err();
            assert!(matches!(err, Error::Crypto(_)));
        });
    }

    #[test]
    #[serial]
    fn tampered_ciphertext_fails_to_unwrap() {
        with_isolated_software_provider(|| {
            let dek = [0x99u8; DEK_LEN];
            let mut wrapped = wrap("com.company.orders", &dek).unwrap();
            let last = wrapped.len() - 1;
            wrapped[last] ^= 0x01;
            let err = unwrap("com.company.orders", &wrapped).unwrap_err();
            assert!(matches!(err, Error::Crypto(_)));
        });
    }

    #[test]
    #[serial]
    fn same_dek_wrapped_twice_yields_different_ciphertexts() {
        with_isolated_software_provider(|| {
            let dek = [0x77u8; DEK_LEN];
            let a = wrap("com.company.orders", &dek).unwrap();
            let b = wrap("com.company.orders", &dek).unwrap();
            assert_ne!(a, b, "ephemeral ECDH + random nonce must randomize output");
        });
    }
}
