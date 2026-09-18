//! The provider-agnostic wrap/unwrap protocol:
//! `ECDH(P-256) -> HKDF-SHA256 -> AES-256-GCM`.
//!
//! Every provider (TPM2, PKCS#11, external secret, software, ephemeral)
//! implements the same [`crate::provider::KekHandle::ecdh`] contract, so
//! this module is the *only* place the actual wrap/unwrap algorithm is
//! implemented -- providers never see plaintext DEKs or derived keys.
//!
//! Memory note: the DEK plaintext is kept in stack-allocated `[u8; DEK_LEN]`
//! buffers for the *entire* wrap/unwrap operation -- we deliberately use
//! `AeadInPlace::{encrypt,decrypt}_in_place_detached` instead of the more
//! convenient `Aead::{encrypt,decrypt}`, because the latter allocates a
//! heap `Vec<u8>` internally and, on the decrypt side, that `Vec` would
//! momentarily hold the *decrypted plaintext DEK* on the heap before we
//! could wrap it in `Zeroizing`. The in-place/detached API never touches
//! `alloc` at all for the DEK itself.

use crate::error::{Error, Result}; // this crate's error type + `Result` alias
use crate::payload::{Payload, NONCE_LEN, UNCOMPRESSED_POINT_LEN}; // wire-format struct + its fixed field sizes
use crate::provider; // provider selection functions (`select_for_wrap`, `get_by_type`)
use aes_gcm::{AeadInPlace, Aes256Gcm, Key, KeyInit, Nonce, Tag}; // in-place AEAD trait, concrete cipher, and its key/nonce/tag types (all fixed-size, stack-resident)
use elliptic_curve::sec1::ToEncodedPoint; // lets us serialize the ephemeral public key to SEC1 bytes
use hkdf::Hkdf; // HKDF-SHA256 key derivation
use p256::{PublicKey, SecretKey}; // P-256 key types
use rand_core::{OsRng, RngCore}; // OS RNG + the trait providing `fill_bytes`
use sha2::Sha256; // hash algorithm used inside HKDF
use zeroize::{Zeroize, Zeroizing}; // `Zeroize` for explicit scrubbing of stack arrays, `Zeroizing` for auto-scrubbing owned buffers

const HKDF_INFO_PREFIX: &[u8] = b"hkdfguard-wrap-v1:"; // domain-separation prefix; concatenated with the service name as HKDF's "info"
const AAD: &[u8] = b"hkdfguard-dek-v1"; // additional authenticated data binding ciphertext to this protocol/version
const TAG_LEN: usize = 16; // AES-GCM's standard 128-bit authentication tag size

pub const DEK_LEN: usize = 32; // the mandated, fixed DEK size in bytes

// Wraps `dek` under the persistent KEK for `service`, returning the
// serialized wrapped payload ready to store/transmit.
pub fn wrap(service: &str, dek: &[u8; DEK_LEN]) -> Result<Vec<u8>> {
    let (provider, handle) = provider::select_for_wrap(service)?; // walk the priority chain to get a usable KEK

    let ephemeral_secret = SecretKey::random(&mut OsRng); // fresh, one-time P-256 keypair for this single wrap operation
    let ephemeral_public = ephemeral_secret.public_key();

    let mut shared_secret = handle.ecdh(&ephemeral_public)?; // ECDH between our ephemeral key and the persistent KEK (already stack-only: see `provider::SharedSecret`)
    let mut wrapping_key = derive_wrapping_key(&shared_secret, service)?; // HKDF-SHA256 turns the shared secret into a 32-byte AES key (also stack-only)
    shared_secret.zeroize(); // the raw ECDH shared secret is no longer needed; scrub it now rather than waiting for scope exit

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes); // fresh random nonce for this one AES-GCM encryption

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*wrapping_key)); // set up AES-256-GCM with the derived key

    // Copy the DEK onto the stack (a plain array-to-array copy, no heap
    // involved) and encrypt it in place: `ct_buf` starts as plaintext and
    // ends as ciphertext, entirely within this stack frame.
    let mut ct_buf: [u8; DEK_LEN] = *dek;
    let tag_result =
        cipher.encrypt_in_place_detached(Nonce::from_slice(&nonce_bytes), AAD, &mut ct_buf);
    wrapping_key.zeroize(); // the derived AES key is no longer needed either way; scrub it immediately

    let tag: Tag = tag_result.map_err(|_| Error::Crypto("AES-256-GCM encryption failed"))?; // propagate any encryption error only after cleanup above
    // `ct_buf` now holds ciphertext, not plaintext -- safe to copy into the
    // (necessarily heap-backed, since it's variable-length) wire payload.
    let mut ciphertext = Vec::with_capacity(DEK_LEN + TAG_LEN);
    ciphertext.extend_from_slice(&ct_buf);
    ciphertext.extend_from_slice(&tag);

    let ephemeral_public_key: [u8; UNCOMPRESSED_POINT_LEN] = ephemeral_public
        .to_encoded_point(false) // `false` = uncompressed SEC1 encoding (0x04 || X || Y)
        .as_bytes()
        .try_into() // convert the slice into a fixed-size array
        .map_err(|_| Error::Crypto("unexpected ephemeral public key encoding length"))?; // defensive check; should never actually fail for P-256

    let payload = Payload {
        provider_type: provider.provider_type(), // records which provider produced this KEK, for `unwrap` to use later
        key_id: handle.key_id().to_vec(),         // provider's diagnostic tag
        ephemeral_public_key,
        nonce: nonce_bytes,
        ciphertext,
    };

    Ok(payload.to_bytes()) // serialize to the final wire format
}

// Reverses `wrap`: parses the payload, re-derives the same wrapping key,
// and decrypts+authenticates the original DEK back out. The recovered DEK
// lives only in the stack-allocated `[u8; DEK_LEN]` returned to the
// caller -- never in a heap buffer at any point.
pub fn unwrap(service: &str, wrapped: &[u8]) -> Result<[u8; DEK_LEN]> {
    let payload = Payload::from_bytes(wrapped)?; // parse and structurally validate the wire format (ciphertext stays a heap Vec, but it's ciphertext, not a secret)

    if payload.ciphertext.len() != DEK_LEN + TAG_LEN {
        return Err(Error::Crypto("wrapped ciphertext has unexpected length")); // malformed/tampered length; bail out before touching any crypto
    }

    let provider = provider::get_by_type(payload.provider_type)?; // must use the exact provider that originally wrapped this DEK
    let handle = provider.get_or_create_kek(service)?; // load (or, for TPM2/software, deterministically regenerate) that provider's KEK for this service

    let ephemeral_public = PublicKey::from_sec1_bytes(&payload.ephemeral_public_key) // parse the wrapper's one-time public key back out
        .map_err(|_| Error::Crypto("malformed ephemeral public key in wrapped payload"))?;

    let mut shared_secret = handle.ecdh(&ephemeral_public)?; // re-derive the same ECDH shared secret used during wrap
    let mut wrapping_key = derive_wrapping_key(&shared_secret, service)?; // re-derive the same AES key
    shared_secret.zeroize(); // scrub the shared secret as soon as we've derived the key from it

    // Split the wire ciphertext (still just ciphertext bytes, not secret)
    // into its AES-GCM ciphertext body and trailing tag, then copy the
    // body onto the stack -- this is the *only* place the decrypted DEK
    // will ever live.
    let (ct_part, tag_part) = payload.ciphertext.split_at(DEK_LEN);
    let mut dek = [0u8; DEK_LEN];
    dek.copy_from_slice(ct_part); // still ciphertext at this point
    let tag = Tag::from_slice(tag_part);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*wrapping_key));
    let auth_result =
        cipher.decrypt_in_place_detached(Nonce::from_slice(&payload.nonce), AAD, &mut dek, tag); // decrypts `dek` in place; on success it now holds the real plaintext DEK
    wrapping_key.zeroize(); // the AES key is no longer needed regardless of whether decryption succeeded

    if auth_result.is_err() {
        // Authentication failed: `dek` may now contain unauthenticated
        // (attacker-influenced or simply garbage) bytes from the in-place
        // decryption -- scrub it before returning rather than ever
        // handing it back to the caller.
        dek.zeroize();
        return Err(Error::Crypto(
            "AES-256-GCM authentication failed (tampered, wrong service, or wrong KEK)",
        ));
    }

    Ok(dek) // genuine plaintext DEK, stack-resident from decryption through to the caller
}

// Turns a raw ECDH shared secret into a 32-byte AES-256 key via
// HKDF-SHA256, using the service name as domain-separating "info" so the
// same shared secret would never accidentally produce the same wrapping
// key for a different service.
fn derive_wrapping_key(
    shared_secret: &[u8; 32],
    service: &str,
) -> Result<Zeroizing<[u8; 32]>> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret); // HKDF-Extract with no explicit salt (the ECDH secret is already high-entropy)
    let mut info = Vec::with_capacity(HKDF_INFO_PREFIX.len() + service.len()); // `info` is a public label, not a secret, so a heap Vec here is fine
    info.extend_from_slice(HKDF_INFO_PREFIX); // fixed prefix for domain separation from any other use of HKDF in this protocol
    info.extend_from_slice(service.as_bytes()); // then the service name itself

    let mut out = Zeroizing::new([0u8; 32]); // 32 bytes = AES-256 key size; stack-backed array wrapped for auto-scrub on drop
    hk.expand(&info, &mut *out) // HKDF-Expand into the output buffer using `info` as context
        .map_err(|_| Error::Crypto("HKDF-SHA256 expand failed"))?; // only fails if the requested output length were invalid (never true here)
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*; // bring `wrap`, `unwrap`, `DEK_LEN`, etc. into scope
    use serial_test::serial; // these tests mutate shared env vars, so they must run one at a time
    use tempfile::tempdir; // throwaway directory for the software provider's storage

    // Points the software provider at a fresh temp directory and disables
    // the external-secret provider, so every test in this module
    // deterministically exercises the software provider.
    fn with_isolated_software_provider<F: FnOnce()>(f: F) {
        let dir = tempdir().unwrap();
        std::env::set_var("HKDFGUARD_SOFTWARE_DIR", dir.path());
        std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", "/nonexistent-for-tests"); // guarantee this provider is unavailable
        f();
        std::env::remove_var("HKDFGUARD_SOFTWARE_DIR");
        std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
    }

    #[test]
    #[serial]
    fn round_trips_through_software_provider() {
        with_isolated_software_provider(|| {
            let dek = [0x42u8; DEK_LEN]; // arbitrary fixed test DEK
            let wrapped = wrap("com.company.orders", &dek).unwrap();
            let recovered = unwrap("com.company.orders", &wrapped).unwrap();
            assert_eq!(dek, recovered); // must get back exactly what was wrapped
        });
    }

    #[test]
    #[serial]
    fn wrong_service_fails_to_unwrap() {
        with_isolated_software_provider(|| {
            let dek = [0x11u8; DEK_LEN];
            let wrapped = wrap("com.company.orders", &dek).unwrap();
            let err = unwrap("com.company.billing", &wrapped).unwrap_err(); // deliberately wrong service name
            assert!(matches!(err, Error::Crypto(_))); // must fail as a crypto/auth error, not silently succeed
        });
    }

    #[test]
    #[serial]
    fn tampered_ciphertext_fails_to_unwrap() {
        with_isolated_software_provider(|| {
            let dek = [0x99u8; DEK_LEN];
            let mut wrapped = wrap("com.company.orders", &dek).unwrap();
            let last = wrapped.len() - 1;
            wrapped[last] ^= 0x01; // flip one bit in the ciphertext/tag
            let err = unwrap("com.company.orders", &wrapped).unwrap_err();
            assert!(matches!(err, Error::Crypto(_))); // AEAD authentication must catch the tamper
        });
    }

    #[test]
    #[serial]
    fn truncated_ciphertext_fails_to_unwrap() {
        with_isolated_software_provider(|| {
            let dek = [0x22u8; DEK_LEN];
            let mut wrapped = wrap("com.company.orders", &dek).unwrap();
            wrapped.truncate(wrapped.len() - 5); // chop bytes out of the ciphertext/tag region
            let err = unwrap("com.company.orders", &wrapped).unwrap_err();
            assert!(matches!(err, Error::Crypto(_))); // must be rejected by the explicit length check, not panic in `split_at`
        });
    }

    #[test]
    #[serial]
    fn same_dek_wrapped_twice_yields_different_ciphertexts() {
        with_isolated_software_provider(|| {
            let dek = [0x77u8; DEK_LEN];
            let a = wrap("com.company.orders", &dek).unwrap();
            let b = wrap("com.company.orders", &dek).unwrap(); // same DEK, same service, wrapped again
            assert_ne!(a, b, "ephemeral ECDH + random nonce must randomize output"); // must not be deterministic
        });
    }

    #[test]
    fn derive_wrapping_key_properties() {
        let secret1 = [0x11u8; 32];
        let secret2 = [0x22u8; 32];

        let k1 = derive_wrapping_key(&secret1, "service.a").unwrap();
        let k1_repeat = derive_wrapping_key(&secret1, "service.a").unwrap();
        assert_eq!(*k1, *k1_repeat, "HKDF must be deterministic for identical inputs");

        let k2 = derive_wrapping_key(&secret1, "service.b").unwrap();
        assert_ne!(*k1, *k2, "service name must provide domain separation");

        let k3 = derive_wrapping_key(&secret2, "service.a").unwrap();
        assert_ne!(*k1, *k3, "different shared secrets must yield different wrapping keys");
    }

    #[test]
    #[serial]
    fn round_trips_various_dek_patterns() {
        with_isolated_software_provider(|| {
            let patterns: [[u8; DEK_LEN]; 4] = [
                [0x00u8; DEK_LEN],
                [0xFFu8; DEK_LEN],
                core::array::from_fn(|i| i as u8),
                core::array::from_fn(|i| (255 - i) as u8),
            ];

            for dek in patterns {
                let wrapped = wrap("com.company.orders", &dek).unwrap();
                let recovered = unwrap("com.company.orders", &wrapped).unwrap();
                assert_eq!(dek, recovered);
            }
        });
    }

    #[test]
    #[serial]
    fn round_trips_through_ephemeral_provider() {
        // Disable external secret and software provider so wrap uses Ephemeral
        std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", "/nonexistent-dir-for-tests");
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::env::set_var("HKDFGUARD_SOFTWARE_DIR", tmp.path());

        let dek = [0x88u8; DEK_LEN];
        let wrapped = wrap("com.company.ephemeral.test", &dek).unwrap();
        let recovered = unwrap("com.company.ephemeral.test", &wrapped).unwrap();
        assert_eq!(dek, recovered);

        std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
        std::env::remove_var("HKDFGUARD_SOFTWARE_DIR");
    }

    #[test]
    #[serial]
    fn tampered_ephemeral_public_key_fails_to_unwrap() {
        with_isolated_software_provider(|| {
            let dek = [0x33u8; DEK_LEN];
            let wrapped = wrap("com.company.orders", &dek).unwrap();
            // In payload layout: offset 0=version, 1=provider, 2..4=key_id_len (N bytes key_id), then 65 bytes ephemeral pubkey
            let mut payload = Payload::from_bytes(&wrapped).unwrap();
            payload.ephemeral_public_key[1] ^= 0x01; // flip a bit in the X coordinate
            let tampered_bytes = payload.to_bytes();

            let err = unwrap("com.company.orders", &tampered_bytes).unwrap_err();
            assert!(matches!(err, Error::Crypto(_)));
        });
    }

    #[test]
    #[serial]
    fn tampered_nonce_fails_to_unwrap() {
        with_isolated_software_provider(|| {
            let dek = [0x44u8; DEK_LEN];
            let wrapped = wrap("com.company.orders", &dek).unwrap();
            let mut payload = Payload::from_bytes(&wrapped).unwrap();
            payload.nonce[0] ^= 0x01; // flip a bit in nonce
            let tampered_bytes = payload.to_bytes();

            let err = unwrap("com.company.orders", &tampered_bytes).unwrap_err();
            assert!(matches!(err, Error::Crypto(_)));
        });
    }
}
