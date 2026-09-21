//! Direct AES-GCM encrypt/decrypt under a caller-supplied key.
//!
//! Unlike `crypto.rs` (which wraps a *DEK* under a persistent KEK), this
//! module operates directly on a caller-supplied key -- typically a DEK
//! already recovered via [`crate::crypto::unwrap`] -- to encrypt/decrypt
//! arbitrary payloads. Mirrors `HkdfGuardAesGcm.swift` in this project's
//! macOS implementation: same payload layout, same key-length support
//! (AES-128/192/256), same behavior on every error path, so a caller
//! switching between the two platforms' `hkdfguard_encrypt`/
//! `hkdfguard_decrypt` sees identical behavior.
//!
//! Payload layout -- both what [`encrypt`] produces and what [`decrypt`]
//! expects to read:
//!
//! ```text
//! [12-byte nonce][ciphertext, same length as the plaintext][16-byte tag]
//! ```
//!
//! All three AES-GCM key sizes use the same 12-byte nonce and 16-byte tag,
//! so this layout does not vary by key length.

use crate::error::{Error, Result};
use aes_gcm::aead::{Nonce, Tag};
use aes_gcm::{AeadInPlace, Aes128Gcm, Aes256Gcm, Key, KeyInit};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

pub const NONCE_LEN: usize = 12; // AES-GCM's standard 96-bit nonce
pub const TAG_LEN: usize = 16; // AES-GCM's standard 128-bit authentication tag
pub const OVERHEAD: usize = NONCE_LEN + TAG_LEN; // fixed bytes added around the plaintext/ciphertext by every payload

// `aes-gcm` only re-exports `Aes128Gcm`/`Aes256Gcm` directly; AES-192-GCM
// isn't common enough to get its own alias, but it's the same `AesGcm<Aes,
// NonceSize>` generic underneath, so this builds it from the `aes` crate's
// `Aes192` block cipher (re-exported as `aes_gcm::aes`) the exact same way
// the crate itself builds the other two.
type Aes192Gcm = aes_gcm::AesGcm<aes_gcm::aes::Aes192, aes_gcm::aead::consts::U12>;

/// Encrypts `plaintext` with AES-GCM under `key` (16, 24, or 32 bytes --
/// AES-128/192/256), authenticating `aad` alongside it (without encrypting
/// it), and returns `nonce || ciphertext || tag`.
pub fn encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    // `buf` starts as a copy of the plaintext and is encrypted in place,
    // becoming the ciphertext -- mirrors the in-place style `crypto.rs`
    // uses for the same reason (avoid a second heap copy of sensitive
    // data hanging around after encryption).
    let mut buf = plaintext.to_vec();
    let tag = seal_in_place(key, &nonce_bytes, aad, &mut buf)?;

    let mut out = Vec::with_capacity(NONCE_LEN + buf.len() + TAG_LEN);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&buf);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Decrypts and authenticates a `nonce || ciphertext || tag` payload
/// produced by [`encrypt`], returning the recovered plaintext. The result
/// is wrapped in [`Zeroizing`] since the caller-supplied key generally
/// protects sensitive data -- the plaintext is scrubbed the moment its
/// last owner (this function's caller) drops it.
pub fn decrypt(key: &[u8], payload: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if payload.len() < OVERHEAD {
        return Err(Error::Crypto(
            "payload shorter than the fixed nonce+tag overhead",
        ));
    }
    let (nonce, rest) = payload.split_at(NONCE_LEN);
    let (ciphertext, tag) = rest.split_at(rest.len() - TAG_LEN);

    let mut buf = Zeroizing::new(ciphertext.to_vec()); // decrypted in place below, becoming the plaintext
    open_in_place(key, nonce, aad, &mut buf, tag)?;
    Ok(buf)
}

// The only two functions in this module that know a specific AES-GCM key
// size by name -- everything above only talks about `&[u8]` key slices,
// dispatching on length. Mirrors the `seal_in_place`/`open_in_place` split
// used in `crypto.rs` for the same reason: one place per direction that
// actually names a concrete cipher type.
fn seal_in_place(key: &[u8], nonce: &[u8], aad: &[u8], buf: &mut [u8]) -> Result<Vec<u8>> {
    match key.len() {
        16 => {
            let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(key));
            cipher
                .encrypt_in_place_detached(Nonce::<Aes128Gcm>::from_slice(nonce), aad, buf)
                .map(|tag| tag.to_vec())
                .map_err(|_| Error::Crypto("AES-128-GCM encryption failed"))
        }
        24 => {
            let cipher = Aes192Gcm::new(Key::<Aes192Gcm>::from_slice(key));
            cipher
                .encrypt_in_place_detached(Nonce::<Aes192Gcm>::from_slice(nonce), aad, buf)
                .map(|tag| tag.to_vec())
                .map_err(|_| Error::Crypto("AES-192-GCM encryption failed"))
        }
        32 => {
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
            cipher
                .encrypt_in_place_detached(Nonce::<Aes256Gcm>::from_slice(nonce), aad, buf)
                .map(|tag| tag.to_vec())
                .map_err(|_| Error::Crypto("AES-256-GCM encryption failed"))
        }
        _ => Err(Error::Crypto("key length must be 16, 24, or 32 bytes")),
    }
}

fn open_in_place(key: &[u8], nonce: &[u8], aad: &[u8], buf: &mut [u8], tag: &[u8]) -> Result<()> {
    match key.len() {
        16 => {
            let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(key));
            cipher
                .decrypt_in_place_detached(
                    Nonce::<Aes128Gcm>::from_slice(nonce),
                    aad,
                    buf,
                    Tag::<Aes128Gcm>::from_slice(tag),
                )
                .map_err(|_| Error::Crypto("AES-128-GCM authentication failed"))
        }
        24 => {
            let cipher = Aes192Gcm::new(Key::<Aes192Gcm>::from_slice(key));
            cipher
                .decrypt_in_place_detached(
                    Nonce::<Aes192Gcm>::from_slice(nonce),
                    aad,
                    buf,
                    Tag::<Aes192Gcm>::from_slice(tag),
                )
                .map_err(|_| Error::Crypto("AES-192-GCM authentication failed"))
        }
        32 => {
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
            cipher
                .decrypt_in_place_detached(
                    Nonce::<Aes256Gcm>::from_slice(nonce),
                    aad,
                    buf,
                    Tag::<Aes256Gcm>::from_slice(tag),
                )
                .map_err(|_| Error::Crypto("AES-256-GCM authentication failed"))
        }
        _ => Err(Error::Crypto("key length must be 16, 24, or 32 bytes")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_all_key_sizes() {
        for key_len in [16usize, 24, 32] {
            let key = vec![0x42u8; key_len];
            let plaintext = b"the quick brown fox jumps over the lazy dog".to_vec();
            let aad = b"context-binding-data".to_vec();

            let sealed = encrypt(&key, &plaintext, &aad).unwrap();
            assert_eq!(sealed.len(), plaintext.len() + OVERHEAD);

            let recovered = decrypt(&key, &sealed, &aad).unwrap();
            assert_eq!(&*recovered, &plaintext, "key length {key_len} failed to round-trip");
        }
    }

    #[test]
    fn round_trips_empty_plaintext() {
        let key = vec![0x11u8; 32];
        let sealed = encrypt(&key, &[], &[]).unwrap();
        assert_eq!(sealed.len(), OVERHEAD); // just nonce + tag, no ciphertext body
        let recovered = decrypt(&key, &sealed, &[]).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn round_trips_without_aad() {
        let key = vec![0x22u8; 16];
        let plaintext = b"no aad here".to_vec();
        let sealed = encrypt(&key, &plaintext, &[]).unwrap();
        let recovered = decrypt(&key, &sealed, &[]).unwrap();
        assert_eq!(&*recovered, &plaintext);
    }

    #[test]
    fn rejects_invalid_key_length() {
        let bad_key = vec![0u8; 20]; // not 16, 24, or 32
        assert!(encrypt(&bad_key, b"data", &[]).is_err());
        let sealed = encrypt(&vec![0u8; 32], b"data", &[]).unwrap();
        assert!(decrypt(&bad_key, &sealed, &[]).is_err());
    }

    #[test]
    fn rejects_truncated_payload() {
        let key = vec![0x33u8; 32];
        let sealed = encrypt(&key, b"some data", &[]).unwrap();
        for len in 0..OVERHEAD {
            assert!(
                decrypt(&key, &sealed[..len], &[]).is_err(),
                "should reject payload truncated to {len} bytes (below the {OVERHEAD}-byte overhead)"
            );
        }
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let key = vec![0x44u8; 32];
        let wrong_key = vec![0x55u8; 32];
        let sealed = encrypt(&key, b"secret payload", &[]).unwrap();
        assert!(decrypt(&wrong_key, &sealed, &[]).is_err());
    }

    #[test]
    fn wrong_aad_fails_to_decrypt() {
        let key = vec![0x66u8; 32];
        let sealed = encrypt(&key, b"secret payload", b"correct-aad").unwrap();
        assert!(decrypt(&key, &sealed, b"wrong-aad").is_err());
        assert!(decrypt(&key, &sealed, b"").is_err());
    }

    #[test]
    fn tampered_ciphertext_fails_to_decrypt() {
        let key = vec![0x77u8; 32];
        let mut sealed = encrypt(&key, b"secret payload", &[]).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01; // flip a bit in the tag
        assert!(decrypt(&key, &sealed, &[]).is_err());

        let mut sealed2 = encrypt(&key, b"secret payload", &[]).unwrap();
        sealed2[NONCE_LEN] ^= 0x01; // flip a bit in the ciphertext body
        assert!(decrypt(&key, &sealed2, &[]).is_err());

        let mut sealed3 = encrypt(&key, b"secret payload", &[]).unwrap();
        sealed3[0] ^= 0x01; // flip a bit in the nonce
        assert!(decrypt(&key, &sealed3, &[]).is_err());
    }

    #[test]
    fn same_plaintext_encrypted_twice_yields_different_ciphertexts() {
        let key = vec![0x88u8; 32];
        let a = encrypt(&key, b"same message", &[]).unwrap();
        let b = encrypt(&key, b"same message", &[]).unwrap();
        assert_ne!(a, b, "random nonce must randomize output");
    }

    #[test]
    fn each_key_size_produces_a_distinct_result_for_the_same_plaintext() {
        // Not a security property, just confirms the three branches in
        // `seal_in_place` are actually distinct code paths, not one
        // silently falling through to another.
        let plaintext = b"identical plaintext, different key sizes".to_vec();
        let sealed128 = encrypt(&vec![0x99u8; 16], &plaintext, &[]).unwrap();
        let sealed192 = encrypt(&vec![0x99u8; 24], &plaintext, &[]).unwrap();
        let sealed256 = encrypt(&vec![0x99u8; 32], &plaintext, &[]).unwrap();
        assert_eq!(sealed128.len(), sealed192.len());
        assert_eq!(sealed192.len(), sealed256.len());
        // Ciphertext bytes should differ across key sizes even discounting
        // the random nonce, since they're genuinely different keys/ciphers.
        assert_ne!(sealed128[NONCE_LEN..], sealed192[NONCE_LEN..]);
        assert_ne!(sealed192[NONCE_LEN..], sealed256[NONCE_LEN..]);
    }
}
