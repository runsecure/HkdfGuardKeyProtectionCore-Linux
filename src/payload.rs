//! Self-describing wire format for a wrapped DEK.
//!
//! Deliberately hand-rolled rather than `serde`+`bincode`: this is a
//! security-critical, cross-language, cross-version wire format that other
//! implementations (macOS Secure Enclave, Windows TPM/CNG) must be able to
//! parse byte-for-byte, so every field width and order is pinned here
//! explicitly rather than left to a serialization library's defaults.
//!
//! Layout (all integers little-endian):
//!
//! ```text
//! offset  size  field
//! 0       1     version            (currently 1)
//! 1       1     provider_type      (1=TPM2 2=PKCS11 3=EXTERNAL_SECRET 5=EPHEMERAL;
//!                                   4 was SOFTWARE, retired -- see `ProviderType`)
//! 2       2     key_id_len (u16)
//! 4       N     key_id             (provider-specific opaque identifier)
//! 4+N     32    salt               (per-payload random HKDF salt)
//! 36+N    12    nonce              (AES-256-GCM 96-bit nonce)
//! 48+N    4     ciphertext_len (u32)
//! 52+N    M     ciphertext         (AES-256-GCM ciphertext, includes 16-byte tag)
//! 52+N+M  32    fingerprint        (SHA-256 of the persistent KEK's public key --
//!                                   see `crypto::kek_fingerprint` -- checked by
//!                                   `unwrap` before any ECDH/AES-GCM is attempted)
//! ```
//!
//! The service name is intentionally NOT part of this payload -- per spec it
//! is supplied out-of-band on every wrap/unwrap call. It is nonetheless
//! bound into the key derivation; see [`crate::crypto`].
//!
//! The leading version byte exists so the layout can evolve without a
//! future parser ever misreading an old blob as a new one; `from_bytes`
//! rejects any value other than [`VERSION`] outright. Note the `salt`
//! field is deliberately a random HKDF salt and *not* an ephemeral ECDH
//! public key -- see [`crate::crypto`] for why the protocol derives the
//! wrapping key from a fixed point rather than an ephemeral one.
//!
//! Every field here except the ciphertext is authenticated, both as the
//! AEAD's associated data and as part of the HKDF `info` -- see
//! [`Payload::authenticated_bytes`].

use crate::error::{Error, Result}; // this module's own error type + `Result<T, Error>` alias
use crate::provider::ProviderType; // the 1..=5 provider tag stored in the payload

pub const VERSION: u8 = 1; // current wire-format version; bump and branch in `from_bytes` if the layout ever changes
pub const SALT_LEN: usize = 32; // per-payload HKDF salt; 32 bytes matches SHA-256's output size, HKDF's natural salt width
pub const NONCE_LEN: usize = 12; // AES-GCM's standard 96-bit nonce size
pub const FINGERPRINT_LEN: usize = 32; // SHA-256 digest size

// Plain Rust struct mirroring the wire layout above; `to_bytes`/`from_bytes`
// are the only places that translate between this and raw bytes.
#[derive(Debug)]
pub struct Payload {
    pub provider_type: ProviderType, // which provider produced (and must later reload) the KEK
    pub key_id: Vec<u8>,             // provider-specific opaque tag, variable length
    pub salt: [u8; SALT_LEN],        // per-payload random HKDF salt; what makes each payload's wrapping key unique
    pub nonce: [u8; NONCE_LEN],      // the AES-GCM nonce used for this one encryption
    pub ciphertext: Vec<u8>,         // AES-GCM ciphertext, tag included at the end
    pub fingerprint: [u8; FINGERPRINT_LEN], // SHA-256 of the persistent KEK's public key at wrap time
}

impl Payload {
    // Length of everything this payload serializes to except the
    // ciphertext bytes and the trailing fingerprint.
    fn prefix_len(&self) -> usize {
        1 + 1 + 2 + self.key_id.len() + SALT_LEN + NONCE_LEN + 4
    }

    // Writes every field except the ciphertext bytes and the trailing
    // fingerprint, in wire order.
    //
    // This is the *single* definition of field order, shared by
    // `to_bytes` and `authenticated_bytes`, so the serialized form and
    // the authenticated form can never drift apart -- a field added here
    // is automatically both written and authenticated. Getting that wrong
    // in either direction is how unauthenticated header fields (and the
    // attacks they enable) creep into a format over time.
    fn write_prefix(&self, out: &mut Vec<u8>) {
        out.push(VERSION); // byte 0: format version
        out.push(self.provider_type as u8); // byte 1: provider tag (enum cast to its u8 discriminant)
        out.extend_from_slice(&(self.key_id.len() as u16).to_le_bytes()); // bytes 2..4: key_id length, little-endian u16
        out.extend_from_slice(&self.key_id); // the key_id bytes themselves
        out.extend_from_slice(&self.salt); // fixed 32-byte per-payload HKDF salt
        out.extend_from_slice(&self.nonce); // fixed 12-byte AES-GCM nonce
        out.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes()); // ciphertext length, little-endian u32
    }

    // Serializes this payload into the exact byte layout documented above.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.prefix_len() + self.ciphertext.len() + FINGERPRINT_LEN);
        self.write_prefix(&mut out);
        out.extend_from_slice(&self.ciphertext); // the ciphertext (+ tag) bytes themselves
        out.extend_from_slice(&self.fingerprint); // fixed 32-byte trailing KEK fingerprint
        out // return the fully assembled buffer
    }

    /// Every byte of this payload except the ciphertext itself: the
    /// header fields in wire order, followed by the trailing fingerprint.
    ///
    /// Used both as the AEAD's associated data and as part of the HKDF
    /// `info`, so every non-ciphertext byte is authenticated *and* bound
    /// into key derivation. The ciphertext is excluded because the AEAD
    /// already authenticates it directly; its declared *length* is
    /// included, since that is a header field a tamperer could otherwise
    /// shift.
    pub fn authenticated_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.prefix_len() + FINGERPRINT_LEN);
        self.write_prefix(&mut out);
        out.extend_from_slice(&self.fingerprint);
        out
    }

    // Parses a byte slice back into a `Payload`, validating every field as
    // it goes so malformed/truncated/tampered input is rejected cleanly
    // rather than panicking or reading out of bounds.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let mut cursor = Cursor { buf, pos: 0 }; // tracks how far we've consumed `buf`

        let version = cursor.take(1)?[0]; // read 1 byte and unwrap it from the returned slice
        if version != VERSION {
            return Err(Error::Crypto("unsupported wrapped payload version")); // reject anything but the version we know how to parse
        }

        let provider_byte = cursor.take(1)?[0]; // read the raw provider-tag byte
        let provider_type = ProviderType::from_u8(provider_byte) // convert the raw byte into the enum
            .ok_or(Error::Crypto("unknown provider type in wrapped payload"))?; // reject any value outside 1..=5

        let key_id_len = u16::from_le_bytes(cursor.take(2)?.try_into().unwrap()) as usize; // read the 2-byte length prefix, then widen to usize for indexing
        let key_id = cursor.take(key_id_len)?.to_vec(); // read exactly that many bytes and copy them into an owned Vec

        let salt: [u8; SALT_LEN] = cursor.take(SALT_LEN)?.try_into().unwrap(); // read the fixed 32-byte HKDF salt into a fixed-size array

        let nonce: [u8; NONCE_LEN] = cursor.take(NONCE_LEN)?.try_into().unwrap(); // read the fixed 12-byte nonce into a fixed-size array

        let ciphertext_len = u32::from_le_bytes(cursor.take(4)?.try_into().unwrap()) as usize; // read the 4-byte ciphertext length prefix
        let ciphertext = cursor.take(ciphertext_len)?.to_vec(); // read exactly that many ciphertext bytes

        let fingerprint: [u8; FINGERPRINT_LEN] = cursor.take(FINGERPRINT_LEN)?.try_into().unwrap(); // read the fixed 32-byte trailing fingerprint

        if cursor.pos != cursor.buf.len() {
            // anything left over after consuming every declared field means the
            // input was longer than a valid payload -- reject it rather than
            // silently ignoring trailing garbage.
            return Err(Error::Crypto("trailing bytes after wrapped payload"));
        }

        Ok(Payload {
            provider_type,
            key_id,
            salt,
            nonce,
            ciphertext,
            fingerprint,
        }) // hand back the fully reconstructed, validated payload
    }
}

// Minimal forward-only byte reader used only inside `from_bytes`, so each
// field read is a single bounds-checked call instead of manual slicing.
struct Cursor<'a> {
    buf: &'a [u8], // the full input buffer being parsed (borrowed, not copied)
    pos: usize,    // how many bytes have been consumed so far
}

impl<'a> Cursor<'a> {
    // Returns the next `n` bytes and advances the cursor past them, or an
    // error if that would run past the end of the buffer (or overflow).
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n) // guard against `pos + n` overflowing usize on a hostile length field
            .ok_or(Error::Crypto("wrapped payload field length overflow"))?;
        if end > self.buf.len() {
            return Err(Error::Crypto("wrapped payload is truncated")); // requested more bytes than remain
        }
        let slice = &self.buf[self.pos..end]; // the requested slice, borrowed from the original buffer
        self.pos = end; // advance the cursor past what we just returned
        Ok(slice)
    }
}

#[cfg(test)] // this whole module is compiled only when running `cargo test`
mod tests {
    use super::*; // bring `Payload`, `ProviderType`, the length constants, etc. into scope

    #[test]
    fn round_trips() {
        // Build an arbitrary payload...
        let payload = Payload {
            provider_type: ProviderType::ExternalSecret,
            key_id: vec![1, 2, 3, 4],
            salt: [7u8; SALT_LEN],
            nonce: [9u8; NONCE_LEN],
            ciphertext: vec![0xAA; 48],
            fingerprint: [0xEE; FINGERPRINT_LEN],
        };
        let bytes = payload.to_bytes(); // ...serialize it...
        let parsed = Payload::from_bytes(&bytes).unwrap(); // ...and parse it back.
        // Every field should survive the round trip unchanged.
        assert_eq!(parsed.provider_type, payload.provider_type);
        assert_eq!(parsed.key_id, payload.key_id);
        assert_eq!(parsed.salt, payload.salt);
        assert_eq!(parsed.nonce, payload.nonce);
        assert_eq!(parsed.ciphertext, payload.ciphertext);
        assert_eq!(parsed.fingerprint, payload.fingerprint);
    }

    #[test]
    fn round_trips_empty_key_id_and_empty_ciphertext() {
        let payload = Payload {
            provider_type: ProviderType::Ephemeral,
            key_id: vec![],
            salt: [0x04; SALT_LEN],
            nonce: [0x55; NONCE_LEN],
            ciphertext: vec![],
            fingerprint: [0xEE; FINGERPRINT_LEN],
        };
        let bytes = payload.to_bytes();
        let parsed = Payload::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.provider_type, ProviderType::Ephemeral);
        assert!(parsed.key_id.is_empty());
        assert_eq!(parsed.salt, [0x04; SALT_LEN]);
        assert_eq!(parsed.nonce, [0x55; NONCE_LEN]);
        assert!(parsed.ciphertext.is_empty());
    }

    #[test]
    fn round_trips_all_provider_types() {
        for pt in [
            ProviderType::Tpm2,
            ProviderType::Pkcs11,
            ProviderType::ExternalSecret,
            ProviderType::Ephemeral,
        ] {
            let payload = Payload {
                provider_type: pt,
                key_id: vec![0x12, 0x34],
                salt: [0x42; SALT_LEN],
                nonce: [0x24; NONCE_LEN],
                ciphertext: vec![0x99; 48],
                fingerprint: [0xEE; FINGERPRINT_LEN],
            };
            let bytes = payload.to_bytes();
            let parsed = Payload::from_bytes(&bytes).unwrap();
            assert_eq!(parsed.provider_type, pt);
        }
    }

    #[test]
    fn rejects_unsupported_version() {
        let payload = Payload {
            provider_type: ProviderType::ExternalSecret,
            key_id: vec![1, 2],
            salt: [1u8; SALT_LEN],
            nonce: [2u8; NONCE_LEN],
            ciphertext: vec![3u8; 16],
            fingerprint: [0xEE; FINGERPRINT_LEN],
        };
        let mut bytes = payload.to_bytes();
        assert_eq!(bytes[0], VERSION, "byte 0 is the version");
        Payload::from_bytes(&bytes).expect("the current version must parse");

        // Every other value -- below, above, or far above -- is refused
        // rather than misparsed, so a future layout change can never be
        // read through this parser by accident.
        for other in [0u8, 2, 3, 255] {
            bytes[0] = other;
            let err = Payload::from_bytes(&bytes).unwrap_err();
            assert!(
                matches!(err, Error::Crypto("unsupported wrapped payload version")),
                "version byte {other} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_unknown_provider_type() {
        let payload = Payload {
            provider_type: ProviderType::ExternalSecret,
            key_id: vec![1, 2],
            salt: [1u8; SALT_LEN],
            nonce: [2u8; NONCE_LEN],
            ciphertext: vec![3u8; 16],
            fingerprint: [0xEE; FINGERPRINT_LEN],
        };
        let mut bytes = payload.to_bytes();
        bytes[1] = 0; // invalid provider 0
        let err = Payload::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, Error::Crypto("unknown provider type in wrapped payload")));

        bytes[1] = 6; // invalid provider 6
        let err = Payload::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, Error::Crypto("unknown provider type in wrapped payload")));

        bytes[1] = 0xFF; // invalid provider 255
        let err = Payload::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, Error::Crypto("unknown provider type in wrapped payload")));
    }

    #[test]
    fn rejects_truncated_payload() {
        let payload = Payload {
            provider_type: ProviderType::Ephemeral,
            key_id: vec![1, 2, 3],
            salt: [1u8; SALT_LEN],
            nonce: [2u8; NONCE_LEN],
            ciphertext: vec![3u8; 16],
            fingerprint: [0xEE; FINGERPRINT_LEN],
        };
        let bytes = payload.to_bytes();
        // Test truncating at every single possible length up to the full length
        for len in 0..bytes.len() {
            let truncated = &bytes[..len];
            assert!(
                Payload::from_bytes(truncated).is_err(),
                "should reject payload truncated at length {len}"
            );
        }
    }

    #[test]
    fn rejects_trailing_bytes() {
        let payload = Payload {
            provider_type: ProviderType::Ephemeral,
            key_id: vec![],
            salt: [1u8; SALT_LEN],
            nonce: [2u8; NONCE_LEN],
            ciphertext: vec![3u8; 16],
            fingerprint: [0xEE; FINGERPRINT_LEN],
        };
        let mut bytes = payload.to_bytes();
        bytes.push(0xFF); // append one stray byte after a complete, valid payload
        let err = Payload::from_bytes(&bytes).unwrap_err();
        assert!(matches!(err, Error::Crypto("trailing bytes after wrapped payload")));
    }

    #[test]
    fn rejects_invalid_declared_lengths() {
        let payload = Payload {
            provider_type: ProviderType::ExternalSecret,
            key_id: vec![1, 2, 3, 4],
            salt: [1u8; SALT_LEN],
            nonce: [2u8; NONCE_LEN],
            ciphertext: vec![3u8; 16],
            fingerprint: [0xEE; FINGERPRINT_LEN],
        };
        let mut bytes = payload.to_bytes();
        // Modify key_id_len (bytes 2..4) to claim a huge length
        bytes[2] = 0xFF;
        bytes[3] = 0xFF;
        assert!(Payload::from_bytes(&bytes).is_err());

        // Restore and modify ciphertext_len (last 4 bytes before ciphertext)
        let mut bytes2 = payload.to_bytes();
        let ct_len_offset = 1 + 1 + 2 + 4 + SALT_LEN + NONCE_LEN;
        bytes2[ct_len_offset] = 0xFF;
        bytes2[ct_len_offset + 1] = 0xFF;
        bytes2[ct_len_offset + 2] = 0xFF;
        bytes2[ct_len_offset + 3] = 0x7F;
        assert!(Payload::from_bytes(&bytes2).is_err());
    }
}
