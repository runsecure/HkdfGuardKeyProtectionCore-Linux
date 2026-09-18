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
//! 1       1     provider_type      (1=TPM2 2=PKCS11 3=EXTERNAL_SECRET 4=SOFTWARE 5=EPHEMERAL)
//! 2       2     key_id_len (u16)
//! 4       N     key_id             (provider-specific opaque identifier)
//! 4+N     65    ephemeral_public_key (uncompressed SEC1 P-256 point: 0x04 || X || Y)
//! 69+N    12    nonce              (AES-256-GCM 96-bit nonce)
//! 81+N    4     ciphertext_len (u32)
//! 85+N    M     ciphertext         (AES-256-GCM ciphertext, includes 16-byte tag)
//! ```
//!
//! The service name is intentionally NOT part of this payload -- per spec it
//! is supplied out-of-band on every wrap/unwrap call.

use crate::error::{Error, Result}; // this module's own error type + `Result<T, Error>` alias
use crate::provider::ProviderType; // the 1..=5 provider tag stored in the payload

pub const VERSION: u8 = 1; // current wire-format version; bump and branch in `from_bytes` if the layout ever changes
pub const UNCOMPRESSED_POINT_LEN: usize = 65; // SEC1 uncompressed P-256 point: 1 tag byte (0x04) + 32-byte X + 32-byte Y
pub const NONCE_LEN: usize = 12; // AES-GCM's standard 96-bit nonce size

// Plain Rust struct mirroring the wire layout above; `to_bytes`/`from_bytes`
// are the only places that translate between this and raw bytes.
pub struct Payload {
    pub provider_type: ProviderType, // which provider produced (and must later reload) the KEK
    pub key_id: Vec<u8>,             // provider-specific opaque tag, variable length
    pub ephemeral_public_key: [u8; UNCOMPRESSED_POINT_LEN], // the wrapper's one-time ECDH public key
    pub nonce: [u8; NONCE_LEN],      // the AES-GCM nonce used for this one encryption
    pub ciphertext: Vec<u8>,         // AES-GCM ciphertext, tag included at the end
}

impl Payload {
    // Serializes this payload into the exact byte layout documented above.
    pub fn to_bytes(&self) -> Vec<u8> {
        // Pre-size the output buffer so `extend_from_slice` below never
        // needs to reallocate: 1(version) + 1(provider) + 2(key_id len) +
        // key_id + 65(pubkey) + 12(nonce) + 4(ciphertext len) + ciphertext.
        let mut out = Vec::with_capacity(
            2 + 2
                + self.key_id.len()
                + UNCOMPRESSED_POINT_LEN
                + NONCE_LEN
                + 4
                + self.ciphertext.len(),
        );
        out.push(VERSION); // byte 0: format version
        out.push(self.provider_type as u8); // byte 1: provider tag (enum cast to its u8 discriminant)
        out.extend_from_slice(&(self.key_id.len() as u16).to_le_bytes()); // bytes 2..4: key_id length, little-endian u16
        out.extend_from_slice(&self.key_id); // the key_id bytes themselves
        out.extend_from_slice(&self.ephemeral_public_key); // fixed 65-byte ephemeral public key
        out.extend_from_slice(&self.nonce); // fixed 12-byte AES-GCM nonce
        out.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes()); // ciphertext length, little-endian u32
        out.extend_from_slice(&self.ciphertext); // the ciphertext (+ tag) bytes themselves
        out // return the fully assembled buffer
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

        let ephemeral_public_key: [u8; UNCOMPRESSED_POINT_LEN] =
            cursor.take(UNCOMPRESSED_POINT_LEN)?.try_into().unwrap(); // read the fixed 65-byte public key into a fixed-size array

        let nonce: [u8; NONCE_LEN] = cursor.take(NONCE_LEN)?.try_into().unwrap(); // read the fixed 12-byte nonce into a fixed-size array

        let ciphertext_len = u32::from_le_bytes(cursor.take(4)?.try_into().unwrap()) as usize; // read the 4-byte ciphertext length prefix
        let ciphertext = cursor.take(ciphertext_len)?.to_vec(); // read exactly that many ciphertext bytes

        if cursor.pos != cursor.buf.len() {
            // anything left over after consuming every declared field means the
            // input was longer than a valid payload -- reject it rather than
            // silently ignoring trailing garbage.
            return Err(Error::Crypto("trailing bytes after wrapped payload"));
        }

        Ok(Payload {
            provider_type,
            key_id,
            ephemeral_public_key,
            nonce,
            ciphertext,
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
            provider_type: ProviderType::Software,
            key_id: vec![1, 2, 3, 4],
            ephemeral_public_key: [7u8; UNCOMPRESSED_POINT_LEN],
            nonce: [9u8; NONCE_LEN],
            ciphertext: vec![0xAA; 48],
        };
        let bytes = payload.to_bytes(); // ...serialize it...
        let parsed = Payload::from_bytes(&bytes).unwrap(); // ...and parse it back.
        // Every field should survive the round trip unchanged.
        assert_eq!(parsed.provider_type, payload.provider_type);
        assert_eq!(parsed.key_id, payload.key_id);
        assert_eq!(parsed.ephemeral_public_key, payload.ephemeral_public_key);
        assert_eq!(parsed.nonce, payload.nonce);
        assert_eq!(parsed.ciphertext, payload.ciphertext);
    }

    #[test]
    fn rejects_truncated_payload() {
        let payload = Payload {
            provider_type: ProviderType::Ephemeral,
            key_id: vec![],
            ephemeral_public_key: [1u8; UNCOMPRESSED_POINT_LEN],
            nonce: [2u8; NONCE_LEN],
            ciphertext: vec![3u8; 16],
        };
        let mut bytes = payload.to_bytes();
        bytes.truncate(bytes.len() - 5); // chop off the last 5 bytes to simulate truncation/corruption
        assert!(Payload::from_bytes(&bytes).is_err()); // parsing must fail cleanly, not panic
    }

    #[test]
    fn rejects_trailing_bytes() {
        let payload = Payload {
            provider_type: ProviderType::Ephemeral,
            key_id: vec![],
            ephemeral_public_key: [1u8; UNCOMPRESSED_POINT_LEN],
            nonce: [2u8; NONCE_LEN],
            ciphertext: vec![3u8; 16],
        };
        let mut bytes = payload.to_bytes();
        bytes.push(0xFF); // append one stray byte after a complete, valid payload
        assert!(Payload::from_bytes(&bytes).is_err()); // the trailing-bytes check must catch this
    }
}
