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

use crate::error::{Error, Result};
use crate::provider::ProviderType;

pub const VERSION: u8 = 1;
pub const UNCOMPRESSED_POINT_LEN: usize = 65;
pub const NONCE_LEN: usize = 12;

pub struct Payload {
    pub provider_type: ProviderType,
    pub key_id: Vec<u8>,
    pub ephemeral_public_key: [u8; UNCOMPRESSED_POINT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

impl Payload {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            2 + 2
                + self.key_id.len()
                + UNCOMPRESSED_POINT_LEN
                + NONCE_LEN
                + 4
                + self.ciphertext.len(),
        );
        out.push(VERSION);
        out.push(self.provider_type as u8);
        out.extend_from_slice(&(self.key_id.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.key_id);
        out.extend_from_slice(&self.ephemeral_public_key);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let mut cursor = Cursor { buf, pos: 0 };

        let version = cursor.take(1)?[0];
        if version != VERSION {
            return Err(Error::Crypto("unsupported wrapped payload version"));
        }

        let provider_byte = cursor.take(1)?[0];
        let provider_type = ProviderType::from_u8(provider_byte)
            .ok_or(Error::Crypto("unknown provider type in wrapped payload"))?;

        let key_id_len = u16::from_le_bytes(cursor.take(2)?.try_into().unwrap()) as usize;
        let key_id = cursor.take(key_id_len)?.to_vec();

        let ephemeral_public_key: [u8; UNCOMPRESSED_POINT_LEN] =
            cursor.take(UNCOMPRESSED_POINT_LEN)?.try_into().unwrap();

        let nonce: [u8; NONCE_LEN] = cursor.take(NONCE_LEN)?.try_into().unwrap();

        let ciphertext_len = u32::from_le_bytes(cursor.take(4)?.try_into().unwrap()) as usize;
        let ciphertext = cursor.take(ciphertext_len)?.to_vec();

        if cursor.pos != cursor.buf.len() {
            return Err(Error::Crypto("trailing bytes after wrapped payload"));
        }

        Ok(Payload {
            provider_type,
            key_id,
            ephemeral_public_key,
            nonce,
            ciphertext,
        })
    }
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(Error::Crypto("wrapped payload field length overflow"))?;
        if end > self.buf.len() {
            return Err(Error::Crypto("wrapped payload is truncated"));
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let payload = Payload {
            provider_type: ProviderType::Software,
            key_id: vec![1, 2, 3, 4],
            ephemeral_public_key: [7u8; UNCOMPRESSED_POINT_LEN],
            nonce: [9u8; NONCE_LEN],
            ciphertext: vec![0xAA; 48],
        };
        let bytes = payload.to_bytes();
        let parsed = Payload::from_bytes(&bytes).unwrap();
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
        bytes.truncate(bytes.len() - 5);
        assert!(Payload::from_bytes(&bytes).is_err());
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
        bytes.push(0xFF);
        assert!(Payload::from_bytes(&bytes).is_err());
    }
}
