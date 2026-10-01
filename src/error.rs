//! Internal error type and the stable C ABI status codes it maps to.
//!
//! Nothing in [`Error`] ever crosses the ABI boundary directly -- `lib.rs`
//! converts every variant to a plain `i32` via [`Error::status_code`] before
//! returning to the caller, and log messages built from `Error` values are
//! restricted to shapes/lengths/identifiers, never key material.
//!
//! Argument validation (null pointers, wrong DEK length, invalid UTF-8,
//! output buffer sizing) happens directly in `lib.rs` against the raw
//! `status` codes below, before any call into this crate's internal
//! `Result<_, Error>` plumbing -- so `Error` itself only has variants for
//! failures that can occur *after* validation, inside the provider/crypto
//! layer.

use std::fmt; // brings `fmt::Display`/`fmt::Formatter` into scope for the impl below

/// Status codes returned by the public C ABI. Kept in sync with
/// `include/hkdfguard.h` -- if you add a variant here, add it there too.
pub mod status {
    // Each constant below is one possible return value of the two exported
    // C functions; all are plain `i32`s so nothing Rust-specific crosses
    // the FFI boundary.
    pub const OK: i32 = 0; // success
    pub const INVALID_ARGUMENT: i32 = -1; // null pointer, wrong DEK length, negative capacity, etc. -- never a service-string problem, see INVALID_SERVICE_NAME
    pub const BUFFER_TOO_SMALL: i32 = -2; // caller's output buffer capacity is smaller than required
    pub const PROVIDER_UNAVAILABLE: i32 = -3; // no KEK provider could be reached at all
    pub const PROVIDER_ERROR: i32 = -4; // a provider was reachable but failed to produce/load a key
    pub const CRYPTO_ERROR: i32 = -5; // malformed payload or AEAD authentication failure
    pub const INTERNAL_ERROR: i32 = -6; // an unexpected panic was caught at the FFI boundary
    // -7 (formerly INVALID_UTF8) is reserved, no longer returned by
    // anything: a `service` string that isn't valid UTF-8 is now just one
    // more way for it to be invalid, folded into INVALID_SERVICE_NAME below
    // -- see that constant's comment. Kept reserved, not reused, so a
    // caller pattern-matching on -7 doesn't silently start matching
    // something unrelated (same policy this project's macOS status table
    // uses for its own reserved codes).
    pub const INVALID_SERVICE_NAME: i32 = -8; // `service` is null, empty, not valid UTF-8, over MAX_SERVICE_LEN bytes, contains a character other than an ASCII letter, digit, or '.', starts with '.', or contains ".." -- one code for every way the service identifier itself can be wrong, matching macOS's invalidServiceIdentifier and Windows's HKDFGUARD_ERR_SERVICE_NAME_INVALID
    pub const KEK_NOT_FOUND: i32 = -9; // no persistent KEK exists yet for this service; call hkdfguard_create_kek first
    // -10..-15 are intentionally unassigned here: on macOS (Secure Enclave)
    // those numbers cover enclave/keychain-specific failure modes with no
    // Linux equivalent (kekCorrupted, accessControlCreationFailed,
    // keyGenerationFailed, keychainWriteFailed, kekVerificationFailed).
    // FINGERPRINT_MISMATCH is deliberately given the *same* code macOS
    // (and now Windows) use for the same concept, since it's a
    // cross-platform notion, unlike the gap above it.
    pub const FINGERPRINT_MISMATCH: i32 = -16; // wrapped payload's embedded KEK fingerprint doesn't match the current KEK's public key
    pub const PROCESS_HARDENING_FAILED: i32 = -17; // hkdfguard_harden_process could not disable core dumps or ptrace access
}

#[derive(Debug)] // lets `Error` be formatted with `{:?}` in tests/logs
pub enum Error {
    /// No KEK provider is available at all (should only happen if every
    /// optional provider feature is disabled AND ephemeral is disabled).
    NoProviderAvailable, // terminal failure: the provider chain produced nothing usable
    /// A provider was selected but failed to create/load/operate on a KEK
    /// (TPM error, PKCS#11 error, filesystem error, malformed key file...).
    Provider(String), // carries a human-readable description of what went wrong, for logs only
    /// Soft, expected condition: this provider is reachable in general but
    /// has no key for this particular service, either because it's not
    /// allowed to create one (the external-secret provider, always) or
    /// because creation wasn't requested (every other provider, when asked
    /// to only load an existing key -- see `KekProvider::load_kek`).
    /// Causes the selection chain to fall through quietly rather than
    /// logging a warning.
    KeyNotProvisioned(&'static str), // static message; no allocation needed since it's always a fixed string
    /// Wrapped payload was malformed, or AEAD authentication failed
    /// (tamper, wrong service, wrong KEK, wrong provider).
    Crypto(&'static str), // static message describing which crypto/parsing step failed
    /// No provider in the (policy-allowed) chain has an existing KEK for
    /// this service. Distinct from `KeyNotProvisioned`, which is the
    /// per-provider decline signal that causes the chain to keep trying the
    /// next provider -- this is the aggregate "the whole chain was walked
    /// and nothing has one" result, surfaced to the caller so they know to
    /// call `hkdfguard_create_kek` first.
    KekNotFound,
    /// The wrapped payload's embedded KEK fingerprint (a SHA-256 hash of
    /// the persistent KEK's public key, appended to every payload -- see
    /// `crypto::kek_fingerprint`) doesn't match the public key of the KEK
    /// `service` currently resolves to: this payload was not wrapped
    /// under the key `unwrap` is about to use. Detected before any
    /// ECDH/AES-GCM is attempted -- unlike `Crypto`, this specifically
    /// means "wrong KEK," not "right KEK, but tampered/mismatched data."
    FingerprintMismatch,
}

impl Error {
    // Maps each internal error variant to the public status code the FFI
    // layer will actually return to the C caller.
    pub fn status_code(&self) -> i32 {
        match self {
            Error::NoProviderAvailable => status::PROVIDER_UNAVAILABLE, // no provider at all -> PROVIDER_UNAVAILABLE
            Error::Provider(_) => status::PROVIDER_ERROR, // provider-level failure -> PROVIDER_ERROR (message is dropped, never sent over FFI)
            Error::KeyNotProvisioned(_) => status::PROVIDER_ERROR, // treated the same as a generic provider error from the caller's perspective
            Error::Crypto(_) => status::CRYPTO_ERROR, // decryption/parsing failure -> CRYPTO_ERROR
            Error::KekNotFound => status::KEK_NOT_FOUND,
            Error::FingerprintMismatch => status::FINGERPRINT_MISMATCH,
        }
    }
}

impl fmt::Display for Error {
    // Human-readable rendering used only in `log::error!`/`log::warn!`
    // calls -- never returned to the C caller.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NoProviderAvailable => write!(f, "no KEK provider is available"), // fixed message, no data to interpolate
            Error::Provider(msg) => write!(f, "provider error: {msg}"), // interpolate the provider's own description
            Error::KeyNotProvisioned(msg) => write!(f, "no key provisioned: {msg}"), // interpolate the static reason string
            Error::Crypto(msg) => write!(f, "cryptographic error: {msg}"), // interpolate the static reason string
            Error::KekNotFound => write!(f, "no KEK exists for this service; call hkdfguard_create_kek first"),
            Error::FingerprintMismatch => write!(
                f,
                "wrapped payload's KEK fingerprint does not match the current KEK for this service"
            ),
        }
    }
}

impl std::error::Error for Error {} // opts `Error` into the standard error trait (needed so `{e}` formatting and `?` interop work smoothly)

pub type Result<T> = std::result::Result<T, Error>; // shorthand alias used throughout the crate instead of spelling out `Result<T, Error>`

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_status_codes_match_contract() {
        assert_eq!(
            Error::NoProviderAvailable.status_code(),
            status::PROVIDER_UNAVAILABLE
        );
        assert_eq!(
            Error::Provider("device failure".into()).status_code(),
            status::PROVIDER_ERROR
        );
        assert_eq!(
            Error::KeyNotProvisioned("missing file").status_code(),
            status::PROVIDER_ERROR
        );
        assert_eq!(
            Error::Crypto("invalid tag").status_code(),
            status::CRYPTO_ERROR
        );
        assert_eq!(Error::KekNotFound.status_code(), status::KEK_NOT_FOUND);
        assert_eq!(
            Error::FingerprintMismatch.status_code(),
            status::FINGERPRINT_MISMATCH
        );
        assert_eq!(status::FINGERPRINT_MISMATCH, -16); // pinned to match macOS's HKDFGuardStatus.fingerprintMismatch
    }

    #[test]
    fn error_display_formatting() {
        assert_eq!(
            Error::NoProviderAvailable.to_string(),
            "no KEK provider is available"
        );
        assert_eq!(
            Error::Provider("TPM timeout".into()).to_string(),
            "provider error: TPM timeout"
        );
        assert_eq!(
            Error::KeyNotProvisioned("not found").to_string(),
            "no key provisioned: not found"
        );
        assert_eq!(
            Error::Crypto("bad MAC").to_string(),
            "cryptographic error: bad MAC"
        );
    }

    #[test]
    fn error_debug_formatting() {
        let err = Error::Provider("io err".into());
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Provider"));
        assert!(dbg.contains("io err"));
    }
}
