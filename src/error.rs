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

use std::fmt;

/// Status codes returned by the public C ABI. Kept in sync with
/// `include/hkdfguard.h` -- if you add a variant here, add it there too.
pub mod status {
    pub const OK: i32 = 0;
    pub const INVALID_ARGUMENT: i32 = -1;
    pub const BUFFER_TOO_SMALL: i32 = -2;
    pub const PROVIDER_UNAVAILABLE: i32 = -3;
    pub const PROVIDER_ERROR: i32 = -4;
    pub const CRYPTO_ERROR: i32 = -5;
    pub const INTERNAL_ERROR: i32 = -6;
    pub const INVALID_UTF8: i32 = -7;
}

#[derive(Debug)]
pub enum Error {
    /// No KEK provider is available at all (should only happen if every
    /// optional provider feature is disabled AND ephemeral is disabled).
    NoProviderAvailable,
    /// A provider was selected but failed to create/load/operate on a KEK
    /// (TPM error, PKCS#11 error, filesystem error, malformed key file...).
    Provider(String),
    /// Soft, expected condition: this provider is reachable in general but
    /// has no key provisioned for this particular service and is not
    /// allowed to create one (currently only the external-secret
    /// provider). Causes the selection chain to fall through quietly
    /// rather than logging a warning.
    KeyNotProvisioned(&'static str),
    /// Wrapped payload was malformed, or AEAD authentication failed
    /// (tamper, wrong service, wrong KEK, wrong provider).
    Crypto(&'static str),
}

impl Error {
    pub fn status_code(&self) -> i32 {
        match self {
            Error::NoProviderAvailable => status::PROVIDER_UNAVAILABLE,
            Error::Provider(_) => status::PROVIDER_ERROR,
            Error::KeyNotProvisioned(_) => status::PROVIDER_ERROR,
            Error::Crypto(_) => status::CRYPTO_ERROR,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NoProviderAvailable => write!(f, "no KEK provider is available"),
            Error::Provider(msg) => write!(f, "provider error: {msg}"),
            Error::KeyNotProvisioned(msg) => write!(f, "no key provisioned: {msg}"),
            Error::Crypto(msg) => write!(f, "cryptographic error: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
