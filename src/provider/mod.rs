//! Provider abstraction and the priority-ordered selection chain.
//!
//! Every provider implements the identical ECDH -> HKDF-SHA256 -> AES-256-GCM
//! protocol (see `crypto.rs`); the only thing that differs between providers
//! is *where the persistent P-256 KEK private key lives* and *who performs
//! the ECDH operation*. Software and PKCS#11/TPM2 providers never hand the
//! private scalar back to this crate -- `ecdh()` returns only the derived
//! shared secret.

// Each provider module is only compiled in when its feature is enabled, so
// a build with e.g. `tpm2` disabled never even sees TPM-related code.
#[cfg(feature = "ephemeral")]
pub mod ephemeral;
#[cfg(feature = "external-secret")]
pub mod external_secret;
#[cfg(feature = "pkcs11")]
pub mod pkcs11;
#[cfg(feature = "software")]
pub mod software;
#[cfg(feature = "tpm2")]
pub mod tpm2;

use crate::error::Result; // this crate's `Result<T, Error>` alias
use p256::PublicKey; // the caller's ephemeral P-256 public key type used in `ecdh`
use std::sync::{Arc, OnceLock}; // `Arc` for shared provider ownership, `OnceLock` for the one-time warning flag
use zeroize::Zeroizing; // wrapper that scrubs its contents from memory when dropped

/// 32-byte X9.63 ECDH shared secret (the raw shared point's X-coordinate),
/// zeroized on drop. Never logged, never returned across the FFI boundary.
pub type SharedSecret = Zeroizing<[u8; 32]>; // alias so every provider returns the same self-zeroizing type

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)] // cheap to copy/compare/hash; needed for logging, matching, and use as a map-ish key
#[repr(u8)] // pins the enum's in-memory representation to a single byte, matching the wire format's provider tag
pub enum ProviderType {
    Tpm2 = 1,           // matches payload byte value 1
    Pkcs11 = 2,          // matches payload byte value 2
    ExternalSecret = 3, // matches payload byte value 3
    Software = 4,        // matches payload byte value 4
    Ephemeral = 5,       // matches payload byte value 5
}

impl ProviderType {
    // Converts a raw wire-format byte back into the enum, rejecting
    // anything outside the five defined values.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(ProviderType::Tpm2),
            2 => Some(ProviderType::Pkcs11),
            3 => Some(ProviderType::ExternalSecret),
            4 => Some(ProviderType::Software),
            5 => Some(ProviderType::Ephemeral),
            _ => None, // any other byte value is not a valid provider tag
        }
    }

    // Human-readable name used only in log messages.
    pub fn as_str(&self) -> &'static str {
        match self {
            ProviderType::Tpm2 => "TPM2",
            ProviderType::Pkcs11 => "PKCS11",
            ProviderType::ExternalSecret => "EXTERNAL_SECRET",
            ProviderType::Software => "SOFTWARE",
            ProviderType::Ephemeral => "EPHEMERAL",
        }
    }
}

/// A handle to a loaded-or-created persistent service KEK. The private key
/// material never leaves the provider that produced this handle -- only
/// [`KekHandle::ecdh`]'s *output* (a shared secret) crosses back into
/// `crypto.rs`.
pub trait KekHandle {
    /// Provider-specific opaque identifier for this KEK, recorded (not
    /// secret) in the wrapped payload for diagnostics and provider
    /// migration detection. Never used as the sole lookup key -- the
    /// `service` string is always the logical identity.
    fn key_id(&self) -> &[u8]; // borrowed, non-secret bytes to embed in the payload

    /// Perform ECDH between this KEK's persistent private key and the given
    /// ephemeral public key, returning the raw shared secret.
    fn ecdh(&self, ephemeral_public_key: &PublicKey) -> Result<SharedSecret>; // never exposes the private key itself
}

// `Send + Sync` because providers are shared across calls via `Arc` and
// must be safe to use from whatever thread the FFI caller is on.
pub trait KekProvider: Send + Sync {
    fn provider_type(&self) -> ProviderType; // which of the 5 tags this provider implements

    /// Cheap, side-effect-free check: is this provider's backing store
    /// reachable on this host right now (TPM device present, PKCS#11 module
    /// loadable and a token present, secret mount present, filesystem
    /// writable, ...)? Must not create or persist anything.
    fn probe(&self) -> bool;

    /// Load the persistent KEK for `service`, creating it (in this
    /// provider's backing store) if it does not already exist.
    fn get_or_create_kek(&self, service: &str) -> Result<Box<dyn KekHandle>>; // `Box<dyn _>` since each provider returns a different concrete handle type
}

/// Returns every provider compiled into this build, in the mandated
/// selection priority order (strongest first). Providers are constructed
/// but not yet probed.
#[allow(clippy::vec_init_then_push)] // each push is independently feature-gated
fn all_providers() -> Vec<Arc<dyn KekProvider>> {
    #[allow(unused_mut)] // `mut` is only needed when at least one push below is compiled in
    let mut providers: Vec<Arc<dyn KekProvider>> = Vec::new(); // start empty; grow with whichever providers are feature-enabled

    #[cfg(feature = "tpm2")]
    providers.push(Arc::new(tpm2::Tpm2Provider::new())); // priority 1

    #[cfg(feature = "pkcs11")]
    providers.push(Arc::new(pkcs11::Pkcs11Provider::new())); // priority 2

    #[cfg(feature = "external-secret")]
    providers.push(Arc::new(external_secret::ExternalSecretProvider::new())); // priority 3

    #[cfg(feature = "software")]
    providers.push(Arc::new(software::SoftwareProvider::new())); // priority 4

    #[cfg(feature = "ephemeral")]
    providers.push(Arc::new(ephemeral::EphemeralProvider::new())); // priority 5, last resort

    providers // order of pushes above IS the selection priority order
}

/// Ensures the "no persistent provider available, running on EPHEMERAL"
/// warning is logged once per process rather than on every wrap call.
static EPHEMERAL_WARNED: OnceLock<()> = OnceLock::new(); // `set()` succeeds exactly once per process; later calls fail harmlessly

/// Walks the mandated priority chain (TPM2 -> PKCS#11 -> External Secret ->
/// Software -> Ephemeral) for `service`, probing each provider's gross
/// availability and then asking it for a KEK. A provider can decline a
/// specific service (currently only External Secret, when no secret has
/// been provisioned for it) via [`crate::error::Error::KeyNotProvisioned`],
/// in which case the chain quietly falls through to the next provider;
/// any other error is logged as a warning before falling through. The
/// chain always terminates successfully because Ephemeral never declines
/// and never errors.
///
/// Note: availability is re-checked on every call (no caching) so that a
/// provider that becomes available later (TPM enrolled, secret mounted) is
/// picked up without a process restart. If probing cost matters in your
/// deployment, cache calls to this crate's `wrap`/`unwrap` at a layer that
/// knows your traffic pattern.
pub fn select_for_wrap(service: &str) -> Result<(Arc<dyn KekProvider>, Box<dyn KekHandle>)> {
    let mut last_err = crate::error::Error::NoProviderAvailable; // returned only if every single provider fails (should never happen: Ephemeral always succeeds)

    for provider in all_providers() {
        // priority order, TPM2 first
        if !provider.probe() {
            // provider's backing store isn't reachable at all right now
            log::debug!(
                "hkdfguard: provider {} unavailable, trying next",
                provider.provider_type().as_str()
            );
            continue; // move on to the next provider in priority order
        }

        match provider.get_or_create_kek(service) {
            Ok(handle) => {
                // this provider successfully produced a usable KEK handle
                log::debug!(
                    "hkdfguard: using provider {} for this service",
                    provider.provider_type().as_str()
                );
                if matches!(provider.provider_type(), ProviderType::Ephemeral)
                    && EPHEMERAL_WARNED.set(()).is_ok()
                    // `.set()` only returns Ok the first time; subsequent calls see it already set
                {
                    log::warn!(
                        "hkdfguard: no persistent KEK provider is available; falling back to \
                         an EPHEMERAL in-memory KEK. DEKs wrapped in this process cannot be \
                         unwrapped after a process restart."
                    );
                }
                return Ok((provider, handle)); // stop the chain walk; this is the provider+handle to use
            }
            Err(crate::error::Error::KeyNotProvisioned(msg)) => {
                // soft decline (currently only External Secret): quietly try the next provider
                log::debug!(
                    "hkdfguard: provider {} has no key for this service ({msg}), trying next",
                    provider.provider_type().as_str()
                );
                last_err = crate::error::Error::KeyNotProvisioned(msg); // remember in case nothing else works either
            }
            Err(e) => {
                // a real failure (TPM/PKCS11/filesystem error) -- log it loudly, then still fall through
                log::warn!(
                    "hkdfguard: provider {} failed ({e}), trying next",
                    provider.provider_type().as_str()
                );
                last_err = e;
            }
        }
    }

    Err(last_err) // every provider was tried and none produced a key
}

/// Reports the provider that `select_for_wrap` would currently pick,
/// without touching any specific service's key (used only to log migration
/// hints from `get_by_type`).
fn current_best_provider_type() -> Option<ProviderType> {
    all_providers()
        .into_iter() // consume the Vec, we don't need it afterwards
        .find(|p| p.probe()) // first provider (in priority order) that's currently reachable
        .map(|p| p.provider_type()) // extract just its type tag
}

/// Looks up a specific provider by the type recorded in a wrapped payload
/// (used by `unwrap`, which must use whichever provider originally wrapped
/// the DEK, not necessarily the currently-strongest one). Logs a migration
/// hint if `provider_type` differs from what `select_for_wrap` would
/// currently pick, so operators can see when it's time to re-wrap DEKs
/// onto a stronger provider.
pub fn get_by_type(provider_type: ProviderType) -> Result<Arc<dyn KekProvider>> {
    if let Some(best) = current_best_provider_type() {
        if best != provider_type {
            // the DEK was wrapped under a different (usually weaker) provider than what's best today
            log::info!(
                "hkdfguard: migration event - DEK was wrapped with {} but {} is now the \
                 preferred provider; consider re-wrapping",
                provider_type.as_str(),
                best.as_str()
            );
        }
    }

    all_providers()
        .into_iter()
        .find(|p| p.provider_type() == provider_type) // find the exact provider that matches the payload's tag
        .ok_or(crate::error::Error::NoProviderAvailable) // that provider type isn't compiled into this build at all
}

#[cfg(test)]
mod tests {
    use super::*; // bring `ProviderType` etc. into scope

    #[test]
    fn provider_type_round_trips_through_u8() {
        for t in [
            ProviderType::Tpm2,
            ProviderType::Pkcs11,
            ProviderType::ExternalSecret,
            ProviderType::Software,
            ProviderType::Ephemeral,
        ] {
            // casting to u8 and back through `from_u8` must return the same variant
            assert_eq!(ProviderType::from_u8(t as u8), Some(t));
        }
        // 0 and 6 are outside the valid 1..=5 range and must be rejected
        assert_eq!(ProviderType::from_u8(0), None);
        assert_eq!(ProviderType::from_u8(6), None);
    }
}
