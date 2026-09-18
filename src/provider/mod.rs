//! Provider abstraction and the priority-ordered selection chain.
//!
//! Every provider implements the identical ECDH -> HKDF-SHA256 -> AES-256-GCM
//! protocol (see `crypto.rs`); the only thing that differs between providers
//! is *where the persistent P-256 KEK private key lives* and *who performs
//! the ECDH operation*. Software and PKCS#11/TPM2 providers never hand the
//! private scalar back to this crate -- `ecdh()` returns only the derived
//! shared secret.

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

use crate::error::Result;
use p256::PublicKey;
use std::sync::{Arc, OnceLock};
use zeroize::Zeroizing;

/// 32-byte X9.63 ECDH shared secret (the raw shared point's X-coordinate),
/// zeroized on drop. Never logged, never returned across the FFI boundary.
pub type SharedSecret = Zeroizing<[u8; 32]>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ProviderType {
    Tpm2 = 1,
    Pkcs11 = 2,
    ExternalSecret = 3,
    Software = 4,
    Ephemeral = 5,
}

impl ProviderType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(ProviderType::Tpm2),
            2 => Some(ProviderType::Pkcs11),
            3 => Some(ProviderType::ExternalSecret),
            4 => Some(ProviderType::Software),
            5 => Some(ProviderType::Ephemeral),
            _ => None,
        }
    }

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
    fn key_id(&self) -> &[u8];

    /// Perform ECDH between this KEK's persistent private key and the given
    /// ephemeral public key, returning the raw shared secret.
    fn ecdh(&self, ephemeral_public_key: &PublicKey) -> Result<SharedSecret>;
}

pub trait KekProvider: Send + Sync {
    fn provider_type(&self) -> ProviderType;

    /// Cheap, side-effect-free check: is this provider's backing store
    /// reachable on this host right now (TPM device present, PKCS#11 module
    /// loadable and a token present, secret mount present, filesystem
    /// writable, ...)? Must not create or persist anything.
    fn probe(&self) -> bool;

    /// Load the persistent KEK for `service`, creating it (in this
    /// provider's backing store) if it does not already exist.
    fn get_or_create_kek(&self, service: &str) -> Result<Box<dyn KekHandle>>;
}

/// Returns every provider compiled into this build, in the mandated
/// selection priority order (strongest first). Providers are constructed
/// but not yet probed.
#[allow(clippy::vec_init_then_push)] // each push is independently feature-gated
fn all_providers() -> Vec<Arc<dyn KekProvider>> {
    #[allow(unused_mut)]
    let mut providers: Vec<Arc<dyn KekProvider>> = Vec::new();

    #[cfg(feature = "tpm2")]
    providers.push(Arc::new(tpm2::Tpm2Provider::new()));

    #[cfg(feature = "pkcs11")]
    providers.push(Arc::new(pkcs11::Pkcs11Provider::new()));

    #[cfg(feature = "external-secret")]
    providers.push(Arc::new(external_secret::ExternalSecretProvider::new()));

    #[cfg(feature = "software")]
    providers.push(Arc::new(software::SoftwareProvider::new()));

    #[cfg(feature = "ephemeral")]
    providers.push(Arc::new(ephemeral::EphemeralProvider::new()));

    providers
}

/// Ensures the "no persistent provider available, running on EPHEMERAL"
/// warning is logged once per process rather than on every wrap call.
static EPHEMERAL_WARNED: OnceLock<()> = OnceLock::new();

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
    let mut last_err = crate::error::Error::NoProviderAvailable;

    for provider in all_providers() {
        if !provider.probe() {
            log::debug!(
                "hkdfguard: provider {} unavailable, trying next",
                provider.provider_type().as_str()
            );
            continue;
        }

        match provider.get_or_create_kek(service) {
            Ok(handle) => {
                log::debug!(
                    "hkdfguard: using provider {} for this service",
                    provider.provider_type().as_str()
                );
                if matches!(provider.provider_type(), ProviderType::Ephemeral)
                    && EPHEMERAL_WARNED.set(()).is_ok()
                {
                    log::warn!(
                        "hkdfguard: no persistent KEK provider is available; falling back to \
                         an EPHEMERAL in-memory KEK. DEKs wrapped in this process cannot be \
                         unwrapped after a process restart."
                    );
                }
                return Ok((provider, handle));
            }
            Err(crate::error::Error::KeyNotProvisioned(msg)) => {
                log::debug!(
                    "hkdfguard: provider {} has no key for this service ({msg}), trying next",
                    provider.provider_type().as_str()
                );
                last_err = crate::error::Error::KeyNotProvisioned(msg);
            }
            Err(e) => {
                log::warn!(
                    "hkdfguard: provider {} failed ({e}), trying next",
                    provider.provider_type().as_str()
                );
                last_err = e;
            }
        }
    }

    Err(last_err)
}

/// Reports the provider that `select_for_wrap` would currently pick,
/// without touching any specific service's key (used only to log migration
/// hints from `get_by_type`).
fn current_best_provider_type() -> Option<ProviderType> {
    all_providers()
        .into_iter()
        .find(|p| p.probe())
        .map(|p| p.provider_type())
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
        .find(|p| p.provider_type() == provider_type)
        .ok_or(crate::error::Error::NoProviderAvailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_type_round_trips_through_u8() {
        for t in [
            ProviderType::Tpm2,
            ProviderType::Pkcs11,
            ProviderType::ExternalSecret,
            ProviderType::Software,
            ProviderType::Ephemeral,
        ] {
            assert_eq!(ProviderType::from_u8(t as u8), Some(t));
        }
        assert_eq!(ProviderType::from_u8(0), None);
        assert_eq!(ProviderType::from_u8(6), None);
    }
}
