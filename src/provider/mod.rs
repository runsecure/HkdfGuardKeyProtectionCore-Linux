//! Provider abstraction and the priority-ordered selection chain.
//!
//! Every provider implements the identical ECDH -> HKDF-SHA512 -> AES-256-GCM
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
use std::sync::{Arc, OnceLock, RwLock}; // `Arc` for shared provider ownership, `OnceLock` for the one-time warning flag, `RwLock` for the resettable provider cache
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

/// Once a persistent (non-Ephemeral) provider has produced a usable KEK for
/// any service, it's cached here and reused for the remaining lifetime of
/// this process by [`select_for_wrap`] and [`get_by_type`] -- skipping the
/// provider-discovery walk (which reconstructs every compiled-in provider,
/// including expensive TPM2/PKCS#11 session setup -- see e.g.
/// `pkcs11::Pkcs11Provider::new`) on every subsequent wrap/unwrap.
///
/// Deliberately left unset while only Ephemeral succeeds (see
/// `select_for_wrap`), so a provider that becomes available later (TPM
/// enrolled, secret mounted) is still picked up without a process restart.
/// An `RwLock` rather than a `OnceLock` only so tests -- which construct
/// many independent provider configurations via env vars within one
/// process -- can reset it between runs; production code only ever writes
/// to it once.
static SELECTED_PROVIDER: RwLock<Option<Arc<dyn KekProvider>>> = RwLock::new(None);

/// Test-only: clears the cached provider selection so the next
/// `select_for_wrap`/`get_by_type` call re-runs full discovery instead of
/// reusing whatever a previous, unrelated test settled on.
#[cfg(test)]
pub(crate) fn reset_selected_provider_for_tests() {
    *SELECTED_PROVIDER.write().unwrap() = None;
}

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
/// Once a persistent provider has been used successfully, it's cached in
/// [`SELECTED_PROVIDER`] and every later call tries it directly first,
/// skipping the full discovery walk. If the cached provider declines or
/// fails for one particular service (e.g. External Secret opts services in
/// individually), that single call falls through to full discovery without
/// disturbing the cache -- the cached provider may still be correct for
/// every other service.
pub fn select_for_wrap(service: &str) -> Result<(Arc<dyn KekProvider>, Box<dyn KekHandle>)> {
    if let Some(cached) = SELECTED_PROVIDER.read().unwrap().clone() {
        match cached.get_or_create_kek(service) {
            Ok(handle) => return Ok((cached, handle)),
            Err(crate::error::Error::KeyNotProvisioned(msg)) => {
                log::debug!(
                    "hkdfguard: cached provider {} has no key for this service ({msg}); running full discovery for this call",
                    cached.provider_type().as_str()
                );
            }
            Err(e) => {
                log::warn!(
                    "hkdfguard: cached provider {} failed ({e}); running full discovery for this call",
                    cached.provider_type().as_str()
                );
            }
        }
    }

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
                if matches!(provider.provider_type(), ProviderType::Ephemeral) {
                    // Deliberately not cached -- see SELECTED_PROVIDER's doc comment.
                    if EPHEMERAL_WARNED.set(()).is_ok() {
                        // `.set()` only returns Ok the first time; subsequent calls see it already set
                        log::warn!(
                            "hkdfguard: no persistent KEK provider is available; falling back to \
                             an EPHEMERAL in-memory KEK. DEKs wrapped in this process cannot be \
                             unwrapped after a process restart."
                        );
                    }
                } else {
                    *SELECTED_PROVIDER.write().unwrap() = Some(Arc::clone(&provider));
                    log::info!(
                        "hkdfguard: settled on provider {} for the remaining lifetime of this process",
                        provider.provider_type().as_str()
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
/// hints from `get_by_type`). Consults the cache first, same as
/// `select_for_wrap`.
fn current_best_provider_type() -> Option<ProviderType> {
    if let Some(cached) = SELECTED_PROVIDER.read().unwrap().as_ref() {
        return Some(cached.provider_type());
    }
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
///
/// Reuses the cached provider from [`SELECTED_PROVIDER`] when its type
/// matches -- the common case, unwrapping a DEK wrapped under whatever's
/// currently preferred. A mismatch (an older DEK wrapped under a provider
/// that's since been superseded) falls back to constructing that specific
/// provider fresh, since only the currently-preferred provider is cached.
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

    if let Some(cached) = SELECTED_PROVIDER.read().unwrap().clone() {
        if cached.provider_type() == provider_type {
            return Ok(cached);
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
    use serial_test::serial;
    use tempfile::tempdir;

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
        assert_eq!(ProviderType::from_u8(255), None);
    }

    #[test]
    fn provider_type_as_str() {
        assert_eq!(ProviderType::Tpm2.as_str(), "TPM2");
        assert_eq!(ProviderType::Pkcs11.as_str(), "PKCS11");
        assert_eq!(ProviderType::ExternalSecret.as_str(), "EXTERNAL_SECRET");
        assert_eq!(ProviderType::Software.as_str(), "SOFTWARE");
        assert_eq!(ProviderType::Ephemeral.as_str(), "EPHEMERAL");
    }

    #[test]
    #[serial]
    fn get_by_type_finds_compiled_providers() {
        #[cfg(feature = "ephemeral")]
        {
            let p = get_by_type(ProviderType::Ephemeral).unwrap();
            assert_eq!(p.provider_type(), ProviderType::Ephemeral);
        }
        #[cfg(feature = "software")]
        {
            let p = get_by_type(ProviderType::Software).unwrap();
            assert_eq!(p.provider_type(), ProviderType::Software);
        }
        #[cfg(feature = "external-secret")]
        {
            let p = get_by_type(ProviderType::ExternalSecret).unwrap();
            assert_eq!(p.provider_type(), ProviderType::ExternalSecret);
        }
    }

    #[test]
    #[serial]
    fn select_for_wrap_prefers_external_secret_when_provisioned() {
        #[cfg(all(feature = "external-secret", feature = "software"))]
        {
            use p256::SecretKey;
            use rand_core::OsRng;

            reset_selected_provider_for_tests(); // don't let an earlier test's cached choice short-circuit this one

            let ext_dir = tempdir().unwrap();
            let soft_dir = tempdir().unwrap();

            std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", ext_dir.path());
            std::env::set_var("HKDFGUARD_SOFTWARE_DIR", soft_dir.path());

            // Write an external secret for "com.company.orders"
            let secret_key = SecretKey::random(&mut OsRng);
            std::fs::write(ext_dir.path().join("com.company.orders"), secret_key.to_bytes()).unwrap();

            let (provider, handle) = select_for_wrap("com.company.orders").unwrap();
            assert_eq!(provider.provider_type(), ProviderType::ExternalSecret);
            assert_eq!(handle.key_id(), b"external:com.company.orders");

            // For unprovisioned service, it falls through to Software
            let (provider2, handle2) = select_for_wrap("com.company.billing").unwrap();
            assert_eq!(provider2.provider_type(), ProviderType::Software);
            assert_eq!(handle2.key_id().len(), 64);

            std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
            std::env::remove_var("HKDFGUARD_SOFTWARE_DIR");
            reset_selected_provider_for_tests(); // don't leak this test's cached choice into whatever runs next
        }
    }

    #[test]
    #[serial]
    fn select_for_wrap_falls_back_to_ephemeral_when_software_fails() {
        #[cfg(all(feature = "ephemeral", feature = "software"))]
        {
            reset_selected_provider_for_tests(); // don't let an earlier test's cached choice short-circuit this one

            // Point external secret to nonexistent dir
            std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", "/nonexistent-dir-for-tests");
            // Point software to a file rather than a directory, causing directory creation/read to fail
            let tmp = tempfile::NamedTempFile::new().unwrap();
            std::env::set_var("HKDFGUARD_SOFTWARE_DIR", tmp.path());

            let (provider, handle) = select_for_wrap("com.company.orders").unwrap();
            assert_eq!(provider.provider_type(), ProviderType::Ephemeral);
            assert_eq!(handle.key_id(), b"ephemeral:com.company.orders");

            std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
            std::env::remove_var("HKDFGUARD_SOFTWARE_DIR");
        }
    }

    #[test]
    #[serial]
    fn select_for_wrap_reuses_cached_provider_instance_across_calls() {
        #[cfg(all(feature = "software", feature = "external-secret"))]
        {
            reset_selected_provider_for_tests();
            std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", "/nonexistent-dir-for-tests");
            let dir = tempdir().unwrap();
            std::env::set_var("HKDFGUARD_SOFTWARE_DIR", dir.path());

            let (provider1, _handle1) = select_for_wrap("com.company.a").unwrap();
            assert_eq!(provider1.provider_type(), ProviderType::Software);

            let (provider2, _handle2) = select_for_wrap("com.company.b").unwrap();
            // Same underlying provider *instance*, not merely the same type --
            // proves the second call skipped full discovery and reused the
            // cached one, rather than constructing a fresh Software provider.
            assert!(
                Arc::ptr_eq(&provider1, &provider2),
                "second call must reuse the exact cached provider instance"
            );

            std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
            std::env::remove_var("HKDFGUARD_SOFTWARE_DIR");
            reset_selected_provider_for_tests();
        }
    }

    #[test]
    #[serial]
    fn select_for_wrap_does_not_cache_ephemeral() {
        #[cfg(all(feature = "ephemeral", feature = "software"))]
        {
            reset_selected_provider_for_tests();
            std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", "/nonexistent-dir-for-tests");
            let tmp = tempfile::NamedTempFile::new().unwrap(); // a file, not a dir: makes Software fail so only Ephemeral succeeds
            std::env::set_var("HKDFGUARD_SOFTWARE_DIR", tmp.path());

            let (provider, _handle) = select_for_wrap("com.company.orders").unwrap();
            assert_eq!(provider.provider_type(), ProviderType::Ephemeral);
            assert!(
                SELECTED_PROVIDER.read().unwrap().is_none(),
                "an Ephemeral-only resolution must not populate the cache"
            );

            std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
            std::env::remove_var("HKDFGUARD_SOFTWARE_DIR");
        }
    }
}
