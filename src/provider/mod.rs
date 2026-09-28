//! Provider abstraction, the priority-ordered selection chain, and the
//! optional provider allow-list policy.
//!
//! Every provider implements the identical ECDH -> HKDF-SHA512 -> AES-256-GCM
//! protocol (see `crypto.rs`); the only thing that differs between providers
//! is *where the persistent P-256 KEK private key lives* and *who performs
//! the ECDH operation*. PKCS#11/TPM2 providers never hand the private scalar
//! back to this crate -- `ecdh()` returns only the derived shared secret.
//!
//! There is deliberately no software-backed (locally-generated,
//! filesystem-encrypted-at-rest) provider: a deployment without TPM2 or
//! PKCS#11 hardware is expected to provision a KEK via the external-secret
//! provider instead. Ephemeral (in-memory, lost on restart) is never used
//! unless a policy file explicitly allows it -- see [`allowed_chain`].
//!
//! Providers no longer auto-create a KEK on first wrap/unwrap: `wrap` calls
//! [`select_existing`], which only *loads* an already-created KEK and fails
//! with [`crate::error::Error::KekNotFound`] if none exists yet; a KEK is
//! created only via the explicit [`create_kek`] (the `hkdfguard_create_kek`
//! C entry point). [`kek_exists`] answers "would `select_existing` succeed"
//! without creating anything. TPM2 is the one exception -- see its own
//! `kek_exists`/`load_kek` doc comments for why.
//!
//! The "allow-list" is now the full administrative policy engine in
//! `crate::policy` (`/etc/hkdfguard/policy.yaml`) -- see [`allowed_chain`],
//! the sole point where every provider-selection function below crosses
//! from "what's compiled into this build" to "what policy currently
//! allows, and in what order."

// Each provider module is only compiled in when its feature is enabled, so
// a build with e.g. `tpm2` disabled never even sees TPM-related code.
#[cfg(feature = "ephemeral")]
pub mod ephemeral;
#[cfg(feature = "external-secret")]
pub mod external_secret;
#[cfg(feature = "pkcs11")]
pub mod pkcs11;
#[cfg(feature = "tpm2")]
pub mod tpm2;

use crate::error::{Error, Result}; // this crate's error type + `Result` alias
use crate::policy::PolicyEvaluator; // brings `.allowed_providers()` into scope on `crate::policy::Policy`
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
    // 4 was SOFTWARE (a locally-generated, filesystem-encrypted-at-rest
    // provider), removed. Deliberately left unassigned rather than reused
    // or renumbered, so a payload wrapped under the old provider is
    // rejected outright by `from_u8` as an unknown tag rather than
    // misinterpreted as whatever a future provider 4 might be.
    Ephemeral = 5,       // matches payload byte value 5
}

impl ProviderType {
    // Converts a raw wire-format byte back into the enum, rejecting
    // anything outside the currently defined values (byte 4 included --
    // see the `ProviderType` doc comment on the removed SOFTWARE tag).
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(ProviderType::Tpm2),
            2 => Some(ProviderType::Pkcs11),
            3 => Some(ProviderType::ExternalSecret),
            5 => Some(ProviderType::Ephemeral),
            _ => None, // any other byte value (including the retired 4) is not a valid provider tag
        }
    }

    // Human-readable name used only in log messages (the administrative
    // policy file has its own, distinct vocabulary -- see `crate::policy`).
    pub fn as_str(&self) -> &'static str {
        match self {
            ProviderType::Tpm2 => "TPM2",
            ProviderType::Pkcs11 => "PKCS11",
            ProviderType::ExternalSecret => "EXTERNAL_SECRET",
            ProviderType::Ephemeral => "EPHEMERAL",
        }
    }
}

/// A handle to a loaded persistent service KEK. The private key material
/// never leaves the provider that produced this handle -- only
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

    /// This KEK's own public key -- never secret (it's the public half of
    /// the persistent keypair), used only by `crypto::wrap`/`crypto::unwrap`
    /// to compute/verify the payload's embedded fingerprint (see
    /// `crypto::kek_fingerprint`) before any ECDH is attempted.
    fn public_key(&self) -> Result<PublicKey>;
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

    /// Whether a persistent KEK already exists for `service`, without
    /// creating one. Must be side-effect-free.
    fn kek_exists(&self, service: &str) -> Result<bool>;

    /// Loads the persistent KEK for `service`. If `create_if_missing` is
    /// `true`, generates and persists one first when none exists yet
    /// (idempotent if one already does). If `false`, fails with
    /// [`Error::KeyNotProvisioned`] when none exists rather than creating
    /// one.
    fn load_kek(&self, service: &str, create_if_missing: bool) -> Result<Box<dyn KekHandle>>; // `Box<dyn _>` since each provider returns a different concrete handle type
}

/// Every provider type compiled into this build, in the mandated selection
/// priority order (strongest first). A static list -- nothing is
/// constructed, connected, or logged into here -- so policy can be
/// evaluated against it at zero cost before any provider is built.
#[allow(clippy::vec_init_then_push)] // each push is independently feature-gated
fn compiled_provider_types() -> Vec<ProviderType> {
    #[allow(unused_mut)] // `mut` is only needed when at least one push below is compiled in
    let mut types = Vec::new();

    #[cfg(feature = "tpm2")]
    types.push(ProviderType::Tpm2); // priority 1

    #[cfg(feature = "pkcs11")]
    types.push(ProviderType::Pkcs11); // priority 2

    #[cfg(feature = "external-secret")]
    types.push(ProviderType::ExternalSecret); // priority 3

    #[cfg(feature = "ephemeral")]
    types.push(ProviderType::Ephemeral); // priority 4, and only ever when a policy names it

    types // order of pushes above IS the selection priority order
}

/// Constructs exactly one provider, fresh. This is the expensive step --
/// for TPM2 it opens a TCTI connection, for PKCS#11 it loads the module
/// and logs in -- and it's deliberately done per call and torn down when
/// the returned `Arc` drops: no session, login, or device connection is
/// ever kept alive between calls. That's a deliberate posture, not an
/// oversight: a standing logged-in PKCS#11 session (or, once the TPM key
/// carries an authValue, a standing authorized TPM context) is ambient
/// authority that anything running in this process could use without ever
/// presenting the credential again. Re-authenticating per call costs a
/// connection per wrap/unwrap; callers are expected to cache the
/// *unwrapped DEK* for as long as they need it, not to call in here at
/// high frequency. Returns `None` only for a type not compiled into this
/// build.
fn construct_provider(provider_type: ProviderType) -> Option<Arc<dyn KekProvider>> {
    match provider_type {
        #[cfg(feature = "tpm2")]
        ProviderType::Tpm2 => Some(Arc::new(tpm2::Tpm2Provider::new())),
        #[cfg(feature = "pkcs11")]
        ProviderType::Pkcs11 => Some(Arc::new(pkcs11::Pkcs11Provider::new())),
        #[cfg(feature = "external-secret")]
        ProviderType::ExternalSecret => Some(Arc::new(external_secret::ExternalSecretProvider::new())),
        #[cfg(feature = "ephemeral")]
        ProviderType::Ephemeral => Some(Arc::new(ephemeral::EphemeralProvider::new())),
        #[allow(unreachable_patterns)] // only reachable for a type whose feature is compiled out
        _ => None,
    }
}

/// The provider types this process is currently allowed to use, in
/// try-order: the compiled-in list ([`compiled_provider_types`]), filtered
/// down to and reordered by the administrative policy in `crate::policy`
/// (`/etc/hkdfguard/policy.yaml`, or `HKDFGUARD_POLICY_FILE`) if one is
/// configured. Pure policy evaluation over types -- no provider is
/// constructed here -- so a policy of e.g. `require: external-secret`
/// never causes a TPM connection or an HSM login just to be told no.
/// Every selection/creation/existence-check function below goes through
/// this, so the policy applies uniformly to wrap, unwrap, create, and
/// exists.
///
/// Ephemeral is **excluded** unless a policy explicitly names it (as the
/// sole provider under `require`, or by name in `preferred_order`) -- see
/// `crate::policy::Policy::ephemeral_explicitly_listed`. With no policy
/// file at all, nothing can be named, so it's always excluded then too.
/// Its keys live only in process memory, so every DEK wrapped under one is
/// permanently lost on restart; silently falling back to it -- because a
/// secret mount wasn't there yet at startup, or a TPM failed its
/// self-test -- would turn a transient provider outage into permanent
/// data loss.
fn allowed_types() -> Result<Vec<ProviderType>> {
    let compiled = compiled_provider_types();
    let Some(policy) = crate::policy::load() else {
        return Ok(compiled
            .into_iter()
            .filter(|t| *t != ProviderType::Ephemeral)
            .collect()); // no policy configured: default order, minus Ephemeral (named-only)
    };
    let policy = policy?; // a configured-but-malformed/self-contradictory policy fails every operation, on purpose (fail closed)
    policy.allowed_providers(&compiled)
}

/// Ensures the "no persistent provider available, running on EPHEMERAL"
/// warning is logged once per process rather than on every wrap call.
static EPHEMERAL_WARNED: OnceLock<()> = OnceLock::new(); // `set()` succeeds exactly once per process; later calls fail harmlessly

/// Shared walk behind [`create_kek`] and [`select_existing`]: for each
/// policy-allowed type in priority order, constructs that one provider
/// (see [`construct_provider`]), probes it, and calls
/// `provider.load_kek(service, create_if_missing)`; the first to succeed
/// wins and the walk stops -- providers later in the order are never even
/// constructed. A provider declining via [`Error::KeyNotProvisioned`] is a
/// soft "try the next provider" signal; any other error is logged as a
/// warning before falling through too. `not_found_err` is what's returned
/// if the entire chain is exhausted without a hard error along the way.
fn walk_chain(
    service: &str,
    create_if_missing: bool,
    not_found_err: Error,
) -> Result<(Arc<dyn KekProvider>, Box<dyn KekHandle>)> {
    let mut last_err = not_found_err;

    for provider_type in allowed_types()? {
        // priority order, per the configured policy (or the default compiled-in order)
        let Some(provider) = construct_provider(provider_type) else {
            continue; // not compiled into this build (policy can name a type the build lacks)
        };
        if !provider.probe() {
            // provider's backing store isn't reachable at all right now
            log::debug!(
                "hkdfguard: provider {} unavailable, trying next",
                provider_type.as_str()
            );
            continue; // move on to the next provider in priority order
        }

        match provider.load_kek(service, create_if_missing) {
            Ok(handle) => {
                // this provider successfully produced a usable KEK handle
                log::debug!("hkdfguard: using provider {} for this call", provider_type.as_str());
                if matches!(provider_type, ProviderType::Ephemeral) && EPHEMERAL_WARNED.set(()).is_ok() {
                    // `.set()` only returns Ok the first time; subsequent calls see it already set
                    log::warn!(
                        "hkdfguard: no persistent KEK provider is available; falling back to \
                         an EPHEMERAL in-memory KEK. DEKs wrapped in this process cannot be \
                         unwrapped after a process restart."
                    );
                }
                return Ok((provider, handle)); // stop the chain walk; this is the provider+handle to use
            }
            Err(Error::KeyNotProvisioned(msg)) => {
                // soft decline: quietly try the next provider, without
                // overwriting `last_err` -- an expected, common case (no
                // key created here yet), not itself informative enough to
                // surface over `not_found_err`.
                log::debug!(
                    "hkdfguard: provider {} has no key for this service ({msg}), trying next",
                    provider_type.as_str()
                );
            }
            Err(e) => {
                // a real failure (TPM/PKCS11/filesystem error) -- log it loudly, remember it, then still fall through
                log::warn!(
                    "hkdfguard: provider {} failed ({e}), trying next",
                    provider_type.as_str()
                );
                last_err = e;
            }
        }
        // `provider` drops here: session logged out / module finalized /
        // TCTI closed before the next candidate is even constructed.
    }

    Err(last_err) // every provider was tried and none produced a key
}

/// Walks the policy-allowed priority chain (TPM2 -> PKCS#11 -> External
/// Secret -> Ephemeral, or whatever subset/order the policy configures)
/// and creates (or reuses, if one already exists) a persistent
/// KEK for `service` on the first reachable, allowed provider. This is now
/// the *only* path that ever creates a KEK -- `wrap`/`unwrap` (via
/// [`select_existing`]) only ever load one. Backs `hkdfguard_create_kek`.
///
/// If a policy is configured and every provider it names is unreachable,
/// this fails (with whichever error the last attempt produced, or
/// [`Error::NoProviderAvailable`] if every provider simply declined/wasn't
/// reachable) -- unlike the old unrestricted chain, there's no guaranteed
/// Ephemeral fallback once a policy excludes it.
pub fn create_kek(service: &str) -> Result<(Arc<dyn KekProvider>, Box<dyn KekHandle>)> {
    walk_chain(service, true, Error::NoProviderAvailable)
}

/// Walks the policy-allowed priority chain looking for a provider that
/// already has a persistent KEK for `service`, loading (never creating)
/// it. Backs `wrap`. Fails with [`Error::KekNotFound`] if the whole chain
/// is walked without finding one -- the caller must call [`create_kek`]
/// first.
pub fn select_existing(service: &str) -> Result<(Arc<dyn KekProvider>, Box<dyn KekHandle>)> {
    walk_chain(service, false, Error::KekNotFound)
}

/// Walks the policy-allowed chain checking whether a persistent KEK already
/// exists for `service`, without creating one anywhere. `Ok(false)` (not an
/// error) means the chain was fully walked and nothing has one yet -- call
/// [`create_kek`] to provision one. Backs `hkdfguard_kek_exists`. Like
/// [`walk_chain`], constructs providers one at a time and stops at the
/// first that has the key.
pub fn kek_exists(service: &str) -> Result<bool> {
    for provider_type in allowed_types()? {
        let Some(provider) = construct_provider(provider_type) else {
            continue;
        };
        if !provider.probe() {
            continue;
        }
        match provider.kek_exists(service) {
            Ok(true) => return Ok(true),
            Ok(false) => continue,
            Err(e) => {
                log::warn!(
                    "hkdfguard: provider {} kek_exists check failed ({e}), trying next",
                    provider_type.as_str()
                );
                continue;
            }
        }
    }
    Ok(false)
}

/// Looks up a specific provider by the type recorded in a wrapped payload
/// (used by `unwrap`, which must use whichever provider originally wrapped
/// the DEK, not necessarily the currently-preferred one). Constructs it
/// fresh for this call, like everything else here.
///
/// Enforces the current policy: a provider excluded by policy is treated
/// exactly like one that isn't compiled into this build at all
/// (`Error::NoProviderAvailable`) -- disabling a provider stops it from
/// being used for *both* new wraps and unwrapping payloads it already
/// produced, matching how disabling a TLS cipher suite stops it being used
/// for new and resumed connections alike.
///
/// Also logs a (debug-level) migration hint if `provider_type` isn't the
/// policy's first choice, so operators can see when it's time to re-wrap
/// DEKs onto a stronger provider. "First choice" here is by policy order,
/// not by probing what's reachable -- probing would mean constructing (and
/// connecting to) every stronger provider on every unwrap purely to decide
/// whether to log a hint.
pub fn get_by_type(provider_type: ProviderType) -> Result<Arc<dyn KekProvider>> {
    let allowed = allowed_types()?;
    if !allowed.contains(&provider_type) {
        return Err(Error::NoProviderAvailable); // not compiled into this build, or excluded by the current policy
    }
    if let Some(&preferred) = allowed.first() {
        if preferred != provider_type {
            // the DEK was wrapped under a different (usually weaker) provider than what policy prefers today
            log::debug!(
                "hkdfguard: migration event - DEK was wrapped with {} but {} is now the \
                 policy-preferred provider; consider re-wrapping",
                provider_type.as_str(),
                preferred.as_str()
            );
        }
    }
    construct_provider(provider_type).ok_or(Error::NoProviderAvailable)
}

#[cfg(test)]
mod tests {
    use super::*; // bring `ProviderType` etc. into scope
    use serial_test::serial;
    use tempfile::tempdir;

    // Points HKDFGUARD_POLICY_FILE somewhere guaranteed not to exist, so
    // tests that don't care about policy behavior aren't accidentally
    // affected by a real /etc/hkdfguard/policy.conf on the test host.
    fn clear_policy_env() {
        std::env::set_var("HKDFGUARD_POLICY_FILE", "/nonexistent-hkdfguard-policy-for-tests");
    }

    // Stand-in for `.unwrap_err()`: the `Ok` type here is
    // `(Arc<dyn KekProvider>, Box<dyn KekHandle>)`, which doesn't (and
    // shouldn't) implement `Debug`, so `.unwrap_err()`'s `T: Debug` bound
    // doesn't apply -- this extracts the error without needing that.
    fn expect_err<T>(r: Result<T>) -> Error {
        match r {
            Err(e) => e,
            Ok(_) => panic!("expected an error, got Ok"),
        }
    }

    // Asserts the invariant "Ephemeral is never selected unless policy
    // names it", for tests that deliberately run with *no* usable
    // external-secret mount and therefore can't pin a provider.
    //
    // Both outcomes are correct and which one occurs is a property of
    // the test host, not of the code under test: on a bare container
    // nothing is left and selection fails, while on a host with a
    // reachable TPM or PKCS#11 token that provider legitimately serves
    // the key. Asserting either one specifically would make the test
    // track hardware presence instead of the invariant.
    fn assert_never_ephemeral(result: Result<(Arc<dyn KekProvider>, Box<dyn KekHandle>)>) {
        match result {
            Ok((provider, _handle)) => assert_ne!(
                provider.provider_type(),
                ProviderType::Ephemeral,
                "Ephemeral must not be selected unless policy explicitly names it"
            ),
            Err(Error::NoProviderAvailable) | Err(Error::Provider(_)) => {}
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn provider_type_round_trips_through_u8() {
        for t in [
            ProviderType::Tpm2,
            ProviderType::Pkcs11,
            ProviderType::ExternalSecret,
            ProviderType::Ephemeral,
        ] {
            // casting to u8 and back through `from_u8` must return the same variant
            assert_eq!(ProviderType::from_u8(t as u8), Some(t));
        }
        // 0, the retired 4 (formerly SOFTWARE), and 6 are all outside the
        // currently valid set and must be rejected.
        assert_eq!(ProviderType::from_u8(0), None);
        assert_eq!(ProviderType::from_u8(4), None);
        assert_eq!(ProviderType::from_u8(6), None);
        assert_eq!(ProviderType::from_u8(255), None);
    }

    #[test]
    fn provider_type_as_str() {
        assert_eq!(ProviderType::Tpm2.as_str(), "TPM2");
        assert_eq!(ProviderType::Pkcs11.as_str(), "PKCS11");
        assert_eq!(ProviderType::ExternalSecret.as_str(), "EXTERNAL_SECRET");
        assert_eq!(ProviderType::Ephemeral.as_str(), "EPHEMERAL");
    }

    #[test]
    #[serial]
    fn get_by_type_finds_compiled_providers() {
        clear_policy_env();
        #[cfg(feature = "external-secret")]
        {
            let p = get_by_type(ProviderType::ExternalSecret).unwrap();
            assert_eq!(p.provider_type(), ProviderType::ExternalSecret);
        }
        #[cfg(feature = "ephemeral")]
        {
            // Compiled in, but with no policy file it's excluded -- even
            // for unwrap, which is what get_by_type backs.
            assert!(matches!(
                get_by_type(ProviderType::Ephemeral).map(|_| ()),
                Err(Error::NoProviderAvailable)
            ));

            let _policy = crate::policy::allow_ephemeral_policy_for_tests();
            let p = get_by_type(ProviderType::Ephemeral).unwrap();
            assert_eq!(p.provider_type(), ProviderType::Ephemeral);
        }
        std::env::remove_var("HKDFGUARD_POLICY_FILE");
    }

    #[test]
    #[serial]
    fn create_kek_prefers_external_secret_when_provisioned() {
        #[cfg(all(feature = "external-secret", feature = "ephemeral"))]
        {
            use p256::SecretKey;
            use rand_core::OsRng;

            let _policy = crate::policy::allow_ephemeral_policy_for_tests(); // the billing fall-through below needs Ephemeral opted in

            let ext_dir = tempdir().unwrap();
            std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", ext_dir.path());

            // Write an external secret for "com.company.orders"
            let secret_key = SecretKey::random(&mut OsRng);
            std::fs::write(ext_dir.path().join("com.company.orders"), secret_key.to_bytes()).unwrap();

            let (provider, handle) = create_kek("com.company.orders").unwrap();
            assert_eq!(provider.provider_type(), ProviderType::ExternalSecret);
            assert_eq!(handle.key_id(), b"external:com.company.orders");

            // For an unprovisioned service, it falls through to Ephemeral
            // (external-secret never creates one itself).
            let (provider2, handle2) = create_kek("com.company.billing").unwrap();
            assert_eq!(provider2.provider_type(), ProviderType::Ephemeral);
            assert_eq!(handle2.key_id(), b"ephemeral:com.company.billing");

            std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
            std::env::remove_var("HKDFGUARD_POLICY_FILE");
        }
    }

    #[test]
    #[serial]
    fn create_kek_does_not_fall_back_to_ephemeral_without_a_policy() {
        #[cfg(feature = "ephemeral")]
        {
            clear_policy_env(); // no policy file at all

            // External secret unreachable, so on a host with no hardware
            // provider Ephemeral is the only thing left -- and it must
            // NOT be used: a transient outage must not silently become a
            // key that's lost on restart. The subject here is the
            // *no-policy default*, so the policy deliberately isn't
            // pinned; see `assert_never_ephemeral` for why the outcome is
            // asserted as an invariant rather than one fixed result.
            std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", "/nonexistent-dir-for-tests");

            assert_never_ephemeral(create_kek("com.company.orders.nopolicy"));

            std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
            std::env::remove_var("HKDFGUARD_POLICY_FILE");
        }
    }

    #[test]
    #[serial]
    fn create_kek_falls_back_to_ephemeral_only_when_policy_allows_it() {
        #[cfg(feature = "ephemeral")]
        {
            let _policy = crate::policy::allow_ephemeral_policy_for_tests();
            std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", "/nonexistent-dir-for-tests");

            let (provider, handle) = create_kek("com.company.orders").unwrap();
            assert_eq!(provider.provider_type(), ProviderType::Ephemeral);
            assert_eq!(handle.key_id(), b"ephemeral:com.company.orders");

            std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
            std::env::remove_var("HKDFGUARD_POLICY_FILE");
        }
    }

    #[test]
    #[serial]
    fn create_kek_constructs_a_fresh_provider_on_every_call() {
        #[cfg(feature = "external-secret")]
        {
            use p256::SecretKey;
            use rand_core::OsRng;

            // This test is about external-secret specifically (that a
            // fresh instance of it is constructed per call), so pin the
            // chain to it -- otherwise a reachable TPM or PKCS#11 token
            // wins the chain and the assertions below compare the wrong
            // provider.
            let _policy = crate::policy::require_provider_policy_for_tests("external-secret");
            let ext_dir = tempdir().unwrap();
            std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", ext_dir.path());

            // external-secret never creates a key itself, so both
            // services need to be pre-provisioned.
            let key_a = SecretKey::random(&mut OsRng);
            let key_b = SecretKey::random(&mut OsRng);
            std::fs::write(ext_dir.path().join("com.company.a"), key_a.to_bytes()).unwrap();
            std::fs::write(ext_dir.path().join("com.company.b"), key_b.to_bytes()).unwrap();

            let (provider1, _handle1) = create_kek("com.company.a").unwrap();
            assert_eq!(provider1.provider_type(), ProviderType::ExternalSecret);

            let (provider2, _handle2) = create_kek("com.company.b").unwrap();
            assert_eq!(provider2.provider_type(), ProviderType::ExternalSecret);
            // A *different* instance each call: nothing is kept alive
            // between calls -- no standing session, login, or device
            // connection (see `construct_provider`'s doc comment).
            assert!(
                !Arc::ptr_eq(&provider1, &provider2),
                "each call must construct its own provider; no instance may be retained between calls"
            );

            std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
            std::env::remove_var("HKDFGUARD_POLICY_FILE");
        }
    }

    #[test]
    #[serial]
    fn select_existing_fails_until_create_kek_is_called() {
        #[cfg(feature = "ephemeral")]
        {
            // A service name unique to this test: Ephemeral's key map is
            // process-global and never cleared between tests, so reusing
            // a name another test also resolves via Ephemeral could find
            // it already "created" here.
            let service = "com.company.nevercreated.selectexisting";
            let _policy = crate::policy::allow_ephemeral_policy_for_tests();
            std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", "/nonexistent-dir-for-tests");

            let err = expect_err(select_existing(service));
            assert!(matches!(err, Error::KekNotFound));
            assert!(!kek_exists(service).unwrap());

            create_kek(service).unwrap();

            assert!(kek_exists(service).unwrap());
            let (provider, _handle) = select_existing(service).unwrap();
            assert_eq!(provider.provider_type(), ProviderType::Ephemeral);

            std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
            std::env::remove_var("HKDFGUARD_POLICY_FILE");
        }
    }

    // Writes `yaml` to a fresh temp file and points HKDFGUARD_POLICY_FILE
    // at it, returning the owning `TempDir` -- callers must keep that
    // binding alive for as long as the policy file needs to exist (an
    // unbound `tempdir().unwrap().path().join(...)` drops the directory,
    // and everything in it, at the end of that statement).
    fn write_policy(yaml: &str) -> tempfile::TempDir {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("policy.yaml"), yaml).unwrap();
        std::env::set_var("HKDFGUARD_POLICY_FILE", dir.path().join("policy.yaml"));
        dir
    }

    #[test]
    #[serial]
    fn policy_prefer_mode_restricts_to_named_providers_in_order() {
        #[cfg(all(feature = "external-secret", feature = "ephemeral"))]
        {
            std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", "/nonexistent-dir-for-tests");

            // Deliberately excludes external-secret; naming Ephemeral in
            // preferred_order is what makes it reachable at all.
            let _policy_dir = write_policy("selection:\n  mode: prefer\npreferred_order:\n  - ephemeral\n");

            let (provider, _handle) = create_kek("com.company.orders").unwrap();
            assert_eq!(
                provider.provider_type(),
                ProviderType::Ephemeral,
                "policy names only Ephemeral, so it must be used"
            );

            std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
            std::env::remove_var("HKDFGUARD_POLICY_FILE");
        }
    }

    #[test]
    #[serial]
    fn policy_require_provider_fails_closed_when_unreachable() {
        #[cfg(feature = "pkcs11")]
        {
            // PKCS#11 is compiled in but never reachable in this test
            // environment (no HKDFGUARD_PKCS11_PIN set), and the policy
            // requires exactly it -- so there must be no fallback to
            // Ephemeral/external-secret, unlike the unrestricted default
            // chain (this is the Linux equivalent of "Require TPM
            // failure" when TPM hardware isn't present).
            let _policy_dir = write_policy("selection:\n  mode: require\n  provider: pkcs11\n");

            let err = expect_err(create_kek("com.company.orders"));
            assert!(matches!(err, Error::NoProviderAvailable | Error::Provider(_)));

            std::env::remove_var("HKDFGUARD_POLICY_FILE");
        }
    }

    #[test]
    #[serial]
    fn policy_prefer_mode_falls_through_unreachable_providers_to_a_reachable_one() {
        #[cfg(all(feature = "pkcs11", feature = "external-secret"))]
        {
            let ext_dir = tempdir().unwrap();
            std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", ext_dir.path()); // reachable

            // Pre-provision the external secret so it's actually usable
            // once the chain reaches it (this provider never creates one
            // itself).
            let secret_key = p256::SecretKey::random(&mut rand_core::OsRng);
            std::fs::write(ext_dir.path().join("com.company.orders"), secret_key.to_bytes()).unwrap();

            // PKCS#11 (no PIN configured) is unreachable; policy must
            // fall through to external-secret.
            let _policy_dir = write_policy(
                "selection:\n  mode: prefer\npreferred_order:\n  - pkcs11\n  - external-secret\n  - ephemeral\n",
            );

            let (provider, _handle) = create_kek("com.company.orders").unwrap();
            assert_eq!(provider.provider_type(), ProviderType::ExternalSecret);

            std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
            std::env::remove_var("HKDFGUARD_POLICY_FILE");
        }
    }

    #[test]
    #[serial]
    fn policy_ephemeral_disallowed_by_default_end_to_end() {
        #[cfg(feature = "ephemeral")]
        {
            std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", "/nonexistent-dir-for-tests"); // unreachable

            // No preferred_order at all -- ephemeral must default to
            // disallowed (never named), even where it would otherwise be
            // the only reachable provider.
            let _policy_dir = write_policy("selection:\n  mode: prefer\n");

            assert_never_ephemeral(create_kek("com.company.orders"));

            std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
            std::env::remove_var("HKDFGUARD_POLICY_FILE");
        }
    }

    #[test]
    #[serial]
    fn policy_ephemeral_allowed_end_to_end_when_policy_permits() {
        #[cfg(feature = "ephemeral")]
        {
            std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", "/nonexistent-dir-for-tests");

            let _policy_dir = write_policy("selection:\n  mode: prefer\npreferred_order:\n  - ephemeral\n");

            let (provider, _handle) = create_kek("com.company.orders").unwrap();
            assert_eq!(provider.provider_type(), ProviderType::Ephemeral);

            std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
            std::env::remove_var("HKDFGUARD_POLICY_FILE");
        }
    }

    #[test]
    #[serial]
    fn policy_minimum_protection_enforced_end_to_end() {
        #[cfg(feature = "ephemeral")]
        {
            std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", "/nonexistent-dir-for-tests"); // no external secret provisioned

            // Ephemeral is explicitly named (clearing that gate), so
            // minimum_protection: external is the *only* thing standing
            // between it and being selected -- isolating exactly the
            // mechanism this test means to exercise.
            let _policy_dir = write_policy(
                "key_requirements:\n  minimum_protection: external\nselection:\n  mode: prefer\npreferred_order:\n  - ephemeral\n",
            );

            let err = expect_err(create_kek("com.company.orders"));
            assert!(matches!(err, Error::NoProviderAvailable | Error::Provider(_)));

            std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
            std::env::remove_var("HKDFGUARD_POLICY_FILE");
        }
    }

    #[test]
    #[serial]
    fn malformed_policy_fails_closed_even_when_providers_are_available() {
        std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", "/nonexistent-dir-for-tests");

        let _policy_dir = write_policy("selection:\n  mode: require\n  provider: quantum-vault\n");

        let err = expect_err(create_kek("com.company.orders"));
        assert!(matches!(err, Error::Provider(_)), "a malformed policy must fail closed, not fall back to the default chain");

        std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
        std::env::remove_var("HKDFGUARD_POLICY_FILE");
    }
}
