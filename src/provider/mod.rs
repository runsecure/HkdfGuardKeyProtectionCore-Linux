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
//! `crate::policy` (`/etc/hkdfguard/policy.toml`) -- see [`allowed_chain`],
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

/// What a provider found when it was constructed. The distinction between
/// the last two is what keeps the chain fail-closed: only an `Absent`
/// provider lets the chain move on to the next (usually weaker) one.
#[cfg_attr(not(any(feature = "tpm2", feature = "pkcs11", feature = "external-secret")), allow(dead_code))]
#[derive(Debug, PartialEq)]
pub(crate) enum Backend<T> {
    /// Connected and usable.
    Ready(T),
    /// Not on this host, or not configured for use here (no TPM device we
    /// can open, no derivation secret, no PKCS#11 module or PIN file, no
    /// secret mount). The provider takes no part in the chain.
    Absent,
    /// There and configured, but unusable or untrustworthy: a secret with
    /// the wrong owner or mode, a TPM that fails its self-test, a module
    /// that won't load, a token that can't be selected. Every call that
    /// reaches this provider fails with this reason, rather than quietly
    /// falling through to a weaker provider -- a misconfiguration or outage
    /// of the strong provider must not silently turn into new DEKs wrapped
    /// under a weak (or, with Ephemeral, a lost-on-restart) KEK.
    Refused(String),
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

    /// Cheap, side-effect-free check: is this provider present on this
    /// host -- ready, or there but refused ([`Backend::Refused`])? Only a
    /// `false` here lets the chain skip the provider; a refused provider
    /// reports `true` and fails `kek_exists`/`load_kek` with its reason.
    /// Must not create or persist anything.
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
/// (`/etc/hkdfguard/policy.toml`, or `HKDFGUARD_POLICY_FILE`) if one is
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

/// Warnings already logged by [`warn_once`], by their exact text.
static WARNED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Logs `message` at warn level the first time this process sees it, and
/// never again. For events that are worth an operator's attention but
/// would repeat on every call -- a fallback, a migration hint -- so the
/// log shows each distinct one once instead of flooding. Messages never
/// carry a service name (see the C ABI's "(redacted)" lines), so this is
/// bounded by the number of provider combinations, not of services.
fn warn_once(message: String) {
    let mut warned = WARNED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if !warned.contains(&message) {
        log::warn!("{message}");
        warned.push(message);
    }
}

/// Test-only: forget which warnings were logged, so a test can see its own.
#[cfg(test)]
fn reset_warn_once() {
    WARNED.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clear();
}

/// Shared walk behind [`create_kek`] and [`select_existing`]: for each
/// policy-allowed type in priority order, constructs that one provider
/// (see [`construct_provider`]), probes it, and calls
/// `provider.load_kek(service, create_if_missing)`; the first to succeed
/// wins and the walk stops -- providers later in the order are never even
/// constructed.
///
/// The walk moves on past a provider in exactly two cases: it isn't
/// present at all (`probe()` is false -- see [`Backend::Absent`]), or it is
/// present but has no key for this service ([`Error::KeyNotProvisioned`]).
/// Any other error from a present provider ends the walk and is returned:
/// a TPM, token, or secret mount that is there but failing must not quietly
/// hand the call to a weaker provider, because every DEK wrapped meanwhile
/// would land under that weaker KEK -- or, with Ephemeral, under one that
/// is gone at the next restart. `not_found_err` is returned if the walk
/// runs out of providers.
///
/// The returned error is logged by the caller (the C ABI layer), not here;
/// an `Error::Provider` is prefixed with the provider's name so that one
/// line still says which provider failed.
fn walk_chain(
    service: &str,
    create_if_missing: bool,
    not_found_err: Error,
) -> Result<(Arc<dyn KekProvider>, Box<dyn KekHandle>)> {
    // Every provider this call passed over, and why: if a later one serves
    // the call, an operator should know a preferred one didn't.
    let mut passed_over: Vec<String> = Vec::new();
    for provider_type in allowed_types()? {
        // priority order, per the configured policy (or the default compiled-in order)
        let Some(provider) = construct_provider(provider_type) else {
            continue; // not compiled into this build (policy can name a type the build lacks)
        };
        if !provider.probe() {
            log::debug!("hkdfguard: provider {} not present, trying next", provider_type.as_str());
            passed_over.push(format!("{}: not present", provider_type.as_str()));
            continue;
        }

        match provider.load_kek(service, create_if_missing) {
            Ok(handle) => {
                log::debug!("hkdfguard: using provider {} for this call", provider_type.as_str());
                if !passed_over.is_empty() {
                    warn_once(format!(
                        "hkdfguard: {} is serving calls in place of a provider earlier in the policy order ({}); \
                         if that isn't intended, make the earlier provider available, or take it out of \
                         preferred_order (logged once per process)",
                        provider_type.as_str(),
                        passed_over.join("; ")
                    ));
                }
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
                log::debug!(
                    "hkdfguard: provider {} has no key for this service ({msg}), trying next",
                    provider_type.as_str()
                );
                passed_over.push(format!("{}: {msg}", provider_type.as_str()));
            }
            Err(e) => return Err(attribute(provider_type, e)),
        }
        // `provider` drops here: session logged out / module finalized /
        // TCTI closed before the next candidate is even constructed.
    }
    Err(not_found_err)
}

// Names the provider in a `Provider` error's message, for the caller's log line.
fn attribute(provider_type: ProviderType, e: Error) -> Error {
    match e {
        Error::Provider(msg) => Error::Provider(format!("{}: {msg}", provider_type.as_str())),
        other => other,
    }
}

/// Walks the policy-allowed priority chain (TPM2 -> PKCS#11 -> External
/// Secret -> Ephemeral, or whatever subset/order the policy configures)
/// and creates (or reuses, if one already exists) a persistent
/// KEK for `service` on the first reachable, allowed provider. This is now
/// the *only* path that ever creates a KEK -- `wrap`/`unwrap` (via
/// [`select_existing`]) only ever load one. Backs `hkdfguard_create_kek`.
///
/// Fails with the error of the first provider that is present but failing
/// (see [`walk_chain`]), or [`Error::NoProviderAvailable`] if every allowed
/// provider is absent or declined.
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
/// error) means the chain was fully walked, every present provider answered,
/// and none has one yet -- call
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
        // An error is returned, not read as "no key": the caller would
        // otherwise go on to `create_kek`, and a strong provider that is
        // failing must not be the reason a key gets created somewhere weaker.
        if provider.kek_exists(service).map_err(|e| attribute(provider_type, e))? {
            return Ok(true);
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
/// Also logs a migration hint -- a warning, once per process for each pair
/// of providers -- if `provider_type` isn't the policy's first choice, so
/// operators can see DEKs still held under a provider they no longer
/// prefer. "First choice" here is by policy order,
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
            warn_once(format!(
                "hkdfguard: unwrapping a DEK wrapped under {}, but policy now prefers {}; \
                 DEKs wrapped from now on go to the preferred provider when it is available \
                 (logged once per process)",
                provider_type.as_str(),
                preferred.as_str()
            ));
        }
    }
    construct_provider(provider_type).ok_or(Error::NoProviderAvailable)
}

#[cfg(test)]
mod tests {
    use super::*; // bring `ProviderType` etc. into scope
    use serial_test::serial;

    // Points HKDFGUARD_POLICY_FILE somewhere guaranteed not to exist, so
    // tests that don't care about policy behavior aren't accidentally
    // affected by a real /etc/hkdfguard/policy.conf on the test host.
    fn clear_policy_env() {
        let _no_policy = crate::policy::test_support::TestPolicy::absent();
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
    }

    #[test]
    #[serial]
    fn create_kek_prefers_external_secret_when_provisioned() {
        #[cfg(all(feature = "external-secret", feature = "ephemeral"))]
        {
            use p256::SecretKey;
            use rand_core::OsRng;

            let _policy = crate::policy::allow_ephemeral_policy_for_tests(); // the billing fall-through below needs Ephemeral opted in

            let ext_dir = crate::secure_file::private_tempdir();
            let _secret_mount = crate::policy::test_support::secret_mount(ext_dir.path());

            // Write an external secret for "com.company.orders", owner-only
            // as the provider requires of a KEK file.
            let secret_key = SecretKey::random(&mut OsRng);
            let secret_path = ext_dir.path().join("com.company.orders");
            std::fs::write(&secret_path, secret_key.to_bytes()).unwrap();
            std::fs::set_permissions(&secret_path, <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600)).unwrap();

            let (provider, handle) = create_kek("com.company.orders").unwrap();
            assert_eq!(provider.provider_type(), ProviderType::ExternalSecret);
            assert_eq!(handle.key_id(), b"external:com.company.orders");

            // For an unprovisioned service, it falls through to Ephemeral
            // (external-secret never creates one itself).
            let (provider2, handle2) = create_kek("com.company.billing").unwrap();
            assert_eq!(provider2.provider_type(), ProviderType::Ephemeral);
            assert_eq!(handle2.key_id(), b"ephemeral:com.company.billing");

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

            assert_never_ephemeral(create_kek("com.company.orders.nopolicy"));

        }
    }

    #[test]
    #[serial]
    fn create_kek_falls_back_to_ephemeral_only_when_policy_allows_it() {
        #[cfg(feature = "ephemeral")]
        {
            let _policy = crate::policy::allow_ephemeral_policy_for_tests();

            let (provider, handle) = create_kek("com.company.orders").unwrap();
            assert_eq!(provider.provider_type(), ProviderType::Ephemeral);
            assert_eq!(handle.key_id(), b"ephemeral:com.company.orders");

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
            let ext_dir = crate::secure_file::private_tempdir();
            let _secret_mount = crate::policy::test_support::secret_mount(ext_dir.path());

            // external-secret never creates a key itself, so both
            // services need to be pre-provisioned.
            let key_a = SecretKey::random(&mut OsRng);
            let key_b = SecretKey::random(&mut OsRng);
            for (name, key) in [("com.company.a", &key_a), ("com.company.b", &key_b)] {
                let path = ext_dir.path().join(name);
                std::fs::write(&path, key.to_bytes()).unwrap();
                std::fs::set_permissions(&path, <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600)).unwrap(); // owner-only, as the provider requires
            }

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

            let err = expect_err(select_existing(service));
            assert!(matches!(err, Error::KekNotFound));
            assert!(!kek_exists(service).unwrap());

            create_kek(service).unwrap();

            assert!(kek_exists(service).unwrap());
            let (provider, _handle) = select_existing(service).unwrap();
            assert_eq!(provider.provider_type(), ProviderType::Ephemeral);

        }
    }

    // `doc` as the policy while the returned guard lives -- bind it
    // (`let _policy = ...`), or it is gone at the end of the statement.
    fn write_policy(doc: &str) -> crate::policy::test_support::TestPolicy {
        crate::policy::test_support::TestPolicy::write(doc)
    }

    #[test]
    #[serial]
    fn policy_prefer_mode_restricts_to_named_providers_in_order() {
        #[cfg(all(feature = "external-secret", feature = "ephemeral"))]
        {

            // Deliberately excludes external-secret; naming Ephemeral in
            // preferred_order is what makes it reachable at all.
            let _policy_dir = write_policy("preferred_order = [\"ephemeral\"]\n[selection]\nmode = \"prefer\"\n");

            let (provider, _handle) = create_kek("com.company.orders").unwrap();
            assert_eq!(
                provider.provider_type(),
                ProviderType::Ephemeral,
                "policy names only Ephemeral, so it must be used"
            );

        }
    }

    #[test]
    #[serial]
    fn policy_require_provider_fails_closed_when_unreachable() {
        #[cfg(feature = "pkcs11")]
        {
            // Nothing from the harness: no PKCS#11 module or PIN file.
            let _isolated = crate::policy::test_support::TestPolicy::absent();
            // PKCS#11 is compiled in but not reachable here (the policy
            // names no module), and the policy
            // requires exactly it -- so there must be no fallback to
            // Ephemeral/external-secret, unlike the unrestricted default
            // chain (this is the Linux equivalent of "Require TPM
            // failure" when TPM hardware isn't present).
            let _policy_dir = write_policy("[selection]\nmode = \"require\"\nprovider = \"pkcs11\"\n");

            let err = expect_err(create_kek("com.company.orders"));
            assert!(matches!(err, Error::NoProviderAvailable | Error::Provider(_)));

        }
    }

    #[test]
    #[serial]
    fn policy_prefer_mode_falls_through_unreachable_providers_to_a_reachable_one() {
        #[cfg(all(feature = "pkcs11", feature = "external-secret"))]
        {
            // Nothing from the harness: no PKCS#11 module or PIN file.
            let _isolated = crate::policy::test_support::TestPolicy::absent();
            let ext_dir = crate::secure_file::private_tempdir();
            let _secret_mount = crate::policy::test_support::secret_mount(ext_dir.path());

            // Pre-provision the external secret so it's actually usable
            // once the chain reaches it (this provider never creates one
            // itself).
            let secret_key = p256::SecretKey::random(&mut rand_core::OsRng);
            let secret_path = ext_dir.path().join("com.company.orders");
            std::fs::write(&secret_path, secret_key.to_bytes()).unwrap();
            std::fs::set_permissions(&secret_path, <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600)).unwrap(); // owner-only, as the provider requires

            // PKCS#11 (no PIN configured) is unreachable; policy must
            // fall through to external-secret.
            let _policy_dir = write_policy(
                "preferred_order = [\"pkcs11\", \"external-secret\", \"ephemeral\"]\n[selection]\nmode = \"prefer\"\n",
            );

            let (provider, _handle) = create_kek("com.company.orders").unwrap();
            assert_eq!(provider.provider_type(), ProviderType::ExternalSecret);

        }
    }

    #[test]
    #[serial]
    fn policy_ephemeral_disallowed_by_default_end_to_end() {
        #[cfg(feature = "ephemeral")]
        {

            // No preferred_order at all -- ephemeral must default to
            // disallowed (never named), even where it would otherwise be
            // the only reachable provider.
            let _policy_dir = write_policy("[selection]\nmode = \"prefer\"\n");

            assert_never_ephemeral(create_kek("com.company.orders"));

        }
    }

    #[test]
    #[serial]
    fn policy_ephemeral_allowed_end_to_end_when_policy_permits() {
        #[cfg(feature = "ephemeral")]
        {

            let _policy_dir = write_policy("preferred_order = [\"ephemeral\"]\n[selection]\nmode = \"prefer\"\n");

            let (provider, _handle) = create_kek("com.company.orders").unwrap();
            assert_eq!(provider.provider_type(), ProviderType::Ephemeral);

        }
    }

    #[test]
    #[serial]
    fn policy_minimum_protection_enforced_end_to_end() {
        #[cfg(feature = "ephemeral")]
        {

            // Ephemeral is explicitly named (clearing that gate), so
            // minimum_protection: external is the *only* thing standing
            // between it and being selected -- isolating exactly the
            // mechanism this test means to exercise.
            let _policy_dir = write_policy(
                "preferred_order = [\"ephemeral\"]\n[key_requirements]\nminimum_protection = \"external\"\n[selection]\nmode = \"prefer\"\n",
            );

            let err = expect_err(create_kek("com.company.orders"));
            assert!(matches!(err, Error::NoProviderAvailable | Error::Provider(_)));

        }
    }

    // ---- each provider failure is logged exactly once ----

    struct CapturingLogger(std::sync::Mutex<Vec<String>>);

    impl log::Log for CapturingLogger {
        fn enabled(&self, metadata: &log::Metadata) -> bool {
            metadata.level() <= log::Level::Warn
        }
        fn log(&self, record: &log::Record) {
            if self.enabled(record.metadata()) {
                self.0.lock().unwrap().push(format!("{}", record.args()));
            }
        }
        fn flush(&self) {}
    }

    static CAPTURED: CapturingLogger = CapturingLogger(std::sync::Mutex::new(Vec::new()));

    // Runs `f` and returns every warn/error line it logged that contains
    // `marker`. `#[serial]` callers keep other tests' lines out.
    fn logged_lines_containing(marker: &str, f: impl FnOnce()) -> Vec<String> {
        if log::set_logger(&CAPTURED).is_ok() {
            log::set_max_level(log::LevelFilter::Warn);
        }
        CAPTURED.0.lock().unwrap().clear();
        f();
        CAPTURED.0.lock().unwrap().iter().filter(|l| l.contains(marker)).cloned().collect()
    }

    // An external-secret mount holding a group-readable key for `service`:
    // a hard provider failure ("permissions too broad"), not a soft decline.
    // Both halves must stay bound for the test's duration: the mount
    // directory, and the policy layer pointing the provider at it.
    fn mount_with_untrusted_secret(service: &str) -> (tempfile::TempDir, crate::policy::test_support::TestPolicy) {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::secure_file::private_tempdir();
        let path = dir.path().join(service);
        std::fs::write(&path, p256::SecretKey::random(&mut rand_core::OsRng).to_bytes()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let mount = crate::policy::test_support::secret_mount(dir.path());
        (dir, mount)
    }

    #[test]
    #[serial]
    fn a_provider_failure_that_fails_the_call_is_logged_once() {
        #[cfg(feature = "external-secret")]
        {
            let service = "com.company.logonce";
            let _mount = mount_with_untrusted_secret(service);
            let _policy = crate::policy::require_provider_policy_for_tests("external-secret");

            let lines = logged_lines_containing("permissions too broad", || {
                let c = std::ffi::CString::new(service).unwrap();
                assert_ne!(crate::hkdfguard_create_kek(c.as_ptr()), crate::status::OK);
            });

            assert_eq!(lines.len(), 1, "the failure must be logged exactly once, got: {lines:#?}");
            assert!(lines[0].contains("EXTERNAL_SECRET"), "the one line must still name the provider: {}", lines[0]);
        }
    }

    #[test]
    #[serial]
    fn serving_from_a_later_provider_is_a_warning_logged_once() {
        #[cfg(all(feature = "external-secret", feature = "ephemeral"))]
        {
            // External-secret is first and present, but has no key for this
            // service, so Ephemeral serves it: the call succeeds, and an
            // operator must still be told -- once, not on every call.
            let empty_mount = crate::secure_file::private_tempdir();
            let _mount = crate::policy::test_support::secret_mount(empty_mount.path());
            let _policy = crate::policy::allow_ephemeral_policy_for_tests(); // external-secret, then ephemeral
            reset_warn_once();

            let lines = logged_lines_containing("in place of a provider earlier", || {
                for _ in 0..3 {
                    let (provider, _handle) = create_kek("com.company.fallbackwarn")
                        .unwrap_or_else(|e| panic!("ephemeral should serve the call: {e}"));
                    assert_eq!(provider.provider_type(), ProviderType::Ephemeral);
                }
            });
            assert_eq!(lines.len(), 1, "logged once per process, not per call: {lines:#?}");
            assert!(lines[0].contains("EPHEMERAL"), "names the provider that served the call: {}", lines[0]);
            assert!(lines[0].contains("EXTERNAL_SECRET: "), "says what was passed over, and why: {}", lines[0]);
            assert!(!lines[0].contains("fallbackwarn"), "never names the service: {}", lines[0]);
        }
    }

    #[test]
    #[serial]
    fn a_failing_provider_stops_the_chain_instead_of_falling_back_to_a_weaker_one() {
        #[cfg(all(feature = "external-secret", feature = "ephemeral"))]
        {
            // The platform's secret drifted to a group-readable mode. Policy
            // would let Ephemeral serve the service -- but only for a service
            // external-secret doesn't have, not one it has and can't trust:
            // otherwise every DEK from here on is wrapped under a key that is
            // gone at the next restart, and no call ever reports a problem.
            let service = "com.company.nofallback";
            let _mount = mount_with_untrusted_secret(service);
            let _policy = crate::policy::allow_ephemeral_policy_for_tests(); // external-secret, then ephemeral
            let c = std::ffi::CString::new(service).unwrap();

            let lines = logged_lines_containing("permissions too broad", || {
                assert_eq!(crate::hkdfguard_create_kek(c.as_ptr()), crate::status::PROVIDER_ERROR);
            });
            assert_eq!(lines.len(), 1, "the failure must be logged exactly once, got: {lines:#?}");
            assert!(lines[0].contains("EXTERNAL_SECRET"), "the line must name the provider: {}", lines[0]);

            // kek_exists must surface it too, rather than answer "no", which
            // would invite the caller to create a key somewhere weaker.
            let mut exists: std::os::raw::c_int = -1;
            assert_eq!(crate::hkdfguard_kek_exists(c.as_ptr(), &mut exists), crate::status::PROVIDER_ERROR);
            assert_eq!(exists, -1, "untouched on error");
            assert!(kek_exists(service).is_err());

            // And nothing was quietly created on Ephemeral.
            assert!(matches!(
                crate::provider::ephemeral::EphemeralProvider::new().kek_exists(service),
                Ok(false)
            ));

        }
    }

    #[test]
    #[serial]
    fn an_absent_provider_or_a_missing_key_still_moves_the_chain_on() {
        #[cfg(all(feature = "external-secret", feature = "ephemeral"))]
        {
            let _policy = crate::policy::allow_ephemeral_policy_for_tests();

            // No mount at all: absent.
            let (provider, _) = create_kek("com.company.absentmount").unwrap();
            assert_eq!(provider.provider_type(), ProviderType::Ephemeral);

            // A trusted mount with nothing for this service: declined.
            let mount = crate::secure_file::private_tempdir();
            let _secret_mount = crate::policy::test_support::secret_mount(mount.path());
            let (provider, _) = create_kek("com.company.notinmount").unwrap();
            assert_eq!(provider.provider_type(), ProviderType::Ephemeral);

        }
    }

    #[test]
    #[serial]
    fn malformed_policy_fails_closed_even_when_providers_are_available() {

        let _policy_dir = write_policy("[selection]\nmode = \"require\"\nprovider = \"quantum-vault\"\n");

        let err = expect_err(create_kek("com.company.orders"));
        assert!(matches!(err, Error::Provider(_)), "a malformed policy must fail closed, not fall back to the default chain");

    }
}
