//! Provider 1: TPM2 (preferred provider).
//!
//! ```text
//!  ______________________________________________________________________
//! | HARDWARE-DEPENDENT CODE                                                |
//! |                                                                        |
//! | Verified (see docker/): natively built and linked against real        |
//! | `libtss2-esys` 3.2.1 on Debian bookworm/aarch64, and the              |
//! | `#[ignore]`d test below passed against a real `swtpm` instance --     |
//! | TPM2_CreatePrimary + TPM2_ECDH_ZGen executed for real and produced    |
//! | the same key deterministically across two calls. Not yet exercised   |
//! | against a physical/discrete TPM chip or a TPM firmware TPM (fTPM);    |
//! | re-run `docker/run-tests.sh` (or the steps in `docker/README.md`      |
//! | for passing through a real `/dev/tpmrm0`) after any change here.      |
//! |______________________________________________________________________|
//! ```
//!
//! ## Design
//!
//! Rather than creating a child key and persisting it into the TPM's
//! limited persistent-handle range (which requires an owner-authorization
//! session for `EvictControl` and a local mapping from `service` to a
//! specific handle number that must never collide or leak), this provider
//! uses `TPM2_CreatePrimary` with a per-service `unique` seed value in the
//! public template.
//!
//! `TPM2_CreatePrimary` is *deterministic*: for a fixed hierarchy, fixed
//! public template (including the `unique` field, when the caller supplies
//! one) and unchanged TPM primary seed, it reproduces the exact same key
//! every time -- this is the same mechanism TPMs use internally to avoid
//! ever having to store a Storage Root Key. By setting `unique` to a
//! deterministic, non-secret, per-service label (`SHA-256(service)`), each
//! service gets its own key, reproducible on demand, with:
//!
//! - no persistent-handle bookkeeping or exhaustion risk,
//! - no local (service -> handle) mapping file to protect or lose,
//! - a private key that never leaves the TPM and is not derived from any
//!   host-identifying attribute -- it is derived from the TPM's own
//!   internal primary seed (injected at manufacture, never exported),
//!   using the service label purely for domain separation, exactly like
//!   this protocol already uses `service` as HKDF `info`. This is *not*
//!   the "derive a KEK from a machine fingerprint" pattern the spec
//!   prohibits: the secret input is the TPM's seed, not the label.
//!
//! The resulting primary key is loaded transiently for the duration of one
//! `ECDH_ZGen` call and flushed immediately after -- "persistent" here
//! means deterministically reproducible, not resident in NV storage.

use crate::error::{Error, Result}; // this crate's error type + `Result` alias
use crate::provider::{KekHandle, KekProvider, ProviderType, SharedSecret}; // traits/types this module implements
use elliptic_curve::sec1::ToEncodedPoint; // lets us split the caller's ephemeral public key into X/Y coordinates
use p256::PublicKey; // the caller's ephemeral public key type
use sha2::{Digest as ShaDigest, Sha256}; // hashing used to build the per-service `unique` label (aliased to avoid clashing with tss-esapi's own `Digest`)
use std::path::PathBuf; // location of the derivation-secret file
use std::str::FromStr; // brings `TctiNameConf::from_str` into scope
use std::sync::{Arc, Mutex, OnceLock}; // shared, lock-protected TPM context; `OnceLock` for the per-process conformance verdict
use zeroize::{Zeroize, Zeroizing}; // scrubs the derivation secret and its digest once they're no longer needed

use tss_esapi::attributes::ObjectAttributesBuilder; // builds the TPM object-attribute bitfield
use tss_esapi::handles::KeyHandle; // opaque TPM-side handle to a loaded key
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm}; // enum constants for "SHA-256" and "ECC"
use tss_esapi::interface_types::ecc::EccCurve; // enum constant for "NIST P-256"
use tss_esapi::interface_types::resource_handles::Hierarchy; // selects the Owner hierarchy for CreatePrimary
use tss_esapi::structures::{
    EccParameter, EccPoint, EccScheme, KeyDerivationFunctionScheme, Name, Public, PublicBuilder,
    PublicEccParametersBuilder,
}; // the TPM public-template types this module builds, plus the TPM2_ReadPublic "Name" value
use tss_esapi::traits::Marshall; // `.marshall()`, for serializing a `Public` area to its wire bytes
use tss_esapi::{Context, TctiNameConf}; // the ESAPI connection handle and its configuration type

// ---------------------------------------------------------------------
// Extra secret entropy in the key derivation.
// ---------------------------------------------------------------------
//
// `TPM2_CreatePrimary` derives the primary object from the TPM's primary
// seed and the public template, of which the `unique` field is the part a
// caller controls. With `unique` set only to a public per-service label,
// the derivation depends on nothing secret to the *host*: any process
// that can open the TPM device can issue the identical CreatePrimary and
// obtain the identical key. An authValue cannot close that gap, because
// the authValue is not an input to the derivation -- an attacker simply
// re-derives the same key with an authValue of their own choosing.
//
// Folding a root-owned host secret into `unique` makes the derived key
// depend on the TPM seed *and* a file the attacker must also be able to
// read, so local TPM access alone is no longer enough.
//
// `inSensitive.data` would seem like the more natural channel for this,
// and it is *not* usable here: for an asymmetric object the TPM requires
// `TPMA_OBJECT.sensitiveDataOrigin` to be SET (the TPM must originate the
// private key itself; supplying sensitive data would mean supplying the
// private key, which is `TPM2_Import`'s job). Clearing it to pass
// `inSensitive.data` makes `TPM2_CreatePrimary` fail with
// `TPM_RC_ATTRIBUTES` -- verified against swtpm, not merely assumed.
// `unique` is the designed channel, and it is the same mechanism
// `validate_tpm_compatibility` already proves this TPM honors when it
// checks that different services derive different keys.
//
// The folded label is security-critical: anyone who learns it can derive
// the key, so it is treated like the secret itself (zeroized, never
// logged). It is not exposed by the TPM -- `out_public.unique` holds the
// *generated* public point, not the label fed into the request template.
//
// Because this changes the derivation, enabling it changes the KEK: DEKs
// wrapped before the secret was provisioned will fail their fingerprint
// check (status -16) rather than decrypt to garbage. See README.

/// Default location of the TPM derivation secret. Overridable with
/// `HKDFGUARD_TPM_DERIVATION_SECRET_FILE`.
const DEFAULT_DERIVATION_SECRET_FILE: &str = "/etc/hkdfguard/tpm.derivation-secret";

/// Upper bound on the derivation-secret file's size. It only ever gets
/// hashed down to 32 bytes, so this is purely a sanity limit.
const MAX_DERIVATION_SECRET_LEN: usize = 4096;

/// Domain-separation prefix, so these bytes can never collide with any
/// other use of the same file's contents.
const DERIVATION_SECRET_DOMAIN: &[u8] = b"hkdfguard-tpm2-derivation-secret-v1:";

fn derivation_secret_path() -> PathBuf {
    std::env::var("HKDFGUARD_TPM_DERIVATION_SECRET_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_DERIVATION_SECRET_FILE))
}

/// Reads the optional derivation secret and condenses it to the fixed 32
/// bytes handed to `TPM2_CreatePrimary` as `inSensitive.data`.
///
/// - Absent, and policy doesn't require one: `Ok(None)` -- derivation
///   falls back to seed + service label, exactly as before.
/// - Absent, with `tpm.require_derivation_secret: true`: `Err`.
/// - Present but untrustworthy (wrong owner, group/other-accessible, a
///   symlink, oversized, empty): always `Err`. A secret that exists but
///   can't be trusted is never silently skipped, since that would quietly
///   swap the strong key for the weak one.
///
/// Read fresh on every call, like the policy file and for the same reason
/// -- there is no cached copy of it anywhere in the process.
fn read_derivation_secret() -> Result<Option<Zeroizing<[u8; 32]>>> {
    use crate::secure_file::{
        open_checked, FileRequirements, Owner, SecretBuffer, FORBID_GROUP_OTHER_ACCESS,
    };

    let path = derivation_secret_path();
    let requirements = FileRequirements {
        owner: Some(Owner::RootOrCurrentUser),
        forbidden_mode_bits: FORBID_GROUP_OTHER_ACCESS, // owner-only, e.g. 0600/0400
        follow_symlinks: false, // the secret must not be reachable through a link we don't control
    };

    let mut file = match open_checked(&path, &requirements) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if crate::policy::require_tpm_derivation_secret() {
                return Err(Error::Provider(format!(
                    "TPM derivation secret is required by policy but {} does not exist",
                    path.display()
                )));
            }
            return Ok(None);
        }
        Err(e) => {
            return Err(Error::Provider(format!(
                "TPM derivation secret at {} is present but unusable: {e}",
                path.display()
            )));
        }
    };

    let mut raw = SecretBuffer::read_from(&mut file, MAX_DERIVATION_SECRET_LEN)
        .map_err(|e| Error::Provider(format!("failed to read TPM derivation secret: {e}")))?;
    if raw.as_slice().is_empty() {
        raw.wipe();
        return Err(Error::Provider(format!(
            "TPM derivation secret at {} is empty",
            path.display()
        )));
    }

    // The file's bytes are used *exactly* as they appear on disk -- no
    // newline or whitespace trimming. Any trimming rule would silently
    // change the derived key for a secret that happened to end in that
    // byte, and the resulting KEK change is unrecoverable. Generate the
    // file with something like `head -c 32 /dev/urandom > <path>`.
    let mut hasher = Sha256::new();
    hasher.update(DERIVATION_SECRET_DOMAIN);
    hasher.update(raw.as_slice());
    let mut digest = hasher.finalize();
    raw.wipe();

    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&digest);
    digest.as_mut_slice().zeroize(); // the digest is as sensitive as the file it came from
    Ok(Some(out))
}


// Holds the shared, lazily-usable connection to the TPM. `None` means no
// TPM was reachable at construction time (this provider is then simply
// unavailable).
pub struct Tpm2Provider {
    // A TPM ESYS context is not safe to drive concurrently; serialize
    // access to the (typically low-throughput, one DEK-wrap-at-a-time) TPM
    // channel behind a mutex instead of opening a context per call. Shared
    // (via Arc) with every handle so the actual CreatePrimary+ECDH_ZGen
    // round trip can happen lazily in `KekHandle::ecdh`, once the caller's
    // ephemeral public key is available.
    context: Arc<Mutex<Option<Context>>>,
}

impl Tpm2Provider {
    pub fn new() -> Self {
        Tpm2Provider {
            context: Arc::new(Mutex::new(open_context())), // try to connect once, at construction time
        }
    }
}

impl Default for Tpm2Provider {
    fn default() -> Self {
        Self::new()
    }
}

// Attempts to open a connection to a TPM: first via the standard
// TCTI-selecting environment variables, then falling back to the default
// Linux TPM resource-manager device node. Refuses to hand back a
// connection to a TPM that fails `validate_tpm_compatibility` -- see that
// function's doc comment -- treating it exactly like a connection that
// couldn't be established at all, so `probe()`/`kek_exists()` correctly
// report this provider as unavailable rather than silently producing KEKs
// this crate's persistence model can't actually rely on.
fn open_context() -> Option<Context> {
    let tcti = TctiNameConf::from_environment_variable() // e.g. TPM2TOOLS_TCTI / TCTI / TEST_TCTI, useful for pointing at swtpm
        .or_else(|_| TctiNameConf::from_str("device:/dev/tpmrm0")) // otherwise assume a real, kernel-managed TPM device
        .ok()?; // if neither resolves to a valid config, there's no TPM to use
    let mut ctx = Context::new(tcti).ok()?; // actually establish the ESAPI connection; `None` on any failure

    // Resolve the derivation secret before the self-test, purely so a
    // missing-but-required (or present-but-untrustworthy) secret reports
    // *that* rather than surfacing as an opaque "self-test could not run".
    if let Err(e) = read_derivation_secret() {
        log::warn!("hkdfguard: TPM unavailable: {e}");
        return None;
    }

    // The conformance verdict is a fact about the TPM's *behavior*, not a
    // credential, so it's established once per process rather than on
    // every connection -- providers are constructed (and this runs) per
    // call, and re-running three CreatePrimary round trips on each one
    // would triple the per-call TPM cost for no security benefit. Only a
    // definitive verdict is cached; a self-test that couldn't run at all
    // (TPM busy, command error) makes the TPM unavailable for *this* call
    // only and is retried next time.
    let compatible = match TPM_CONFORMANCE_VERDICT.get() {
        Some(verdict) => *verdict,
        None => match validate_tpm_compatibility(&mut ctx) {
            Ok(verdict) => *TPM_CONFORMANCE_VERDICT.get_or_init(|| verdict), // first definitive verdict wins; a concurrent one agrees
            Err(e) => {
                log::warn!("hkdfguard: TPM conformance self-test could not run ({e}); TPM unavailable for this call");
                return None;
            }
        },
    };
    if !compatible {
        log::warn!("hkdfguard: TPM failed conformance self-test, treating as unavailable");
        return None;
    }

    // Deliberately cached separately from the verdict above rather than
    // folded into it: this check is only meaningful while a derivation
    // secret is configured, so a process that starts without one and has
    // one provisioned underneath it must still run it the first time the
    // secret is actually used, instead of inheriting a verdict that never
    // examined it.
    match TPM_DERIVATION_SECRET_VERDICT.get() {
        Some(true) => {}
        Some(false) => return None, // already reported when the verdict was established
        None => match validate_derivation_secret_is_honored(&mut ctx) {
            Ok(None) => {} // no secret configured, so nothing to verify and nothing cached
            Ok(Some(verdict)) => {
                if !*TPM_DERIVATION_SECRET_VERDICT.get_or_init(|| verdict) {
                    return None;
                }
            }
            Err(e) => {
                log::warn!("hkdfguard: could not verify that the TPM honors the derivation secret ({e}); TPM unavailable for this call");
                return None;
            }
        },
    }

    Some(ctx)
}

/// Once-per-process result of [`validate_derivation_secret_is_honored`].
/// Only ever populated while a derivation secret is configured -- see the
/// call site in [`open_context`] for why it isn't part of
/// [`TPM_CONFORMANCE_VERDICT`].
static TPM_DERIVATION_SECRET_VERDICT: OnceLock<bool> = OnceLock::new();

/// Once-per-process result of `validate_tpm_compatibility`: `true` if the
/// TPM this process talks to behaves as hkdfguard requires, `false` if it
/// definitively doesn't. Unset until a self-test has actually completed.
static TPM_CONFORMANCE_VERDICT: OnceLock<bool> = OnceLock::new();

// ---------------------------------------------------------------------
// Name verification.
// ---------------------------------------------------------------------

/// `TPM_ALG_SHA256`, as it appears in the two-byte algorithm prefix of a
/// TPM Name.
const TPM_ALG_SHA256: [u8; 2] = [0x00, 0x0B];

/// Recomputes a loaded object's TPM Name from the public area the TPM
/// returned for it: `nameAlg || H_nameAlg(marshalled TPMT_PUBLIC)`.
fn computed_name(public: &Public) -> Result<Vec<u8>> {
    let Public::Ecc {
        name_hashing_algorithm,
        ..
    } = public
    else {
        return Err(Error::Provider(
            "TPM primary key is not an ECC public key".into(), // defensive: our own template always requests ECC
        ));
    };
    if *name_hashing_algorithm != HashingAlgorithm::Sha256 {
        return Err(Error::Provider(
            "TPM object uses an unexpected Name hash algorithm".into(), // our template always requests SHA-256
        ));
    }

    let marshalled = public
        .marshall()
        .map_err(|e| Error::Provider(format!("failed to marshal TPM public area: {e}")))?;
    let digest = Sha256::digest(&marshalled);

    let mut out = Vec::with_capacity(TPM_ALG_SHA256.len() + digest.len());
    out.extend_from_slice(&TPM_ALG_SHA256);
    out.extend_from_slice(&digest);
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Two independent checks on the identity of the key the TPM just handed
/// back, in increasing order of strength:
///
/// 1. **Self-consistency.** The reported Name must equal the Name
///    recomputed from the reported public area. Since a Name is a
///    *public* function of the public area, anyone able to substitute one
///    could recompute the other, so this does **not** stop an active
///    man-in-the-middle -- it catches a non-conformant TPM or stack, a
///    buggy resource manager, and transport corruption.
///
///    This depends on `tss-esapi`'s marshalling reproducing, byte for
///    byte, the `TPMT_PUBLIC` the TPM itself hashed. That equivalence is
///    not assumed: `tpm_reported_name_matches_the_client_recomputed_name`
///    asserts it against a live TPM, and has passed against swtpm, which
///    is why this is enforced rather than merely logged.
///
/// 2. **Administrative pinning.** If policy records an expected Name for
///    this service (`tpm.pinned_names`), the reported Name must match it.
///    This one *is* anti-substitution: the expected value comes from the
///    root-owned policy file rather than from the TPM being questioned,
///    and it compares the TPM's own Name bytes directly, so it does not
///    depend on marshalling at all.
///
/// Both are cheap next to the CreatePrimary that precedes them, so they
/// run on every path that obtains a key -- wrap, unwrap, and the
/// connection-time self-test alike.
fn verify_name(service: &str, public: &Public, name: &Name) -> Result<()> {
    let expected = computed_name(public)?;
    if name.value() != expected.as_slice() {
        return Err(Error::Provider(format!(
            "TPM Name mismatch: the TPM reported Name {} for a public area whose recomputed Name is {}",
            hex(name.value()),
            hex(&expected)
        )));
    }

    if let Some(pinned) = crate::policy::pinned_tpm_name(service)? {
        if name.value() != pinned.as_slice() {
            return Err(Error::Provider(format!(
                "TPM Name for this service does not match the Name pinned in policy (pinned {}, got {})",
                hex(&pinned),
                hex(name.value())
            )));
        }
    }

    Ok(())
}

// Low-level, provider-instance-independent CreatePrimary: reads the
// derivation secret, builds this service's deterministic template, runs
// TPM2_CreatePrimary, reads back the resulting object's public area and
// Name via TPM2_ReadPublic, and verifies both before handing anything
// back. Returns the *still-loaded* handle -- the caller owns flushing it
// -- so the same derivation can feed both TPM2_ECDH_ZGen and a plain
// public-key read without diverging. Every internal failure path flushes
// before returning.
//
// Every path that needs this service's key goes through here, which is
// what guarantees `ecdh` and `public_key` derive the *same* key: if they
// disagreed on the template or the sensitive data, the fingerprint check
// in `crypto::unwrap` would reject every payload.
fn create_and_verify_primary(
    ctx: &mut Context,
    service: &str,
) -> Result<(KeyHandle, Public, Name)> {
    let secret = read_derivation_secret()?;
    create_and_verify_primary_with(ctx, service, secret.as_ref())
}

fn create_and_verify_primary_with(
    ctx: &mut Context,
    service: &str,
    secret: Option<&Zeroizing<[u8; 32]>>,
) -> Result<(KeyHandle, Public, Name)> {
    // The derivation secret rides in the template's `unique` field, not
    // in `inSensitive.data` -- the TPM rejects the latter for an
    // asymmetric key. See this module's extra-entropy note.
    let template = service_public_template(service, secret)?;

    let key_handle = ctx
        .execute_with_nullauth_session(|ctx| {
            // TPM2_CreatePrimary: deterministically (re)derives this service's key from the TPM's own seed + `template`
            ctx.create_primary(Hierarchy::Owner, template.clone(), None, None, None, None)
        })
        .map_err(|e| Error::Provider(format!("TPM2_CreatePrimary failed: {e}")))?
        .key_handle;

    let (public, name, _qualified_name) = match ctx.read_public(key_handle) {
        // TPM2_ReadPublic: the public area + Name, straight from the TPM
        Ok(v) => v,
        Err(e) => {
            let _ = ctx.flush_context(key_handle.into()); // never leak a transient object slot
            return Err(Error::Provider(format!("TPM2_ReadPublic failed: {e}")));
        }
    };

    if let Err(e) = verify_name(service, &public, &name) {
        let _ = ctx.flush_context(key_handle.into());
        return Err(e);
    }

    Ok((key_handle, public, name))
}

// `create_and_verify_primary` for callers that only want the public area
// and Name: flushes the transient primary before returning, on every path.
fn create_and_read_primary(ctx: &mut Context, service: &str) -> Result<(Public, Name)> {
    let (key_handle, public, name) = create_and_verify_primary(ctx, service)?;
    let _ = ctx.flush_context(key_handle.into());
    Ok((public, name))
}

// Service labels used only by `validate_tpm_compatibility`'s self-test --
// never real service identities, so the leading double-underscore (which
// `hkdfguard_wrap_dek`'s own service-name charset wouldn't accept) is a
// deliberate, unmistakable "this is internal" marker.
const SELFTEST_SERVICE: &str = "__hkdfguard_selftest__";
const SELFTEST_ALT_SERVICE: &str = "__hkdfguard_selftest_alt__";

/// Empirically validates, against the real TPM this process just
/// connected to, the behavior this provider's whole persistence model
/// depends on (see the module-level design note): `TPM2_CreatePrimary`
/// must be deterministic for a fixed service (so a KEK can be reproduced
/// on demand rather than only existing for the lifetime of one call), and
/// distinct services must produce distinct keys (so the per-service
/// `unique` template field is actually influencing derivation, not being
/// ignored). Called once, at connection time (see `open_context`) --
/// paying for a couple of extra `CreatePrimary`/`ReadPublic` round trips
/// up front is worth refusing a TPM that can't actually honor the
/// semantics this crate promises, rather than discovering that the first
/// time a wrapped DEK turns out to be unrecoverable.
///
/// Returns `Ok(true)` if the TPM is compatible, `Ok(false)` if it
/// definitively is not (a verdict `open_context` caches for the process),
/// and `Err` only if the self-test itself couldn't be carried out -- a
/// command failure, which says nothing about the TPM's determinism and so
/// must not be cached as a verdict.
fn validate_tpm_compatibility(ctx: &mut Context) -> Result<bool> {
    let (public1, _) = create_and_read_primary(ctx, SELFTEST_SERVICE)?;
    let (public2, _) = create_and_read_primary(ctx, SELFTEST_SERVICE)?;
    let bytes1 = public1.marshall().map_err(|e| Error::Provider(format!("failed to marshal TPM public area: {e}")))?;
    let bytes2 = public2.marshall().map_err(|e| Error::Provider(format!("failed to marshal TPM public area: {e}")))?;
    if bytes1 != bytes2 {
        log::warn!("hkdfguard: TPM behavior incompatible with hkdfguard requirements: the same service did not reproduce the same key");
        return Ok(false);
    }

    let (public_alt, _) = create_and_read_primary(ctx, SELFTEST_ALT_SERVICE)?;
    let bytes_alt = public_alt.marshall().map_err(|e| Error::Provider(format!("failed to marshal TPM public area: {e}")))?;
    if bytes1 == bytes_alt {
        log::warn!("hkdfguard: TPM behavior incompatible with hkdfguard requirements: different services reproduced the same key (unique field ignored)");
        return Ok(false);
    }

    Ok(true)
}

/// When a derivation secret is configured, empirically confirms that this
/// TPM's key derivation actually depends on it.
///
/// This check exists because the failure mode it guards against is
/// silent: a TPM that accepted the request but derived the same key
/// regardless would leave the derivation secret appearing to work while
/// protecting nothing. Rather than trust the specification here, compare
/// the two derivations and refuse the TPM if they match. (The earlier
/// attempt to carry the secret in `inSensitive.data` failed loudly with
/// `TPM_RC_ATTRIBUTES` instead of silently -- but a quiet failure is the
/// case worth defending against, so the check stays.)
///
/// `Ok(None)` when no secret is configured -- there is nothing to verify,
/// and nothing may be cached, since a secret provisioned later still
/// needs checking. `Ok(Some(true))` when the secret demonstrably changes
/// the derived key, `Ok(Some(false))` -- which makes the provider
/// unavailable for the rest of the process -- when it makes no difference.
fn validate_derivation_secret_is_honored(ctx: &mut Context) -> Result<Option<bool>> {
    let secret = read_derivation_secret()?;
    let Some(secret) = secret else {
        return Ok(None); // no secret configured; nothing to validate or cache
    };

    let (handle_with, public_with, _) =
        create_and_verify_primary_with(ctx, SELFTEST_SERVICE, Some(&secret))?;
    let _ = ctx.flush_context(handle_with.into());
    let (handle_without, public_without, _) =
        create_and_verify_primary_with(ctx, SELFTEST_SERVICE, None)?;
    let _ = ctx.flush_context(handle_without.into());

    let with = public_with
        .marshall()
        .map_err(|e| Error::Provider(format!("failed to marshal TPM public area: {e}")))?;
    let without = public_without
        .marshall()
        .map_err(|e| Error::Provider(format!("failed to marshal TPM public area: {e}")))?;

    if with == without {
        log::error!(
            "hkdfguard: this TPM derives the same primary key whether or not the host derivation \
             secret is mixed into the template's unique field, so the configured TPM derivation \
             secret would provide no protection; treating the TPM as unavailable rather than \
             deriving a key any local process could reproduce"
        );
        return Ok(Some(false));
    }

    Ok(Some(true))
}

// Handle type returned from `get_or_create_kek`; deliberately does *not*
// hold a loaded TPM key -- that's created fresh (deterministically) inside
// `ecdh`, once the peer's ephemeral public key is known.
struct Tpm2Handle {
    key_id: Vec<u8>,     // diagnostic-only tag embedded in the wrapped payload
    service: String,      // the service name, needed to rebuild the same deterministic template later
    context: Arc<Mutex<Option<Context>>>, // shared handle back to the TPM connection
}

impl KekHandle for Tpm2Handle {
    fn key_id(&self) -> &[u8] {
        &self.key_id
    }

    fn ecdh(&self, ephemeral_public_key: &PublicKey) -> Result<SharedSecret> {
        let mut guard = self
            .context
            .lock() // only one caller may talk to the TPM at a time
            .map_err(|_| Error::Provider("TPM context lock poisoned".into()))?;
        let ctx = guard
            .as_mut()
            .ok_or(Error::Provider("TPM context not available".into()))?; // connection failed at construction time

        let peer_point = encode_peer_point(ephemeral_public_key)?; // the caller's ephemeral public key, TPM-encoded

        // Derives the key, reads it back, and verifies its Name (and any
        // policy-pinned Name) *before* it is used for ECDH -- so a key
        // that isn't the one policy expects never computes a shared
        // secret at all.
        let (key_handle, _public, _name) = create_and_verify_primary(ctx, &self.service)?;

        let z_result = ctx
            .execute_with_nullauth_session(|ctx| ctx.ecdh_z_gen(key_handle, peer_point.clone())); // TPM2_ECDH_ZGen: computes the shared point Z inside the TPM

        // Always flush the transient primary, even on ECDH failure, so we
        // never leak TPM transient-object slots.
        let _ = ctx.flush_context(key_handle.into()); // best-effort cleanup; ignore errors since we're already on an error/success path either way

        let z = z_result.map_err(|e| Error::Provider(format!("TPM2_ECDH_ZGen failed: {e}")))?; // now propagate any ECDH failure

        let mut secret = [0u8; 32];
        let x_bytes = z.x().value(); // the shared secret is conventionally just the X-coordinate of Z
        if x_bytes.len() != 32 {
            return Err(Error::Provider(
                "TPM returned unexpected ECDH shared point size".into(), // defensive: should always be 32 for P-256
            ));
        }
        secret.copy_from_slice(x_bytes);
        Ok(SharedSecret::new(secret)) // wrap in the zeroizing alias before returning
    }

    // A standalone TPM2_CreatePrimary, independent of `ecdh`'s own --
    // TPM2_CreatePrimary is deterministic (see the module-level design
    // note), so this reproduces the exact same key and simply reads back
    // its public part instead of proceeding to TPM2_ECDH_ZGen. Costs one
    // extra CreatePrimary per wrap/unwrap versus not fingerprinting at
    // all; deliberately *not* shared/cached with `ecdh`'s own call, since
    // that would require keeping a transient TPM object slot alive across
    // two separate trait-method invocations, which risks leaking it if
    // the caller (see `crypto::unwrap`) never calls `ecdh` at all -- e.g.
    // exactly when the fingerprint doesn't match.
    fn public_key(&self) -> Result<PublicKey> {
        let mut guard = self
            .context
            .lock()
            .map_err(|_| Error::Provider("TPM context lock poisoned".into()))?;
        let ctx = guard
            .as_mut()
            .ok_or(Error::Provider("TPM context not available".into()))?;

        // Same verified derivation path `ecdh` uses, so the public key
        // reported here (and hence the fingerprint written into the
        // payload) is guaranteed to belong to the key `ecdh` would use.
        let (public, _name) = create_and_read_primary(ctx, &self.service)?;
        encode_tpm_public_key(&public)
    }
}

// Converts the ECC public point the TPM handed back in `out_public` (the
// *actual* generated point, not the `unique` seed value fed into the
// request template -- see `service_public_template`) into a `p256::PublicKey`.
fn encode_tpm_public_key(public: &Public) -> Result<PublicKey> {
    let Public::Ecc { unique, .. } = public else {
        return Err(Error::Provider(
            "TPM primary key is not an ECC public key".into(), // defensive: our own template always requests ECC
        ));
    };

    let x = unique.x().value();
    let y = unique.y().value();
    if x.len() != 32 || y.len() != 32 {
        return Err(Error::Provider(
            "TPM returned unexpected ECC public key coordinate size".into(), // defensive; should always be 32 for P-256
        ));
    }

    let mut point = [0u8; 65]; // uncompressed SEC1 point: 0x04 || X || Y
    point[0] = 0x04;
    point[1..33].copy_from_slice(x);
    point[33..65].copy_from_slice(y);

    PublicKey::from_sec1_bytes(&point)
        .map_err(|_| Error::Provider("TPM returned an invalid ECC public key".into()))
}

impl KekProvider for Tpm2Provider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Tpm2
    }

    fn probe(&self) -> bool {
        self.context
            .lock()
            .map(|guard| guard.is_some()) // "available" means we successfully connected at construction time
            .unwrap_or(false) // a poisoned lock is treated as "not available" rather than panicking
    }

    // TPM2_CreatePrimary is deterministic (see the module-level design
    // note): for a fixed TPM seed and template, it always reproduces the
    // exact same key. There is no separate persisted "does this key exist"
    // state to check -- the key conceptually already exists for every
    // possible service string the moment the TPM itself is reachable. So
    // this always answers `true` once `probe()` does, and `load_kek` below
    // ignores `create_if_missing` entirely: there is nothing to create.
    fn kek_exists(&self, _service: &str) -> Result<bool> {
        Ok(self.probe())
    }

    fn load_kek(&self, service: &str, _create_if_missing: bool) -> Result<Box<dyn KekHandle>> {
        if !self.probe() {
            return Err(Error::Provider("TPM context not available".into()));
        }
        // The actual TPM2_CreatePrimary + TPM2_ECDH_ZGen round trip is
        // deferred to `KekHandle::ecdh`, once the caller's ephemeral
        // public key is available -- see the module-level design note for
        // why CreatePrimary-on-demand stands in for "load a persistent KEK".
        Ok(Box::new(Tpm2Handle {
            key_id: service_fingerprint(service),
            service: service.to_string(),
            context: Arc::clone(&self.context), // clone the Arc (cheap: just bumps a refcount), not the underlying context
        }))
    }
}

// Non-secret diagnostic tag for the wrapped payload: just a hash of the
// service name, carrying no key material.
fn service_fingerprint(service: &str) -> Vec<u8> {
    Sha256::digest(service.as_bytes()).to_vec()
}

/// Builds the per-service ECC P-256 public template used with
/// `TPM2_CreatePrimary`: an unrestricted decryption key (required for
/// `TPM2_ECDH_ZGen`), non-signing, fixed to this TPM and this parent
/// (i.e. not duplicable/exportable), with `unique` set to a deterministic,
/// non-secret per-service label so each service reproducibly derives a
/// distinct key from the TPM's primary seed.
///
/// `secret`, when present, is folded into the `unique` label so the
/// derived key depends on it -- see this module's extra-entropy note. The
/// object attributes are identical either way; only `unique` differs.
fn service_public_template(
    service: &str,
    secret: Option<&Zeroizing<[u8; 32]>>,
) -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true) // key can never be moved to a different TPM
        .with_fixed_parent(true) // key can never be re-parented/duplicated
        .with_sensitive_data_origin(true) // the private part is generated by the TPM itself; required for an asymmetric key
        .with_user_with_auth(true) // standard "USER role" authorization is sufficient to use the key
        .with_decrypt(true) // required: this key will be used for a decryption-family operation (ECDH)
        .with_sign_encrypt(false) // this key must not be usable for signing
        .with_restricted(false) // unrestricted, so it's usable directly with TPM2_ECDH_ZGen
        .build()
        .map_err(|e| Error::Provider(format!("failed to build TPM object attributes: {e}")))?;

    let ecc_params = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::Null) // no fixed signing/KDF scheme baked into the key itself
        .with_curve(EccCurve::NistP256) // the mandated curve
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null) // no on-TPM KDF; this crate does its own HKDF afterward
        .with_is_decryption_key(true) // mirrors the object attribute above, for the builder's own consistency checks
        .with_is_signing_key(false)
        .with_restricted(false)
        .build()
        .map_err(|e| Error::Provider(format!("failed to build TPM ECC parameters: {e}")))?;

    let unique = service_unique_point(service, secret)?; // the per-service (and, with a secret, per-host) label that differentiates this key

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(unique) // this is what makes CreatePrimary produce a different key per service
        .build()
        .map_err(|e| Error::Provider(format!("failed to build TPM public template: {e}")))
}

// Derives the deterministic `unique` point (x, y) fed into the public
// template above. Without a secret this is a non-secret per-service
// label; with one it also depends on the host secret, and is then as
// sensitive as the secret itself.
//
// Caveat worth knowing: `EccParameter` (and the marshalled command buffer
// tss-esapi builds from it) is not a zeroizing type, so with a secret
// configured these 32-byte halves briefly live in heap memory this crate
// can't scrub. They are one-way hashes rather than the secret itself, and
// the secret file is already readable by the same uid, so this is a
// known, bounded residue rather than a new exposure.
fn service_unique_point(
    service: &str,
    secret: Option<&Zeroizing<[u8; 32]>>,
) -> Result<EccPoint> {
    let x = unique_half(b"hkdfguard-tpm2-unique-x:", service, secret); // distinct prefix for the X half
    let y = unique_half(b"hkdfguard-tpm2-unique-y:", service, secret); // distinct prefix for the Y half

    let x_param = EccParameter::try_from(x.to_vec()) // convert the raw hash bytes into the TPM's ECC-parameter buffer type
        .map_err(|e| Error::Provider(format!("failed to build TPM unique.x: {e}")))?;
    let y_param = EccParameter::try_from(y.to_vec())
        .map_err(|e| Error::Provider(format!("failed to build TPM unique.y: {e}")))?;

    Ok(EccPoint::new(x_param, y_param))
}

// One half of the `unique` point. With `secret` absent this hashes
// exactly what it always has -- prefix followed by the service name --
// so a deployment that never provisions a secret keeps deriving the
// identical KEK it did before this input existed.
fn unique_half(
    prefix: &[u8],
    service: &str,
    secret: Option<&Zeroizing<[u8; 32]>>,
) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(prefix);
    hasher.update(service.as_bytes());
    if let Some(secret) = secret {
        hasher.update(b":secret:"); // separates the secret from the service name it follows
        hasher.update(&secret[..]);
    }
    let mut digest = hasher.finalize();

    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&digest);
    digest.as_mut_slice().zeroize();
    out
}

// Converts the caller's ephemeral P-256 public key (a `p256::PublicKey`)
// into the TPM crate's `EccPoint` representation, as required by
// `ecdh_z_gen`.
fn encode_peer_point(peer_public: &PublicKey) -> Result<EccPoint> {
    let encoded = peer_public.to_encoded_point(false); // uncompressed SEC1 encoding, so X and Y are both directly available
    let x = encoded
        .x()
        .ok_or(Error::Provider("ephemeral public key missing X".into()))?; // should never actually be missing for a valid point
    let y = encoded
        .y()
        .ok_or(Error::Provider("ephemeral public key missing Y".into()))?;

    let x_param = EccParameter::try_from(x.to_vec())
        .map_err(|e| Error::Provider(format!("failed to encode peer point X: {e}")))?;
    let y_param = EccParameter::try_from(y.to_vec())
        .map_err(|e| Error::Provider(format!("failed to encode peer point Y: {e}")))?;

    Ok(EccPoint::new(x_param, y_param))
}

#[cfg(test)]
mod tests {
    use super::*; // bring `Tpm2Provider` etc. into scope
    use serial_test::serial; // the tests below set process-wide env vars

    // ---------------------------------------------------------------
    // Derivation-secret and Name handling.
    //
    // Unlike the conformance suite further down, these need no TPM --
    // they exercise file handling, policy interaction, and the
    // client-side Name computation -- so they run under a plain
    // `cargo test --features tpm2`.
    // ---------------------------------------------------------------

    // Points HKDFGUARD_TPM_DERIVATION_SECRET_FILE at a fresh temp file
    // holding `contents` with mode `mode`, runs `f`, and always clears the
    // env var afterward. The TempDir is kept alive for the whole closure.
    fn with_secret_file<T>(contents: &[u8], mode: u32, f: impl FnOnce(&std::path::Path) -> T) -> T {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tpm.derivation-secret");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(contents).unwrap();
        file.flush().unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();

        std::env::set_var("HKDFGUARD_TPM_DERIVATION_SECRET_FILE", &path);
        let result = f(&path);
        std::env::remove_var("HKDFGUARD_TPM_DERIVATION_SECRET_FILE");
        result
    }

    // Points the env var at a path that doesn't exist.
    fn with_no_secret_file<T>(f: impl FnOnce() -> T) -> T {
        std::env::set_var(
            "HKDFGUARD_TPM_DERIVATION_SECRET_FILE",
            "/nonexistent-hkdfguard-tpm-secret-for-tests",
        );
        let result = f();
        std::env::remove_var("HKDFGUARD_TPM_DERIVATION_SECRET_FILE");
        result
    }

    #[test]
    #[serial]
    fn absent_secret_is_none_when_policy_does_not_require_one() {
        std::env::set_var("HKDFGUARD_POLICY_FILE", "/nonexistent-hkdfguard-policy-for-tests");
        let result = with_no_secret_file(read_derivation_secret);
        std::env::remove_var("HKDFGUARD_POLICY_FILE");
        assert!(result.unwrap().is_none(), "no secret and no policy must derive as before");
    }

    #[test]
    #[serial]
    fn absent_secret_is_an_error_when_policy_requires_one() {
        let dir = tempfile::tempdir().unwrap();
        let policy = dir.path().join("policy.yaml");
        std::fs::write(
            &policy,
            "selection:\n  mode: require\n  provider: tpm2\ntpm:\n  require_derivation_secret: true\n",
        )
        .unwrap();
        std::env::set_var("HKDFGUARD_POLICY_FILE", &policy);
        let result = with_no_secret_file(read_derivation_secret);
        std::env::remove_var("HKDFGUARD_POLICY_FILE");
        assert!(result.is_err(), "a required-but-missing secret must fail closed");
    }

    #[test]
    #[serial]
    fn secret_is_read_and_is_stable_and_domain_separated() {
        let first = with_secret_file(b"correct horse battery staple", 0o600, |_| {
            read_derivation_secret().unwrap().unwrap()
        });
        let again = with_secret_file(b"correct horse battery staple", 0o600, |_| {
            read_derivation_secret().unwrap().unwrap()
        });
        assert_eq!(*first, *again, "the same secret bytes must condense to the same 32 bytes");

        // Domain separation: the result is not a bare SHA-256 of the file,
        // so these bytes can't collide with any other use of the file.
        let bare = Sha256::digest(b"correct horse battery staple");
        assert_ne!(first.as_slice(), bare.as_slice());

        let different = with_secret_file(b"a different secret", 0o600, |_| {
            read_derivation_secret().unwrap().unwrap()
        });
        assert_ne!(*first, *different, "different secrets must condense differently");
    }

    #[test]
    #[serial]
    fn secret_bytes_are_used_verbatim_including_a_trailing_newline() {
        // Documented behavior: no trimming, because any trimming rule
        // would silently change the derived key for a secret ending in
        // that byte -- and a changed key is unrecoverable.
        let without = with_secret_file(b"secret", 0o600, |_| read_derivation_secret().unwrap().unwrap());
        let with_nl = with_secret_file(b"secret\n", 0o600, |_| read_derivation_secret().unwrap().unwrap());
        assert_ne!(*without, *with_nl, "a trailing newline must not be silently stripped");
    }

    #[test]
    #[serial]
    fn present_but_untrustworthy_secret_is_an_error_never_silently_skipped() {
        // Group-readable: rejected rather than used, and rejected rather
        // than treated as absent (which would quietly swap the strong key
        // for the weak one).
        let result = with_secret_file(b"secret", 0o640, |_| read_derivation_secret());
        assert!(result.is_err(), "a group-readable secret must be rejected");

        // Empty file.
        let result = with_secret_file(b"", 0o600, |_| read_derivation_secret());
        assert!(result.is_err(), "an empty secret file must be rejected");
    }

    #[test]
    #[serial]
    fn a_symlinked_secret_is_rejected() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real-secret");
        let mut f = std::fs::File::create(&target).unwrap();
        f.write_all(b"secret").unwrap();
        f.flush().unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();

        let link = dir.path().join("link-to-secret");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        std::env::set_var("HKDFGUARD_TPM_DERIVATION_SECRET_FILE", &link);
        let result = read_derivation_secret();
        std::env::remove_var("HKDFGUARD_TPM_DERIVATION_SECRET_FILE");
        assert!(result.is_err(), "the secret must not be reachable through a symlink");
    }

    #[test]
    #[serial]
    fn oversized_secret_file_is_rejected() {
        let big = vec![b'x'; MAX_DERIVATION_SECRET_LEN + 1];
        let result = with_secret_file(&big, 0o600, |_| read_derivation_secret());
        assert!(result.is_err(), "a secret file over the size limit must be rejected");
    }

    #[test]
    fn the_secret_changes_only_the_unique_field_not_the_attributes() {
        // sensitiveDataOrigin must stay SET either way: the TPM requires
        // it for an asymmetric key, and clearing it to pass
        // inSensitive.data is what produced TPM_RC_ATTRIBUTES against
        // swtpm. The secret therefore rides in `unique` instead, so the
        // attributes are identical and only `unique` differs.
        let secret = Zeroizing::new([0x5au8; 32]);
        let plain = service_public_template("com.company.orders", None).unwrap();
        let with_secret = service_public_template("com.company.orders", Some(&secret)).unwrap();

        let Public::Ecc { object_attributes: plain_attrs, unique: plain_unique, .. } = &plain else {
            panic!("expected an ECC template");
        };
        let Public::Ecc { object_attributes: secret_attrs, unique: secret_unique, .. } = &with_secret else {
            panic!("expected an ECC template");
        };
        assert!(plain_attrs.sensitive_data_origin(), "required for an asymmetric key");
        assert!(secret_attrs.sensitive_data_origin(), "must not be cleared to carry the secret");
        assert_eq!(plain_attrs, secret_attrs, "only `unique` may differ between the two modes");

        assert_ne!(plain_unique.x().value(), secret_unique.x().value(), "the secret must reach unique.x");
        assert_ne!(plain_unique.y().value(), secret_unique.y().value(), "the secret must reach unique.y");

        // And therefore the templates -- and the Names derived from them
        // -- differ, which is why enabling the secret is a KEK change.
        assert_ne!(plain.marshall().unwrap(), with_secret.marshall().unwrap());
        assert_ne!(computed_name(&plain).unwrap(), computed_name(&with_secret).unwrap());
    }

    #[test]
    fn unique_without_a_secret_is_unchanged_from_the_original_derivation() {
        // Backward compatibility: a deployment that never provisions a
        // secret must keep deriving the identical KEK, so the no-secret
        // label must still be exactly prefix || service.
        let expected_x = Sha256::digest([b"hkdfguard-tpm2-unique-x:".as_slice(), b"com.company.orders"].concat());
        let expected_y = Sha256::digest([b"hkdfguard-tpm2-unique-y:".as_slice(), b"com.company.orders"].concat());

        assert_eq!(unique_half(b"hkdfguard-tpm2-unique-x:", "com.company.orders", None).as_slice(), expected_x.as_slice());
        assert_eq!(unique_half(b"hkdfguard-tpm2-unique-y:", "com.company.orders", None).as_slice(), expected_y.as_slice());

        // The two halves must stay distinct from each other.
        assert_ne!(expected_x.as_slice(), expected_y.as_slice());
    }

    #[test]
    fn different_secrets_give_different_unique_labels() {
        let a = Zeroizing::new([0xaau8; 32]);
        let b = Zeroizing::new([0xbbu8; 32]);
        let prefix = b"hkdfguard-tpm2-unique-x:".as_slice();

        let with_a = unique_half(prefix, "com.company.orders", Some(&a));
        let with_b = unique_half(prefix, "com.company.orders", Some(&b));
        assert_ne!(*with_a, *with_b);

        // Same secret, different service: still distinct.
        let other_service = unique_half(prefix, "com.company.billing", Some(&a));
        assert_ne!(*with_a, *other_service);

        // Deterministic for identical inputs.
        assert_eq!(*with_a, *unique_half(prefix, "com.company.orders", Some(&a)));
    }

    #[test]
    fn computed_name_has_the_sha256_prefix_and_tracks_the_public_area() {
        let orders = service_public_template("com.company.orders", None).unwrap();
        let billing = service_public_template("com.company.billing", None).unwrap();

        let name = computed_name(&orders).unwrap();
        assert_eq!(name.len(), 2 + 32, "a SHA-256 TPM Name is the 2-byte alg id plus a 32-byte digest");
        assert_eq!(&name[..2], &TPM_ALG_SHA256);
        // The digest really is over the marshalled public area.
        assert_eq!(&name[2..], Sha256::digest(orders.marshall().unwrap()).as_slice());
        // A different service is a different public area, so a different Name.
        assert_ne!(name, computed_name(&billing).unwrap());
    }

    #[test]
    fn hex_encodes_lowercase_and_zero_pads() {
        assert_eq!(hex(&[0x00, 0x0b, 0xff, 0x10]), "000bff10");
        assert_eq!(hex(&[]), "");
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"] // skipped by default `cargo test`; run explicitly with `-- --ignored`
    fn same_service_produces_same_key_deterministically() {
        let provider = Tpm2Provider::new();
        assert!(provider.probe(), "no TPM available");

        let eph = p256::SecretKey::random(&mut rand_core::OsRng); // stand-in "caller" ephemeral key for this test
        let eph_pub = eph.public_key();

        let h1 = provider.load_kek("com.company.orders", true).unwrap(); // first CreatePrimary for this service
        let h2 = provider.load_kek("com.company.orders", true).unwrap(); // second, independent CreatePrimary for the same service
        assert_eq!(*h1.ecdh(&eph_pub).unwrap(), *h2.ecdh(&eph_pub).unwrap()); // must yield the identical shared secret both times

        // `public_key()` is itself a third, independent CreatePrimary --
        // deterministic CreatePrimary means it must report the exact same
        // public key `ecdh` used, verified by doing ECDH from the
        // ephemeral side against it and checking agreement.
        let reported_public = h1.public_key().unwrap();
        let via_reported = p256::ecdh::diffie_hellman(eph.to_nonzero_scalar(), reported_public.as_affine());
        assert_eq!(h1.ecdh(&eph_pub).unwrap().as_slice(), via_reported.raw_secret_bytes().as_slice());
    }

    // ---------------------------------------------------------------
    // TPM determinism and vendor-compatibility conformance suite.
    //
    // These tests exist to empirically validate (against swtpm, a
    // physical TPM, Intel PTT, AMD fTPM, ...) the assumptions this
    // provider's entire persistence model rests on -- see the
    // module-level design note and `validate_tpm_compatibility`'s own
    // doc comment. All of them require a real or simulated TPM2 device
    // and are `#[ignore]`d so a normal `cargo test` stays portable; run
    // them explicitly with `cargo test --features tpm2 -- --ignored`
    // once you have one (see docker/README.md for a real swtpm run).
    // ---------------------------------------------------------------

    // Constructs a fresh `Tpm2Provider`, confirms it's actually reachable,
    // and hands the caller a `&mut Context` to drive directly -- the
    // shared entry point every helper below goes through.
    fn with_tpm_context<T>(f: impl FnOnce(&mut Context) -> Result<T>) -> Result<T> {
        let provider = Tpm2Provider::new();
        if !provider.probe() {
            return Err(Error::Provider("no TPM available for conformance test".into()));
        }
        let mut guard = provider
            .context
            .lock()
            .map_err(|_| Error::Provider("TPM context lock poisoned".into()))?;
        let ctx = guard
            .as_mut()
            .ok_or(Error::Provider("TPM context not available".into()))?;
        f(ctx)
    }

    // Returns the serialized (marshalled) TPM public area for `service`'s
    // deterministic primary -- a difference in the returned bytes between
    // two calls indicates a different underlying TPM key.
    fn create_primary_and_get_public(service: &str) -> Result<Vec<u8>> {
        with_tpm_context(|ctx| {
            let (public, _name) = create_and_read_primary(ctx, service)?;
            public
                .marshall()
                .map_err(|e| Error::Provider(format!("failed to marshal TPM public area: {e}")))
        })
    }

    // Returns the TPM Name value (TPM2_ReadPublic's own `name` output,
    // computed by the TPM itself, not derived client-side) for `service`'s
    // deterministic primary.
    fn create_primary_and_get_name(service: &str) -> Result<Vec<u8>> {
        with_tpm_context(|ctx| {
            let (_public, name) = create_and_read_primary(ctx, service)?;
            Ok(name.value().to_vec())
        })
    }

    // Runs the exact same `load_kek` + `ecdh` path production code uses
    // (not a parallel test-only reimplementation of it) and returns the
    // resulting shared secret.
    fn create_ecdh_secret(service: &str, peer_key: &p256::PublicKey) -> Result<[u8; 32]> {
        let provider = Tpm2Provider::new();
        if !provider.probe() {
            return Err(Error::Provider("no TPM available for conformance test".into()));
        }
        let handle = provider.load_kek(service, true)?;
        let secret = handle.ecdh(peer_key)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(secret.as_slice());
        Ok(out)
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    fn same_service_produces_identical_public_key() {
        let key1 = create_primary_and_get_public("com.company.orders").unwrap();
        let key2 = create_primary_and_get_public("com.company.orders").unwrap();
        assert_eq!(
            key1, key2,
            "TPM2_CreatePrimary is not deterministic for this TPM -- incompatible with hkdfguard's TPM persistence semantics"
        );
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    fn same_service_produces_identical_name() {
        let name1 = create_primary_and_get_name("com.company.orders").unwrap();
        let name2 = create_primary_and_get_name("com.company.orders").unwrap();
        assert_eq!(name1, name2, "TPM Name is not stable across independent CreatePrimary calls for the same service");
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    fn different_services_produce_different_public_keys() {
        let orders = create_primary_and_get_public("orders").unwrap();
        let billing = create_primary_and_get_public("billing").unwrap();
        let payments = create_primary_and_get_public("payments").unwrap();
        assert_ne!(orders, billing, "the ECC unique field appears to be ignored or ineffective on this TPM");
        assert_ne!(orders, payments, "the ECC unique field appears to be ignored or ineffective on this TPM");
        assert_ne!(billing, payments, "the ECC unique field appears to be ignored or ineffective on this TPM");
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    fn different_services_produce_different_names() {
        let name1 = create_primary_and_get_name("orders").unwrap();
        let name2 = create_primary_and_get_name("billing").unwrap();
        assert_ne!(name1, name2);
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    fn different_services_produce_different_ecdh_secrets() {
        let eph = p256::SecretKey::random(&mut rand_core::OsRng); // one peer keypair, reused for every call below
        let peer = eph.public_key();

        let z_orders = create_ecdh_secret("orders", &peer).unwrap();
        let z_billing = create_ecdh_secret("billing", &peer).unwrap();
        let z_payments = create_ecdh_secret("payments", &peer).unwrap();

        assert_ne!(z_orders, z_billing, "different services must not share a TPM-backed KEK");
        assert_ne!(z_orders, z_payments, "different services must not share a TPM-backed KEK");
        assert_ne!(z_billing, z_payments, "different services must not share a TPM-backed KEK");
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    fn ecdh_repeatability_for_same_service() {
        let eph = p256::SecretKey::random(&mut rand_core::OsRng);
        let peer = eph.public_key();

        let z1 = create_ecdh_secret("orders", &peer).unwrap();
        let z2 = create_ecdh_secret("orders", &peer).unwrap();
        assert_eq!(z1, z2, "end-to-end ECDH is not repeatable for the same service on this TPM");
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    fn service_case_normalization_does_not_change_key() {
        // Applies the exact same normalization production goes through
        // (`crate::normalize_service`, shared with `lib.rs`'s own
        // `cstr_to_service`) rather than a second, potentially-drifting
        // copy of "just lowercase it" -- this is specifically checking
        // that the ABI layer's canonicalization and the TPM layer agree,
        // not re-testing lowercasing itself.
        let key1 = create_primary_and_get_public(&crate::normalize_service("orders")).unwrap();
        let key2 = create_primary_and_get_public(&crate::normalize_service("Orders")).unwrap();
        let key3 = create_primary_and_get_public(&crate::normalize_service("ORDERS")).unwrap();
        assert_eq!(key1, key2);
        assert_eq!(key2, key3);
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    fn longest_valid_service_name_remains_stable() {
        let service = "s".repeat(128); // the mandated maximum service-name length (see lib.rs::MAX_SERVICE_LEN)
        let key1 = create_primary_and_get_public(&service).unwrap();
        let key2 = create_primary_and_get_public(&service).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    fn single_character_service_remains_stable() {
        let key1 = create_primary_and_get_public("a").unwrap();
        let key2 = create_primary_and_get_public("a").unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    fn tpm_conformance_self_test_passes_on_a_compatible_tpm() {
        // Exercises `validate_tpm_compatibility` the same way `open_context`
        // does at connection time: a compatible TPM (swtpm, real hardware,
        // Intel PTT, AMD fTPM) must pass it, and `Tpm2Provider::new()` must
        // therefore still report itself available.
        let provider = Tpm2Provider::new();
        assert!(
            provider.probe(),
            "a compatible TPM must pass validate_tpm_compatibility and remain available"
        );
    }

    // ---------------------------------------------------------------
    // Derivation-secret and Name conformance, against a real TPM.
    //
    // These validate the two load-bearing assumptions behind the
    // hardening above, neither of which can be confirmed by reading the
    // specification alone:
    //
    //   1. `TPM2_CreatePrimary` genuinely mixes `inSensitive.data` into
    //      the derivation. If it didn't, the derivation secret would look
    //      configured while protecting nothing -- which is exactly the
    //      silent failure `validate_supplied_entropy_is_honored` guards
    //      against at runtime.
    //   2. A TPM Name really is `nameAlg || H(marshalled TPMT_PUBLIC)`
    //      *as tss-esapi marshals it*. If the marshalling differed in any
    //      byte, `verify_name` would reject every key the TPM produced.
    // ---------------------------------------------------------------

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn tpm_reported_name_matches_the_client_recomputed_name() {
        // Assumption 2. This is the test that proves `verify_name`'s
        // formula (and tss-esapi's marshalling) agrees with the TPM's own
        // Name computation -- if it doesn't, nothing else here works.
        let (public, name) = with_tpm_context(|ctx| {
            let (handle, public, name) =
                create_and_verify_primary_with(ctx, "com.company.orders", None)?;
            let _ = ctx.flush_context(handle.into());
            Ok((public, name))
        })
        .unwrap();

        assert_eq!(
            name.value(),
            computed_name(&public).unwrap().as_slice(),
            "the TPM's own Name disagrees with nameAlg || SHA-256(marshalled public area)"
        );
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn derivation_secret_changes_the_derived_key() {
        // Assumption 1, and the whole point of the derivation secret: a
        // key derived with it must not be a key an attacker could
        // reproduce with TPM access alone.
        let secret = Zeroizing::new([0x5au8; 32]);

        let (with_secret, without_secret) = with_tpm_context(|ctx| {
            let (h1, p1, _) = create_and_verify_primary_with(ctx, "com.company.orders", Some(&secret))?;
            let _ = ctx.flush_context(h1.into());
            let (h2, p2, _) = create_and_verify_primary_with(ctx, "com.company.orders", None)?;
            let _ = ctx.flush_context(h2.into());
            Ok((p1.marshall().unwrap(), p2.marshall().unwrap()))
        })
        .unwrap();

        assert_ne!(
            with_secret, without_secret,
            "this TPM ignores inSensitive.data, so a derivation secret would protect nothing"
        );
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn same_derivation_secret_reproduces_the_same_key() {
        // Determinism -- the property the whole persistence model rests
        // on -- must survive adding the secret.
        let secret = Zeroizing::new([0x5au8; 32]);

        let (first, second) = with_tpm_context(|ctx| {
            let (h1, p1, _) = create_and_verify_primary_with(ctx, "com.company.orders", Some(&secret))?;
            let _ = ctx.flush_context(h1.into());
            let (h2, p2, _) = create_and_verify_primary_with(ctx, "com.company.orders", Some(&secret))?;
            let _ = ctx.flush_context(h2.into());
            Ok((p1.marshall().unwrap(), p2.marshall().unwrap()))
        })
        .unwrap();

        assert_eq!(first, second, "the same secret must reproduce the same key");
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn different_derivation_secrets_produce_different_keys() {
        let a = Zeroizing::new([0xaau8; 32]);
        let b = Zeroizing::new([0xbbu8; 32]);

        let (from_a, from_b) = with_tpm_context(|ctx| {
            let (h1, p1, _) = create_and_verify_primary_with(ctx, "com.company.orders", Some(&a))?;
            let _ = ctx.flush_context(h1.into());
            let (h2, p2, _) = create_and_verify_primary_with(ctx, "com.company.orders", Some(&b))?;
            let _ = ctx.flush_context(h2.into());
            Ok((p1.marshall().unwrap(), p2.marshall().unwrap()))
        })
        .unwrap();

        assert_ne!(from_a, from_b, "a different host secret must yield a different KEK");
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn derivation_secret_self_test_reports_a_verdict_when_a_secret_is_configured() {
        // With no secret there is nothing to verify and nothing to cache.
        let verdict = with_no_secret_file(|| with_tpm_context(validate_derivation_secret_is_honored)).unwrap();
        assert_eq!(verdict, None, "no secret configured must yield no verdict");

        // With one, a conformant TPM must return a positive verdict.
        let verdict = with_secret_file(b"a-real-host-secret", 0o600, |_| {
            with_tpm_context(validate_derivation_secret_is_honored)
        })
        .unwrap();
        assert_eq!(
            verdict,
            Some(true),
            "a TPM whose derivation depends on the unique field must pass the derivation-secret self-test"
        );
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn tpm_accepts_the_fixed_static_ecdh_point() {
        // The forgery-resistant protocol derives the wrapping key from
        // ECDH(KEK_priv, H) for a fixed H with no known discrete log. If
        // a backend refused to do ECDH against a caller-supplied fixed
        // point, the entire construction would be unusable there -- so
        // confirm it against a real TPM before building on it, rather
        // than assuming as happened with inSensitive.data.
        //
        // Note what cannot be checked here: the *value* of Z can't be
        // independently recomputed, because that would need H's discrete
        // log, which is precisely what nobody has. What is checkable is
        // that the TPM accepts the point, and that the result behaves
        // like a real per-KEK shared secret.
        let h = crate::crypto::static_ecdh_point().unwrap();

        let z1 = create_ecdh_secret("com.company.orders", &h).unwrap();
        let z2 = create_ecdh_secret("com.company.orders", &h).unwrap();
        assert_eq!(z1, z2, "static-point ECDH must be repeatable for the same service");
        assert_ne!(z1, [0u8; 32], "shared secret must not be all zeroes");

        // Each service's KEK must produce its own Z against the same H --
        // this is what gives each service a distinct wrapping key.
        let z_billing = create_ecdh_secret("com.company.billing", &h).unwrap();
        assert_ne!(z1, z_billing, "different KEKs must yield different Z against the same H");

        // H must not be special-cased by the stack: a random point gives
        // a different secret for the same KEK.
        let random_peer = p256::SecretKey::random(&mut rand_core::OsRng).public_key();
        let z_random = create_ecdh_secret("com.company.orders", &random_peer).unwrap();
        assert_ne!(z1, z_random);
    }

    // Writes a policy pinning `service` to `name_hex` and points
    // HKDFGUARD_POLICY_FILE at it for the duration of `f`.
    fn with_pinned_name<T>(service: &str, name_hex: &str, f: impl FnOnce() -> T) -> T {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(
            &path,
            format!(
                "selection:\n  mode: require\n  provider: tpm2\ntpm:\n  pinned_names:\n    {service}: \"{name_hex}\"\n"
            ),
        )
        .unwrap();
        std::env::set_var("HKDFGUARD_POLICY_FILE", &path);
        let result = f();
        std::env::remove_var("HKDFGUARD_POLICY_FILE");
        result
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn a_correctly_pinned_name_is_accepted_and_a_wrong_one_is_rejected() {
        let service = "com.company.orders";

        // Learn this TPM's actual Name for the service, unpinned.
        let actual = with_tpm_context(|ctx| {
            let (handle, _public, name) = create_and_verify_primary_with(ctx, service, None)?;
            let _ = ctx.flush_context(handle.into());
            Ok(name.value().to_vec())
        })
        .unwrap();

        // Pinned to the real value: the derivation succeeds.
        with_pinned_name(service, &hex(&actual), || {
            with_tpm_context(|ctx| {
                let (handle, _p, _n) = create_and_verify_primary_with(ctx, service, None)?;
                let _ = ctx.flush_context(handle.into());
                Ok(())
            })
            .expect("a correctly pinned Name must be accepted");
        });

        // Pinned to anything else: refused, and refused *before* the key
        // is ever used for ECDH.
        let mut wrong = actual.clone();
        wrong[2] ^= 0xff; // corrupt the digest, keeping the alg prefix valid
        with_pinned_name(service, &hex(&wrong), || {
            let result = with_tpm_context(|ctx| {
                let (handle, _p, _n) = create_and_verify_primary_with(ctx, service, None)?;
                let _ = ctx.flush_context(handle.into());
                Ok(())
            });
            assert!(result.is_err(), "a Name that doesn't match the policy pin must be refused");
        });
    }
}
