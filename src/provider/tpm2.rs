//! Provider 1: TPM2 (preferred provider).
//!
//! ```text
//!  ______________________________________________________________________
//! | HARDWARE-DEPENDENT CODE                                                |
//! |                                                                        |
//! | Verified: built and linked against real `libtss2-esys` 4.0.1 on       |
//! | Ubuntu 24.04, with the `#[ignore]`d conformance suite passing against |
//! | swtpm (docker/run-tests.sh) and against real firmware TPMs -- Intel   |
//! | PTT and AMD fTPM (scripts/native-tpm-test.sh). Not yet exercised      |
//! | against a discrete TPM chip (e.g. Infineon, Nuvoton). Re-run both     |
//! | after any change here.                                                |
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
use crate::provider::{Backend, KekHandle, KekProvider, ProviderType, SharedSecret}; // traits/types this module implements
use elliptic_curve::sec1::ToEncodedPoint; // lets us split the caller's ephemeral public key into X/Y coordinates
use p256::PublicKey; // the caller's ephemeral public key type
use sha2::{Digest as ShaDigest, Sha256}; // hashing used to build the per-service `unique` label (aliased to avoid clashing with tss-esapi's own `Digest`)
use std::path::PathBuf; // location of the derivation-secret file
use std::str::FromStr; // brings `TctiNameConf::from_str` into scope
use std::sync::{Arc, Mutex, OnceLock}; // shared, lock-protected TPM context; `OnceLock` for the per-process conformance verdict
use zeroize::{Zeroize, Zeroizing}; // scrubs the derivation secret and its digest once they're no longer needed

use tss_esapi::attributes::{ObjectAttributesBuilder, SessionAttributesBuilder}; // TPM object-attribute and session-attribute bitfields
use tss_esapi::constants::{PropertyTag, SessionType}; // TPM_PT_MANUFACTURER lookup, and the HMAC session type
use tss_esapi::handles::{KeyHandle, SessionHandle}; // opaque TPM-side handles to a loaded key / a started session
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm}; // enum constants for "SHA-256" and "ECC"
use tss_esapi::interface_types::ecc::EccCurve; // enum constant for "NIST P-256"
use tss_esapi::interface_types::resource_handles::Hierarchy; // selects the Owner hierarchy for CreatePrimary
use tss_esapi::interface_types::session_handles::AuthSession; // a started session, as passed to execute_with_session
use tss_esapi::structures::{
    EccParameter, EccPoint, EccScheme, KeyDerivationFunctionScheme, Name, Public, PublicBuilder,
    PublicEccParametersBuilder, SymmetricDefinition,
}; // the TPM public-template types this module builds, the TPM2_ReadPublic "Name" value, and the session cipher
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

/// Location of the TPM derivation secret when the policy names none
/// (`tpm.derivation_secret_file`).
const DEFAULT_DERIVATION_SECRET_FILE: &str = "/etc/hkdfguard/tpm.derivation-secret";

/// Upper bound on the derivation-secret file's size. It only ever gets
/// hashed down to 32 bytes, so this is purely a sanity limit.
const MAX_DERIVATION_SECRET_LEN: usize = 4096;

/// Domain-separation prefix, so these bytes can never collide with any
/// other use of the same file's contents.
const DERIVATION_SECRET_DOMAIN: &[u8] = b"hkdfguard-tpm2-derivation-secret-v1:";

/// `tpm.derivation_secret_file` from policy, else the default. `Err` on a
/// policy that exists but can't be trusted.
fn derivation_secret_path() -> Result<PathBuf> {
    Ok(crate::policy::tpm_derivation_secret_file()?.unwrap_or_else(|| PathBuf::from(DEFAULT_DERIVATION_SECRET_FILE)))
}

fn derivation_secret_is_missing() -> bool {
    matches!(derivation_secret_path().map(std::fs::symlink_metadata), Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound)
}

/// The TCTI used when the policy names none: the kernel's TPM resource
/// manager.
const DEFAULT_TCTI: &str = "device:/dev/tpmrm0";

/// Whether the policy names a TCTI, rather than leaving [`DEFAULT_TCTI`] --
/// i.e. whether someone pointed this process at a particular TPM on purpose.
fn tcti_is_explicit() -> bool {
    matches!(crate::policy::tpm_tcti(), Ok(Some(_)))
}

/// Which TPM to open: `tpm.tcti` from the root-owned policy, else
/// [`DEFAULT_TCTI`]. Never the environment: whoever chooses the TPM
/// chooses who knows its seed.
///
/// A policy TCTI that can't be parsed, or a policy file that can't be
/// trusted, is an error -- the TPM is then unavailable rather than opened
/// at a default the administrator may have meant to avoid.
fn resolve_tcti() -> Result<TctiNameConf> {
    if let Some(tcti) = crate::policy::tpm_tcti()? {
        return TctiNameConf::from_str(&tcti)
            .map_err(|e| Error::Provider(format!("tpm.tcti \"{tcti}\" in policy is not a usable TCTI: {e}")));
    }
    TctiNameConf::from_str(DEFAULT_TCTI).map_err(|e| Error::Provider(format!("default TCTI: {e}")))
}

/// Reads the derivation secret and condenses it to the 32 bytes folded into
/// the primary template's `unique` field (see this module's extra-entropy
/// note).
///
/// - Absent: `Err`, naming the file and how to create it. The secret is
///   required unless policy sets `tpm.require_derivation_secret = false`.
/// - Absent, with that set to `false`: `Ok(None)` -- the derivation then
///   uses the TPM seed and service label alone -- plus a warning, once per
///   process, that any local process with TPM access can reproduce the keys.
/// - Present but untrustworthy (wrong owner, group/other-accessible, a
///   symlink, oversized, empty): always `Err`. A secret that exists but
///   can't be trusted is never silently skipped, since that would quietly
///   swap the strong key for the weak one.
///
/// Read fresh on every call, like the policy file and for the same reason
/// -- there is no cached copy of it anywhere in the process.
/// Logged once: running without a derivation secret because policy allows it.
static MISSING_SECRET_WARNED: OnceLock<()> = OnceLock::new();

fn read_derivation_secret() -> Result<Option<Zeroizing<[u8; 32]>>> {
    use crate::secure_file::{
        check_location, config_owner, open_checked, FileRequirements, SecretBuffer, FORBID_GROUP_OTHER_ACCESS,
    };

    let path = derivation_secret_path()?;
    // Root-owned, like the policy: if the service could write it, any
    // process running as the service could change every TPM KEK, making
    // every DEK already wrapped permanently unopenable.
    let requirements = FileRequirements {
        owner: Some(config_owner()),
        forbidden_mode_bits: FORBID_GROUP_OTHER_ACCESS, // 0400, or 0440 when root-owned (see below)
        follow_symlinks: false, // the secret must not be reachable through a link we don't control
        allow_group_read_if_root_owned: true, // root:<service-group> 0440 for a non-root service
    };

    let opened = check_location(&path, config_owner()).and_then(|()| open_checked(&path, &requirements));
    let mut file = match opened {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if crate::policy::require_tpm_derivation_secret() {
                return Err(Error::Provider(format!(
                    "TPM derivation secret {path} does not exist. Create it as root: (umask 077; \
                     head -c 32 /dev/urandom > {path}); for a service that doesn't run as root, \
                     also chgrp <service-group> {path} && chmod 0440 {path} -- or, to run without \
                     one, set tpm.require_derivation_secret = false in the policy",
                    path = path.display()
                )));
            }
            MISSING_SECRET_WARNED.get_or_init(|| {
                log::warn!(
                    "hkdfguard: no TPM derivation secret at {} and tpm.require_derivation_secret = false: \
                     TPM keys are derived from the TPM seed and the service name alone, so any local \
                     process that can open the TPM can reproduce them",
                    path.display()
                );
            });
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
    // Set when a TPM is there but can't be trusted or used (see
    // `crate::provider::Backend::Refused`); every call then fails with it.
    refused: Option<String>,
}

impl Tpm2Provider {
    pub fn new() -> Self {
        // try to connect once, at construction time
        let (context, refused) = match open_context() {
            Backend::Ready(ctx) => (Some(ctx), None),
            Backend::Absent => (None, None),
            Backend::Refused(reason) => {
                log::error!("hkdfguard: TPM refused: {reason}");
                (None, Some(reason))
            }
        };
        Tpm2Provider { context: Arc::new(Mutex::new(context)), refused }
    }

    fn connected(&self) -> bool {
        self.context.lock().map(|guard| guard.is_some()).unwrap_or(false) // a poisoned lock counts as not connected
    }

    fn check_not_refused(&self) -> Result<()> {
        match &self.refused {
            Some(reason) => Err(Error::Provider(format!("TPM refused: {reason}"))),
            None => Ok(()),
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
fn open_context() -> Backend<Context> {
    // Checked before the TCTI is even opened: tpm2-tss starts logging from
    // the first command.
    if let Some(level) = std::env::var_os("TSS2_LOG") {
        if tss2_log_exposes_secrets(&level.to_string_lossy()) {
            return Backend::Refused(
                "TSS2_LOG enables debug/trace logging in tpm2-tss, which writes raw TPM commands and \
                 responses (including ECDH shared secrets), session keys and plaintext parameters to \
                 its log; unset TSS2_LOG or lower it to info or below"
                    .to_string(),
            );
        }
    }

    let tcti = match resolve_tcti() {
        Ok(tcti) => tcti,
        Err(e) => return Backend::Refused(e.to_string()),
    };
    let mut ctx = match Context::new(tcti) {
        Ok(ctx) => ctx,
        // The default device failing to open is the normal state of a host
        // with no TPM, or one this service isn't meant to use (not in the
        // `tss` group). A TCTI someone configured on purpose is different:
        // its TPM is meant to be used, so failing to reach it is an outage.
        Err(e) if tcti_is_explicit() => return Backend::Refused(format!("could not open the configured TCTI: {e}")),
        Err(e) => {
            log::debug!("hkdfguard: no usable TPM at {DEFAULT_TCTI} ({e})");
            return Backend::Absent;
        }
    };

    // Resolve the derivation secret before the self-test, purely so a
    // missing-but-required (or present-but-untrustworthy) secret reports
    // *that* rather than surfacing as an opaque "self-test could not run".
    // A missing one means the TPM isn't set up for use on this host; its
    // directory is root-controlled (see `read_derivation_secret`), so its
    // absence can't be forced by anyone else.
    if let Err(e) = read_derivation_secret() {
        if derivation_secret_is_missing() {
            log::warn!("hkdfguard: TPM not used: {e}");
            return Backend::Absent;
        }
        return Backend::Refused(e.to_string());
    }

    // The conformance verdict is a fact about the TPM's *behavior*, not a
    // credential, so it's established once per process rather than on
    // every connection -- providers are constructed (and this runs) per
    // call, and re-running three CreatePrimary round trips on each one
    // would triple the per-call TPM cost for no security benefit. Only a
    // definitive verdict is cached; a self-test that couldn't run at all
    // (TPM busy, command error) refuses the TPM for *this* call only and
    // is retried next time.
    let compatible = match TPM_CONFORMANCE_VERDICT.get() {
        Some(verdict) => *verdict,
        None => match validate_tpm_compatibility(&mut ctx) {
            Ok(verdict) => *TPM_CONFORMANCE_VERDICT.get_or_init(|| verdict), // first definitive verdict wins; a concurrent one agrees
            Err(e) => return Backend::Refused(format!("conformance self-test could not run ({e})")),
        },
    };
    if !compatible {
        return Backend::Refused("failed its conformance self-test".to_string());
    }

    // Deliberately cached separately from the verdict above rather than
    // folded into it: this check is only meaningful while a derivation
    // secret is configured, so a process that starts without one and has
    // one provisioned underneath it must still run it the first time the
    // secret is actually used, instead of inheriting a verdict that never
    // examined it.
    let secret_refused = || Backend::Refused("derives the same key with or without the derivation secret".to_string());
    match TPM_DERIVATION_SECRET_VERDICT.get() {
        Some(true) => {}
        Some(false) => return secret_refused(),
        None => match validate_derivation_secret_is_honored(&mut ctx) {
            Ok(None) => {} // no secret configured, so nothing to verify and nothing cached
            Ok(Some(verdict)) => {
                if !*TPM_DERIVATION_SECRET_VERDICT.get_or_init(|| verdict) {
                    return secret_refused();
                }
            }
            Err(e) => return Backend::Refused(format!("could not verify that it honors the derivation secret ({e})")),
        },
    }

    Backend::Ready(ctx)
}

/// Whether a `TSS2_LOG` value turns on tpm2-tss logging at `debug` or
/// `trace` for any module. At those levels its TCTI layer logs raw command
/// and response bytes -- `TPM2_ECDH_ZGen`'s response is the shared secret,
/// and `TPM2_CreatePrimary`'s command carries the derivation-secret-derived
/// template label -- and its ESAPI layer logs session keys and parameters
/// before encryption. `TSS2_LOGFILE` can send all of that to any path.
///
/// Mirrors tpm2-tss's own parser (src/util/log.c, `getLogLevel`): every `+`
/// introduces a level, matched case-insensitively by prefix. The module
/// before the `+` is deliberately ignored: any module at these levels
/// leaks.
fn tss2_log_exposes_secrets(value: &str) -> bool {
    value.split('+').skip(1).any(|after_plus| {
        let lower = after_plus.to_ascii_lowercase();
        lower.starts_with("debug") || lower.starts_with("trace")
    })
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

// Low-level, provider-instance-independent CreatePrimary: builds this
// service's deterministic template from `secret`, runs
// TPM2_CreatePrimary, reads back the resulting object's public area and
// Name via TPM2_ReadPublic, and verifies both before handing anything
// back. Returns the *still-loaded* handle -- the caller owns flushing it
// -- so the same derivation can feed both TPM2_ECDH_ZGen and a plain
// public-key read without diverging. Every internal failure path flushes
// before returning.
//
// The secret is a parameter, never read here, so that a caller making
// several derivations that must agree reads the file exactly once and
// passes the same bytes to each. Re-reading per derivation would let a
// secret rotated between two of them produce two different keys -- e.g.
// a payload whose fingerprint is one KEK and whose ciphertext is another,
// unopenable forever.
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

// `create_and_verify_primary_with` for callers that only want the public
// area and Name: flushes the transient primary before returning, on every
// path.
fn create_and_read_primary(
    ctx: &mut Context,
    service: &str,
    secret: Option<&Zeroizing<[u8; 32]>>,
) -> Result<(Public, Name)> {
    let (key_handle, public, name) = create_and_verify_primary_with(ctx, service, secret)?;
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
    // Read once for all three derivations: a secret rotated between them
    // would make the determinism check fail, and that verdict is cached
    // for the life of the process.
    let secret = read_derivation_secret()?;
    let secret = secret.as_ref();
    let (public1, _) = create_and_read_primary(ctx, SELFTEST_SERVICE, secret)?;
    let (public2, _) = create_and_read_primary(ctx, SELFTEST_SERVICE, secret)?;
    let bytes1 = public1.marshall().map_err(|e| Error::Provider(format!("failed to marshal TPM public area: {e}")))?;
    let bytes2 = public2.marshall().map_err(|e| Error::Provider(format!("failed to marshal TPM public area: {e}")))?;
    if bytes1 != bytes2 {
        log::warn!("hkdfguard: TPM behavior incompatible with hkdfguard requirements: the same service did not reproduce the same key");
        return Ok(false);
    }

    let (public_alt, _) = create_and_read_primary(ctx, SELFTEST_ALT_SERVICE, secret)?;
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

// ---------------------------------------------------------------------
// Session parameter encryption.
// ---------------------------------------------------------------------
//
// A discrete TPM sits on an LPC or SPI bus that an interposer can read
// byte-for-byte. `TPM2_ECDH_ZGen`'s response is the shared point Z for
// one payload; a captured response opens that payload (the per-payload
// hashed point in crypto.rs keeps it from opening any other), and an
// interposer that stays on the bus captures every subsequent one. A
// firmware TPM (Intel PTT, AMD fTPM) or a virtual TPM has
// no external bus, so this is pure overhead there -- hence the `auto`
// policy mode, which skips it only for known-internal manufacturers.
// That decision rests on `TPM_PT_MANUFACTURER`, read over the very bus in
// question, so an active interposer can forge it: `auto` defeats passive
// sniffing only. Once a salt key is pinned, `auto` stops asking and always
// encrypts (see `session_encryption_enabled`).
//
// The mechanism is the TPM 2.0 specification's own (Part 1 §19.6): an
// HMAC session started with `tpmKey` set to a TPM-resident decrypt key,
// so the session salt is encrypted to that key (one-pass ECDH) and the
// session key derived from it is never on the bus in cleartext; with
// `TPMA_SESSION.encrypt` set, the first response parameter -- here
// `outPoint`, i.e. Z -- is AES-128-CFB encrypted under a key derived from
// the session key. The cryptography lives in tpm2-tss's ESAPI layer,
// which tss-esapi wraps; this module only configures the session.
//
// Two things are load-bearing. An *unsalted* session's key derives from
// the two nonces, both visible on the bus, so the interposer computes it
// too -- salting is the entire defense, not an option. And the salt
// key's public half is itself learned over the bus at `TPM2_ReadPublic`,
// so an interposer can substitute its own and man-in-the-middle the
// session; that is what `tpm.pinned_session_salt_key_name` defeats, and
// why `required` mode refuses to run without a pin.
//
// Known limitation on a discrete TPM: parameter encryption covers only
// the *first* parameter of a command, and `TPM2_CreatePrimary`'s first
// parameter is `inSensitive`, not `inPublic`. The derivation-secret-
// derived `unique` label therefore still crosses the bus in cleartext
// when the service key is (re)created, and an interposer that captures
// it can re-derive the key itself. On a discrete TPM, the derivation
// secret protects against *software* attackers only; closing this needs
// a persisted, parent-encrypted key blob (`TPM2_Create` + `TPM2_Load`)
// rather than a derived primary.

/// Label for the deterministic salt key's `unique` field. Leading
/// underscores keep it outside the service-name charset, so no real
/// service can ever collide with it.
const SESSION_SALT_KEY_LABEL: &str = "__hkdfguard_session_salt_key__";

/// `TPM_PT_MANUFACTURER` identifiers of TPMs that live inside the SoC or
/// a hypervisor and so have no external bus to probe. Anything not listed
/// is treated as discrete and encrypted: `auto` only ever *skips*
/// encryption for a TPM positively known to be internal.
///
/// The property is four ASCII bytes packed big-endian; vendors shorter
/// than four characters pad with a space *or* a NUL depending on the
/// implementation (libtpms/swtpm reports `"IBM\0"`), so comparison is on
/// the identifier with trailing padding stripped.
const NO_EXTERNAL_BUS_MANUFACTURERS: &[&[u8]] = &[
    b"INTC", // Intel PTT (fTPM inside the CSME)
    b"AMD",  // AMD fTPM (inside the PSP)
    b"QCOM", // Qualcomm fTPM
    b"MSFT", // Hyper-V vTPM
    b"IBM",  // IBM software TPM, i.e. swtpm / libtpms
    b"GOOG", // Google Cloud vTPM
    b"VMW",  // VMware vTPM
];

/// The manufacturer identifier with trailing space/NUL padding removed.
fn manufacturer_id_bytes(id: u32) -> Vec<u8> {
    let bytes = id.to_be_bytes();
    let end = bytes
        .iter()
        .rposition(|b| *b != b' ' && *b != 0)
        .map_or(0, |i| i + 1);
    bytes[..end].to_vec()
}

fn manufacturer_has_no_external_bus(id: u32) -> bool {
    let trimmed = manufacturer_id_bytes(id);
    NO_EXTERNAL_BUS_MANUFACTURERS.iter().any(|m| *m == trimmed.as_slice())
}

/// Once-per-process `auto`-mode verdict: does this TPM lack an external
/// bus? A fact about the hardware, so cached like the conformance
/// verdict. Only consulted under `auto`; `required`/`off` are policy and
/// are re-read on every call like everything else.
static TPM_NO_EXTERNAL_BUS: OnceLock<bool> = OnceLock::new();

/// Logged once: `auto` chose to encrypt but no salt-key Name is pinned.
static UNPINNED_SALT_KEY_WARNED: OnceLock<()> = OnceLock::new();

/// Whether `TPM2_ECDH_ZGen` should run inside an encrypted session on
/// this call, per `tpm.session_encryption`.
fn session_encryption_enabled(ctx: &mut Context) -> Result<bool> {
    use crate::policy::SessionEncryption;
    match crate::policy::tpm_session_encryption() {
        SessionEncryption::Required => Ok(true),
        SessionEncryption::Off => Ok(false),
        SessionEncryption::Auto => {
            // A pinned salt key is the operator's statement that this TPM
            // may have a bus worth defending, and it is what makes the
            // encryption hold against an active interposer. Don't let a
            // manufacturer string read over that same bus -- which such an
            // interposer can rewrite to "INTC" -- switch it back off.
            if crate::policy::pinned_session_salt_key_name()?.is_some() {
                return Ok(true);
            }
            if let Some(internal) = TPM_NO_EXTERNAL_BUS.get() {
                return Ok(!internal);
            }
            let internal = match ctx.get_tpm_property(PropertyTag::Manufacturer) {
                Ok(Some(id)) if manufacturer_has_no_external_bus(id) => {
                    log::info!(
                        "hkdfguard: TPM manufacturer {:?} has no external bus; session encryption skipped (tpm.session_encryption = \"auto\")",
                        String::from_utf8_lossy(&id.to_be_bytes())
                    );
                    true
                }
                Ok(Some(id)) => {
                    log::info!(
                        "hkdfguard: TPM manufacturer {:?} treated as discrete; ECDH runs in a salted, parameter-encrypted session",
                        String::from_utf8_lossy(&id.to_be_bytes())
                    );
                    false
                }
                Ok(None) => {
                    log::warn!("hkdfguard: TPM did not report a manufacturer; assuming discrete and encrypting sessions");
                    false
                }
                Err(e) => {
                    return Err(Error::Provider(format!("TPM2_GetCapability(manufacturer) failed: {e}")));
                }
            };
            Ok(!*TPM_NO_EXTERNAL_BUS.get_or_init(|| internal))
        }
    }
}

/// Derives the deterministic session salt key: the same proven template
/// shape as a service key (ECC P-256, unrestricted decrypt, no scheme --
/// a valid `tpmKey` for `TPM2_StartAuthSession`'s one-pass-ECDH salt),
/// under a fixed label and with **no** derivation secret. It must be
/// derivable before anything secret is trusted, and it protects nothing
/// on its own: its private half only ever unwraps session salts. Verifies
/// the Name (self-consistency, and the policy pin if one is set) before
/// returning the still-loaded handle; the caller flushes it.
fn create_session_salt_key(ctx: &mut Context) -> Result<KeyHandle> {
    let template = service_public_template(SESSION_SALT_KEY_LABEL, None)?;
    let key_handle = ctx
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, template.clone(), None, None, None, None)
        })
        .map_err(|e| Error::Provider(format!("TPM2_CreatePrimary (session salt key) failed: {e}")))?
        .key_handle;

    let (public, name, _qualified_name) = match ctx.read_public(key_handle) {
        Ok(v) => v,
        Err(e) => {
            let _ = ctx.flush_context(key_handle.into());
            return Err(Error::Provider(format!("TPM2_ReadPublic (session salt key) failed: {e}")));
        }
    };
    if let Err(e) = verify_salt_key_name(&public, &name) {
        let _ = ctx.flush_context(key_handle.into());
        return Err(e);
    }
    Ok(key_handle)
}

// Same two checks as `verify_name`, against the session salt key's own
// policy pin. The pin is what stops a bus-resident attacker substituting
// their salt key; `required` mode can't load without one (enforced at
// policy validation), and `auto` warns once when it's missing.
fn verify_salt_key_name(public: &Public, name: &Name) -> Result<()> {
    let expected = computed_name(public)?;
    if name.value() != expected.as_slice() {
        return Err(Error::Provider(format!(
            "session salt key Name mismatch: TPM reported {} for a public area whose Name is {}",
            hex(name.value()),
            hex(&expected)
        )));
    }
    match crate::policy::pinned_session_salt_key_name()? {
        Some(pinned) if name.value() != pinned.as_slice() => Err(Error::Provider(format!(
            "session salt key Name {} does not match the Name pinned in policy ({})",
            hex(name.value()),
            hex(&pinned)
        ))),
        Some(_) => Ok(()),
        None => {
            UNPINNED_SALT_KEY_WARNED.get_or_init(|| {
                log::warn!(
                    "hkdfguard: encrypting TPM sessions with an unpinned salt key (Name {}); this defeats passive bus sniffing but not an active interposer -- set tpm.pinned_session_salt_key_name to close that",
                    hex(name.value())
                );
            });
            Ok(())
        }
    }
}

/// Starts a salted HMAC session with response and command parameter
/// encryption (AES-128-CFB). The caller flushes it.
fn start_encrypted_session(ctx: &mut Context, salt_key: KeyHandle) -> Result<AuthSession> {
    let session = ctx
        .start_auth_session(
            Some(salt_key), // salted: the session key depends on a secret only this TPM can unwrap
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .map_err(|e| Error::Provider(format!("TPM2_StartAuthSession failed: {e}")))?
        .ok_or_else(|| Error::Provider("TPM2_StartAuthSession returned no session".into()))?;

    let (attributes, mask) = SessionAttributesBuilder::new()
        .with_decrypt(true) // encrypt the command's first parameter (inPoint)
        .with_encrypt(true) // encrypt the response's first parameter (outPoint, i.e. Z)
        .with_continue_session(true)
        .build();
    if let Err(e) = ctx.tr_sess_set_attributes(session, attributes, mask) {
        let _ = ctx.flush_context(SessionHandle::from(session).into());
        return Err(Error::Provider(format!("failed to set TPM session attributes: {e}")));
    }
    Ok(session)
}

/// `TPM2_ECDH_ZGen` inside a salted, parameter-encrypted session, owning
/// the salt key's and the session's lifecycles: both are flushed on every
/// path, so neither a transient-object slot nor a session slot (TPMs have
/// very few) can leak.
fn ecdh_z_gen_encrypted(ctx: &mut Context, key_handle: KeyHandle, peer_point: &EccPoint) -> Result<EccPoint> {
    let salt_key = create_session_salt_key(ctx)?;
    let result = match start_encrypted_session(ctx, salt_key) {
        Err(e) => Err(e),
        Ok(session) => {
            let z = ctx
                .execute_with_session(Some(session), |ctx| ctx.ecdh_z_gen(key_handle, peer_point.clone()))
                .map_err(|e| Error::Provider(format!("TPM2_ECDH_ZGen (encrypted session) failed: {e}")));
            let _ = ctx.flush_context(SessionHandle::from(session).into());
            z
        }
    };
    let _ = ctx.flush_context(salt_key.into());
    result
}

// Handle type returned from `load_kek`; deliberately does *not* hold a
// loaded TPM key -- that's created fresh (deterministically) inside each
// method. It does hold the derivation secret, read once in `load_kek`, so
// `public_key` and `ecdh` within one wrap/unwrap derive from identical
// bytes. The handle lives for a single call and the secret is zeroized
// when it drops, so this is not caching across calls.
struct Tpm2Handle {
    key_id: Vec<u8>,     // diagnostic-only tag embedded in the wrapped payload
    service: String,      // the service name, needed to rebuild the same deterministic template later
    secret: Option<Zeroizing<[u8; 32]>>, // derivation secret snapshot for this handle's lifetime
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
        let (key_handle, _public, _name) =
            create_and_verify_primary_with(ctx, &self.service, self.secret.as_ref())?;

        // TPM2_ECDH_ZGen: computes the shared point Z inside the TPM. Under
        // an encrypted session its response -- Z itself -- is AES-CFB
        // encrypted before it crosses the bus; see `ecdh_z_gen_encrypted`.
        let z_result = match session_encryption_enabled(ctx) {
            Err(e) => Err(e),
            Ok(true) => ecdh_z_gen_encrypted(ctx, key_handle, &peer_point),
            Ok(false) => ctx
                .execute_with_nullauth_session(|ctx| ctx.ecdh_z_gen(key_handle, peer_point.clone()))
                .map_err(|e| Error::Provider(format!("TPM2_ECDH_ZGen failed: {e}"))),
        };

        // Always flush the transient primary, even on ECDH failure, so we
        // never leak TPM transient-object slots.
        let _ = ctx.flush_context(key_handle.into()); // best-effort cleanup; ignore errors since we're already on an error/success path either way

        let z = z_result?; // now propagate any ECDH failure

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

        // Same verified derivation path and the same secret bytes `ecdh`
        // uses, so the public key reported here (and hence the fingerprint
        // written into the payload) is guaranteed to belong to the key
        // `ecdh` will use, even if the secret file is rotated in between.
        let (public, _name) = create_and_read_primary(ctx, &self.service, self.secret.as_ref())?;
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
        self.refused.is_some() || self.connected()
    }

    // TPM2_CreatePrimary is deterministic (see the module-level design
    // note): for a fixed TPM seed and template, it always reproduces the
    // exact same key, so the TPM itself has no notion of a key "existing".
    // Provisioning state therefore lives in policy: under
    // `tpm.require_pinned_names`, a service exists iff its Name is pinned
    // (see `service_is_provisioned`); without it, every service exists the
    // moment the TPM is reachable.
    fn kek_exists(&self, service: &str) -> Result<bool> {
        self.check_not_refused()?;
        if !self.connected() {
            return Ok(false);
        }
        service_is_provisioned(service)
    }

    fn load_kek(&self, service: &str, create_if_missing: bool) -> Result<Box<dyn KekHandle>> {
        self.check_not_refused()?;
        if !self.connected() {
            return Err(Error::Provider("TPM context not available".into()));
        }
        if !service_is_provisioned(service)? {
            if create_if_missing {
                // Provisioning here means a root-owned policy edit, which
                // this process can't (and mustn't) make itself. Do the part
                // it can: derive the key and report the exact Name to pin.
                return Err(Error::Provider(unpinned_service_instructions(&self.context, service)));
            }
            return Err(Error::KeyNotProvisioned(
                "tpm.require_pinned_names is set and policy pins no TPM Name for this service",
            ));
        }
        // The actual TPM2_CreatePrimary + TPM2_ECDH_ZGen round trip is
        // deferred to `KekHandle::ecdh`, once the caller's ephemeral
        // public key is available -- see the module-level design note for
        // why CreatePrimary-on-demand stands in for "load a persistent KEK".
        Ok(Box::new(Tpm2Handle {
            key_id: service_fingerprint(service),
            service: service.to_string(),
            secret: read_derivation_secret()?, // the one read this handle's derivations share
            context: Arc::clone(&self.context), // clone the Arc (cheap: just bumps a refcount), not the underlying context
        }))
    }
}

/// Whether `service` counts as provisioned on the TPM. Always true unless
/// policy sets `tpm.require_pinned_names`, in which case only services with
/// an entry in `tpm.pinned_names` are. A policy file that exists but is
/// broken fails closed: the allowlist applies, and the pin lookup errors.
fn service_is_provisioned(service: &str) -> Result<bool> {
    if !crate::policy::require_tpm_pinned_names() {
        return Ok(true);
    }
    Ok(crate::policy::pinned_tpm_name(service)?.is_some())
}

/// The message `provision` gets for an unpinned service under
/// `tpm.require_pinned_names`: the Name this TPM derives for it, in the
/// form to paste into policy. Derived through the production path, so it
/// honors the derivation secret. If derivation itself fails, says so
/// rather than hiding the reason the service can't be provisioned.
fn unpinned_service_instructions(context: &Arc<Mutex<Option<Context>>>, service: &str) -> String {
    let name = (|| -> Result<String> {
        let mut guard = context
            .lock()
            .map_err(|_| Error::Provider("TPM context lock poisoned".into()))?;
        let ctx = guard
            .as_mut()
            .ok_or(Error::Provider("TPM context not available".into()))?;
        let secret = read_derivation_secret()?;
        let (_public, name) = create_and_read_primary(ctx, service, secret.as_ref())?;
        Ok(hex(name.value()))
    })();
    match name {
        Ok(name) => format!(
            "tpm.require_pinned_names is set and this service has no pinned TPM Name. To provision \
             it, add this to the policy file and run provision again:\n  [tpm.pinned_names]\n  \
             \"{service}\" = \"{name}\""
        ),
        Err(e) => format!(
            "tpm.require_pinned_names is set and this service has no pinned TPM Name; deriving its \
             Name to report it failed: {e}"
        ),
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
    use crate::policy::test_support::TestPolicy;
    use serial_test::serial; // the tests below set process-wide env vars

    // ---------------------------------------------------------------
    // Derivation-secret and Name handling.
    //
    // Unlike the conformance suite further down, these need no TPM --
    // they exercise file handling, policy interaction, and the
    // client-side Name computation -- so they run under a plain
    // `cargo test --features tpm2`.
    // ---------------------------------------------------------------

    // Points `tpm.derivation_secret_file` at a fresh temp file holding
    // `contents` with mode `mode`, for the duration of `f`.
    fn with_secret_file<T>(contents: &[u8], mode: u32, f: impl FnOnce(&std::path::Path) -> T) -> T {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let dir = crate::secure_file::private_tempdir();
        let path = dir.path().join("tpm.derivation-secret");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(contents).unwrap();
        file.flush().unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();

        with_secret_path(&path, || f(&path))
    }

    // Points `tpm.derivation_secret_file` at `path` for the duration of
    // `f`, layered over the policy in force -- so the harness's TCTI, and
    // any policy the test itself set, still apply.
    fn with_secret_path<T>(path: impl AsRef<std::path::Path>, f: impl FnOnce() -> T) -> T {
        let _secret = TestPolicy::write(&format!("[tpm]\nderivation_secret_file = \"{}\"\n", path.as_ref().display()));
        f()
    }

    // Points the derivation secret at a path that doesn't exist.
    fn with_no_secret_file<T>(f: impl FnOnce() -> T) -> T {
        with_secret_path("/nonexistent-hkdfguard-tpm-secret-for-tests", f)
    }

    #[test]
    #[serial]
    fn absent_secret_is_an_error_by_default() {
        // No policy file at all: the secret is still required.
        let _no_policy = TestPolicy::absent();
        let result = with_no_secret_file(read_derivation_secret);
        match result {
            Err(Error::Provider(msg)) => assert!(msg.contains("head -c 32 /dev/urandom"), "the error must say how to create it: {msg}"),
            other => panic!("a missing secret must be an error by default, got {:?}", other.map(|v| v.is_some())),
        }
    }

    #[test]
    #[serial]
    fn absent_secret_is_allowed_only_when_policy_turns_the_requirement_off() {
        let result = with_policy(
            "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nrequire_derivation_secret = false\n",
            || with_no_secret_file(read_derivation_secret),
        );
        assert!(result.unwrap().is_none(), "with the requirement off, a missing secret derives without one");
    }

    #[test]
    #[serial]
    fn absent_secret_is_an_error_when_policy_requires_one() {
        let _policy = TestPolicy::write("[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nrequire_derivation_secret = true\n");
        let result = with_no_secret_file(read_derivation_secret);
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
        // Readable by others, or group-writable: rejected rather than used,
        // and rejected rather than treated as absent (which would quietly
        // swap the strong key for the weak one). These are wrong for any
        // owner; group *read* is allowed when root owns the file.
        for mode in [0o604, 0o620] {
            let result = with_secret_file(b"secret", mode, |_| read_derivation_secret());
            assert!(result.is_err(), "mode {mode:o} must be rejected");
        }
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            let result = with_secret_file(b"secret", 0o640, |_| read_derivation_secret());
            assert!(result.is_err(), "a group-readable secret the service owns itself must be rejected");
        }

        // Empty file.
        let result = with_secret_file(b"", 0o600, |_| read_derivation_secret());
        assert!(result.is_err(), "an empty secret file must be rejected");
    }

    #[test]
    #[serial]
    fn a_symlinked_secret_is_rejected() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let dir = crate::secure_file::private_tempdir();
        let target = dir.path().join("real-secret");
        let mut f = std::fs::File::create(&target).unwrap();
        f.write_all(b"secret").unwrap();
        f.flush().unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();

        let link = dir.path().join("link-to-secret");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let result = with_secret_path(&link, read_derivation_secret);
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

    // `doc`, layered over the policy in force, for the duration of `f`.
    fn with_policy<T>(doc: &str, f: impl FnOnce() -> T) -> T {
        let _policy = TestPolicy::write(doc);
        f()
    }

    const SOME_NAME: &str = "000b0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    #[test]
    #[serial]
    fn every_service_is_provisioned_without_the_allowlist() {
        let _no_policy = TestPolicy::absent();
        let no_policy = service_is_provisioned("com.company.anything").unwrap();
        assert!(no_policy, "with no policy, the TPM serves every service (the historical behavior)");

        let off = with_policy("[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n", || {
            service_is_provisioned("com.company.anything").unwrap()
        });
        assert!(off, "require_pinned_names defaults to false");
    }

    #[test]
    #[serial]
    fn only_pinned_services_are_provisioned_under_the_allowlist() {
        let doc = format!(
            "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nrequire_pinned_names = true\n[tpm.pinned_names]\n\"com.company.orders\" = \"{SOME_NAME}\"\n"
        );
        let (pinned, pinned_other_case, unpinned) = with_policy(&doc, || {
            (
                service_is_provisioned("com.company.orders").unwrap(),
                service_is_provisioned(&crate::normalize_service("COM.COMPANY.ORDERS")).unwrap(),
                service_is_provisioned("com.company.billing").unwrap(),
            )
        });
        assert!(pinned);
        assert!(pinned_other_case, "lookup goes through the same normalization as the C ABI");
        assert!(!unpinned, "a service with no pinned Name must not count as provisioned");
    }

    #[test]
    #[serial]
    fn a_broken_policy_is_an_error_not_provisioned() {
        // Fails closed: neither "everything is provisioned" nor a quiet
        // "not provisioned" that could let the chain fall through.
        let result = with_policy("[selection]\nmode = \"require\"\n", || service_is_provisioned("com.company.orders"));
        assert!(result.is_err());
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
            let secret = read_derivation_secret()?;
            let (public, _name) = create_and_read_primary(ctx, service, secret.as_ref())?;
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
            let secret = read_derivation_secret()?;
            let (_public, name) = create_and_read_primary(ctx, service, secret.as_ref())?;
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
    #[serial]
    fn an_untrusted_derivation_secret_refuses_the_tpm_rather_than_skipping_it() {
        // Present (so the chain stops here) but failing every call: a TPM
        // whose secret can't be trusted must not quietly hand the service to
        // a weaker provider further down the chain.
        let (present, err) = with_secret_file(b"secret", 0o604, |_| {
            let provider = Tpm2Provider::new();
            (provider.probe(), provider.load_kek("com.company.orders", false).err())
        });
        assert!(present, "a refused TPM is still present");
        match err {
            Some(Error::Provider(msg)) => assert!(msg.contains("refused"), "unexpected: {msg}"),
            other => panic!("expected a Provider error, got {other:?}"),
        }
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn a_missing_derivation_secret_leaves_the_tpm_absent() {
        // Not set up for use on this host: the chain may move on.
        let present = with_no_secret_file(|| Tpm2Provider::new().probe());
        assert!(!present);
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
    fn rotating_the_secret_mid_handle_does_not_split_public_key_and_ecdh() {
        // A wrap calls `public_key()` (for the fingerprint) and then
        // `ecdh()` (for the wrapping key). If each re-read the secret file,
        // a rotation between them would produce a payload whose
        // fingerprint names one KEK and whose ciphertext is under another
        // -- unopenable forever. The handle must use one snapshot for both.
        let service = "com.company.rotation";
        let peer = crate::crypto::payload_ecdh_point(&[0x42u8; 32]).unwrap();

        let (before, after, z_handle) = with_secret_file(b"secret-before-rotation", 0o600, |path| {
            let provider = Tpm2Provider::new();
            assert!(provider.probe(), "no TPM available");
            let handle = provider.load_kek(service, false).unwrap();
            let before = handle.public_key().unwrap();

            // Rotate the file underneath the live handle.
            std::fs::write(path, b"secret-after-rotation").unwrap();

            let after = handle.public_key().unwrap();
            let z = handle.ecdh(&peer).unwrap();
            (before, after, *z)
        });

        assert_eq!(before, after, "public_key() must not change when the secret file is rotated mid-handle");

        // And ecdh() used that same key, not one derived from the new
        // file: Z computed by the handle must equal the reference value
        // obtained by deriving directly with the pre-rotation secret.
        let pre = with_secret_file(b"secret-before-rotation", 0o600, |_| read_derivation_secret().unwrap().unwrap());
        let z_reference = with_tpm_context(|ctx| {
            let (key, _p, _n) = create_and_verify_primary_with(ctx, service, Some(&pre))?;
            let encoded = encode_peer_point(&peer)?;
            let z = ctx
                .execute_with_nullauth_session(|ctx| ctx.ecdh_z_gen(key, encoded.clone()))
                .map_err(|e| Error::Provider(e.to_string()));
            let _ = ctx.flush_context(key.into());
            let mut out = [0u8; 32];
            out.copy_from_slice(z?.x().value());
            Ok(out)
        })
        .unwrap();
        assert_eq!(z_handle, z_reference, "ecdh() must use the snapshot taken at load_kek, not the rotated file");
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn derivation_secret_self_test_reports_a_verdict_when_a_secret_is_configured() {
        // With no secret there is nothing to verify and nothing to cache.
        let verdict = with_policy(
            "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nrequire_derivation_secret = false\n",
            || with_no_secret_file(|| with_tpm_context(validate_derivation_secret_is_honored)),
        )
        .unwrap();
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
    fn tpm_accepts_hashed_payload_points() {
        // The forgery-resistant protocol derives the wrapping key from
        // ECDH(KEK_priv, H_salt) for a point hashed from the payload
        // salt, whose discrete log nobody knows. If a backend refused to
        // do ECDH against such a caller-supplied point, the entire
        // construction would be unusable there -- so confirm it against
        // a real TPM before building on it, rather than assuming as
        // happened with inSensitive.data.
        //
        // Note what cannot be checked here: the *value* of Z can't be
        // independently recomputed, because that would need the point's
        // discrete log, which is precisely what nobody has. What is
        // checkable is that the TPM accepts the point, and that the
        // result behaves like a real per-KEK, per-salt shared secret.
        let h = crate::crypto::payload_ecdh_point(&[0x42u8; 32]).unwrap();

        let z1 = create_ecdh_secret("com.company.orders", &h).unwrap();
        let z2 = create_ecdh_secret("com.company.orders", &h).unwrap();
        assert_eq!(z1, z2, "ECDH against the same point must be repeatable for the same service");
        assert_ne!(z1, [0u8; 32], "shared secret must not be all zeroes");

        // Each service's KEK must produce its own Z against the same point
        // -- this is what gives each service a distinct wrapping key.
        let z_billing = create_ecdh_secret("com.company.billing", &h).unwrap();
        assert_ne!(z1, z_billing, "different KEKs must yield different Z against the same point");

        // And each salt's point must produce its own Z for the same KEK --
        // this is what makes a captured Z worth one payload, not all.
        let h2 = crate::crypto::payload_ecdh_point(&[0x43u8; 32]).unwrap();
        let z_other_salt = create_ecdh_secret("com.company.orders", &h2).unwrap();
        assert_ne!(z1, z_other_salt, "different salts must yield different Z for the same KEK");
    }

    // ---- session parameter encryption ----

    // ---- TCTI selection: policy, else the default; never the environment ----

    fn tcti_of(result: Result<TctiNameConf>) -> String {
        format!("{:?}", result.expect("a TCTI should resolve"))
    }

    #[test]
    #[serial]
    fn tcti_defaults_to_the_kernel_resource_manager() {
        let _no_policy = TestPolicy::absent();
        assert_eq!(tcti_of(resolve_tcti()), tcti_of(TctiNameConf::from_str(DEFAULT_TCTI).map_err(|e| Error::Provider(e.to_string()))));
    }

    #[test]
    #[serial]
    fn the_policy_tcti_is_used() {
        let doc = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\ntcti = \"swtpm:host=127.0.0.1,port=9999\"\n";
        let shown = tcti_of(with_policy(doc, resolve_tcti));
        assert!(shown.contains("9999"), "policy TCTI must be used, got {shown}");
    }

    #[test]
    #[serial]
    fn the_environment_never_chooses_the_tpm() {
        // Whoever chooses the TPM chooses who knows its seed, so the
        // tpm2-tools variables are ignored in every build -- this test
        // binary included.
        let _no_policy = TestPolicy::absent();
        let saved: Vec<_> = ["TPM2TOOLS_TCTI", "TCTI", "TEST_TCTI"].iter().map(|n| (*n, std::env::var_os(n))).collect();
        for (name, _) in &saved {
            std::env::set_var(name, "swtpm:host=127.0.0.1,port=7777");
        }
        let resolved = resolve_tcti();
        let explicit = tcti_is_explicit();
        for (name, value) in saved {
            match value {
                Some(v) => std::env::set_var(name, v),
                None => std::env::remove_var(name),
            }
        }
        assert!(!tcti_of(resolved).contains("7777"), "an environment TCTI must be ignored");
        assert!(!explicit);
    }

    #[test]
    #[serial]
    fn an_unusable_policy_tcti_makes_the_tpm_unavailable_not_the_default() {
        // Passes the policy's kind check but can't be parsed as a TCTI.
        let doc = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\ntcti = \"mssim:port=notaport\"\n";
        assert!(with_policy(doc, resolve_tcti).is_err(), "a bad policy TCTI must not fall back to the default device");

        // And a broken policy file is an error too, not the default.
        assert!(with_policy("[selection]\nmode = \"require\"\n", resolve_tcti).is_err());
    }

    #[test]
    fn tss2_log_at_debug_or_trace_is_refused_and_lower_levels_are_not() {
        for leaky in [
            "all+debug",
            "all+trace",
            "all+DEBUG",
            "tcti+debug",
            "esys+Trace",
            "all+warning,tcti+debug",
            "esys+info,all+trace",
            "all+debugging", // tpm2-tss matches levels by prefix
        ] {
            assert!(tss2_log_exposes_secrets(leaky), "{leaky:?} must be refused");
        }
        for safe in ["", "all+none", "all+error", "all+warning", "all+info", "esys+info,tcti+warning", "debug", "trace"] {
            assert!(!tss2_log_exposes_secrets(safe), "{safe:?} must be allowed");
        }
    }

    #[test]
    fn manufacturer_classification_skips_only_known_internal_tpms() {
        let id = |s: &[u8; 4]| u32::from_be_bytes(*s);
        // Known fTPM / vTPM vendors: no bus, skip -- whether the short
        // identifier is padded with spaces or with NULs.
        for m in [b"INTC", b"AMD ", b"AMD\0", b"IBM ", b"IBM\0", b"MSFT", b"VMW\0"] {
            assert!(manufacturer_has_no_external_bus(id(m)), "{:?}", String::from_utf8_lossy(m));
        }
        // Discrete vendors: encrypt.
        for m in [b"IFX ", b"IFX\0", b"STM ", b"NTC ", b"ATML"] {
            assert!(!manufacturer_has_no_external_bus(id(m)), "{:?}", String::from_utf8_lossy(m));
        }
        // Unknown: encrypt -- auto only ever skips for a positive match.
        assert!(!manufacturer_has_no_external_bus(id(b"ZZZZ")));
        assert!(!manufacturer_has_no_external_bus(0)); // all-NUL trims to empty, which matches nothing

        // Padding is stripped, and only padding.
        assert_eq!(manufacturer_id_bytes(id(b"IBM\0")), b"IBM");
        assert_eq!(manufacturer_id_bytes(id(b"IBM ")), b"IBM");
        assert_eq!(manufacturer_id_bytes(id(b"INTC")), b"INTC");
        assert_eq!(manufacturer_id_bytes(0), b"");
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn encrypted_session_ecdh_yields_the_same_z_as_a_plain_session() {
        // Correctness: parameter encryption must be transparent -- the
        // TPM computes the same Z, ESAPI decrypts the response, and the
        // caller sees identical bytes. If the salt key template weren't
        // an acceptable `tpmKey`, or the attributes were wrong, this is
        // where it would fail.
        let h = crate::crypto::payload_ecdh_point(&[0x42u8; 32]).unwrap();
        let peer = encode_peer_point(&h).unwrap();

        let (plain, encrypted) = with_tpm_context(|ctx| {
            let (key, _p, _n) = create_and_verify_primary_with(ctx, "com.company.orders", None)?;
            let plain = ctx
                .execute_with_nullauth_session(|ctx| ctx.ecdh_z_gen(key, peer.clone()))
                .map_err(|e| Error::Provider(format!("plain ECDH failed: {e}")));
            let encrypted = ecdh_z_gen_encrypted(ctx, key, &peer);
            let _ = ctx.flush_context(key.into());
            Ok((plain?, encrypted?))
        })
        .unwrap();

        assert_eq!(plain.x().value(), encrypted.x().value(), "Z must be identical through an encrypted session");
        assert_eq!(plain.y().value(), encrypted.y().value());
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn session_salt_key_is_deterministic_and_pinnable() {
        let names = with_tpm_context(|ctx| {
            let mut names = Vec::new();
            for _ in 0..2 {
                let key = create_session_salt_key(ctx)?;
                let (_p, name, _q) = ctx.read_public(key).map_err(|e| Error::Provider(e.to_string()))?;
                let _ = ctx.flush_context(key.into());
                names.push(name.value().to_vec());
            }
            Ok(names)
        })
        .unwrap();
        assert_eq!(names[0], names[1], "the salt key must be stable, or it could never be pinned");

        // Pinned to the real Name under `required`: loads. Pinned to a
        // corrupted Name: refused before any session is started.
        let real = hex(&names[0]);
        let mut wrong = names[0].clone();
        wrong[2] ^= 0xff;
        let policy_for = |name_hex: &str| {
            format!("[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nsession_encryption = \"required\"\npinned_session_salt_key_name = \"{name_hex}\"\n")
        };
        with_policy(&policy_for(&real), || {
            with_tpm_context(|ctx| {
                let key = create_session_salt_key(ctx)?;
                let _ = ctx.flush_context(key.into());
                Ok(())
            })
        })
        .expect("a correctly pinned salt key must load");

        let refused = with_policy(&policy_for(&hex(&wrong)), || {
            with_tpm_context(|ctx| create_session_salt_key(ctx).map(|k| { let _ = ctx.flush_context(k.into()); }))
        });
        assert!(refused.is_err(), "a salt key whose Name doesn't match the pin must be refused");
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn auto_mode_skips_encryption_on_swtpm_unless_pinned_and_required_forces_it() {
        // swtpm reports manufacturer "IBM ", a known no-bus TPM, so `auto`
        // (the default, no policy file) skips encryption; `required` still
        // encrypts. Both paths must still produce a working ECDH.
        let (auto, reported) = with_tpm_context(|ctx| {
            let reported = ctx
                .get_tpm_property(PropertyTag::Manufacturer)
                .map_err(|e| Error::Provider(e.to_string()))?;
            Ok((session_encryption_enabled(ctx)?, reported))
        })
        .unwrap();
        // Report what the TPM actually said, so a classification miss
        // explains itself instead of just failing.
        assert!(
            !auto,
            "auto must skip encryption on swtpm; TPM_PT_MANUFACTURER was {:?} (raw {reported:?})",
            reported.map(|id| String::from_utf8_lossy(&id.to_be_bytes()).into_owned())
        );

        // `required` needs a pin; learn the real salt-key Name first.
        let real = with_tpm_context(|ctx| {
            let key = create_session_salt_key(ctx)?;
            let (_p, name, _q) = ctx.read_public(key).map_err(|e| Error::Provider(e.to_string()))?;
            let _ = ctx.flush_context(key.into());
            Ok(hex(name.value()))
        })
        .unwrap();
        let _policy = TestPolicy::write(&format!(
            "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nsession_encryption = \"required\"\npinned_session_salt_key_name = \"{real}\"\n"
        ));
        let required = with_tpm_context(session_encryption_enabled).unwrap();
        drop(_policy);

        // `auto` with a pinned salt key encrypts too, even on a TPM whose
        // manufacturer it would otherwise skip: the manufacturer is read
        // over the bus, so an interposer could have written it.
        let pinned_auto = {
            let _policy = TestPolicy::write(&format!(
                "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nsession_encryption = \"auto\"\npinned_session_salt_key_name = \"{real}\"\n"
            ));
            with_tpm_context(session_encryption_enabled).unwrap()
        };
        assert!(pinned_auto, "auto with a pinned salt key must encrypt, whatever the manufacturer");

        let _policy = TestPolicy::write(&format!(
            "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nsession_encryption = \"required\"\npinned_session_salt_key_name = \"{real}\"\n"
        ));
        // And the full production path -- load_kek + ecdh -- works under it.
        let h = crate::crypto::payload_ecdh_point(&[0x42u8; 32]).unwrap();
        let z = create_ecdh_secret("com.company.orders", &h);
        assert!(required, "required must encrypt regardless of manufacturer");
        assert_ne!(z.unwrap(), [0u8; 32], "ECDH through the encrypted session must succeed");
    }

    // ---- operator helpers: obtain the Names to pin in policy ----
    //
    // Not assertions. Run with `-- --ignored --exact --nocapture` to print
    // the Name the *real* TPM reports, for `tpm.pinned_session_salt_key_name`
    // and `tpm.pinned_names`. They go through the production derivation,
    // so they honor a configured derivation secret and any pins already in
    // policy -- a pin learned without a derivation secret will not match
    // once one is provisioned. `scripts/native-tpm-test.sh` drives these.

    #[test]
    #[ignore = "operator helper (prints the session salt key Name to pin); requires a TPM2 device"]
    #[serial]
    fn print_session_salt_key_name_for_pinning() {
        let name = with_tpm_context(|ctx| {
            let key = create_session_salt_key(ctx)?;
            let (_public, name, _qualified) = ctx.read_public(key).map_err(|e| Error::Provider(e.to_string()))?;
            let _ = ctx.flush_context(key.into());
            Ok(hex(name.value()))
        })
        .expect("no TPM available, or the salt key failed its checks");
        println!("SALT_KEY_NAME={name}");
    }

    #[test]
    #[ignore = "operator helper (prints a service key's Name to pin); requires a TPM2 device"]
    #[serial]
    fn print_service_key_name_for_pinning() {
        // Which service, via env -- there is no other way to pass a value
        // to a test. Normalized exactly as the C ABI would normalize it.
        let service = std::env::var("HKDFGUARD_PIN_SERVICE").unwrap_or_else(|_| "com.company.orders".to_string());
        let service = crate::normalize_service(&service);
        let (_public, name) = with_tpm_context(|ctx| {
            let secret = read_derivation_secret()?;
            create_and_read_primary(ctx, &service, secret.as_ref())
        })
            .expect("no TPM available, or the service key failed its checks");
        println!("SERVICE={service}");
        println!("SERVICE_KEY_NAME={}", hex(name.value()));
    }

    // A policy pinning `service` to `name_hex`, for the duration of `f`.
    fn with_pinned_name<T>(service: &str, name_hex: &str, f: impl FnOnce() -> T) -> T {
        with_policy(
            &format!("[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm.pinned_names]\n\"{service}\" = \"{name_hex}\"\n"),
            f,
        )
    }

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    #[serial]
    fn require_pinned_names_makes_provisioning_a_real_gate() {
        with_no_secret_file(|| {
            let service = "com.company.allowlisted";
            let allowlist_only = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nrequire_pinned_names = true\nrequire_derivation_secret = false\n";

            // Unpinned: not provisioned, wrap/unwrap decline softly, and
            // "create" is refused with the exact Name to pin.
            let message = with_policy(allowlist_only, || {
                let provider = Tpm2Provider::new();
                assert!(provider.probe(), "no TPM available");
                assert!(!provider.kek_exists(service).unwrap(), "an unpinned service must not exist");
                assert!(
                    matches!(provider.load_kek(service, false), Err(Error::KeyNotProvisioned(_))),
                    "loading an unpinned service must decline"
                );
                match provider.load_kek(service, true) {
                    Err(Error::Provider(msg)) => msg,
                    Err(other) => panic!("expected Provider error with pinning instructions, got {other:?}"),
                    Ok(_) => panic!("creating an unpinned service must be refused"),
                }
            });

            // The Name in the message is the one this TPM actually derives
            // (under the same policy: no derivation secret).
            let actual = with_policy(allowlist_only, || {
                with_tpm_context(|ctx| {
                    let (_public, name) = create_and_read_primary(ctx, service, None)?;
                    Ok(hex(name.value()))
                })
            })
            .unwrap();
            assert!(
                message.contains(&format!("\"{service}\" = \"{actual}\"")),
                "the refusal must carry a paste-ready pin for the real Name; got: {message}"
            );

            // Pinned (as the operator would, from that message): now it exists,
            // loads, and works end to end.
            let pinned = format!("{allowlist_only}[tpm.pinned_names]\n\"{service}\" = \"{actual}\"\n");
            with_policy(&pinned, || {
                let provider = Tpm2Provider::new();
                assert!(provider.kek_exists(service).unwrap(), "a pinned service must exist");
                let handle = provider.load_kek(service, false).unwrap();
                let h = crate::crypto::payload_ecdh_point(&[0x42u8; 32]).unwrap();
                assert_ne!(*handle.ecdh(&h).unwrap(), [0u8; 32]);
                // Other services are still refused.
                assert!(!provider.kek_exists("com.company.notpinned").unwrap());
            });
        });
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
