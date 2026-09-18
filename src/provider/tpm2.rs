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

use crate::error::{Error, Result};
use crate::provider::{KekHandle, KekProvider, ProviderType, SharedSecret};
use elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;
use sha2::{Digest as ShaDigest, Sha256};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::{
    EccParameter, EccPoint, EccScheme, KeyDerivationFunctionScheme, Public, PublicBuilder,
    PublicEccParametersBuilder,
};
use tss_esapi::{Context, TctiNameConf};

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
            context: Arc::new(Mutex::new(open_context())),
        }
    }
}

impl Default for Tpm2Provider {
    fn default() -> Self {
        Self::new()
    }
}

fn open_context() -> Option<Context> {
    let tcti = TctiNameConf::from_environment_variable()
        .or_else(|_| TctiNameConf::from_str("device:/dev/tpmrm0"))
        .ok()?;
    Context::new(tcti).ok()
}

struct Tpm2Handle {
    key_id: Vec<u8>,
    service: String,
    context: Arc<Mutex<Option<Context>>>,
}

impl KekHandle for Tpm2Handle {
    fn key_id(&self) -> &[u8] {
        &self.key_id
    }

    fn ecdh(&self, ephemeral_public_key: &PublicKey) -> Result<SharedSecret> {
        let mut guard = self
            .context
            .lock()
            .map_err(|_| Error::Provider("TPM context lock poisoned".into()))?;
        let ctx = guard
            .as_mut()
            .ok_or(Error::Provider("TPM context not available".into()))?;

        let template = service_public_template(&self.service)?;
        let peer_point = encode_peer_point(ephemeral_public_key)?;

        let key_handle: KeyHandle = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(Hierarchy::Owner, template.clone(), None, None, None, None)
            })
            .map_err(|e| Error::Provider(format!("TPM2_CreatePrimary failed: {e}")))?
            .key_handle;

        let z_result = ctx
            .execute_with_nullauth_session(|ctx| ctx.ecdh_z_gen(key_handle, peer_point.clone()));

        // Always flush the transient primary, even on ECDH failure, so we
        // never leak TPM transient-object slots.
        let _ = ctx.flush_context(key_handle.into());

        let z = z_result.map_err(|e| Error::Provider(format!("TPM2_ECDH_ZGen failed: {e}")))?;

        let mut secret = [0u8; 32];
        let x_bytes = z.x().value();
        if x_bytes.len() != 32 {
            return Err(Error::Provider(
                "TPM returned unexpected ECDH shared point size".into(),
            ));
        }
        secret.copy_from_slice(x_bytes);
        Ok(SharedSecret::new(secret))
    }
}

impl KekProvider for Tpm2Provider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Tpm2
    }

    fn probe(&self) -> bool {
        self.context
            .lock()
            .map(|guard| guard.is_some())
            .unwrap_or(false)
    }

    fn get_or_create_kek(&self, service: &str) -> Result<Box<dyn KekHandle>> {
        if !self.probe() {
            return Err(Error::Provider("TPM context not available".into()));
        }
        // The actual TPM2_CreatePrimary + TPM2_ECDH_ZGen round trip is
        // deferred to `KekHandle::ecdh`, once the caller's ephemeral
        // public key is available -- see the module-level design note for
        // why CreatePrimary-on-demand stands in for "load or create
        // persistent KEK".
        Ok(Box::new(Tpm2Handle {
            key_id: service_fingerprint(service),
            service: service.to_string(),
            context: Arc::clone(&self.context),
        }))
    }
}

fn service_fingerprint(service: &str) -> Vec<u8> {
    Sha256::digest(service.as_bytes()).to_vec()
}

/// Builds the per-service ECC P-256 public template used with
/// `TPM2_CreatePrimary`: an unrestricted decryption key (required for
/// `TPM2_ECDH_ZGen`), non-signing, fixed to this TPM and this parent
/// (i.e. not duplicable/exportable), with `unique` set to a deterministic,
/// non-secret per-service label so each service reproducibly derives a
/// distinct key from the TPM's primary seed.
fn service_public_template(service: &str) -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .with_restricted(false)
        .build()
        .map_err(|e| Error::Provider(format!("failed to build TPM object attributes: {e}")))?;

    let ecc_params = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::Null)
        .with_curve(EccCurve::NistP256)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .with_is_decryption_key(true)
        .with_is_signing_key(false)
        .with_restricted(false)
        .build()
        .map_err(|e| Error::Provider(format!("failed to build TPM ECC parameters: {e}")))?;

    let unique = service_unique_point(service)?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(unique)
        .build()
        .map_err(|e| Error::Provider(format!("failed to build TPM public template: {e}")))
}

fn service_unique_point(service: &str) -> Result<EccPoint> {
    let x = Sha256::digest([b"hkdfguard-tpm2-unique-x:".as_slice(), service.as_bytes()].concat());
    let y = Sha256::digest([b"hkdfguard-tpm2-unique-y:".as_slice(), service.as_bytes()].concat());

    let x_param = EccParameter::try_from(x.to_vec())
        .map_err(|e| Error::Provider(format!("failed to build TPM unique.x: {e}")))?;
    let y_param = EccParameter::try_from(y.to_vec())
        .map_err(|e| Error::Provider(format!("failed to build TPM unique.y: {e}")))?;

    Ok(EccPoint::new(x_param, y_param))
}

fn encode_peer_point(peer_public: &PublicKey) -> Result<EccPoint> {
    let encoded = peer_public.to_encoded_point(false);
    let x = encoded
        .x()
        .ok_or(Error::Provider("ephemeral public key missing X".into()))?;
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
    use super::*;

    #[test]
    #[ignore = "requires a real or simulated (swtpm) TPM2 device"]
    fn same_service_produces_same_key_deterministically() {
        let provider = Tpm2Provider::new();
        assert!(provider.probe(), "no TPM available");

        let eph = p256::SecretKey::random(&mut rand_core::OsRng);
        let eph_pub = eph.public_key();

        let h1 = provider.get_or_create_kek("com.company.orders").unwrap();
        let h2 = provider.get_or_create_kek("com.company.orders").unwrap();
        assert_eq!(*h1.ecdh(&eph_pub).unwrap(), *h2.ecdh(&eph_pub).unwrap());
    }
}
