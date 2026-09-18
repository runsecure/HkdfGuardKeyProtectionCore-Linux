//! Provider 2: PKCS#11 (used when TPM2 is unavailable).
//!
//! ```text
//!  ______________________________________________________________________
//! | HARDWARE/MODULE-DEPENDENT CODE                                        |
//! |                                                                        |
//! | Verified (see docker/): natively built against real `cryptoki` 0.6.2  |
//! | on Debian bookworm/aarch64, and the `#[ignore]`d test below passed    |
//! | against a real SoftHSM2 token -- C_GenerateKeyPair + CKM_ECDH1_DERIVE |
//! | executed for real and produced the same key deterministically across |
//! | two calls. Not yet exercised against a hardware HSM/YubiHSM; re-run  |
//! | `docker/run-tests.sh` after any change here, and re-test against     |
//! | your production module/HSM before relying on this with it.           |
//! |______________________________________________________________________|
//! ```
//!
//! ## Configuration
//!
//! - `HKDFGUARD_PKCS11_MODULE`: path to the PKCS#11 module `.so`. If unset,
//!   a small list of common SoftHSM2 install paths is tried.
//! - `HKDFGUARD_PKCS11_SLOT`: slot index to use (default: first slot with a
//!   token present).
//! - `HKDFGUARD_PKCS11_PIN`: user PIN used to log in for key
//!   generation/derivation.
//!
//! ## Design
//!
//! For each service, finds (or generates, if absent) a **non-extractable**
//! token-persistent EC P-256 key pair labelled `hkdfguard:<service>`
//! (`CKA_TOKEN=true`, `CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=false`,
//! `CKA_DERIVE=true`). ECDH is performed on-token via `CKM_ECDH1_DERIVE`
//! (`CKD_NULL` -- no token-side KDF; this crate does its own HKDF-SHA256
//! outside, per the shared protocol), which derives a session-local,
//! extractable generic-secret object holding the raw shared X-coordinate.
//! That value is read out, the temporary derived object is destroyed
//! immediately, and the raw bytes are wrapped in a zeroizing buffer before
//! returning -- the *persistent* private key never leaves the token.

use crate::error::{Error, Result};
use crate::provider::{KekHandle, KekProvider, ProviderType, SharedSecret};
use elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;
use sha2::{Digest as ShaDigest, Sha256};
use std::sync::{Arc, Mutex};

use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::elliptic_curve::{EcKdf, Ecdh1DeriveParams};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

const DEFAULT_MODULE_PATHS: &[&str] = &[
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib64/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
];

// DER encoding of the secp256r1 (P-256 / prime256v1) OID, as required for
// CKA_EC_PARAMS.
const P256_EC_PARAMS: &[u8] = &[
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
];

struct OpenSession {
    session: Session,
}

pub struct Pkcs11Provider {
    state: Arc<Mutex<Option<OpenSession>>>,
}

impl Pkcs11Provider {
    pub fn new() -> Self {
        Pkcs11Provider {
            state: Arc::new(Mutex::new(open_session())),
        }
    }
}

impl Default for Pkcs11Provider {
    fn default() -> Self {
        Self::new()
    }
}

fn candidate_module_paths() -> Vec<String> {
    if let Ok(p) = std::env::var("HKDFGUARD_PKCS11_MODULE") {
        return vec![p];
    }
    DEFAULT_MODULE_PATHS.iter().map(|s| s.to_string()).collect()
}

fn open_session() -> Option<OpenSession> {
    let pin = std::env::var("HKDFGUARD_PKCS11_PIN").ok()?;

    let pkcs11 = candidate_module_paths()
        .into_iter()
        .find_map(|path| Pkcs11::new(path).ok())?;
    pkcs11.initialize(CInitializeArgs::OsThreads).ok()?;

    let slot: Slot = if let Ok(idx) = std::env::var("HKDFGUARD_PKCS11_SLOT") {
        let idx: usize = idx.parse().ok()?;
        *pkcs11.get_slots_with_token().ok()?.get(idx)?
    } else {
        *pkcs11.get_slots_with_token().ok()?.first()?
    };

    let session = pkcs11.open_rw_session(slot).ok()?;
    session
        .login(UserType::User, Some(&AuthPin::new(pin)))
        .ok()?;

    Some(OpenSession { session })
}

struct Pkcs11Handle {
    key_id: Vec<u8>,
    service: String,
    state: Arc<Mutex<Option<OpenSession>>>,
}

impl KekHandle for Pkcs11Handle {
    fn key_id(&self) -> &[u8] {
        &self.key_id
    }

    fn ecdh(&self, ephemeral_public_key: &PublicKey) -> Result<SharedSecret> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| Error::Provider("PKCS#11 session lock poisoned".into()))?;
        let open = guard
            .as_mut()
            .ok_or(Error::Provider("PKCS#11 session not available".into()))?;

        let private_key = find_or_generate_key_pair(&open.session, &self.service)?;
        let peer_point_bytes = ephemeral_public_key.to_encoded_point(false).as_bytes().to_vec();

        let params = Ecdh1DeriveParams::new(EcKdf::null(), &peer_point_bytes);
        let derive_template = [
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::Token(false),
            Attribute::Sensitive(false),
            Attribute::Extractable(true),
            Attribute::ValueLen(32.into()),
        ];

        let derived = open
            .session
            .derive_key(
                &Mechanism::Ecdh1Derive(params),
                private_key,
                &derive_template,
            )
            .map_err(|e| Error::Provider(format!("CKM_ECDH1_DERIVE failed: {e}")))?;

        let value = read_value(&open.session, derived, 32)?;
        // Best-effort: remove the temporary session object immediately
        // rather than waiting for session close.
        let _ = open.session.destroy_object(derived);

        if value.len() != 32 {
            return Err(Error::Provider(
                "PKCS#11 token returned unexpected shared secret length".into(),
            ));
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&value);
        Ok(SharedSecret::new(secret))
    }
}

impl KekProvider for Pkcs11Provider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Pkcs11
    }

    fn probe(&self) -> bool {
        self.state
            .lock()
            .map(|guard| guard.is_some())
            .unwrap_or(false)
    }

    fn get_or_create_kek(&self, service: &str) -> Result<Box<dyn KekHandle>> {
        if !self.probe() {
            return Err(Error::Provider("PKCS#11 session not available".into()));
        }
        Ok(Box::new(Pkcs11Handle {
            key_id: format!("hkdfguard:{service}").into_bytes(),
            service: service.to_string(),
            state: Arc::clone(&self.state),
        }))
    }
}

fn key_label(service: &str) -> String {
    format!("hkdfguard:{service}")
}

fn find_or_generate_key_pair(session: &Session, service: &str) -> Result<ObjectHandle> {
    let label = key_label(service);

    let find_template = [
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::EC),
        Attribute::Label(label.clone().into_bytes()),
    ];
    let found = session
        .find_objects(&find_template)
        .map_err(|e| Error::Provider(format!("PKCS#11 find_objects failed: {e}")))?;

    if let Some(handle) = found.into_iter().next() {
        return Ok(handle);
    }

    let key_id = Sha256::digest(service.as_bytes()).to_vec();

    let public_template = [
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(KeyType::EC),
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Verify(false),
        Attribute::EcParams(P256_EC_PARAMS.to_vec()),
        Attribute::Label(label.clone().into_bytes()),
        Attribute::Id(key_id.clone()),
    ];
    let private_template = [
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::EC),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Derive(true),
        Attribute::Sign(false),
        Attribute::Label(label.into_bytes()),
        Attribute::Id(key_id),
    ];

    let (_public, private) = session
        .generate_key_pair(
            &Mechanism::EccKeyPairGen,
            &public_template,
            &private_template,
        )
        .map_err(|e| Error::Provider(format!("PKCS#11 EC key pair generation failed: {e}")))?;

    Ok(private)
}

fn read_value(session: &Session, handle: ObjectHandle, expected_len: usize) -> Result<Vec<u8>> {
    let attrs = session
        .get_attributes(handle, &[AttributeType::Value])
        .map_err(|e| Error::Provider(format!("PKCS#11 get_attributes failed: {e}")))?;

    for attr in attrs {
        if let Attribute::Value(bytes) = attr {
            if bytes.len() == expected_len {
                return Ok(bytes);
            }
        }
    }
    Err(Error::Provider(
        "PKCS#11 token did not return a CKA_VALUE for derived secret".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires a configured SoftHSM2 (or other PKCS#11) module + token"]
    fn same_service_reuses_same_key_pair() {
        let provider = Pkcs11Provider::new();
        assert!(provider.probe(), "no PKCS#11 session available");

        let eph = p256::SecretKey::random(&mut rand_core::OsRng);
        let eph_pub = eph.public_key();

        let h1 = provider.get_or_create_kek("com.company.orders").unwrap();
        let h2 = provider.get_or_create_kek("com.company.orders").unwrap();
        assert_eq!(*h1.ecdh(&eph_pub).unwrap(), *h2.ecdh(&eph_pub).unwrap());
    }
}
