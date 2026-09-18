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

use crate::error::{Error, Result}; // this crate's error type + `Result` alias
use crate::provider::{KekHandle, KekProvider, ProviderType, SharedSecret}; // traits/types this module implements
use elliptic_curve::sec1::ToEncodedPoint; // encodes our ephemeral public key into the raw bytes the token expects
use p256::PublicKey; // the caller's ephemeral public key type
use sha2::{Digest as ShaDigest, Sha256}; // used for the CKA_ID tag (aliased to avoid clashing with cryptoki's own naming)
use std::sync::{Arc, Mutex}; // shared, lock-protected PKCS#11 session
use zeroize::Zeroizing; // scrubs the shared secret read off the token as soon as it's no longer needed

use cryptoki::context::{CInitializeArgs, Pkcs11}; // loads the PKCS#11 module and initializes the library
use cryptoki::mechanism::elliptic_curve::{EcKdf, Ecdh1DeriveParams}; // parameters for the CKM_ECDH1_DERIVE mechanism
use cryptoki::mechanism::Mechanism; // the mechanism enum (EccKeyPairGen, Ecdh1Derive, ...)
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle}; // PKCS#11 object attributes/handles
use cryptoki::session::{Session, UserType}; // an open session against a slot/token, and the login role
use cryptoki::slot::Slot; // identifies a PKCS#11 slot
use cryptoki::types::AuthPin; // wraps a PIN for login

// Common install locations for SoftHSM2's module, tried in order when no
// explicit path is configured.
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

// Bundles the open session (there's nothing else to track: the module
// context is only needed to open it).
struct OpenSession {
    session: Session,
}

// Holds the shared, lazily-usable PKCS#11 session. `None` in `state` means
// no module/token/PIN was usable at construction time.
pub struct Pkcs11Provider {
    state: Arc<Mutex<Option<OpenSession>>>,
}

impl Pkcs11Provider {
    pub fn new() -> Self {
        Pkcs11Provider {
            state: Arc::new(Mutex::new(open_session())), // try to set everything up once, at construction time
        }
    }
}

impl Default for Pkcs11Provider {
    fn default() -> Self {
        Self::new()
    }
}

// Resolves which module path(s) to try loading, honoring an explicit
// override or falling back to the built-in SoftHSM2 candidate list.
fn candidate_module_paths() -> Vec<String> {
    if let Ok(p) = std::env::var("HKDFGUARD_PKCS11_MODULE") {
        return vec![p]; // explicit override: try only this one path
    }
    DEFAULT_MODULE_PATHS.iter().map(|s| s.to_string()).collect()
}

// Loads the module, initializes the library, picks a slot, opens a
// read/write session, and logs in -- or returns `None` at the first step
// that isn't possible (missing PIN, no module found, no token, bad PIN,
// ...).
fn open_session() -> Option<OpenSession> {
    let pin = std::env::var("HKDFGUARD_PKCS11_PIN").ok()?; // no PIN configured means this provider can't do anything

    let pkcs11 = candidate_module_paths()
        .into_iter()
        .find_map(|path| Pkcs11::new(path).ok())?; // first path that actually loads as a valid PKCS#11 module
    pkcs11.initialize(CInitializeArgs::OsThreads).ok()?; // C_Initialize, telling the module we may call it from multiple OS threads

    let slot: Slot = if let Ok(idx) = std::env::var("HKDFGUARD_PKCS11_SLOT") {
        let idx: usize = idx.parse().ok()?; // explicit slot index requested
        *pkcs11.get_slots_with_token().ok()?.get(idx)? // must exist among the slots that actually have a token present
    } else {
        *pkcs11.get_slots_with_token().ok()?.first()? // otherwise just take the first slot with a token
    };

    let session = pkcs11.open_rw_session(slot).ok()?; // read/write, since we may need to generate keys
    session
        .login(UserType::User, Some(&AuthPin::new(pin))) // C_Login as the normal user role, required before key generation/derivation
        .ok()?;

    Some(OpenSession { session })
}

// Handle type returned from `get_or_create_kek`; holds only the service
// name and a shared reference to the session -- the actual PKCS#11 key
// object is looked up (or created) lazily inside `ecdh`.
struct Pkcs11Handle {
    key_id: Vec<u8>,   // diagnostic-only tag embedded in the wrapped payload
    service: String,   // needed to (re)locate this service's key object by label
    state: Arc<Mutex<Option<OpenSession>>>, // shared handle back to the open PKCS#11 session
}

impl KekHandle for Pkcs11Handle {
    fn key_id(&self) -> &[u8] {
        &self.key_id
    }

    fn ecdh(&self, ephemeral_public_key: &PublicKey) -> Result<SharedSecret> {
        let mut guard = self
            .state
            .lock() // only one caller may drive the session at a time
            .map_err(|_| Error::Provider("PKCS#11 session lock poisoned".into()))?;
        let open = guard
            .as_mut()
            .ok_or(Error::Provider("PKCS#11 session not available".into()))?; // session setup failed at construction time

        let private_key = find_or_generate_key_pair(&open.session, &self.service)?; // load or create this service's persistent key pair
        let peer_point_bytes = ephemeral_public_key.to_encoded_point(false).as_bytes().to_vec(); // raw uncompressed point bytes the token expects as CKM_ECDH1_DERIVE's public data

        let params = Ecdh1DeriveParams::new(EcKdf::null(), &peer_point_bytes); // CKD_NULL: no extra KDF on-token, we do HKDF ourselves afterward
        let derive_template = [
            // attributes for the *temporary* object the derive operation will create
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::Token(false),      // session object only, never written to the token's persistent storage
            Attribute::Sensitive(false),  // must be readable, since we need to read the shared secret back out
            Attribute::Extractable(true), // ditto
            Attribute::ValueLen(32.into()), // we want exactly 32 bytes (the X-coordinate size for P-256)
        ];

        let derived = open
            .session
            .derive_key(
                &Mechanism::Ecdh1Derive(params), // C_DeriveKey with CKM_ECDH1_DERIVE
                private_key,                      // our service's non-extractable persistent private key
                &derive_template,
            )
            .map_err(|e| Error::Provider(format!("CKM_ECDH1_DERIVE failed: {e}")))?;

        let value = read_value(&open.session, derived, 32)?; // read the raw shared-secret bytes out of the temporary object, already Zeroizing-wrapped
        // Best-effort: remove the temporary session object immediately
        // rather than waiting for session close.
        let _ = open.session.destroy_object(derived); // ignore errors here; the session closing later would clean it up anyway

        if value.len() != 32 {
            return Err(Error::Provider(
                "PKCS#11 token returned unexpected shared secret length".into(), // defensive; should always be 32 given ValueLen above
            ));
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&value);
        Ok(SharedSecret::new(secret)) // wrap in the zeroizing alias before returning; `value` (the heap copy) is dropped and scrubbed right after this line
    }
}

impl KekProvider for Pkcs11Provider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Pkcs11
    }

    fn probe(&self) -> bool {
        self.state
            .lock()
            .map(|guard| guard.is_some()) // "available" means the session was successfully opened at construction time
            .unwrap_or(false) // a poisoned lock is treated as "not available" rather than panicking
    }

    fn get_or_create_kek(&self, service: &str) -> Result<Box<dyn KekHandle>> {
        if !self.probe() {
            return Err(Error::Provider("PKCS#11 session not available".into()));
        }
        Ok(Box::new(Pkcs11Handle {
            key_id: format!("hkdfguard:{service}").into_bytes(),
            service: service.to_string(),
            state: Arc::clone(&self.state), // cheap refcount bump, not a clone of the underlying session
        }))
    }
}

// The CKA_LABEL used to identify a service's key pair on the token.
fn key_label(service: &str) -> String {
    format!("hkdfguard:{service}")
}

// Looks up the service's private key object by label; generates a new,
// non-extractable EC key pair on the token if none exists yet.
fn find_or_generate_key_pair(session: &Session, service: &str) -> Result<ObjectHandle> {
    let label = key_label(service);

    let find_template = [
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::EC),
        Attribute::Label(label.clone().into_bytes()),
    ];
    let found = session
        .find_objects(&find_template) // C_FindObjects: search the token for a matching private key
        .map_err(|e| Error::Provider(format!("PKCS#11 find_objects failed: {e}")))?;

    if let Some(handle) = found.into_iter().next() {
        return Ok(handle); // already provisioned for this service: reuse it
    }

    let key_id = Sha256::digest(service.as_bytes()).to_vec(); // non-secret CKA_ID tag, derived from the service name

    let public_template = [
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(KeyType::EC),
        Attribute::Token(true),  // persist on the token, not just this session
        Attribute::Private(false), // the public half doesn't need PKCS#11-level access restriction
        Attribute::Verify(false),  // this key pair is for ECDH, not signing/verification
        Attribute::EcParams(P256_EC_PARAMS.to_vec()), // selects the P-256 curve
        Attribute::Label(label.clone().into_bytes()),
        Attribute::Id(key_id.clone()),
    ];
    let private_template = [
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::EC),
        Attribute::Token(true),        // persist on the token
        Attribute::Private(true),      // requires login to use
        Attribute::Sensitive(true),    // value can never be read out
        Attribute::Extractable(false), // and can never be wrapped/exported either
        Attribute::Derive(true),       // required: we need to use this key with C_DeriveKey (ECDH)
        Attribute::Sign(false),        // must not be usable for signing
        Attribute::Label(label.into_bytes()),
        Attribute::Id(key_id),
    ];

    let (_public, private) = session
        .generate_key_pair(
            &Mechanism::EccKeyPairGen, // C_GenerateKeyPair with the EC key pair generation mechanism
            &public_template,
            &private_template,
        )
        .map_err(|e| Error::Provider(format!("PKCS#11 EC key pair generation failed: {e}")))?;

    Ok(private) // only the private key's handle is needed for subsequent ECDH derives
}

// Reads a single attribute (here, always CKA_VALUE) off a PKCS#11 object
// and returns its raw bytes, validating the expected length. The bytes
// are wrapped in `Zeroizing` immediately -- `get_attributes` necessarily
// returns a heap `Vec<u8>` (the cryptoki crate allocates it to marshal
// the C_GetAttributeValue result), and since it holds live key-derivation
// output (the ECDH shared secret, in this module's only caller), it must
// not be dropped un-scrubbed.
fn read_value(session: &Session, handle: ObjectHandle, expected_len: usize) -> Result<Zeroizing<Vec<u8>>> {
    let attrs = session
        .get_attributes(handle, &[AttributeType::Value]) // C_GetAttributeValue for just CKA_VALUE
        .map_err(|e| Error::Provider(format!("PKCS#11 get_attributes failed: {e}")))?;

    for attr in attrs {
        if let Attribute::Value(bytes) = attr {
            if bytes.len() == expected_len {
                return Ok(Zeroizing::new(bytes)); // found a CKA_VALUE of the expected size
            }
        }
    }
    Err(Error::Provider(
        "PKCS#11 token did not return a CKA_VALUE for derived secret".into(), // shouldn't happen given how `derive_template` was built
    ))
}

#[cfg(test)]
mod tests {
    use super::*; // bring `Pkcs11Provider` etc. into scope

    #[test]
    #[ignore = "requires a configured SoftHSM2 (or other PKCS#11) module + token"] // skipped by default; run explicitly with `-- --ignored`
    fn same_service_reuses_same_key_pair() {
        let provider = Pkcs11Provider::new();
        assert!(provider.probe(), "no PKCS#11 session available");

        let eph = p256::SecretKey::random(&mut rand_core::OsRng); // stand-in "caller" ephemeral key for this test
        let eph_pub = eph.public_key();

        let h1 = provider.get_or_create_kek("com.company.orders").unwrap(); // first call: generates the key pair on the token
        let h2 = provider.get_or_create_kek("com.company.orders").unwrap(); // second call: must find and reuse the same one
        assert_eq!(*h1.ecdh(&eph_pub).unwrap(), *h2.ecdh(&eph_pub).unwrap()); // same underlying key -> same shared secret
    }
}
