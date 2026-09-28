//! Provider 5: Ephemeral Memory-Only KEK (final fallback).
//!
//! Generates a fresh, cryptographically random P-256 KEK per service the
//! first time it is requested, keeps it in memory for the lifetime of the
//! process, and never persists it. Always available, so it is guaranteed to
//! terminate the selection chain.
//!
//! Consequence (mandated by spec, logged loudly at selection time in
//! `provider::select`): a process restart makes every DEK wrapped under an
//! ephemeral KEK permanently unrecoverable.

use crate::error::{Error, Result}; // this crate's error type + `Result` alias
use crate::provider::{KekHandle, KekProvider, ProviderType, SharedSecret}; // the traits/types this module implements
use p256::{PublicKey, SecretKey}; // P-256 key types from RustCrypto's `p256` crate
use rand_core::OsRng; // OS-backed cryptographically secure RNG, used to generate new keys
use std::collections::HashMap; // in-memory service -> key table
use std::sync::{Arc, Mutex, OnceLock}; // guards the table so concurrent calls don't race

static PROCESS_KEYS: OnceLock<Arc<Mutex<HashMap<String, SecretKey>>>> = OnceLock::new();

// Holds one P-256 private key per service name, entirely in process
// memory. Nothing here is ever written to disk.
pub struct EphemeralProvider {
    keys: Arc<Mutex<HashMap<String, SecretKey>>>, // service name -> that service's persistent-for-this-process KEK
}

impl EphemeralProvider {
    pub fn new() -> Self {
        let keys = PROCESS_KEYS
            .get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
            .clone();
        EphemeralProvider { keys }
    }
}

impl Default for EphemeralProvider {
    fn default() -> Self {
        Self::new() // `Default` just delegates to the same constructor
    }
}

// The handle type this provider hands back from `load_kek`; holds a clone
// of the in-memory secret key long enough to perform one ECDH.
struct EphemeralHandle {
    key_id: Vec<u8>,       // diagnostic-only tag, embedded in the wrapped payload
    secret_key: SecretKey, // the actual private key material for this service
}

impl KekHandle for EphemeralHandle {
    fn key_id(&self) -> &[u8] {
        &self.key_id // just hand back the borrowed bytes
    }

    fn ecdh(&self, ephemeral_public_key: &PublicKey) -> Result<SharedSecret> {
        // Standard P-256 ECDH: combine our private scalar with the caller's
        // ephemeral public point to get the shared secret.
        let shared = p256::ecdh::diffie_hellman(
            self.secret_key.to_nonzero_scalar(), // our persistent (for this process) private scalar
            ephemeral_public_key.as_affine(),     // the caller's one-time public point
        );
        let mut out = [0u8; 32]; // fixed-size buffer to hold the 32-byte shared secret
        out.copy_from_slice(shared.raw_secret_bytes().as_slice()); // copy the shared X-coordinate bytes in
        Ok(SharedSecret::new(out)) // wrap in the zeroizing `SharedSecret` alias before returning
    }

    fn public_key(&self) -> Result<PublicKey> {
        Ok(self.secret_key.public_key()) // trivial: the public half is always derivable from the private key we already hold
    }
}

impl KekProvider for EphemeralProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Ephemeral // tags every payload wrapped by this provider with `5`
    }

    fn probe(&self) -> bool {
        // Always available: this is the final, guaranteed fallback.
        true
    }

    fn kek_exists(&self, service: &str) -> Result<bool> {
        let keys = self
            .keys
            .lock()
            .map_err(|_| Error::Provider("ephemeral key map lock poisoned".into()))?;
        Ok(keys.contains_key(service))
    }

    fn load_kek(&self, service: &str, create_if_missing: bool) -> Result<Box<dyn KekHandle>> {
        let mut keys = self
            .keys
            .lock() // acquire the mutex; blocks if another call is using the map right now
            .map_err(|_| Error::Provider("ephemeral key map lock poisoned".into()))?; // a prior panic while holding the lock would poison it

        let secret_key = if let Some(existing) = keys.get(service) {
            existing.clone()
        } else {
            if !create_if_missing {
                return Err(Error::KeyNotProvisioned(
                    "no ephemeral KEK created yet for this service",
                ));
            }
            let fresh = SecretKey::random(&mut OsRng); // generate a brand-new random key only since none exists yet
            keys.insert(service.to_string(), fresh.clone());
            fresh
        }; // lock released once this block ends, before returning

        // key_id is a stable-per-process, non-secret tag derived from the
        // service name only for human-readable diagnostics; it carries no
        // key material and is not used for lookup (the service string is).
        let key_id = format!("ephemeral:{service}").into_bytes();

        Ok(Box::new(EphemeralHandle {
            key_id,
            secret_key,
        })) // box it up as the trait-object handle the caller expects
    }
}

#[cfg(test)]
mod tests {
    use super::*; // bring `EphemeralProvider`, `SecretKey`, etc. into scope
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn probe_and_provider_type() {
        let provider = EphemeralProvider::new();
        assert!(provider.probe());
        assert_eq!(provider.provider_type(), ProviderType::Ephemeral);

        let default_provider = EphemeralProvider::default();
        assert!(default_provider.probe());
    }

    #[test]
    fn kek_exists_is_false_until_created_then_true_and_load_kek_declines_without_create() {
        let provider = EphemeralProvider::new();
        // A service name unique to this test, since PROCESS_KEYS is shared
        // process-wide across every EphemeralProvider instance/test.
        let service = "com.company.kek-exists-test";

        assert!(!provider.kek_exists(service).unwrap());
        match provider.load_kek(service, false) {
            Err(Error::KeyNotProvisioned(_)) => {}
            Err(other) => panic!("expected KeyNotProvisioned, got {other:?}"),
            Ok(_) => panic!("expected KeyNotProvisioned, got Ok"),
        }

        provider.load_kek(service, true).unwrap(); // now actually create it

        assert!(provider.kek_exists(service).unwrap());
        provider.load_kek(service, false).unwrap(); // now loads fine without creating
    }

    #[test]
    fn public_key_matches_the_key_used_for_ecdh() {
        let provider = EphemeralProvider::new();
        let handle = provider.load_kek("com.company.pubkey-test", true).unwrap();
        let reported_public = handle.public_key().unwrap();

        let eph = SecretKey::random(&mut OsRng);
        let eph_pub = eph.public_key();

        let via_handle = handle.ecdh(&eph_pub).unwrap();
        let via_reported = p256::ecdh::diffie_hellman(eph.to_nonzero_scalar(), reported_public.as_affine());

        assert_eq!(via_handle.as_slice(), via_reported.raw_secret_bytes().as_slice());
    }

    #[test]
    fn key_id_format() {
        let provider = EphemeralProvider::new();
        let handle = provider.load_kek("com.company.orders", true).unwrap();
        assert_eq!(handle.key_id(), b"ephemeral:com.company.orders");
    }

    #[test]
    fn same_service_returns_same_key_within_process() {
        let provider = EphemeralProvider::new();
        let h1 = provider.load_kek("com.company.orders", true).unwrap(); // first call creates the key
        let h2 = provider.load_kek("com.company.orders", true).unwrap(); // second call must reuse it

        let eph = SecretKey::random(&mut OsRng); // a throwaway "caller" ephemeral key for this test
        let eph_pub = eph.public_key();

        let s1 = h1.ecdh(&eph_pub).unwrap();
        let s2 = h2.ecdh(&eph_pub).unwrap();
        assert_eq!(*s1, *s2); // same underlying key -> same shared secret against the same peer point
    }

    #[test]
    fn different_services_have_different_keys() {
        let provider = EphemeralProvider::new();
        let h1 = provider.load_kek("com.company.orders", true).unwrap();
        let h2 = provider.load_kek("com.company.billing", true).unwrap(); // a different service name

        let eph = SecretKey::random(&mut OsRng);
        let eph_pub = eph.public_key();

        let s1 = h1.ecdh(&eph_pub).unwrap();
        let s2 = h2.ecdh(&eph_pub).unwrap();
        assert_ne!(*s1, *s2); // different services must never share a KEK, so the secrets must differ
    }

    #[test]
    fn concurrent_access_is_thread_safe() {
        let provider = Arc::new(EphemeralProvider::new());
        let mut handles = Vec::new();

        for i in 0..8 {
            let p = Arc::clone(&provider);
            handles.push(thread::spawn(move || {
                let service = if i % 2 == 0 { "service.a" } else { "service.b" };
                let h = p.load_kek(service, true).unwrap();
                let eph = SecretKey::random(&mut OsRng);
                h.ecdh(&eph.public_key()).unwrap()
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // Verify that keys for service.a and service.b are stable
        let ha = provider.load_kek("service.a", true).unwrap();
        let hb = provider.load_kek("service.b", true).unwrap();
        let eph = SecretKey::random(&mut OsRng);
        assert_ne!(
            *ha.ecdh(&eph.public_key()).unwrap(),
            *hb.ecdh(&eph.public_key()).unwrap()
        );
    }
}
