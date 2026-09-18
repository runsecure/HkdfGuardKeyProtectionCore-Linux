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

use crate::error::{Error, Result};
use crate::provider::{KekHandle, KekProvider, ProviderType, SharedSecret};
use p256::{PublicKey, SecretKey};
use rand_core::OsRng;
use std::collections::HashMap;
use std::sync::Mutex;

pub struct EphemeralProvider {
    keys: Mutex<HashMap<String, SecretKey>>,
}

impl EphemeralProvider {
    pub fn new() -> Self {
        EphemeralProvider {
            keys: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for EphemeralProvider {
    fn default() -> Self {
        Self::new()
    }
}

struct EphemeralHandle {
    key_id: Vec<u8>,
    secret_key: SecretKey,
}

impl KekHandle for EphemeralHandle {
    fn key_id(&self) -> &[u8] {
        &self.key_id
    }

    fn ecdh(&self, ephemeral_public_key: &PublicKey) -> Result<SharedSecret> {
        let shared = p256::ecdh::diffie_hellman(
            self.secret_key.to_nonzero_scalar(),
            ephemeral_public_key.as_affine(),
        );
        let mut out = [0u8; 32];
        out.copy_from_slice(shared.raw_secret_bytes().as_slice());
        Ok(SharedSecret::new(out))
    }
}

impl KekProvider for EphemeralProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Ephemeral
    }

    fn probe(&self) -> bool {
        // Always available: this is the final, guaranteed fallback.
        true
    }

    fn get_or_create_kek(&self, service: &str) -> Result<Box<dyn KekHandle>> {
        let mut keys = self
            .keys
            .lock()
            .map_err(|_| Error::Provider("ephemeral key map lock poisoned".into()))?;

        let secret_key = keys
            .entry(service.to_string())
            .or_insert_with(|| SecretKey::random(&mut OsRng))
            .clone();

        // key_id is a stable-per-process, non-secret tag derived from the
        // service name only for human-readable diagnostics; it carries no
        // key material and is not used for lookup (the service string is).
        let key_id = format!("ephemeral:{service}").into_bytes();

        Ok(Box::new(EphemeralHandle {
            key_id,
            secret_key,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_service_returns_same_key_within_process() {
        let provider = EphemeralProvider::new();
        let h1 = provider.get_or_create_kek("com.company.orders").unwrap();
        let h2 = provider.get_or_create_kek("com.company.orders").unwrap();

        let eph = SecretKey::random(&mut OsRng);
        let eph_pub = eph.public_key();

        let s1 = h1.ecdh(&eph_pub).unwrap();
        let s2 = h2.ecdh(&eph_pub).unwrap();
        assert_eq!(*s1, *s2);
    }

    #[test]
    fn different_services_have_different_keys() {
        let provider = EphemeralProvider::new();
        let h1 = provider.get_or_create_kek("com.company.orders").unwrap();
        let h2 = provider.get_or_create_kek("com.company.billing").unwrap();

        let eph = SecretKey::random(&mut OsRng);
        let eph_pub = eph.public_key();

        let s1 = h1.ecdh(&eph_pub).unwrap();
        let s2 = h2.ecdh(&eph_pub).unwrap();
        assert_ne!(*s1, *s2);
    }
}
