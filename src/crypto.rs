//! The provider-agnostic wrap/unwrap protocol:
//! `ECDH(P-256, fixed point) -> HKDF-SHA512 -> AES-256-GCM`.
//!
//! Every provider (TPM2, PKCS#11, external secret, ephemeral) implements
//! the same [`crate::provider::KekHandle::ecdh`] contract, so
//! this module is the *only* place the actual wrap/unwrap algorithm is
//! implemented -- providers never see plaintext DEKs or derived keys.
//!
//! ## Why a fixed point rather than an ephemeral key
//!
//! The wrapping key comes from `ECDH(KEK_priv, H)`, where `H` is a fixed
//! P-256 point with no known discrete log (see
//! [`STATIC_ECDH_POINT_COMPRESSED`]). Computing it requires the KEK's
//! private key, which never leaves the TPM/HSM/secret file.
//!
//! This replaced an ECIES-style construction that used a fresh ephemeral
//! keypair per wrap. That version was forgeable: the KEK's *public* key
//! is not secret (on a TPM, anyone who can reach the device can
//! recompute it), and `ECDH(eph_priv, KEK_pub)` equals
//! `ECDH(KEK_priv, eph_pub)` -- so anyone holding the public key could
//! derive the wrapping key and mint a payload that unwrapped to a DEK of
//! their choosing. Binding more context into the AAD or KDF does not fix
//! that, because the forger controls those inputs too. The ephemeral key
//! also provided no forward secrecy here, since its public half was
//! stored in the payload.
//!
//! Only this host can now create a payload, and only this host can open
//! one -- which is exactly the deployment model: DEKs arrive from a build
//! server and are wrapped locally, and a wrapped payload is never meant
//! to be produced or read anywhere else.
//!
//! ## What is bound
//!
//! Per-payload key separation comes from a random 32-byte HKDF salt in
//! the payload header. This is load-bearing: the ECDH secret is constant
//! for a given service, so without the salt every payload for a service
//! would share one AES-GCM key.
//!
//! Both the derived key and the AEAD are bound to
//! [`crate::payload::Payload::authenticated_bytes`] -- every byte of the
//! payload except the ciphertext -- plus the length-framed service name.
//! That authenticates the `provider_type` tag (so a payload cannot be
//! replayed as another provider's) and the KEK fingerprint (so the key
//! commits to the KEK's identity, rather than it only being checked).
//!
//! [`unwrap`] additionally checks the wrapped payload's embedded KEK
//! fingerprint (see [`kek_fingerprint`]) against the public key of the KEK
//! `service` currently resolves to, *before* attempting ECDH/AES-GCM --
//! see [`crate::error::Error::FingerprintMismatch`].
//!
//! Memory note: the DEK plaintext is kept in stack-allocated `[u8; DEK_LEN]`
//! buffers for the *entire* wrap/unwrap operation -- we deliberately use
//! `AeadInPlace::{encrypt,decrypt}_in_place_detached` instead of the more
//! convenient `Aead::{encrypt,decrypt}`, because the latter allocates a
//! heap `Vec<u8>` internally and, on the decrypt side, that `Vec` would
//! momentarily hold the *decrypted plaintext DEK* on the heap before we
//! could wrap it in `Zeroizing`. The in-place/detached API never touches
//! `alloc` at all for the DEK itself.

use crate::error::{Error, Result}; // this crate's error type + `Result` alias
use crate::payload::{Payload, FINGERPRINT_LEN, NONCE_LEN, SALT_LEN}; // wire-format struct + its fixed field sizes
use crate::provider; // provider selection functions (`select_existing`, `get_by_type`)
use aes_gcm::{AeadInPlace, Aes256Gcm, Key, KeyInit, Nonce, Tag}; // in-place AEAD trait, concrete cipher, and its key/nonce/tag types (all fixed-size, stack-resident)
use elliptic_curve::sec1::ToEncodedPoint; // lets us serialize the ephemeral public key to SEC1 bytes
use hkdf::Hkdf; // HKDF-SHA512 key derivation
use p256::PublicKey; // P-256 public key type
use rand_core::{OsRng, RngCore}; // OS RNG + the trait providing `fill_bytes`
use sha2::{Digest, Sha256, Sha512}; // `Sha256` for the KEK fingerprint, `Sha512` for HKDF, `Digest` for `Sha256::digest`
use zeroize::{Zeroize, Zeroizing}; // `Zeroize` for explicit scrubbing of stack arrays, `Zeroizing` for auto-scrubbing owned buffers

const HKDF_INFO_PREFIX: &[u8] = b"hkdfguard-wrap-v1:"; // domain-separation prefix; concatenated with the service name as HKDF's "info"
const TAG_LEN: usize = 16; // AES-GCM's standard 128-bit authentication tag size
#[cfg(test)]
const UNCOMPRESSED_POINT_LEN: usize = 65; // SEC1 uncompressed P-256 point: 1 tag byte (0x04) + 32-byte X + 32-byte Y

// ---------------------------------------------------------------------
// The fixed static-ECDH point `H`.
// ---------------------------------------------------------------------
//
// The wrapping key is derived from `Z = ECDH(KEK_priv, H)` where `H` is a
// fixed P-256 point whose discrete logarithm nobody knows. That single
// property is what makes a wrapped payload unforgeable: computing `Z`
// requires either the KEK's private key (which never leaves the
// TPM/HSM/secret file) or `H`'s discrete log (which nobody has). Knowing
// the KEK's *public* key -- which is not secret, and on a TPM is
// recomputable by anyone who can reach the device -- is not enough.
//
// This is deliberately *not* an ECIES construction. An ephemeral-key
// ECIES lets anyone holding the KEK public key derive the same shared
// secret the provider would (`ECDH(eph_priv, KEK_pub)` equals
// `ECDH(KEK_priv, eph_pub)`), and therefore mint a payload that unwraps
// to a DEK of their choosing. Binding more context into the AAD or the
// KDF does not help, because the forger controls those inputs too. The
// ephemeral key also bought no forward secrecy here: its public half was
// stored in the payload, so anyone who ever obtained `KEK_priv` could
// recompute the shared secret for every payload ever written.
//
// Per-payload key separation comes from a random HKDF salt carried in the
// payload header instead. That matters more than it did with an ephemeral
// key: `Z` is now constant for a given service, so the salt is what makes
// the AES-GCM key unique per payload and nonce reuse structurally
// impossible.
//
// `H` is generated by try-and-increment from a fixed seed string so that
// anyone can rederive and audit it -- see `derive_static_ecdh_point`,
// which the test suite runs against the constant below on every build.
// A hash output has no known discrete log, which is the whole
// "nothing up my sleeve" argument. P-256 has cofactor 1, so any point
// that decompresses successfully is in the prime-order group; there is no
// small-subgroup concern.

/// Seed string from which [`STATIC_ECDH_POINT_COMPRESSED`] is derived.
/// Changing this changes every wrapping key, on every platform.
#[cfg(test)] // production reads the hardcoded point; only the derivation check needs the seed
const STATIC_POINT_SEED: &[u8] = b"HkdfGuard-P256-static-ECDH-point-v1";

/// The fixed point `H`, as a compressed SEC1 encoding (`0x02 || X`).
///
/// Must be byte-identical across the Linux, macOS, and Windows
/// implementations of this protocol -- it is part of the wire format in
/// the same way the KDF labels are.
/// Derived with counter 8 (see [`derive_static_ecdh_point`]); counters
/// 0..=7 produced x-coordinates that are not on the curve.
const STATIC_ECDH_POINT_COMPRESSED: [u8; 33] = [
    0x02, 0x2e, 0x73, 0xb6, 0x5b, 0x38, 0x97, 0x9e, 0xf3, 0x16, 0x22, 0x1e, 0xa0, 0xb1, 0x10,
    0xe8, 0x33, 0x6c, 0x53, 0xae, 0x37, 0xc3, 0xbe, 0xe4, 0x9b, 0xe1, 0x56, 0x8c, 0x2d, 0xeb,
    0xca, 0x2b, 0x14,
];

/// Parses [`STATIC_ECDH_POINT_COMPRESSED`] into a usable public key.
///
/// Infallible in practice -- the constant is verified against
/// `derive_static_ecdh_point` by the test suite -- but surfaced as a
/// `Result` rather than a panic so a corrupted build fails the operation
/// instead of aborting the host application.
pub(crate) fn static_ecdh_point() -> Result<PublicKey> {
    PublicKey::from_sec1_bytes(&STATIC_ECDH_POINT_COMPRESSED)
        .map_err(|_| Error::Crypto("the fixed static-ECDH point is not a valid P-256 point"))
}

/// Rederives `H` from [`STATIC_POINT_SEED`] by try-and-increment:
/// `X = SHA-256(seed || counter_be)`, taking the first counter whose `X`
/// is a valid P-256 x-coordinate, with the even-`Y` sign byte. Returns
/// the point and the counter that produced it.
///
/// Test-only: production reads the hardcoded constant instead, and the
/// test suite asserts the two agree. Kept in the source (rather than in a
/// comment or an external script) so the constant can never drift from a
/// documented, executable derivation.
#[cfg(test)]
fn derive_static_ecdh_point() -> (PublicKey, u32, [u8; 33]) {
    for counter in 0u32..10_000 {
        let mut hasher = Sha256::new();
        hasher.update(STATIC_POINT_SEED);
        hasher.update(counter.to_be_bytes());
        let x = hasher.finalize();

        let mut compressed = [0u8; 33];
        compressed[0] = 0x02; // even-Y of the two candidate points
        compressed[1..].copy_from_slice(&x);

        if let Ok(point) = PublicKey::from_sec1_bytes(&compressed) {
            return (point, counter, compressed);
        }
    }
    panic!("no valid P-256 point found for the static-ECDH seed; the seed or curve is wrong");
}

pub const DEK_LEN: usize = 32; // the mandated, fixed DEK size in bytes

// Wraps `dek` under the persistent KEK for `service`, returning the
// serialized wrapped payload ready to store/transmit. The KEK must already
// exist (created via `provider::create_kek`, i.e. `hkdfguard_create_kek`);
// this never creates one itself -- see `provider::select_existing`.
pub fn wrap(service: &str, dek: &[u8; DEK_LEN]) -> Result<Vec<u8>> {
    let (provider, handle) = provider::select_existing(service)?; // walk the priority chain for an already-created KEK

    let fingerprint = kek_fingerprint(&handle.public_key()?); // identifies *which* KEK this payload is wrapped under, for `unwrap` to check before any ECDH/AES-GCM

    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt); // per-payload HKDF salt: what makes this payload's wrapping key unique
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes); // fresh random nonce for this one AES-GCM encryption

    // Build the payload up front, with the ciphertext buffer already at
    // its final size, so `authenticated_bytes` below covers the real
    // declared ciphertext length. The AEAD's associated data has to be
    // fixed before encryption, and the ciphertext is always exactly
    // DEK_LEN + TAG_LEN, so there is no chicken-and-egg problem here.
    let mut payload = Payload {
        provider_type: provider.provider_type(), // records which provider produced this KEK, for `unwrap` to use later
        key_id: handle.key_id().to_vec(),        // provider's diagnostic tag
        salt,
        nonce: nonce_bytes,
        ciphertext: vec![0u8; DEK_LEN + TAG_LEN], // placeholder, filled in below
        fingerprint,
    };
    // Every non-ciphertext byte of the payload, bound into both the key
    // derivation and the AEAD -- see `Payload::authenticated_bytes`. This
    // is what authenticates `provider_type` (so a payload can't be
    // replayed as another provider's) and the fingerprint (so the KEK
    // identity is committed to by the key itself, not only checked).
    let authenticated = payload.authenticated_bytes();

    let mut shared_secret = handle.ecdh(&static_ecdh_point()?)?; // ECDH against the fixed point H -- only the KEK's holder can compute this (already stack-only: see `provider::SharedSecret`)
    let mut wrapping_key = derive_wrapping_key(&shared_secret, service, &salt, &authenticated)?; // HKDF-SHA512 turns the shared secret into a 32-byte AES key (also stack-only)
    shared_secret.zeroize(); // the raw ECDH shared secret is no longer needed; scrub it now rather than waiting for scope exit

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*wrapping_key)); // set up AES-256-GCM with the derived key

    // Copy the DEK onto the stack (a plain array-to-array copy, no heap
    // involved) and encrypt it in place: `ct_buf` starts as plaintext and
    // ends as ciphertext, entirely within this stack frame.
    let mut ct_buf: [u8; DEK_LEN] = *dek;
    let tag_result = cipher.encrypt_in_place_detached(
        Nonce::from_slice(&nonce_bytes),
        &authenticated,
        &mut ct_buf,
    );
    wrapping_key.zeroize(); // the derived AES key is no longer needed either way; scrub it immediately
    salt.zeroize(); // already copied into the payload; don't leave a second copy on the stack

    let tag: Tag = tag_result.map_err(|_| Error::Crypto("AES-256-GCM encryption failed"))?; // propagate any encryption error only after cleanup above
    // `ct_buf` now holds ciphertext, not plaintext -- safe to copy into the
    // (necessarily heap-backed, since it's variable-length) wire payload.
    payload.ciphertext.clear();
    payload.ciphertext.extend_from_slice(&ct_buf);
    payload.ciphertext.extend_from_slice(&tag);
    debug_assert_eq!(
        payload.authenticated_bytes(),
        authenticated,
        "the authenticated bytes must not change once the ciphertext is filled in"
    );

    Ok(payload.to_bytes()) // serialize to the final wire format
}

// Reverses `wrap`: parses the payload, re-derives the same wrapping key,
// and decrypts+authenticates the original DEK back out. The recovered DEK
// lives only in the stack-allocated `[u8; DEK_LEN]` returned to the
// caller -- never in a heap buffer at any point.
pub fn unwrap(service: &str, wrapped: &[u8]) -> Result<[u8; DEK_LEN]> {
    let payload = Payload::from_bytes(wrapped)?; // parse and structurally validate the wire format (ciphertext stays a heap Vec, but it's ciphertext, not a secret)

    if payload.ciphertext.len() != DEK_LEN + TAG_LEN {
        return Err(Error::Crypto("wrapped ciphertext has unexpected length")); // malformed/tampered length; bail out before touching any crypto
    }

    let provider = provider::get_by_type(payload.provider_type)?; // must use the exact provider that originally wrapped this DEK
    let handle = provider.load_kek(service, false)?; // load (never create) that provider's KEK for this service -- TPM2 deterministically regenerates it instead of persisting one

    // Before spending any effort on ECDH/AES-GCM, check that this payload
    // was actually wrapped under the KEK `service` resolves to *right now*
    // -- catches a rotated/replaced/wrong KEK with a specific, unambiguous
    // error instead of collapsing into a generic AEAD authentication
    // failure indistinguishable from tampering (see `Error::FingerprintMismatch`).
    let current_fingerprint = kek_fingerprint(&handle.public_key()?);
    if current_fingerprint != payload.fingerprint {
        return Err(Error::FingerprintMismatch);
    }

    // Must exactly mirror what `wrap` bound: every non-ciphertext byte of
    // the payload. Derived from the parsed payload, so any tampered
    // header byte changes both the derived key and the AEAD's associated
    // data -- the decryption below then fails authentication.
    let authenticated = payload.authenticated_bytes();

    let mut shared_secret = handle.ecdh(&static_ecdh_point()?)?; // re-derive the same ECDH shared secret used during wrap
    let mut wrapping_key = derive_wrapping_key(&shared_secret, service, &payload.salt, &authenticated)?; // re-derive the same AES key
    shared_secret.zeroize(); // scrub the shared secret as soon as we've derived the key from it

    // Split the wire ciphertext (still just ciphertext bytes, not secret)
    // into its AES-GCM ciphertext body and trailing tag, then copy the
    // body onto the stack -- this is the *only* place the decrypted DEK
    // will ever live.
    let (ct_part, tag_part) = payload.ciphertext.split_at(DEK_LEN);
    let mut dek = [0u8; DEK_LEN];
    dek.copy_from_slice(ct_part); // still ciphertext at this point
    let tag = Tag::from_slice(tag_part);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*wrapping_key));
    let auth_result = cipher.decrypt_in_place_detached(
        Nonce::from_slice(&payload.nonce),
        &authenticated,
        &mut dek,
        tag,
    ); // decrypts `dek` in place; on success it now holds the real plaintext DEK
    wrapping_key.zeroize(); // the AES key is no longer needed regardless of whether decryption succeeded

    if auth_result.is_err() {
        // Authentication failed: `dek` may now contain unauthenticated
        // (attacker-influenced or simply garbage) bytes from the in-place
        // decryption -- scrub it before returning rather than ever
        // handing it back to the caller.
        dek.zeroize();
        return Err(Error::Crypto(
            "AES-256-GCM authentication failed (tampered, wrong service, or wrong KEK)",
        ));
    }

    Ok(dek) // genuine plaintext DEK, stack-resident from decryption through to the caller
}

// Turns a raw ECDH shared secret into a 32-byte AES-256 key via
// HKDF-SHA512, using the service name as domain-separating "info" so the
// same shared secret would never accidentally produce the same wrapping
// key for a different service.
fn derive_wrapping_key(
    shared_secret: &[u8; 32],
    service: &str,
    salt: &[u8; SALT_LEN],
    authenticated: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    // HKDF-Extract *with* the payload's random salt. This is load-bearing
    // now in a way it wasn't under the old ephemeral-key protocol: the
    // ECDH secret is constant for a given service, so the salt is the
    // only thing making each payload's wrapping key distinct. Without it,
    // every payload for a service would share one AES key and reuse would
    // come down to nonce collisions alone.
    let hk = Hkdf::<Sha512>::new(Some(salt), shared_secret);

    // `info` = prefix || len(service) || service || every non-ciphertext
    // payload byte. The length prefix keeps the concatenation
    // unambiguous, so no two distinct (service, header) pairs can produce
    // the same `info`. `info` is a public label, not a secret, so a heap
    // Vec here is fine.
    let mut info = Vec::with_capacity(HKDF_INFO_PREFIX.len() + 2 + service.len() + authenticated.len());
    info.extend_from_slice(HKDF_INFO_PREFIX); // fixed prefix for domain separation from any other use of HKDF in this protocol
    info.extend_from_slice(&(service.len() as u16).to_le_bytes()); // unambiguous framing for the variable-length service name
    info.extend_from_slice(service.as_bytes()); // then the service name itself
    info.extend_from_slice(authenticated); // and the payload header + fingerprint

    let mut out = Zeroizing::new([0u8; 32]); // 32 bytes = AES-256 key size; stack-backed array wrapped for auto-scrub on drop
    hk.expand(&info, &mut *out) // HKDF-Expand into the output buffer using `info` as context (truncated to 32 bytes; SHA-512's 64-byte native output is larger than the requested AES-256 key length, which RFC 5869 allows)
        .map_err(|_| Error::Crypto("HKDF-SHA512 expand failed"))?; // only fails if the requested output length were invalid (never true here)
    Ok(out)
}

/// Computes the "fingerprint" appended to every wrapped payload (see
/// [`crate::payload::Payload::fingerprint`]): a SHA-256 hash of the
/// persistent KEK's public key, SEC1-uncompressed-encoded. Not a secret
/// value -- the public key it hashes isn't secret either -- so the
/// equality check against it in [`unwrap`] exists purely to fail fast and
/// cheaply on "this payload wasn't wrapped under the KEK `service`
/// currently resolves to," before spending any effort on ECDH/AES-GCM.
fn kek_fingerprint(public_key: &PublicKey) -> [u8; FINGERPRINT_LEN] {
    let encoded = public_key.to_encoded_point(false); // uncompressed SEC1 point: 0x04 || X || Y
    let digest = Sha256::digest(encoded.as_bytes());
    let mut out = [0u8; FINGERPRINT_LEN];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*; // bring `wrap`, `unwrap`, `DEK_LEN`, etc. into scope
    use p256::SecretKey; // test-only: stands in for an attacker scalar and for fingerprint fixtures
    use serial_test::serial; // these tests mutate shared env vars, so they must run one at a time
    use tempfile::tempdir; // throwaway directory for the external-secret provider's mount, in the rotation test

    // Disables the external-secret provider and writes a policy that
    // explicitly opts Ephemeral in, so every test in this module
    // deterministically exercises the Ephemeral provider. Without that
    // policy Ephemeral is never used (see `provider::allowed_chain`).
    fn with_isolated_ephemeral_provider<F: FnOnce()>(f: F) {
        std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", "/nonexistent-for-tests"); // guarantee this provider is unavailable
        let _policy = crate::policy::allow_ephemeral_policy_for_tests();
        f();
        std::env::remove_var("HKDFGUARD_POLICY_FILE");
        std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
    }

    #[test]
    #[serial]
    fn round_trips_through_ephemeral_provider() {
        with_isolated_ephemeral_provider(|| {
            crate::provider::create_kek("com.company.orders").unwrap(); // wrap no longer creates -- provision the KEK first
            let dek = [0x42u8; DEK_LEN]; // arbitrary fixed test DEK
            let wrapped = wrap("com.company.orders", &dek).unwrap();
            let recovered = unwrap("com.company.orders", &wrapped).unwrap();
            assert_eq!(dek, recovered); // must get back exactly what was wrapped
        });
    }

    #[test]
    #[serial]
    fn wrap_fails_until_create_kek_is_called() {
        with_isolated_ephemeral_provider(|| {
            let dek = [0x55u8; DEK_LEN];
            let err = wrap("com.company.never-created", &dek).unwrap_err();
            assert!(matches!(err, Error::KekNotFound));

            crate::provider::create_kek("com.company.never-created").unwrap();
            wrap("com.company.never-created", &dek).unwrap(); // now succeeds
        });
    }

    #[test]
    #[serial]
    fn wrong_service_fails_to_unwrap() {
        with_isolated_ephemeral_provider(|| {
            // Both services' KEKs must already exist: unwrap now only ever
            // loads (never creates) the KEK for the service it's given, so
            // for this test to actually exercise the fingerprint mismatch
            // (rather than just "billing has no KEK yet"), billing needs a
            // real, distinct KEK of its own.
            crate::provider::create_kek("com.company.orders").unwrap();
            crate::provider::create_kek("com.company.billing").unwrap();
            let dek = [0x11u8; DEK_LEN];
            let wrapped = wrap("com.company.orders", &dek).unwrap();
            let err = unwrap("com.company.billing", &wrapped).unwrap_err(); // deliberately wrong service name
            // Caught by the fingerprint check now, before AEAD is even
            // attempted: billing's KEK has a different public key than
            // orders', so the payload's embedded fingerprint can't match.
            assert!(matches!(err, Error::FingerprintMismatch));
        });
    }

    #[test]
    #[serial]
    fn tampered_ciphertext_fails_to_unwrap() {
        with_isolated_ephemeral_provider(|| {
            crate::provider::create_kek("com.company.orders").unwrap();
            let dek = [0x99u8; DEK_LEN];
            let mut wrapped = wrap("com.company.orders", &dek).unwrap();
            // The wire format's last FINGERPRINT_LEN bytes are the KEK
            // fingerprint, not ciphertext -- flip the last byte actually
            // inside the ciphertext/tag region (right before that
            // trailer), so this still specifically exercises AEAD's own
            // tamper detection rather than the (unrelated) fingerprint check.
            let last_ciphertext_byte = wrapped.len() - FINGERPRINT_LEN - 1;
            wrapped[last_ciphertext_byte] ^= 0x01; // flip one bit in the ciphertext/tag
            let err = unwrap("com.company.orders", &wrapped).unwrap_err();
            assert!(matches!(err, Error::Crypto(_))); // AEAD authentication must catch the tamper
        });
    }

    #[test]
    #[serial]
    fn truncated_ciphertext_fails_to_unwrap() {
        with_isolated_ephemeral_provider(|| {
            crate::provider::create_kek("com.company.orders").unwrap();
            let dek = [0x22u8; DEK_LEN];
            let mut wrapped = wrap("com.company.orders", &dek).unwrap();
            wrapped.truncate(wrapped.len() - 5); // chop bytes out of the ciphertext/tag region
            let err = unwrap("com.company.orders", &wrapped).unwrap_err();
            assert!(matches!(err, Error::Crypto(_))); // must be rejected by the explicit length check, not panic in `split_at`
        });
    }

    #[test]
    #[serial]
    fn same_dek_wrapped_twice_yields_different_ciphertexts() {
        with_isolated_ephemeral_provider(|| {
            crate::provider::create_kek("com.company.orders").unwrap();
            let dek = [0x77u8; DEK_LEN];
            let a = wrap("com.company.orders", &dek).unwrap();
            let b = wrap("com.company.orders", &dek).unwrap(); // same DEK, same service, wrapped again
            assert_ne!(a, b, "ephemeral ECDH + random nonce must randomize output"); // must not be deterministic
        });
    }

    // ---- the fixed static-ECDH point `H` ----

    #[test]
    #[serial]
    fn software_providers_accept_the_fixed_static_ecdh_point() {
        // The hardware backends get their own #[ignore]d versions of this
        // (see the tpm2 and pkcs11 provider tests); this covers the
        // providers that need no device, so the check runs on every build
        // rather than only where swtpm/SoftHSM2 are available.
        with_isolated_ephemeral_provider(|| {
            let h = static_ecdh_point().unwrap();

            let service = "com.company.orders.staticpoint";
            crate::provider::create_kek(service).unwrap();
            let (_provider, handle) = crate::provider::select_existing(service).unwrap();

            let z1 = handle.ecdh(&h).unwrap();
            let z2 = handle.ecdh(&h).unwrap();
            assert_eq!(*z1, *z2, "static-point ECDH must be repeatable");
            assert_ne!(*z1, [0u8; 32], "shared secret must not be all zeroes");

            let other_service = "com.company.billing.staticpoint";
            crate::provider::create_kek(other_service).unwrap();
            let (_provider, other) = crate::provider::select_existing(other_service).unwrap();
            assert_ne!(
                *z1,
                *other.ecdh(&h).unwrap(),
                "different KEKs must yield different Z against the same H"
            );
        });
    }

    #[test]
    fn hardcoded_static_point_matches_its_documented_derivation() {
        // The constant is the authority at runtime; this asserts it is
        // exactly what the documented try-and-increment derivation
        // produces, so the two can never drift apart. If this fails,
        // either the constant or the seed was edited -- and changing
        // either one silently changes every wrapping key on every
        // platform.
        let (derived, counter, compressed) = derive_static_ecdh_point();
        assert_eq!(counter, 8, "the seed must still resolve at the documented counter");
        assert_eq!(compressed, STATIC_ECDH_POINT_COMPRESSED);
        assert_eq!(derived, static_ecdh_point().unwrap());
    }

    #[test]
    fn static_point_is_a_valid_usable_curve_point() {
        let h = static_ecdh_point().unwrap();

        // Not the identity, and a real point we can actually do ECDH
        // against from the scalar side.
        let encoded = h.to_encoded_point(false);
        assert_eq!(encoded.as_bytes().len(), UNCOMPRESSED_POINT_LEN);
        assert_eq!(encoded.as_bytes()[0], 0x04);

        // Round-trips through the uncompressed form the providers use.
        assert_eq!(PublicKey::from_sec1_bytes(encoded.as_bytes()).unwrap(), h);

        // ECDH against it succeeds and is deterministic.
        let k = SecretKey::random(&mut OsRng);
        let z1 = p256::ecdh::diffie_hellman(k.to_nonzero_scalar(), h.as_affine());
        let z2 = p256::ecdh::diffie_hellman(k.to_nonzero_scalar(), h.as_affine());
        assert_eq!(z1.raw_secret_bytes(), z2.raw_secret_bytes());

        // Different KEKs must yield different Z against the same H --
        // this is what gives each service its own wrapping key.
        let other = SecretKey::random(&mut OsRng);
        let z_other = p256::ecdh::diffie_hellman(other.to_nonzero_scalar(), h.as_affine());
        assert_ne!(z1.raw_secret_bytes(), z_other.raw_secret_bytes());
    }

    // A payload with distinctive, easily-perturbed field values.
    fn sample_payload() -> Payload {
        Payload {
            provider_type: crate::provider::ProviderType::Ephemeral,
            key_id: b"key-id".to_vec(),
            salt: [0x11u8; SALT_LEN],
            nonce: [0x22u8; NONCE_LEN],
            ciphertext: vec![0x33u8; DEK_LEN + TAG_LEN],
            fingerprint: [0x44u8; FINGERPRINT_LEN],
        }
    }

    #[test]
    fn derive_wrapping_key_binds_every_input() {
        let secret = [0x99u8; 32];
        let payload = sample_payload();
        let salt = payload.salt;
        let authenticated = payload.authenticated_bytes();

        let base = derive_wrapping_key(&secret, "service.a", &salt, &authenticated).unwrap();
        assert_eq!(
            *base,
            *derive_wrapping_key(&secret, "service.a", &salt, &authenticated).unwrap(),
            "must be deterministic for identical inputs"
        );

        // Service name.
        assert_ne!(
            *base,
            *derive_wrapping_key(&secret, "service.b", &salt, &authenticated).unwrap(),
            "the service name must change the derived key"
        );

        // Shared secret (i.e. a different KEK).
        assert_ne!(
            *base,
            *derive_wrapping_key(&[0x98u8; 32], "service.a", &salt, &authenticated).unwrap(),
            "a different shared secret must change the derived key"
        );

        // Salt -- the per-payload separation that replaced the ephemeral key.
        let mut other_salt = salt;
        other_salt[0] ^= 0x01;
        assert_ne!(
            *base,
            *derive_wrapping_key(&secret, "service.a", &other_salt, &authenticated).unwrap(),
            "the salt must change the derived key, or every payload would share one"
        );

        // Every single byte of the authenticated header, including the
        // provider_type tag (#9) and the fingerprint (#10), must reach the
        // key derivation -- not merely the AEAD's associated data.
        for i in 0..authenticated.len() {
            let mut tampered = authenticated.clone();
            tampered[i] ^= 0x01;
            assert_ne!(
                *base,
                *derive_wrapping_key(&secret, "service.a", &salt, &tampered).unwrap(),
                "flipping authenticated byte {i} must change the derived key"
            );
        }
    }

    #[test]
    fn service_name_framing_is_unambiguous() {
        // The length prefix on the service name is what stops two
        // different (service, header) pairs from concatenating to the same
        // `info`. Without it, ("ab", <header starting c>) and
        // ("abc", <header>) could collide.
        let secret = [0x99u8; 32];
        let salt = [0u8; SALT_LEN];

        let k1 = derive_wrapping_key(&secret, "ab", &salt, b"cXYZ").unwrap();
        let k2 = derive_wrapping_key(&secret, "abc", &salt, b"XYZ").unwrap();
        assert_ne!(*k1, *k2, "service/header boundary must not be ambiguous");
    }

    #[test]
    #[serial]
    fn tampering_with_the_wire_fingerprint_bytes_breaks_aead_authentication_directly() {
        // `wrap`/`unwrap`'s own fingerprint pre-check already rejects a
        // tampered fingerprint before AES-GCM is ever attempted (see
        // `wrong_service_fails_to_unwrap` and the module doc comment), so
        // going through the public API can't observe AEAD's own tamper
        // detection in isolation -- by the time `unwrap` builds its AAD,
        // the pre-check has already forced it to agree with whatever the
        // payload's fingerprint bytes currently are. This test instead
        // re-derives the same wrapping key `wrap` used and decrypts
        // directly with `Aes256Gcm`, to prove independently that AAD
        // including the fingerprint is what's actually protecting those
        // bytes cryptographically, not just the application-level check.
        with_isolated_ephemeral_provider(|| {
            let service = "com.company.aadtest";
            crate::provider::create_kek(service).unwrap();
            let dek = [0x66u8; DEK_LEN];
            let wrapped = wrap(service, &dek).unwrap();
            let payload = Payload::from_bytes(&wrapped).unwrap();

            let (provider, handle) = crate::provider::select_existing(service).unwrap();
            let _ = provider;
            let mut shared_secret = handle.ecdh(&static_ecdh_point().unwrap()).unwrap();
            let correct_aad = payload.authenticated_bytes();
            let wrapping_key =
                derive_wrapping_key(&shared_secret, service, &payload.salt, &correct_aad).unwrap();
            shared_secret.zeroize();

            let (ct_part, tag_part) = payload.ciphertext.split_at(DEK_LEN);
            let tag = Tag::from_slice(tag_part);
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*wrapping_key));

            // Decrypting with the exact original AAD must succeed --
            // establishes this is a faithful re-derivation, not a setup bug.
            let mut buf = [0u8; DEK_LEN];
            buf.copy_from_slice(ct_part);
            assert!(cipher.decrypt_in_place_detached(Nonce::from_slice(&payload.nonce), &correct_aad, &mut buf, tag).is_ok());
            assert_eq!(buf, dek);

            // A single bit flipped in *only* the fingerprint half of the
            // AAD (the ciphertext, tag, and nonce are all untouched) must
            // make AES-GCM itself refuse to authenticate.
            let mut tampered_fingerprint_aad = correct_aad.clone();
            *tampered_fingerprint_aad.last_mut().unwrap() ^= 0x01;
            let mut buf = [0u8; DEK_LEN];
            buf.copy_from_slice(ct_part);
            assert!(
                cipher.decrypt_in_place_detached(Nonce::from_slice(&payload.nonce), &tampered_fingerprint_aad, &mut buf, tag).is_err(),
                "AES-GCM must reject a payload whose fingerprint-half AAD bytes were altered"
            );

            // Same for the provider_type tag, which is byte 1 of the
            // header -- finding #9. Under the old format this byte steered
            // which provider unwrapped the payload while being
            // unauthenticated, so it was attacker-malleable.
            let mut tampered_provider_aad = correct_aad.clone();
            tampered_provider_aad[1] ^= 0x01;
            let mut buf = [0u8; DEK_LEN];
            buf.copy_from_slice(ct_part);
            assert!(
                cipher.decrypt_in_place_detached(Nonce::from_slice(&payload.nonce), &tampered_provider_aad, &mut buf, tag).is_err(),
                "AES-GCM must reject a payload whose provider_type byte was altered"
            );
        });
    }

    #[test]
    #[serial]
    fn a_public_key_holder_cannot_forge_a_payload() {
        // The point of the static-H design (finding #4). Under the old
        // ephemeral-ECDH protocol an attacker holding only the KEK's
        // *public* key could compute the same shared secret the provider
        // would (ECDH(eph_priv, KEK_pub) == ECDH(KEK_priv, eph_pub)),
        // derive the wrapping key, and mint a payload that unwrapped to a
        // DEK of their choosing. Now the shared secret is ECDH(KEK_priv,
        // H), so reproducing it needs the KEK's private key or H's
        // discrete log -- neither of which a public-key holder has.
        with_isolated_ephemeral_provider(|| {
            let service = "com.company.forgery";
            crate::provider::create_kek(service).unwrap();

            let genuine = wrap(service, &[0x01u8; DEK_LEN]).unwrap();
            let payload = Payload::from_bytes(&genuine).unwrap();

            // Everything the attacker is assumed to know: the KEK's public
            // key (not secret -- on a TPM anyone reaching the device can
            // recompute it), the wire format, and the fixed point H.
            let (_provider, handle) = crate::provider::select_existing(service).unwrap();
            let kek_public = handle.public_key().unwrap();
            let h = static_ecdh_point().unwrap();

            // The old attack, attempted: pick an ephemeral scalar, do ECDH
            // against the KEK's public key, and try to derive the wrapping
            // key from it.
            let attacker_scalar = SecretKey::random(&mut OsRng);
            let attacker_z = p256::ecdh::diffie_hellman(
                attacker_scalar.to_nonzero_scalar(),
                kek_public.as_affine(),
            );
            let mut attacker_secret = [0u8; 32];
            attacker_secret.copy_from_slice(attacker_z.raw_secret_bytes().as_slice());

            let authenticated = payload.authenticated_bytes();
            let forged_key =
                derive_wrapping_key(&attacker_secret, service, &payload.salt, &authenticated).unwrap();

            // The genuine key, for comparison.
            let mut genuine_z = handle.ecdh(&h).unwrap();
            let genuine_key =
                derive_wrapping_key(&genuine_z, service, &payload.salt, &authenticated).unwrap();
            genuine_z.zeroize();

            assert_ne!(
                *forged_key, *genuine_key,
                "a KEK-public-key holder must not be able to derive the wrapping key"
            );

            // And concretely: a payload encrypted under the attacker's key
            // does not unwrap, even though every header byte is
            // well-formed and the fingerprint is correct.
            let attacker_dek = [0xEEu8; DEK_LEN];
            let mut ct_buf = attacker_dek;
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*forged_key));
            let tag = cipher
                .encrypt_in_place_detached(Nonce::from_slice(&payload.nonce), &authenticated, &mut ct_buf)
                .unwrap();

            let mut forged = Payload {
                provider_type: payload.provider_type,
                key_id: payload.key_id.clone(),
                salt: payload.salt,
                nonce: payload.nonce,
                ciphertext: Vec::new(),
                fingerprint: payload.fingerprint, // the correct fingerprint: the pre-check will pass
            };
            forged.ciphertext.extend_from_slice(&ct_buf);
            forged.ciphertext.extend_from_slice(&tag);

            let err = unwrap(service, &forged.to_bytes()).unwrap_err();
            assert!(
                matches!(err, Error::Crypto(_)),
                "a forged payload must fail AEAD authentication, got {err:?}"
            );

            // The genuine payload still works, so the test isn't passing
            // for an unrelated reason.
            assert_eq!(unwrap(service, &genuine).unwrap(), [0x01u8; DEK_LEN]);
        });
    }

    #[test]
    fn kek_fingerprint_properties() {
        let key1 = SecretKey::random(&mut OsRng).public_key();
        let key2 = SecretKey::random(&mut OsRng).public_key();

        let f1 = kek_fingerprint(&key1);
        let f1_repeat = kek_fingerprint(&key1);
        assert_eq!(f1, f1_repeat, "must be deterministic for the same public key");
        assert_eq!(f1.len(), FINGERPRINT_LEN);

        let f2 = kek_fingerprint(&key2);
        assert_ne!(f1, f2, "different public keys must yield different fingerprints");
    }

    #[test]
    #[serial]
    fn round_trips_various_dek_patterns() {
        with_isolated_ephemeral_provider(|| {
            crate::provider::create_kek("com.company.orders").unwrap();
            let patterns: [[u8; DEK_LEN]; 4] = [
                [0x00u8; DEK_LEN],
                [0xFFu8; DEK_LEN],
                core::array::from_fn(|i| i as u8),
                core::array::from_fn(|i| (255 - i) as u8),
            ];

            for dek in patterns {
                let wrapped = wrap("com.company.orders", &dek).unwrap();
                let recovered = unwrap("com.company.orders", &wrapped).unwrap();
                assert_eq!(dek, recovered);
            }
        });
    }

    #[test]
    #[serial]
    fn fingerprint_mismatch_detected_after_kek_rotation() {
        #[cfg(feature = "external-secret")]
        {
            // external-secret is the provider used here rather than
            // Ephemeral, specifically because this test needs key
            // material that something *outside* this process can
            // rewrite -- Ephemeral is in-memory only, so there's no file
            // to rotate out from under it. Pinned by policy, or a
            // reachable TPM/PKCS#11 device would win the chain and there
            // would be nothing for the rotation below to rotate.
            let _policy = crate::policy::require_provider_policy_for_tests("external-secret");
            let ext_dir = tempdir().unwrap();
            std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", ext_dir.path());
            let service = "com.company.rotated";
            let secret_path = ext_dir.path().join(service);

            let key_a = SecretKey::random(&mut OsRng);
            std::fs::write(&secret_path, key_a.to_bytes()).unwrap();

            let dek = [0x77u8; DEK_LEN];
            let wrapped = wrap(service, &dek).unwrap();

            // Simulate an out-of-band KEK rotation: the deployment
            // platform (Vault Agent, a Kubernetes Secret, ...) rewrites
            // the mounted secret file with a brand new, unrelated key
            // under the exact same service name -- the scenario this
            // whole feature exists to catch.
            let key_b = SecretKey::random(&mut OsRng);
            std::fs::write(&secret_path, key_b.to_bytes()).unwrap();

            let err = unwrap(service, &wrapped).unwrap_err();
            // Caught by the fingerprint check, before ECDH/AES-GCM is ever
            // attempted -- not a generic `Error::Crypto`, which is what
            // this would have looked like before this check existed.
            assert!(matches!(err, Error::FingerprintMismatch));

            std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
            std::env::remove_var("HKDFGUARD_POLICY_FILE");
        }
    }

    #[test]
    #[serial]
    fn tampered_salt_fails_to_unwrap() {
        // The salt replaced the ephemeral public key in v3. Tampering
        // with it changes the HKDF salt *and* the authenticated bytes, so
        // the re-derived key is wrong and the AEAD rejects the payload.
        with_isolated_ephemeral_provider(|| {
            crate::provider::create_kek("com.company.orders").unwrap();
            let dek = [0x33u8; DEK_LEN];
            let wrapped = wrap("com.company.orders", &dek).unwrap();
            let mut payload = Payload::from_bytes(&wrapped).unwrap();
            payload.salt[0] ^= 0x01;
            let tampered_bytes = payload.to_bytes();

            let err = unwrap("com.company.orders", &tampered_bytes).unwrap_err();
            assert!(matches!(err, Error::Crypto(_)));
        });
    }

    #[test]
    #[serial]
    fn tampered_provider_type_fails_to_unwrap() {
        // Finding #9: the provider tag steers which provider unwraps the
        // payload, and was previously unauthenticated. Changing it must
        // now fail rather than being honored.
        with_isolated_ephemeral_provider(|| {
            crate::provider::create_kek("com.company.orders").unwrap();
            let dek = [0x34u8; DEK_LEN];
            let wrapped = wrap("com.company.orders", &dek).unwrap();

            let mut bytes = wrapped.clone();
            bytes[1] = crate::provider::ProviderType::ExternalSecret as u8; // byte 1 is provider_type

            // The property that matters is that it never *succeeds*. Which
            // error surfaces depends on the substituted provider: it may
            // be unable to serve this service at all, or it may serve a
            // different KEK and fail the fingerprint check, or the
            // authentication fails because the tag was computed over the
            // original tag byte. The cryptographic proof that the AAD is
            // what protects this byte is
            // `tampering_with_the_wire_fingerprint_bytes_breaks_aead_authentication_directly`,
            // which flips it with the key held constant.
            assert!(
                unwrap("com.company.orders", &bytes).is_err(),
                "a payload whose provider_type was altered must never unwrap"
            );

            // The untampered payload still works.
            assert_eq!(unwrap("com.company.orders", &wrapped).unwrap(), dek);
        });
    }

    #[test]
    #[serial]
    fn tampered_nonce_fails_to_unwrap() {
        with_isolated_ephemeral_provider(|| {
            crate::provider::create_kek("com.company.orders").unwrap();
            let dek = [0x44u8; DEK_LEN];
            let wrapped = wrap("com.company.orders", &dek).unwrap();
            let mut payload = Payload::from_bytes(&wrapped).unwrap();
            payload.nonce[0] ^= 0x01; // flip a bit in nonce
            let tampered_bytes = payload.to_bytes();

            let err = unwrap("com.company.orders", &tampered_bytes).unwrap_err();
            assert!(matches!(err, Error::Crypto(_)));
        });
    }
}
