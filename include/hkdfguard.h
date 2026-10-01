/*
 * hkdfguard.h -- Stable C ABI for HKDFGuard (Linux).
 *
 * Wraps and unwraps 32-byte Data Encryption Keys (DEKs) under a persistent,
 * per-service Key Encryption Key (KEK), using the strongest available
 * provider on the host (TPM2 > PKCS#11 > external secret > ephemeral).
 * See the crate's provider/ module docs for the protocol
 * (ECDH P-256 against a per-payload hashed point -> HKDF-SHA512 -> AES-256-GCM) and
 * provider details. A wrapped payload can only be created, and only be
 * opened, on the host holding the KEK: it is not possible to pre-wrap a
 * DEK for a host from elsewhere.
 *
 * No Rust type, TPM handle, OpenSSL structure, or PKCS#11 object ever
 * crosses this boundary. No exception/panic ever crosses this boundary --
 * every function below returns a plain status code.
 */

#ifndef HKDFGUARD_H
#define HKDFGUARD_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Required length of a DEK, in bytes. */
#define HKDFGUARD_DEK_LEN 32

/* Status codes returned by every hkdfguard_* function. */
#define HKDFGUARD_OK                   0
#define HKDFGUARD_ERR_INVALID_ARGUMENT (-1) /* null pointer, wrong DEK length, negative capacity, etc. -- never a service-string problem, see HKDFGUARD_ERR_INVALID_SERVICE_NAME */
#define HKDFGUARD_ERR_BUFFER_TOO_SMALL (-2)
#define HKDFGUARD_ERR_PROVIDER_UNAVAILABLE (-3)
#define HKDFGUARD_ERR_PROVIDER_ERROR   (-4)
#define HKDFGUARD_ERR_CRYPTO_ERROR     (-5)
#define HKDFGUARD_ERR_INTERNAL_ERROR   (-6)
/* -7 (formerly INVALID_UTF8) is reserved, no longer returned by anything --
 * a `service` string that isn't valid UTF-8 is now just one more way for it
 * to be invalid, folded into HKDFGUARD_ERR_INVALID_SERVICE_NAME below. */
#define HKDFGUARD_ERR_INVALID_SERVICE_NAME (-8) /* service is null, empty, not valid UTF-8, over 128 bytes, contains a character other than an ASCII letter, digit, or '.', starts with '.', or contains ".." */
#define HKDFGUARD_ERR_KEK_NOT_FOUND    (-9)
/* -10..-15 intentionally unassigned here -- see hkdfguard's error.rs. */
#define HKDFGUARD_ERR_FINGERPRINT_MISMATCH (-16)
#define HKDFGUARD_ERR_PROCESS_HARDENING_FAILED (-17) /* hkdfguard_harden_process could not disable core dumps or ptrace access */

/*
 * Opt-in hardening of the *calling process* against memory disclosure:
 * disables core dumps (RLIMIT_CORE = 0, soft and hard) and, on Linux,
 * calls prctl(PR_SET_DUMPABLE, 0), which also stops other non-root
 * processes of the same user from ptrace-attaching or reading
 * /proc/<pid>/mem. Keys and DEKs that pass through this library then
 * can't be recovered from a crash dump or a same-user debugger.
 *
 * It changes process-wide state, so debuggers and crash reporters stop
 * working for the process -- hence opt-in. Call once, early in startup,
 * and after any privilege change (the kernel resets the dumpable flag
 * when credentials change). Root and CAP_SYS_PTRACE are unaffected; that
 * is host configuration. Idempotent.
 *
 * Returns HKDFGUARD_OK, or HKDFGUARD_ERR_PROCESS_HARDENING_FAILED.
 */
int hkdfguard_harden_process(void);

/*
 * Ensures a persistent KEK exists for `service`, creating one (on the
 * strongest available, policy-allowed provider) if it does not already.
 * Idempotent: safe to call again for a `service` that already has one --
 * this just confirms it's still there, doesn't rotate or recreate it.
 *
 * This is the *only* way a KEK ever gets created: hkdfguard_wrap_dek and
 * hkdfguard_generate_and_wrap_dek both return HKDFGUARD_ERR_KEK_NOT_FOUND
 * if called before this for a given `service`.
 *
 * TPM2 exception: the TPM derives a KEK for any service on demand, so by
 * default every service already "exists" there and this call has nothing
 * to create. With `tpm.require_pinned_names: true` in the policy file, a
 * service exists on the TPM only if policy pins its Name; for an unpinned
 * service this call fails and logs (at error level) the exact policy entry
 * to add. Provisioning on TPM is that root-owned policy edit.
 *
 * Deliberately slow: this and hkdfguard_kek_exists are setup calls, meant
 * to run once per application startup, and each takes at least
 * `startup_behavior.setup_min_delay_ms` (policy file; default 1000 ms)
 * of wall-clock time whatever its outcome, and they are serialized with
 * each other across threads. Do not call them per request; call once at
 * startup and then use hkdfguard_wrap_dek / hkdfguard_unwrap_dek.
 * Argument errors (bad pointer or service name) return immediately.
 *
 * service:  see hkdfguard_wrap_dek below.
 *
 * Returns HKDFGUARD_OK on success, or a negative HKDFGUARD_ERR_* code.
 */
int hkdfguard_create_kek(const char* service);

/*
 * Reports whether a persistent KEK already exists for `service`, without
 * creating one. Subject to the same startup latency floor and
 * serialization as hkdfguard_create_kek above; "exists" and "doesn't
 * exist" take the same time. On TPM2, always 1 when the TPM is reachable
 * unless policy sets `tpm.require_pinned_names` (see hkdfguard_create_kek).
 *
 * service:  see hkdfguard_wrap_dek below.
 * exists:   out-parameter; on HKDFGUARD_OK, set to 1 if a KEK exists for
 *           `service`, 0 otherwise (including "chain fully walked and
 *           nothing has one yet" -- call hkdfguard_create_kek to
 *           provision one). Untouched on any other return code.
 *
 * Returns HKDFGUARD_OK on success, or a negative HKDFGUARD_ERR_* code.
 */
int hkdfguard_kek_exists(const char* service, int* exists);

/*
 * Wraps a 32-byte DEK under the persistent KEK identified by `service`.
 * The KEK must already exist -- see hkdfguard_create_kek above; this
 * never creates one itself.
 *
 * The wrapped payload embeds a 32-byte SHA-256 fingerprint of this KEK's
 * public key, which hkdfguard_unwrap_dek checks before decrypting -- see
 * its own doc comment below.
 *
 * service:  NUL-terminated UTF-8 string, 1..=128 bytes. The logical,
 *           cross-platform identity of the KEK (e.g. "com.company.orders").
 *           Only ASCII alphanumeric characters and '.' are allowed, and it
 *           may not start with '.' or contain two consecutive dots (".."),
 *           so it can never name ".", "..", or a hidden file. NULL, an
 *           empty string, a string over 128 bytes, non-UTF-8 bytes, a
 *           disallowed character, or a dot rule violation all return
 *           HKDFGUARD_ERR_INVALID_SERVICE_NAME. Case-insensitive: normalized
 *           to lowercase internally, so e.g. "Com.Example.Orders" and
 *           "com.example.orders" always resolve to the same KEK. Distinct
 *           (after normalization) service strings always resolve to
 *           different KEKs.
 * dek:      pointer to exactly `dek_len` bytes to wrap.
 * dek_len:  must be exactly HKDFGUARD_DEK_LEN (32); any other value
 *           returns HKDFGUARD_ERR_INVALID_ARGUMENT.
 * out:      buffer to receive the wrapped payload. May be NULL only if
 *           *out_len is 0 (to probe the required size).
 * out_len:  in: capacity of `out` in bytes.
 *           out: on HKDFGUARD_OK, the number of bytes written to `out`.
 *                on HKDFGUARD_ERR_BUFFER_TOO_SMALL, the required capacity;
 *                `out` is left untouched and the call should be retried
 *                with a larger buffer. 512 bytes is a safe fixed size for
 *                a 32-byte DEK.
 *
 * Returns HKDFGUARD_OK on success, or a negative HKDFGUARD_ERR_* code.
 */
int hkdfguard_wrap_dek(
    const char* service,
    const uint8_t* dek,
    int dek_len,
    uint8_t* out,
    int* out_len);

/*
 * Unwraps a payload previously produced by hkdfguard_wrap_dek for the same
 * `service`, recovering the original 32-byte DEK.
 *
 * Before attempting any decryption, checks the wrapped payload's embedded
 * KEK fingerprint against the public key of the KEK `service` currently
 * resolves to, failing fast with HKDFGUARD_ERR_FINGERPRINT_MISMATCH (-16)
 * if they don't match -- this specifically means "wrong/rotated KEK," as
 * opposed to HKDFGUARD_ERR_CRYPTO_ERROR, which means "right KEK, but the
 * payload itself is tampered or otherwise unauthenticated."
 *
 * service:      must match the value used when the payload was wrapped
 *                (case-insensitively -- see hkdfguard_wrap_dek); any other
 *                mismatch is indistinguishable from tampering and returns
 *                HKDFGUARD_ERR_CRYPTO_ERROR. An invalid service string (see
 *                hkdfguard_wrap_dek) returns HKDFGUARD_ERR_INVALID_SERVICE_NAME.
 * wrapped:       pointer to the wrapped payload bytes.
 * wrapped_len:   length of `wrapped` in bytes.
 * out:           buffer to receive the recovered 32-byte DEK.
 * out_len:       in: capacity of `out` in bytes.
 *                out: on HKDFGUARD_OK, always HKDFGUARD_DEK_LEN (32).
 *                     on HKDFGUARD_ERR_BUFFER_TOO_SMALL, the required
 *                     capacity (HKDFGUARD_DEK_LEN).
 *
 * On ANY non-OK return, every byte of the caller's originally-declared
 * `out` capacity is zeroed before returning -- no partial or stale key
 * material is ever left in `out`.
 *
 * Returns HKDFGUARD_OK on success, or a negative HKDFGUARD_ERR_* code.
 */
int hkdfguard_unwrap_dek(
    const char* service,
    const uint8_t* wrapped,
    int wrapped_len,
    uint8_t* out,
    int* out_len);

/*
 * Generates a fresh, cryptographically random 32-byte DEK and immediately
 * wraps it under the persistent KEK identified by `service`, in one call --
 * for callers that want a brand new Ephemeral Data Protection Key without
 * having to source their own randomness.
 *
 * The newly generated plaintext DEK never crosses this ABI boundary: it is
 * zeroed internally the instant it has been wrapped, before this function
 * returns. To recover it later, unwrap the resulting payload via
 * hkdfguard_unwrap_dek, passing the same `service`.
 *
 * service:  see hkdfguard_wrap_dek.
 * out:      buffer to receive the wrapped payload. May be NULL only if
 *           *out_len is 0 (to probe the required size).
 * out_len:  in: capacity of `out` in bytes.
 *           out: on HKDFGUARD_OK, the number of bytes written to `out`.
 *                on HKDFGUARD_ERR_BUFFER_TOO_SMALL, the required capacity;
 *                `out` is left untouched and the call should be retried
 *                with a larger buffer.
 *
 * Returns HKDFGUARD_OK on success, or a negative HKDFGUARD_ERR_* code.
 */
int hkdfguard_generate_and_wrap_dek(
    const char* service,
    uint8_t* out,
    int* out_len);

#ifdef __cplusplus
}
#endif

#endif /* HKDFGUARD_H */
