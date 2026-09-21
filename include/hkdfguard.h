/*
 * hkdfguard.h -- Stable C ABI for HKDFGuard (Linux).
 *
 * Wraps and unwraps 32-byte Data Encryption Keys (DEKs) under a persistent,
 * per-service Key Encryption Key (KEK), using the strongest available
 * provider on the host (TPM2 > PKCS#11 > external secret > software >
 * ephemeral). See the crate's provider/ module docs for the protocol
 * (ECDH P-256 -> HKDF-SHA512 -> AES-256-GCM) and provider details.
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
#define HKDFGUARD_ERR_INVALID_ARGUMENT (-1)
#define HKDFGUARD_ERR_BUFFER_TOO_SMALL (-2)
#define HKDFGUARD_ERR_PROVIDER_UNAVAILABLE (-3)
#define HKDFGUARD_ERR_PROVIDER_ERROR   (-4)
#define HKDFGUARD_ERR_CRYPTO_ERROR     (-5)
#define HKDFGUARD_ERR_INTERNAL_ERROR   (-6)
#define HKDFGUARD_ERR_INVALID_UTF8     (-7)
#define HKDFGUARD_ERR_MISSING_SERVICE_NAME (-8)

/*
 * Wraps a 32-byte DEK under the persistent KEK identified by `service`.
 *
 * service:  NUL-terminated UTF-8 string, 1..=255 bytes. The logical,
 *           cross-platform identity of the KEK (e.g. "com.company.orders").
 *           Different service strings always resolve to different KEKs.
 *           NULL or an empty string returns
 *           HKDFGUARD_ERR_MISSING_SERVICE_NAME.
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
 * service:      must match the value used when the payload was wrapped;
 *                any mismatch is indistinguishable from tampering and
 *                returns HKDFGUARD_ERR_CRYPTO_ERROR. NULL or an empty
 *                string returns HKDFGUARD_ERR_MISSING_SERVICE_NAME.
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

#ifdef __cplusplus
}
#endif

#endif /* HKDFGUARD_H */
