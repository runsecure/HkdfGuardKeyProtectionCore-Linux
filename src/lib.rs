//! HKDFGuard (Linux): `ECDH(P-256) -> HKDF-SHA256 -> AES-256-GCM` DEK
//! wrapping backed by a priority-ordered chain of KEK providers (TPM2,
//! PKCS#11, external secret, software, ephemeral).
//!
//! This crate's only public interface is the stable C ABI below. No
//! Rust-specific type crosses that boundary, no provider handle (TPM,
//! OpenSSL, PKCS#11 object) is ever exposed, and no panic is allowed to
//! unwind across it -- see [`hkdfguard_wrap_dek`] and
//! [`hkdfguard_unwrap_dek`].

// `aes-gcm` 0.10 / `elliptic-curve` 0.13 (the latest versions compatible
// with each other at the time of writing) still depend on `generic-array`
// 0.14, whose `GenericArray::from_slice`/`as_slice` are deprecated in
// favor of APIs only available via a `generic-array` 1.x upgrade that
// those crates haven't taken yet. Not actionable from this crate without
// pinning to pre-release dependency versions.
#![allow(deprecated)] // crate-wide, silences that specific transitive-dependency warning everywhere

mod crypto; // ECDH -> HKDF -> AES-GCM protocol
mod error; // internal error type + public status codes
mod payload; // wrapped-payload wire format
mod provider; // provider trait + selection chain

pub use error::status; // re-export the status-code constants as part of this crate's public (Rust-side) surface

use std::ffi::CStr; // for reading the caller's NUL-terminated `service` string
use std::os::raw::{c_char, c_int}; // C-ABI-compatible integer/char types
use std::ptr; // raw-pointer helpers (`copy_nonoverlapping`, `write_bytes`)
use zeroize::Zeroize; // scrub sensitive stack buffers before returning

const MAX_SERVICE_LEN: usize = 255; // spec-mandated maximum service-name length in bytes

/// Wraps a 32-byte Data Encryption Key (DEK) under the persistent
/// Key Encryption Key (KEK) identified by `service`, using the currently
/// strongest available provider.
///
/// # Parameters
/// - `service`: NUL-terminated UTF-8 string, 1..=255 bytes, identifying
///   the KEK. The caller retains ownership; it is only read during the
///   call.
/// - `dek` / `dek_len`: the 32-byte DEK to wrap. `dek_len` must be exactly
///   32.
/// - `out` / `out_len`: on input, `*out_len` is the capacity of `out` in
///   bytes. On success, the wrapped payload is written to `out` and
///   `*out_len` is set to its length. On [`status::BUFFER_TOO_SMALL`],
///   nothing is written to `out` and `*out_len` is set to the required
///   length; the caller should retry with a larger buffer (the wrapped
///   payload for a 32-byte DEK is at most a few hundred bytes; callers
///   that want a safe fixed size can allocate 512 bytes).
///
/// # Returns
/// One of the status codes in [`status`]. Never throws/unwinds.
///
/// # Safety
/// `service` must be a valid, NUL-terminated, readable C string pointer.
/// `dek` must be readable for `dek_len` bytes. `out_len` must be a valid,
/// readable and writable pointer to an `int`. `out` must be writable for
/// at least `*out_len` bytes, unless null (in which case `*out_len` must
/// be 0).
#[no_mangle] // keeps the exported symbol name exactly `hkdfguard_wrap_dek`, not a mangled Rust name
pub extern "C" fn hkdfguard_wrap_dek(
    service: *const c_char,
    dek: *const u8,
    dek_len: c_int,
    out: *mut u8,
    out_len: *mut c_int,
) -> c_int {
    // `catch_unwind` is what makes the "no panic ever crosses the ABI"
    // guarantee real: if anything inside `wrap_impl` panics, it's caught
    // here and converted into a normal error code instead of unwinding
    // into the C caller (which would be undefined behavior).
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wrap_impl(service, dek, dek_len, out, out_len)
    })) {
        Ok(code) => code, // normal path: whatever status code `wrap_impl` returned
        Err(_) => {
            log::error!("hkdfguard: internal panic caught at hkdfguard_wrap_dek boundary");
            status::INTERNAL_ERROR // a panic means a bug in this crate, not a normal failure
        }
    }
}

/// Unwraps a payload previously produced by [`hkdfguard_wrap_dek`] for the
/// same `service`, recovering the original 32-byte DEK.
///
/// # Parameters
/// - `service`: must match the value passed to `hkdfguard_wrap_dek` when
///   this payload was produced; any mismatch is indistinguishable from
///   tampering and yields [`status::CRYPTO_ERROR`].
/// - `wrapped` / `wrapped_len`: the wrapped payload bytes.
/// - `out` / `out_len`: on input, `*out_len` is the capacity of `out`. On
///   success, the 32-byte DEK is written to `out` and `*out_len` is set to
///   32. On any failure, every byte of the caller's original buffer
///   capacity is zeroed and no key material is left in `out`.
///
/// # Returns
/// One of the status codes in [`status`]. Never throws/unwinds.
///
/// # Safety
/// Same pointer/length obligations as [`hkdfguard_wrap_dek`], applied to
/// `wrapped`/`wrapped_len` in place of `dek`/`dek_len`.
#[no_mangle]
pub extern "C" fn hkdfguard_unwrap_dek(
    service: *const c_char,
    wrapped: *const u8,
    wrapped_len: c_int,
    out: *mut u8,
    out_len: *mut c_int,
) -> c_int {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        unwrap_impl(service, wrapped, wrapped_len, out, out_len)
    })) {
        Ok(code) => code,
        Err(_) => {
            log::error!("hkdfguard: internal panic caught at hkdfguard_unwrap_dek boundary");
            // Best-effort: we don't know *out_len here without re-deref
            // (which is exactly what panicked, possibly), so we do not
            // attempt to zero `out` in the panic path -- this indicates a
            // bug in this crate, not a normal failure, and is reported at
            // ERROR level above.
            status::INTERNAL_ERROR
        }
    }
}

// Validates and borrows the caller's `service` C string as a Rust `&str`,
// or returns the appropriate status code if it's null, not UTF-8, empty,
// or too long. Shared by both `wrap_impl` and `unwrap_impl`.
fn cstr_to_service<'a>(ptr: *const c_char) -> Result<&'a str, c_int> {
    if ptr.is_null() {
        return Err(status::INVALID_ARGUMENT);
    }
    // SAFETY: caller contract (see function-level Safety docs) guarantees
    // `ptr` is a valid, NUL-terminated, readable C string for the duration
    // of this call.
    let cstr = unsafe { CStr::from_ptr(ptr) };
    let s = cstr.to_str().map_err(|_| status::INVALID_UTF8)?; // reject non-UTF-8 byte sequences
    if s.is_empty() || s.len() > MAX_SERVICE_LEN {
        return Err(status::INVALID_ARGUMENT); // enforce the 1..=255 byte length rule
    }
    Ok(s)
}

// The actual logic behind `hkdfguard_wrap_dek`, running inside the
// `catch_unwind` wrapper above. Returns a plain status code; never panics
// intentionally (validates everything before touching unsafe pointers).
fn wrap_impl(
    service: *const c_char,
    dek: *const u8,
    dek_len: c_int,
    out: *mut u8,
    out_len: *mut c_int,
) -> c_int {
    if dek.is_null() || out_len.is_null() {
        return status::INVALID_ARGUMENT;
    }
    if dek_len != crypto::DEK_LEN as c_int {
        return status::INVALID_ARGUMENT; // DEK must be exactly 32 bytes, per spec
    }

    // SAFETY: out_len is non-null per check above; caller contract
    // guarantees it points at a valid, initialized `int`.
    let capacity = unsafe { *out_len }; // how many bytes the caller says `out` can hold
    if capacity < 0 {
        return status::INVALID_ARGUMENT; // a negative capacity makes no sense
    }

    let service_str = match cstr_to_service(service) {
        Ok(s) => s,
        Err(code) => return code, // bad service string: bail out with the specific reason
    };

    // SAFETY: dek is non-null and dek_len == DEK_LEN; caller contract
    // guarantees dek is readable for that many bytes.
    let dek_slice = unsafe { std::slice::from_raw_parts(dek, crypto::DEK_LEN) }; // borrow the caller's DEK bytes as a Rust slice
    let mut dek_array = [0u8; crypto::DEK_LEN]; // owned, fixed-size copy (the crypto layer wants `&[u8; 32]`)
    dek_array.copy_from_slice(dek_slice);

    let result = crypto::wrap(service_str, &dek_array); // do the actual ECDH -> HKDF -> AES-GCM work
    dek_array.zeroize(); // our local copy of the plaintext DEK is no longer needed; scrub it now

    let wrapped = match result {
        Ok(w) => w,
        Err(e) => {
            log::error!("hkdfguard: wrap failed for service (redacted): {e}"); // logs only the error description, never key material
            return e.status_code();
        }
    };

    if (capacity as usize) < wrapped.len() {
        // caller's buffer is too small: report the required size and write nothing
        // SAFETY: out_len is non-null (checked above).
        unsafe { *out_len = wrapped.len() as c_int };
        return status::BUFFER_TOO_SMALL;
    }
    if out.is_null() {
        return status::INVALID_ARGUMENT; // capacity was fine (possibly 0) but there's nowhere to actually write
    }

    // SAFETY: out is non-null and, per caller contract, writable for at
    // least `capacity` >= wrapped.len() bytes.
    unsafe {
        ptr::copy_nonoverlapping(wrapped.as_ptr(), out, wrapped.len()); // copy the wrapped payload into the caller's buffer
        *out_len = wrapped.len() as c_int; // tell the caller exactly how many bytes were written
    }
    status::OK
}

// The actual logic behind `hkdfguard_unwrap_dek`, running inside the
// `catch_unwind` wrapper above.
fn unwrap_impl(
    service: *const c_char,
    wrapped: *const u8,
    wrapped_len: c_int,
    out: *mut u8,
    out_len: *mut c_int,
) -> c_int {
    if wrapped.is_null() || out_len.is_null() {
        return status::INVALID_ARGUMENT;
    }

    // SAFETY: out_len is non-null; caller contract guarantees it points
    // at a valid, initialized `int`.
    let capacity = unsafe { *out_len }; // the caller's declared output buffer size, captured before we might overwrite *out_len

    // Closure so every failure path below can zero the caller's buffer
    // with one call, using the *original* capacity captured above.
    let zero_out_buffer = || {
        if !out.is_null() && capacity > 0 {
            // SAFETY: out is non-null and, per caller contract, writable
            // for at least `capacity` bytes (the original capacity the
            // caller declared before this call).
            unsafe { ptr::write_bytes(out, 0u8, capacity as usize) }; // overwrite the entire declared buffer with zeros
        }
    };

    if wrapped_len < 0 || capacity < 0 {
        zero_out_buffer();
        return status::INVALID_ARGUMENT;
    }

    let service_str = match cstr_to_service(service) {
        Ok(s) => s,
        Err(code) => {
            zero_out_buffer(); // even an invalid-argument failure must leave `out` zeroed, per spec
            return code;
        }
    };

    // SAFETY: wrapped is non-null and wrapped_len >= 0; caller contract
    // guarantees it is readable for that many bytes.
    let wrapped_slice =
        unsafe { std::slice::from_raw_parts(wrapped, wrapped_len as usize) }; // borrow the caller's wrapped-payload bytes

    let mut dek = match crypto::unwrap(service_str, wrapped_slice) {
        Ok(dek) => dek, // recovered plaintext DEK, still only in this local variable
        Err(e) => {
            log::error!("hkdfguard: unwrap failed for service (redacted): {e}"); // log the reason, never the key material
            zero_out_buffer();
            return e.status_code();
        }
    };

    if (capacity as usize) < crypto::DEK_LEN {
        dek.zeroize(); // don't leave the recovered DEK sitting in a local variable longer than necessary
        zero_out_buffer();
        // SAFETY: out_len is non-null (checked above).
        unsafe { *out_len = crypto::DEK_LEN as c_int }; // tell the caller exactly how big a buffer they need (always 32)
        return status::BUFFER_TOO_SMALL;
    }
    if out.is_null() {
        dek.zeroize();
        return status::INVALID_ARGUMENT;
    }

    // SAFETY: out is non-null and, per caller contract, writable for at
    // least `capacity` >= DEK_LEN bytes.
    unsafe {
        ptr::copy_nonoverlapping(dek.as_ptr(), out, crypto::DEK_LEN); // hand the recovered DEK to the caller
        *out_len = crypto::DEK_LEN as c_int; // always exactly 32 on success
    }
    dek.zeroize(); // our local copy has served its purpose; scrub it now rather than waiting for scope exit
    status::OK
}

#[cfg(test)]
mod ffi_tests {
    use super::*; // bring the exported functions + `status` into scope
    use serial_test::serial; // these tests mutate shared env vars, so they must run one at a time
    use std::ffi::CString; // to build NUL-terminated strings to pass across the "FFI boundary" in tests
    use tempfile::tempdir; // throwaway directory for the software provider's storage

    // Points the software provider at a fresh temp directory and disables
    // the external-secret provider so tests are deterministic.
    fn with_isolated_software_provider<F: FnOnce()>(f: F) {
        let dir = tempdir().unwrap();
        std::env::set_var("HKDFGUARD_SOFTWARE_DIR", dir.path());
        std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", "/nonexistent-for-tests");
        f();
        std::env::remove_var("HKDFGUARD_SOFTWARE_DIR");
        std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
    }

    #[test]
    #[serial]
    fn ffi_round_trip() {
        with_isolated_software_provider(|| {
            let service = CString::new("com.company.orders").unwrap(); // NUL-terminated, as the C ABI requires
            let dek = [0xABu8; 32];
            let mut wrapped_buf = [0u8; 512]; // generously-sized output buffer
            let mut wrapped_len: c_int = wrapped_buf.len() as c_int; // declare its capacity

            let rc = hkdfguard_wrap_dek(
                service.as_ptr(),
                dek.as_ptr(),
                32,
                wrapped_buf.as_mut_ptr(),
                &mut wrapped_len,
            );
            assert_eq!(rc, status::OK);

            let mut out = [0u8; 32]; // exact-size buffer for the recovered DEK
            let mut out_len: c_int = out.len() as c_int;
            let rc = hkdfguard_unwrap_dek(
                service.as_ptr(),
                wrapped_buf.as_ptr(),
                wrapped_len, // the actual wrapped length reported by the wrap call above
                out.as_mut_ptr(),
                &mut out_len,
            );
            assert_eq!(rc, status::OK);
            assert_eq!(out_len, 32);
            assert_eq!(out, dek); // must recover exactly the original DEK
        });
    }

    #[test]
    fn rejects_wrong_dek_length() {
        let service = CString::new("com.company.orders").unwrap();
        let dek = [0u8; 16]; // deliberately wrong size (should be 32)
        let mut wrapped_buf = [0u8; 512];
        let mut wrapped_len: c_int = wrapped_buf.len() as c_int;

        let rc = hkdfguard_wrap_dek(
            service.as_ptr(),
            dek.as_ptr(),
            16, // claims 16, which must be rejected regardless of the actual buffer contents
            wrapped_buf.as_mut_ptr(),
            &mut wrapped_len,
        );
        assert_eq!(rc, status::INVALID_ARGUMENT);
    }

    #[test]
    #[serial]
    fn buffer_too_small_reports_required_size_without_writing() {
        with_isolated_software_provider(|| {
            let service = CString::new("com.company.orders").unwrap();
            let dek = [0x55u8; 32];
            let mut tiny = [0xFFu8; 4]; // way too small to hold a wrapped payload
            let mut tiny_len: c_int = tiny.len() as c_int;

            let rc = hkdfguard_wrap_dek(
                service.as_ptr(),
                dek.as_ptr(),
                32,
                tiny.as_mut_ptr(),
                &mut tiny_len,
            );
            assert_eq!(rc, status::BUFFER_TOO_SMALL);
            assert!(tiny_len > 4); // *out_len was updated to the actually-required size
            assert_eq!(tiny, [0xFFu8; 4], "must not write on BUFFER_TOO_SMALL"); // buffer contents untouched
        });
    }

    #[test]
    #[serial]
    fn unwrap_failure_zeroes_caller_buffer() {
        with_isolated_software_provider(|| {
            let service = CString::new("com.company.orders").unwrap();
            let garbage = [0u8; 8]; // not a valid wrapped payload at all
            let mut out = [0xAAu8; 32]; // pre-filled with a recognizable non-zero pattern
            let mut out_len: c_int = out.len() as c_int;

            let rc = hkdfguard_unwrap_dek(
                service.as_ptr(),
                garbage.as_ptr(),
                garbage.len() as c_int,
                out.as_mut_ptr(),
                &mut out_len,
            );
            assert_ne!(rc, status::OK); // must fail, since `garbage` isn't a valid payload
            assert_eq!(out, [0u8; 32], "output buffer must be zeroed on failure"); // and the buffer must be scrubbed regardless
        });
    }

    #[test]
    fn null_service_is_invalid_argument() {
        let dek = [0u8; 32];
        let mut out = [0u8; 512];
        let mut out_len: c_int = out.len() as c_int;
        let rc = hkdfguard_wrap_dek(
            std::ptr::null(), // deliberately null service pointer
            dek.as_ptr(),
            32,
            out.as_mut_ptr(),
            &mut out_len,
        );
        assert_eq!(rc, status::INVALID_ARGUMENT);
    }
}
