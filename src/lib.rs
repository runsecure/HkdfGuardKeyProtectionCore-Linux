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
#![allow(deprecated)]

mod crypto;
mod error;
mod payload;
mod provider;

pub use error::status;

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::ptr;
use zeroize::Zeroize;

const MAX_SERVICE_LEN: usize = 255;

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
#[no_mangle]
pub extern "C" fn hkdfguard_wrap_dek(
    service: *const c_char,
    dek: *const u8,
    dek_len: c_int,
    out: *mut u8,
    out_len: *mut c_int,
) -> c_int {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wrap_impl(service, dek, dek_len, out, out_len)
    })) {
        Ok(code) => code,
        Err(_) => {
            log::error!("hkdfguard: internal panic caught at hkdfguard_wrap_dek boundary");
            status::INTERNAL_ERROR
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

fn cstr_to_service<'a>(ptr: *const c_char) -> Result<&'a str, c_int> {
    if ptr.is_null() {
        return Err(status::INVALID_ARGUMENT);
    }
    // SAFETY: caller contract (see function-level Safety docs) guarantees
    // `ptr` is a valid, NUL-terminated, readable C string for the duration
    // of this call.
    let cstr = unsafe { CStr::from_ptr(ptr) };
    let s = cstr.to_str().map_err(|_| status::INVALID_UTF8)?;
    if s.is_empty() || s.len() > MAX_SERVICE_LEN {
        return Err(status::INVALID_ARGUMENT);
    }
    Ok(s)
}

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
        return status::INVALID_ARGUMENT;
    }

    // SAFETY: out_len is non-null per check above; caller contract
    // guarantees it points at a valid, initialized `int`.
    let capacity = unsafe { *out_len };
    if capacity < 0 {
        return status::INVALID_ARGUMENT;
    }

    let service_str = match cstr_to_service(service) {
        Ok(s) => s,
        Err(code) => return code,
    };

    // SAFETY: dek is non-null and dek_len == DEK_LEN; caller contract
    // guarantees dek is readable for that many bytes.
    let dek_slice = unsafe { std::slice::from_raw_parts(dek, crypto::DEK_LEN) };
    let mut dek_array = [0u8; crypto::DEK_LEN];
    dek_array.copy_from_slice(dek_slice);

    let result = crypto::wrap(service_str, &dek_array);
    dek_array.zeroize();

    let wrapped = match result {
        Ok(w) => w,
        Err(e) => {
            log::error!("hkdfguard: wrap failed for service (redacted): {e}");
            return e.status_code();
        }
    };

    if (capacity as usize) < wrapped.len() {
        // SAFETY: out_len is non-null (checked above).
        unsafe { *out_len = wrapped.len() as c_int };
        return status::BUFFER_TOO_SMALL;
    }
    if out.is_null() {
        return status::INVALID_ARGUMENT;
    }

    // SAFETY: out is non-null and, per caller contract, writable for at
    // least `capacity` >= wrapped.len() bytes.
    unsafe {
        ptr::copy_nonoverlapping(wrapped.as_ptr(), out, wrapped.len());
        *out_len = wrapped.len() as c_int;
    }
    status::OK
}

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
    let capacity = unsafe { *out_len };

    let zero_out_buffer = || {
        if !out.is_null() && capacity > 0 {
            // SAFETY: out is non-null and, per caller contract, writable
            // for at least `capacity` bytes (the original capacity the
            // caller declared before this call).
            unsafe { ptr::write_bytes(out, 0u8, capacity as usize) };
        }
    };

    if wrapped_len < 0 || capacity < 0 {
        zero_out_buffer();
        return status::INVALID_ARGUMENT;
    }

    let service_str = match cstr_to_service(service) {
        Ok(s) => s,
        Err(code) => {
            zero_out_buffer();
            return code;
        }
    };

    // SAFETY: wrapped is non-null and wrapped_len >= 0; caller contract
    // guarantees it is readable for that many bytes.
    let wrapped_slice =
        unsafe { std::slice::from_raw_parts(wrapped, wrapped_len as usize) };

    let mut dek = match crypto::unwrap(service_str, wrapped_slice) {
        Ok(dek) => dek,
        Err(e) => {
            log::error!("hkdfguard: unwrap failed for service (redacted): {e}");
            zero_out_buffer();
            return e.status_code();
        }
    };

    if (capacity as usize) < crypto::DEK_LEN {
        dek.zeroize();
        zero_out_buffer();
        // SAFETY: out_len is non-null (checked above).
        unsafe { *out_len = crypto::DEK_LEN as c_int };
        return status::BUFFER_TOO_SMALL;
    }
    if out.is_null() {
        dek.zeroize();
        return status::INVALID_ARGUMENT;
    }

    // SAFETY: out is non-null and, per caller contract, writable for at
    // least `capacity` >= DEK_LEN bytes.
    unsafe {
        ptr::copy_nonoverlapping(dek.as_ptr(), out, crypto::DEK_LEN);
        *out_len = crypto::DEK_LEN as c_int;
    }
    dek.zeroize();
    status::OK
}

#[cfg(test)]
mod ffi_tests {
    use super::*;
    use serial_test::serial;
    use std::ffi::CString;
    use tempfile::tempdir;

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
            let service = CString::new("com.company.orders").unwrap();
            let dek = [0xABu8; 32];
            let mut wrapped_buf = [0u8; 512];
            let mut wrapped_len: c_int = wrapped_buf.len() as c_int;

            let rc = hkdfguard_wrap_dek(
                service.as_ptr(),
                dek.as_ptr(),
                32,
                wrapped_buf.as_mut_ptr(),
                &mut wrapped_len,
            );
            assert_eq!(rc, status::OK);

            let mut out = [0u8; 32];
            let mut out_len: c_int = out.len() as c_int;
            let rc = hkdfguard_unwrap_dek(
                service.as_ptr(),
                wrapped_buf.as_ptr(),
                wrapped_len,
                out.as_mut_ptr(),
                &mut out_len,
            );
            assert_eq!(rc, status::OK);
            assert_eq!(out_len, 32);
            assert_eq!(out, dek);
        });
    }

    #[test]
    fn rejects_wrong_dek_length() {
        let service = CString::new("com.company.orders").unwrap();
        let dek = [0u8; 16];
        let mut wrapped_buf = [0u8; 512];
        let mut wrapped_len: c_int = wrapped_buf.len() as c_int;

        let rc = hkdfguard_wrap_dek(
            service.as_ptr(),
            dek.as_ptr(),
            16,
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
            let mut tiny = [0xFFu8; 4];
            let mut tiny_len: c_int = tiny.len() as c_int;

            let rc = hkdfguard_wrap_dek(
                service.as_ptr(),
                dek.as_ptr(),
                32,
                tiny.as_mut_ptr(),
                &mut tiny_len,
            );
            assert_eq!(rc, status::BUFFER_TOO_SMALL);
            assert!(tiny_len > 4);
            assert_eq!(tiny, [0xFFu8; 4], "must not write on BUFFER_TOO_SMALL");
        });
    }

    #[test]
    #[serial]
    fn unwrap_failure_zeroes_caller_buffer() {
        with_isolated_software_provider(|| {
            let service = CString::new("com.company.orders").unwrap();
            let garbage = [0u8; 8];
            let mut out = [0xAAu8; 32];
            let mut out_len: c_int = out.len() as c_int;

            let rc = hkdfguard_unwrap_dek(
                service.as_ptr(),
                garbage.as_ptr(),
                garbage.len() as c_int,
                out.as_mut_ptr(),
                &mut out_len,
            );
            assert_ne!(rc, status::OK);
            assert_eq!(out, [0u8; 32], "output buffer must be zeroed on failure");
        });
    }

    #[test]
    fn null_service_is_invalid_argument() {
        let dek = [0u8; 32];
        let mut out = [0u8; 512];
        let mut out_len: c_int = out.len() as c_int;
        let rc = hkdfguard_wrap_dek(
            std::ptr::null(),
            dek.as_ptr(),
            32,
            out.as_mut_ptr(),
            &mut out_len,
        );
        assert_eq!(rc, status::INVALID_ARGUMENT);
    }
}
