//! HKDFGuard (Linux): `ECDH(P-256) -> HKDF-SHA512 -> AES-256-GCM` DEK
//! wrapping backed by a priority-ordered chain of KEK providers (TPM2,
//! PKCS#11, external secret, ephemeral).
//!
//! This crate's only public interface is the stable C ABI below. No
//! Rust-specific type crosses that boundary, no provider handle (TPM,
//! OpenSSL, PKCS#11 object) is ever exposed, and no panic is allowed to
//! unwind across it -- see [`hkdfguard_wrap_dek`], [`hkdfguard_unwrap_dek`],
//! and [`hkdfguard_generate_and_wrap_dek`].

// `aes-gcm` 0.10 / `elliptic-curve` 0.13 (the latest versions compatible
// with each other at the time of writing) still depend on `generic-array`
// 0.14, whose `GenericArray::from_slice`/`as_slice` are deprecated in
// favor of APIs only available via a `generic-array` 1.x upgrade that
// those crates haven't taken yet. Not actionable from this crate without
// pinning to pre-release dependency versions.
#![allow(deprecated)] // crate-wide, silences that specific transitive-dependency warning everywhere
// The `[lib] name` in Cargo.toml is deliberately `HkdfGuardKeyProtectionLinux`
// (matching the required output artifact name), not snake_case; silence
// rustc's stylistic complaint about that specific, intentional choice.
#![allow(non_snake_case)]

mod crypto; // ECDH -> HKDF -> AES-GCM protocol
mod error; // internal error type + public status codes
mod payload; // wrapped-payload wire format
mod policy; // administrative key-selection policy (/etc/hkdfguard/policy.toml)
mod provider; // provider trait + selection chain
mod secure_file; // hardened, check-then-read-safe file access + self-wiping SecretBuffer

pub use error::status; // re-export the status-code constants as part of this crate's public (Rust-side) surface

use rand_core::{OsRng, RngCore}; // the OS CSPRNG, used by hkdfguard_generate_and_wrap_dek below
use std::os::raw::{c_char, c_int}; // C-ABI-compatible integer/char types
use std::ptr; // raw-pointer helpers (`copy_nonoverlapping`, `write_bytes`)
use std::sync::atomic::{AtomicU32, Ordering}; // per-process count of setup calls, for the misuse warning
use std::sync::Mutex; // serializes setup calls (see `gated_setup`)
use std::time::{Duration, Instant}; // the setup-call latency floor
use zeroize::Zeroize; // scrub sensitive stack buffers before returning

const MAX_SERVICE_LEN: usize = 128; // spec-mandated maximum service-name length in bytes

/// Serializes every setup call (`hkdfguard_create_kek`,
/// `hkdfguard_kek_exists`) so that, combined with the latency floor in
/// `gated_setup`, their aggregate rate is capped at one per
/// `policy::setup_min_delay()` regardless of how many threads call in.
static SETUP_GATE: Mutex<()> = Mutex::new(());

/// How many setup calls this process has made. They're meant to happen
/// once per application startup, so a count well beyond that is the
/// signature of a caller looping on them -- see `SETUP_CALLS_WARN_AT`.
static SETUP_CALLS: AtomicU32 = AtomicU32::new(0);

/// Setup-call count past which a warning is logged (once). Generous enough
/// for a multi-service application's genuine startup, small enough that a
/// hot loop trips it within seconds.
const SETUP_CALLS_WARN_AT: u32 = 10;

/// Test-only override of the setup latency floor. `Some(d)` uses `d`
/// instead of consulting the policy; `None` uses the policy exactly as
/// production does. Defaults to `Some(Duration::ZERO)` so the test suite's
/// dozens of setup calls don't each cost a second; the tests that exercise
/// the floor itself set it explicitly and are `#[serial]`.
#[cfg(test)]
static SETUP_DELAY_OVERRIDE_FOR_TESTS: Mutex<Option<Duration>> = Mutex::new(Some(Duration::ZERO));

#[cfg(test)]
fn set_setup_delay_for_tests(override_delay: Option<Duration>) {
    *SETUP_DELAY_OVERRIDE_FOR_TESTS.lock().unwrap_or_else(|p| p.into_inner()) = override_delay;
}

fn effective_setup_min_delay() -> Duration {
    #[cfg(test)]
    {
        if let Some(d) = *SETUP_DELAY_OVERRIDE_FOR_TESTS.lock().unwrap_or_else(|p| p.into_inner()) {
            return d;
        }
    }
    policy::setup_min_delay()
}

/// Runs `f` (the provider-touching part of a setup call) under the setup
/// gate: serialized against every other setup call, and not returning
/// until at least `policy::setup_min_delay()` has elapsed since entry --
/// whatever `f` returned, and however quickly. Argument validation happens
/// *before* callers reach this, so an invalid pointer or service string
/// still fails immediately; only calls that would actually reach a
/// provider pay the floor. See `policy::setup_min_delay` for the rationale.
fn gated_setup<T>(f: impl FnOnce() -> T) -> T {
    // A panic inside an earlier setup call (caught at the FFI boundary)
    // poisons the mutex; that's not a reason to stop gating, so recover
    // the guard rather than propagating the poison.
    let _serialized = SETUP_GATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let entered = Instant::now();
    let floor = effective_setup_min_delay();

    let result = f();

    let count = SETUP_CALLS.fetch_add(1, Ordering::Relaxed) + 1;
    if count == SETUP_CALLS_WARN_AT + 1 {
        log::warn!(
            "hkdfguard: more than {SETUP_CALLS_WARN_AT} create_kek/kek_exists calls in this process; \
             these are meant to run once per application startup, and each costs a fresh provider \
             connection plus at least {} ms",
            floor.as_millis()
        );
    }

    if let Some(remaining) = floor.checked_sub(entered.elapsed()) {
        if !remaining.is_zero() {
            std::thread::sleep(remaining);
        }
    }
    result
}

/// Wraps a 32-byte Data Encryption Key (DEK) under the persistent
/// Key Encryption Key (KEK) identified by `service`, using the currently
/// strongest available provider.
///
/// # Parameters
/// - `service`: NUL-terminated UTF-8 string, 1..=128 bytes, identifying
///   the KEK; only ASCII alphanumeric characters and `.` are allowed, and
///   it may not start with `.` or contain two consecutive dots (`..`). A
///   null pointer, an empty string, a string over 128 bytes, non-UTF-8
///   bytes, a disallowed character, or a dot rule violation all yield
///   [`status::INVALID_SERVICE_NAME`]. Case-insensitive: normalized
///   to lowercase internally, so e.g. `"Com.Example.Orders"` and
///   `"com.example.orders"` always resolve to the same KEK. The caller
///   retains ownership; it is only read during the call.
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
///   this payload was produced (case-insensitively -- see that function's
///   doc comment); any other mismatch is indistinguishable from tampering
///   and yields [`status::CRYPTO_ERROR`]. An invalid service string (see
///   `hkdfguard_wrap_dek`'s doc comment) yields
///   [`status::INVALID_SERVICE_NAME`].
/// - `wrapped` / `wrapped_len`: the wrapped payload bytes.
/// - `out` / `out_len`: on input, `*out_len` is the capacity of `out`. On
///   success, the 32-byte DEK is written to `out` and `*out_len` is set to
///   32. On any failure, including a caught panic, every byte of the
///   caller's original buffer capacity is zeroed and no key material is
///   left in `out` -- unless `out_len` is NULL, in which case there is no
///   declared capacity and `out` is left untouched.
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
    // Captured before any work, so even a caught panic can honor the
    // "zeroed on every failure" contract. Reading through a raw pointer
    // can't panic; a NULL `out_len` just means there's no known capacity.
    let capacity = declared_capacity(out_len);
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        unwrap_impl(service, wrapped, wrapped_len, out, out_len, capacity)
    })) {
        Ok(code) => code,
        Err(_) => {
            log::error!("hkdfguard: internal panic caught at hkdfguard_unwrap_dek boundary");
            zero_caller_buffer(out, capacity);
            status::INTERNAL_ERROR
        }
    }
}

// `*out_len` as the caller declared it, or 0 when `out_len` is NULL.
fn declared_capacity(out_len: *const c_int) -> c_int {
    if out_len.is_null() {
        return 0;
    }
    // SAFETY: non-null; caller contract guarantees a valid, initialized `int`.
    unsafe { *out_len }
}

// Zeroes the caller's whole declared `out` buffer, for every unwrap
// failure path. A no-op when there is no buffer or no positive capacity
// (a NULL `out_len` gives 0), since then nothing can be safely written.
fn zero_caller_buffer(out: *mut u8, capacity: c_int) {
    if !out.is_null() && capacity > 0 {
        // SAFETY: out is non-null and, per caller contract, writable for
        // the `capacity` bytes the caller declared on entry.
        unsafe { ptr::write_bytes(out, 0u8, capacity as usize) };
    }
}

/// Ensures a persistent KEK exists for `service`, creating one (on the
/// strongest available, policy-allowed provider) if it does not already.
/// Idempotent: safe to call again for a `service` that already has one --
/// this just confirms it's still there, doesn't rotate or recreate it.
///
/// This is the *only* way a KEK ever gets created; [`hkdfguard_wrap_dek`]
/// and [`hkdfguard_generate_and_wrap_dek`] both fail with
/// [`status::KEK_NOT_FOUND`] if called before this for a given `service`.
///
/// # Parameters
/// - `service`: see [`hkdfguard_wrap_dek`].
///
/// # Returns
/// One of the status codes in [`status`]. Never throws/unwinds.
///
/// # Safety
/// `service` must be a valid, NUL-terminated, readable C string pointer.
#[no_mangle]
pub extern "C" fn hkdfguard_create_kek(service: *const c_char) -> c_int {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| create_kek_impl(service))) {
        Ok(code) => code,
        Err(_) => {
            log::error!("hkdfguard: internal panic caught at hkdfguard_create_kek boundary");
            status::INTERNAL_ERROR
        }
    }
}

/// Reports whether a persistent KEK already exists for `service`, without
/// creating one. `Ok`/[`status::OK`] with `*exists` set to `0` means the
/// chain was fully walked and nothing has one yet -- call
/// [`hkdfguard_create_kek`] to provision one.
///
/// # Parameters
/// - `service`: see [`hkdfguard_wrap_dek`].
/// - `exists`: out-parameter; on [`status::OK`], set to `1` if a KEK
///   exists for `service`, `0` otherwise. Untouched on any other status.
///
/// # Returns
/// One of the status codes in [`status`]. Never throws/unwinds.
///
/// # Safety
/// `service` must be a valid, NUL-terminated, readable C string pointer.
/// `exists` must be a valid, writable pointer to an `int`.
#[no_mangle]
pub extern "C" fn hkdfguard_kek_exists(service: *const c_char, exists: *mut c_int) -> c_int {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| kek_exists_impl(service, exists))) {
        Ok(code) => code,
        Err(_) => {
            log::error!("hkdfguard: internal panic caught at hkdfguard_kek_exists boundary");
            status::INTERNAL_ERROR
        }
    }
}

/// Generates a fresh, cryptographically random 32-byte DEK and immediately
/// wraps it under the persistent KEK identified by `service`, in one call --
/// for callers that want a brand new Ephemeral Data Protection Key without
/// having to source their own randomness.
///
/// The newly generated plaintext DEK never crosses this ABI boundary: it is
/// zeroed internally the instant it has been wrapped, before this function
/// returns. To recover it later, unwrap the resulting payload via
/// [`hkdfguard_unwrap_dek`], passing the same `service`.
///
/// # Parameters
/// Same as [`hkdfguard_wrap_dek`], minus `dek`/`dek_len`.
///
/// # Returns
/// One of the status codes in [`status`]. Never throws/unwinds.
///
/// # Safety
/// Same pointer/length obligations as [`hkdfguard_wrap_dek`]'s `service`,
/// `out`, and `out_len` parameters.
#[no_mangle]
pub extern "C" fn hkdfguard_generate_and_wrap_dek(
    service: *const c_char,
    out: *mut u8,
    out_len: *mut c_int,
) -> c_int {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        generate_and_wrap_impl(service, out, out_len)
    })) {
        Ok(code) => code,
        Err(_) => {
            log::error!("hkdfguard: internal panic caught at hkdfguard_generate_and_wrap_dek boundary");
            status::INTERNAL_ERROR
        }
    }
}

/// Hardens the *calling process* against memory disclosure: disables core
/// dumps and, on Linux, marks the process non-dumpable, which also stops
/// other non-root processes running as the same user from attaching with
/// `ptrace` or reading `/proc/<pid>/mem`. Keys and DEKs that pass through
/// this library's memory then can't be recovered from a crash dump or a
/// same-user debugger.
///
/// Opt-in, because it changes process-wide state the host application
/// owns: debuggers and crash reporters stop working for the process.
/// Call it once, early in startup, and *after* any privilege change --
/// the kernel resets the dumpable flag when a process's credentials
/// change. Root, and a process with `CAP_SYS_PTRACE`, can still inspect
/// the process; that is host configuration (see README).
///
/// Linux: sets `RLIMIT_CORE` to 0 (soft and hard, so it can't be raised
/// again) and `prctl(PR_SET_DUMPABLE, 0)`. Other platforms: only the core
/// limit. Idempotent.
///
/// # Returns
/// [`status::OK`], or [`status::PROCESS_HARDENING_FAILED`] if either step
/// failed (logged with the OS error). Never throws/unwinds.
#[no_mangle]
pub extern "C" fn hkdfguard_harden_process() -> c_int {
    match std::panic::catch_unwind(harden_process_impl) {
        Ok(code) => code,
        Err(_) => {
            log::error!("hkdfguard: internal panic caught at hkdfguard_harden_process boundary");
            status::INTERNAL_ERROR
        }
    }
}

fn harden_process_impl() -> c_int {
    let no_core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: setrlimit reads a valid, fully initialized rlimit.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) } != 0 {
        log::error!(
            "hkdfguard: could not disable core dumps (setrlimit RLIMIT_CORE): {}",
            std::io::Error::last_os_error()
        );
        return status::PROCESS_HARDENING_FAILED;
    }

    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_SET_DUMPABLE takes one integer argument; the rest are ignored.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong, 0, 0, 0) } != 0 {
            log::error!(
                "hkdfguard: could not mark the process non-dumpable (prctl PR_SET_DUMPABLE): {}",
                std::io::Error::last_os_error()
            );
            return status::PROCESS_HARDENING_FAILED;
        }
    }

    status::OK
}

// The actual logic behind `hkdfguard_generate_and_wrap_dek`, running inside
// the `catch_unwind` wrapper above. Generates the DEK, then delegates to
// `wrap_impl` (the exact same validation/wrap/copy-out logic
// `hkdfguard_wrap_dek` uses) so that crypto sequence exists in exactly one
// place rather than being duplicated between the two ABI entry points.
fn generate_and_wrap_impl(
    service: *const c_char,
    out: *mut u8,
    out_len: *mut c_int,
) -> c_int {
    // Cryptographically random 32-byte DEK, sourced from the OS CSPRNG --
    // the same `OsRng` this crate's own CLI tool
    // (`hkdfguard-v1-initialize`) uses for its secure-overwrite passes, and
    // the Linux analog of Windows' `BCryptGenRandom` / macOS's
    // `SecRandomCopyBytes` used for the equivalent purpose elsewhere in
    // this project.
    let mut dek = [0u8; crypto::DEK_LEN];
    OsRng.fill_bytes(&mut dek);

    let code = wrap_impl(service, dek.as_ptr(), crypto::DEK_LEN as c_int, out, out_len);
    dek.zeroize(); // our local copy of the freshly generated DEK is no longer needed; scrub it now
    code
}

// Validates the caller's `service` C string and normalizes it to the
// crate's canonical form, or returns the appropriate status code if it's
// null, not UTF-8, empty, too long, or contains a disallowed character.
// Shared by both `wrap_impl` and `unwrap_impl` (and so, transitively, by
// `hkdfguard_generate_and_wrap_dek` too, via `wrap_impl`).
//
// Normalization is lowercasing: two service strings that differ only in
// case (e.g. "Com.Example.Orders" and "com.example.orders") always
// resolve to the exact same KEK, on both the wrap and unwrap side, since
// both go through this same function.
fn cstr_to_service(ptr: *const c_char) -> Result<String, c_int> {
    if ptr.is_null() {
        return Err(status::INVALID_SERVICE_NAME); // no service string supplied at all
    }
    // Bounded scan for the terminator, rather than `CStr::from_ptr`, which
    // would read until it found a NUL -- however far away that was --
    // *before* the length rule below could apply. A caller that passes an
    // unterminated buffer is violating the contract either way, but this
    // reads at most MAX_SERVICE_LEN + 1 bytes and then fails safe, instead
    // of over-reading until it happens to hit a zero byte. Byte-by-byte,
    // so a correctly terminated short string never has anything past its
    // own NUL touched.
    let mut len = 0usize;
    loop {
        if len > MAX_SERVICE_LEN {
            return Err(status::INVALID_SERVICE_NAME); // no NUL within 129 bytes: either over the limit or unterminated; reject without reading further
        }
        // SAFETY: caller contract (see function-level Safety docs)
        // guarantees `ptr` points to a readable, NUL-terminated string. Each
        // read is at offset `len` <= MAX_SERVICE_LEN, and the loop stops at
        // the first NUL, so no byte beyond the terminator -- and never more
        // than MAX_SERVICE_LEN + 1 bytes in total -- is ever read.
        if unsafe { *ptr.add(len) } == 0 {
            break;
        }
        len += 1;
    }
    if len == 0 {
        return Err(status::INVALID_SERVICE_NAME); // a service string was supplied, but it's empty
    }
    // SAFETY: the loop above established that `len` bytes starting at `ptr`
    // are readable and non-NUL.
    let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, len) };
    let s = std::str::from_utf8(bytes).map_err(|_| status::INVALID_SERVICE_NAME)?; // reject non-UTF-8 byte sequences
    if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.') {
        return Err(status::INVALID_SERVICE_NAME); // only ASCII alphanumeric characters and '.' are allowed
    }
    if s.starts_with('.') || s.contains("..") {
        // A service name is used directly as a file name by the
        // external-secret provider (`<mount>/<service>`), so it must
        // never be able to name "." (the mount itself), ".." (its
        // parent), or a hidden dot-file, and never contain an empty
        // label between dots.
        return Err(status::INVALID_SERVICE_NAME);
    }
    Ok(normalize_service(s))
}

// The canonical form a validated service string is reduced to: lowercase,
// so case never affects KEK identity. Exposed at `pub(crate)` (rather than
// inlined into `cstr_to_service` alone) so other code that needs to match
// this exact normalization -- e.g. the TPM2 provider's conformance tests,
// which check that varying a service string's case doesn't change the key
// the same way production's own normalization guarantees -- shares this
// one definition instead of risking drift from a second copy of it.
pub(crate) fn normalize_service(s: &str) -> String {
    s.to_ascii_lowercase()
}

// The actual logic behind `hkdfguard_create_kek`, running inside the
// `catch_unwind` wrapper above.
fn create_kek_impl(service: *const c_char) -> c_int {
    let service_str = match cstr_to_service(service) {
        Ok(s) => s,
        Err(code) => return code,
    };

    gated_setup(|| match provider::create_kek(&service_str) {
        Ok(_) => status::OK,
        Err(e) => {
            log::error!("hkdfguard: create_kek failed for service (redacted): {e}"); // never log the service name or key material
            e.status_code()
        }
    })
}

// The actual logic behind `hkdfguard_kek_exists`, running inside the
// `catch_unwind` wrapper above.
fn kek_exists_impl(service: *const c_char, exists: *mut c_int) -> c_int {
    if exists.is_null() {
        return status::INVALID_ARGUMENT;
    }

    let service_str = match cstr_to_service(service) {
        Ok(s) => s,
        Err(code) => return code,
    };

    gated_setup(|| match provider::kek_exists(&service_str) {
        Ok(found) => {
            // SAFETY: exists is non-null per check above; caller contract
            // guarantees it's a valid, writable pointer to an `int`.
            unsafe { *exists = if found { 1 } else { 0 } };
            status::OK
        }
        Err(e) => {
            log::error!("hkdfguard: kek_exists failed for service (redacted): {e}");
            e.status_code()
        }
    })
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

    let result = crypto::wrap(&service_str, &dek_array); // do the actual ECDH -> HKDF -> AES-GCM work
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
    capacity: c_int, // *out_len as declared on entry (0 if out_len is NULL), read by the caller
) -> c_int {
    // Every failure path below zeroes the caller's buffer using the
    // capacity declared on entry, before *out_len is ever overwritten.
    let zero_out_buffer = || zero_caller_buffer(out, capacity);

    if out_len.is_null() {
        return status::INVALID_ARGUMENT; // no declared capacity, so nothing can be safely zeroed
    }
    if wrapped.is_null() {
        zero_out_buffer();
        return status::INVALID_ARGUMENT;
    }

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

    let mut dek = match crypto::unwrap(&service_str, wrapped_slice) {
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
    // Disables the external-secret provider so tests deterministically
    // land on Ephemeral -- the only provider left reachable once
    // external-secret is unavailable, with no persisted-to-disk
    // software-backed fallback in between.
    fn with_isolated_ephemeral_provider<F: FnOnce()>(f: F) {
        std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", "/nonexistent-for-tests");
        // Ephemeral is only reachable through an explicit policy opt-in
        // (see provider::allowed_chain), so write one.
        let _policy = policy::allow_ephemeral_policy_for_tests();
        f();
        std::env::remove_var("HKDFGUARD_POLICY_FILE");
        std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
    }

    // Calls the real hkdfguard_create_kek FFI entry point and asserts it
    // succeeded -- wrap/generate_and_wrap now only ever load an existing
    // KEK, so every test below that wraps something must provision it
    // first, exactly as a real caller would.
    fn create_kek_for_test(service: &CString) {
        assert_eq!(hkdfguard_create_kek(service.as_ptr()), status::OK);
    }

    // ---- setup-call gate (create_kek / kek_exists latency floor) ----

    // Runs `f` with the setup latency floor overridden to `delay`, then
    // restores the suite-wide zero override whatever happens.
    fn with_setup_delay<F: FnOnce()>(delay: Option<Duration>, f: F) {
        struct Restore;
        impl Drop for Restore {
            fn drop(&mut self) {
                set_setup_delay_for_tests(Some(Duration::ZERO));
            }
        }
        let _restore = Restore;
        set_setup_delay_for_tests(delay);
        f();
    }

    #[test]
    #[serial]
    fn setup_calls_take_at_least_the_configured_floor() {
        with_isolated_ephemeral_provider(|| {
            with_setup_delay(Some(Duration::from_millis(50)), || {
                let service = CString::new("com.company.orders.setupfloor").unwrap();

                let started = Instant::now();
                assert_eq!(hkdfguard_create_kek(service.as_ptr()), status::OK);
                assert!(started.elapsed() >= Duration::from_millis(50), "create_kek returned early");

                let mut exists: c_int = -1;
                let started = Instant::now();
                assert_eq!(hkdfguard_kek_exists(service.as_ptr(), &mut exists), status::OK);
                assert_eq!(exists, 1);
                assert!(started.elapsed() >= Duration::from_millis(50), "kek_exists returned early");
            });
        });
    }

    #[test]
    #[serial]
    fn setup_floor_applies_equally_to_a_missing_kek() {
        // The floor is on latency, not on success: "doesn't exist" must
        // cost the same as "exists", or kek_exists is a fast oracle.
        with_isolated_ephemeral_provider(|| {
            with_setup_delay(Some(Duration::from_millis(50)), || {
                let service = CString::new("com.company.nevercreated.setupfloor").unwrap();
                let mut exists: c_int = -1;
                let started = Instant::now();
                assert_eq!(hkdfguard_kek_exists(service.as_ptr(), &mut exists), status::OK);
                assert_eq!(exists, 0);
                assert!(started.elapsed() >= Duration::from_millis(50));
            });
        });
    }

    #[test]
    #[serial]
    fn setup_floor_applies_to_failed_calls_too() {
        // create_kek must fail here, and must still take the full floor
        // rather than failing fast. Policy pins external-secret and its
        // mount doesn't exist, so the failure is deterministic: relying
        // instead on "no provider happens to be available" would make
        // this pass only on hosts without a reachable TPM or PKCS#11
        // token.
        std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", "/nonexistent-for-tests");
        let _policy = policy::require_provider_policy_for_tests("external-secret");
        with_setup_delay(Some(Duration::from_millis(50)), || {
            let service = CString::new("com.company.orders.setupfloorfail").unwrap();
            let started = Instant::now();
            assert_ne!(hkdfguard_create_kek(service.as_ptr()), status::OK);
            assert!(started.elapsed() >= Duration::from_millis(50));
        });
        std::env::remove_var("HKDFGUARD_POLICY_FILE");
        std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
    }

    #[test]
    #[serial]
    fn invalid_arguments_are_rejected_before_the_floor() {
        // Validation failures never reach a provider, so they shouldn't
        // pay for one: an obviously-bad call returns immediately.
        with_setup_delay(Some(Duration::from_millis(500)), || {
            let bad = CString::new("..evil").unwrap();
            let started = Instant::now();
            assert_eq!(hkdfguard_create_kek(bad.as_ptr()), status::INVALID_SERVICE_NAME);
            assert_eq!(hkdfguard_kek_exists(bad.as_ptr(), ptr::null_mut()), status::INVALID_ARGUMENT);
            assert!(started.elapsed() < Duration::from_millis(500));
        });
    }

    #[test]
    #[serial]
    fn setup_calls_are_serialized_across_threads() {
        // Two concurrent calls must not overlap their floors: total wall
        // time is at least 2x the floor, i.e. the aggregate rate really is
        // capped at one call per floor regardless of thread count.
        with_isolated_ephemeral_provider(|| {
            with_setup_delay(Some(Duration::from_millis(60)), || {
                let started = Instant::now();
                let threads: Vec<_> = (0..2)
                    .map(|i| {
                        std::thread::spawn(move || {
                            let service = CString::new(format!("com.company.orders.serialized{i}")).unwrap();
                            assert_eq!(hkdfguard_create_kek(service.as_ptr()), status::OK);
                        })
                    })
                    .collect();
                for t in threads {
                    t.join().unwrap();
                }
                assert!(
                    started.elapsed() >= Duration::from_millis(120),
                    "two gated calls overlapped: {:?}",
                    started.elapsed()
                );
            });
        });
    }

    #[test]
    #[serial]
    fn setup_floor_is_taken_from_the_policy_file() {
        // With the test override cleared, the floor comes from the same
        // policy file that names the providers -- exactly as in production.
        std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", "/nonexistent-for-tests");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        crate::secure_file::write_world_readable_for_tests(
            &path,
            "preferred_order = [\"ephemeral\"]\n[selection]\nmode = \"prefer\"\n[startup_behavior]\nsetup_min_delay_ms = 80\n",
        );
        std::env::set_var("HKDFGUARD_POLICY_FILE", &path);

        with_setup_delay(None, || {
            let service = CString::new("com.company.orders.policyfloor").unwrap();
            let started = Instant::now();
            assert_eq!(hkdfguard_create_kek(service.as_ptr()), status::OK);
            let elapsed = started.elapsed();
            assert!(elapsed >= Duration::from_millis(80), "policy floor not honored: {elapsed:?}");
            // Sanity check that it's the policy's 80 ms and not the 1 s default.
            assert!(elapsed < Duration::from_millis(1000), "took {elapsed:?}; default floor used instead of policy");
        });

        std::env::remove_var("HKDFGUARD_POLICY_FILE");
        std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
    }

    #[test]
    #[serial]
    fn ffi_round_trip() {
        with_isolated_ephemeral_provider(|| {
            let service = CString::new("com.company.orders").unwrap(); // NUL-terminated, as the C ABI requires
            create_kek_for_test(&service);
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
    #[serial]
    fn generate_and_wrap_round_trip() {
        with_isolated_ephemeral_provider(|| {
            let service = CString::new("com.company.orders").unwrap();
            create_kek_for_test(&service);
            let mut wrapped_buf = [0u8; 512]; // generously-sized output buffer
            let mut wrapped_len: c_int = wrapped_buf.len() as c_int;

            let rc = hkdfguard_generate_and_wrap_dek(
                service.as_ptr(),
                wrapped_buf.as_mut_ptr(),
                &mut wrapped_len,
            );
            assert_eq!(rc, status::OK);

            // Unwrapping it recovers a real 32-byte DEK -- proving the
            // payload generate_and_wrap_dek produced is a genuine,
            // independently unwrappable wrapped payload, not just a
            // plausible-looking buffer.
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
        });
    }

    #[test]
    #[serial]
    fn generate_and_wrap_produces_independent_deks() {
        // Each call sources its own fresh CSPRNG randomness for the DEK
        // itself, not just a fresh nonce/ephemeral key -- this is the
        // check that actually distinguishes "generates a new DEK" from
        // "wraps a fixed/reused buffer."
        with_isolated_ephemeral_provider(|| {
            let service = CString::new("com.company.orders").unwrap();
            create_kek_for_test(&service);

            let mut wrapped1 = [0u8; 512];
            let mut wrapped1_len: c_int = wrapped1.len() as c_int;
            assert_eq!(
                hkdfguard_generate_and_wrap_dek(service.as_ptr(), wrapped1.as_mut_ptr(), &mut wrapped1_len),
                status::OK
            );
            let mut dek1 = [0u8; 32];
            let mut dek1_len: c_int = dek1.len() as c_int;
            assert_eq!(
                hkdfguard_unwrap_dek(service.as_ptr(), wrapped1.as_ptr(), wrapped1_len, dek1.as_mut_ptr(), &mut dek1_len),
                status::OK
            );

            let mut wrapped2 = [0u8; 512];
            let mut wrapped2_len: c_int = wrapped2.len() as c_int;
            assert_eq!(
                hkdfguard_generate_and_wrap_dek(service.as_ptr(), wrapped2.as_mut_ptr(), &mut wrapped2_len),
                status::OK
            );
            let mut dek2 = [0u8; 32];
            let mut dek2_len: c_int = dek2.len() as c_int;
            assert_eq!(
                hkdfguard_unwrap_dek(service.as_ptr(), wrapped2.as_ptr(), wrapped2_len, dek2.as_mut_ptr(), &mut dek2_len),
                status::OK
            );

            assert_ne!(dek1, dek2, "two generate_and_wrap_dek calls must produce different DEKs");
        });
    }

    #[test]
    #[serial]
    fn generate_and_wrap_buffer_too_small_reports_required_size_without_writing() {
        with_isolated_ephemeral_provider(|| {
            let service = CString::new("com.company.orders").unwrap();
            create_kek_for_test(&service);
            let mut tiny = [0xFFu8; 4]; // way too small to hold a wrapped payload
            let mut tiny_len: c_int = tiny.len() as c_int;

            let rc = hkdfguard_generate_and_wrap_dek(service.as_ptr(), tiny.as_mut_ptr(), &mut tiny_len);
            assert_eq!(rc, status::BUFFER_TOO_SMALL);
            assert!(tiny_len > 4); // *out_len was updated to the actually-required size
            assert_eq!(tiny, [0xFFu8; 4], "must not write on BUFFER_TOO_SMALL"); // buffer contents untouched
        });
    }

    #[test]
    fn generate_and_wrap_null_service_is_invalid_service_name() {
        let mut out = [0u8; 512];
        let mut out_len: c_int = out.len() as c_int;
        let rc = hkdfguard_generate_and_wrap_dek(std::ptr::null(), out.as_mut_ptr(), &mut out_len);
        assert_eq!(rc, status::INVALID_SERVICE_NAME);
    }

    #[test]
    fn generate_and_wrap_null_out_len_is_invalid_argument() {
        let service = CString::new("com.company.orders").unwrap();
        let mut out = [0u8; 512];
        let rc = hkdfguard_generate_and_wrap_dek(service.as_ptr(), out.as_mut_ptr(), std::ptr::null_mut());
        assert_eq!(rc, status::INVALID_ARGUMENT);
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
        with_isolated_ephemeral_provider(|| {
            let service = CString::new("com.company.orders").unwrap();
            create_kek_for_test(&service);
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
        with_isolated_ephemeral_provider(|| {
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
    fn null_service_is_invalid_service_name() {
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
        assert_eq!(rc, status::INVALID_SERVICE_NAME);

        let rc = hkdfguard_unwrap_dek(
            std::ptr::null(),
            out.as_ptr(),
            32,
            out.as_mut_ptr(),
            &mut out_len,
        );
        assert_eq!(rc, status::INVALID_SERVICE_NAME);
    }

    #[test]
    fn wrap_null_pointers_and_negative_lengths() {
        let service = CString::new("com.company.orders").unwrap();
        let dek = [0u8; 32];
        let mut out = [0u8; 512];
        let mut out_len: c_int = 512;

        // Null dek pointer
        assert_eq!(
            hkdfguard_wrap_dek(
                service.as_ptr(),
                std::ptr::null(),
                32,
                out.as_mut_ptr(),
                &mut out_len
            ),
            status::INVALID_ARGUMENT
        );

        // Null out_len pointer
        assert_eq!(
            hkdfguard_wrap_dek(
                service.as_ptr(),
                dek.as_ptr(),
                32,
                out.as_mut_ptr(),
                std::ptr::null_mut()
            ),
            status::INVALID_ARGUMENT
        );

        // Negative dek length
        assert_eq!(
            hkdfguard_wrap_dek(
                service.as_ptr(),
                dek.as_ptr(),
                -1,
                out.as_mut_ptr(),
                &mut out_len
            ),
            status::INVALID_ARGUMENT
        );

        // Negative out_len capacity
        let mut neg_len: c_int = -5;
        assert_eq!(
            hkdfguard_wrap_dek(
                service.as_ptr(),
                dek.as_ptr(),
                32,
                out.as_mut_ptr(),
                &mut neg_len
            ),
            status::INVALID_ARGUMENT
        );
    }

    #[test]
    fn unwrap_zeroes_the_buffer_on_every_failure_with_a_known_capacity() {
        let service = CString::new("com.company.orders").unwrap();
        let wrapped = [0u8; 64];

        // NULL `wrapped`: capacity is known, so the buffer must be zeroed.
        let mut out = [0xAAu8; 32];
        let mut out_len: c_int = 32;
        assert_eq!(
            hkdfguard_unwrap_dek(service.as_ptr(), std::ptr::null(), 64, out.as_mut_ptr(), &mut out_len),
            status::INVALID_ARGUMENT
        );
        assert_eq!(out, [0u8; 32], "a NULL wrapped pointer must still leave out zeroed");

        // Invalid service name, then a payload that fails to parse.
        for svc in [std::ptr::null(), service.as_ptr()] {
            let mut out = [0xAAu8; 32];
            let mut out_len: c_int = 32;
            assert_ne!(
                hkdfguard_unwrap_dek(svc, wrapped.as_ptr(), 64, out.as_mut_ptr(), &mut out_len),
                status::OK
            );
            assert_eq!(out, [0u8; 32]);
        }

        // NULL `out_len`: no declared capacity, so nothing may be written.
        let mut out = [0xAAu8; 32];
        assert_eq!(
            hkdfguard_unwrap_dek(service.as_ptr(), wrapped.as_ptr(), 64, out.as_mut_ptr(), std::ptr::null_mut()),
            status::INVALID_ARGUMENT
        );
        assert_eq!(out, [0xAAu8; 32], "with no declared capacity the buffer must be left untouched");
    }

    #[test]
    fn unwrap_null_pointers_and_negative_lengths() {
        let service = CString::new("com.company.orders").unwrap();
        let wrapped = [0u8; 64];
        let mut out = [0x55u8; 32];
        let mut out_len: c_int = 32;

        // Null wrapped pointer
        assert_eq!(
            hkdfguard_unwrap_dek(
                service.as_ptr(),
                std::ptr::null(),
                64,
                out.as_mut_ptr(),
                &mut out_len
            ),
            status::INVALID_ARGUMENT
        );

        // Null out_len pointer
        assert_eq!(
            hkdfguard_unwrap_dek(
                service.as_ptr(),
                wrapped.as_ptr(),
                64,
                out.as_mut_ptr(),
                std::ptr::null_mut()
            ),
            status::INVALID_ARGUMENT
        );

        // Negative wrapped_len
        assert_eq!(
            hkdfguard_unwrap_dek(
                service.as_ptr(),
                wrapped.as_ptr(),
                -1,
                out.as_mut_ptr(),
                &mut out_len
            ),
            status::INVALID_ARGUMENT
        );
        assert_eq!(out, [0u8; 32]);

        // Negative out_len
        let mut neg_len: c_int = -1;
        assert_eq!(
            hkdfguard_unwrap_dek(
                service.as_ptr(),
                wrapped.as_ptr(),
                64,
                out.as_mut_ptr(),
                &mut neg_len
            ),
            status::INVALID_ARGUMENT
        );
    }

    #[test]
    fn service_validation_edge_cases() {
        let dek = [0u8; 32];
        let mut out = [0u8; 512];
        let mut out_len: c_int = 512;

        // Empty service string
        let empty_svc = CString::new("").unwrap();
        assert_eq!(
            hkdfguard_wrap_dek(
                empty_svc.as_ptr(),
                dek.as_ptr(),
                32,
                out.as_mut_ptr(),
                &mut out_len
            ),
            status::INVALID_SERVICE_NAME
        );
        assert_eq!(
            hkdfguard_unwrap_dek(
                empty_svc.as_ptr(),
                out.as_ptr(),
                64,
                out.as_mut_ptr(),
                &mut out_len
            ),
            status::INVALID_SERVICE_NAME
        );

        // Oversized service string (> 128 bytes)
        let long_svc_str = "a".repeat(256);
        let long_svc = CString::new(long_svc_str).unwrap();
        assert_eq!(
            hkdfguard_wrap_dek(
                long_svc.as_ptr(),
                dek.as_ptr(),
                32,
                out.as_mut_ptr(),
                &mut out_len
            ),
            status::INVALID_SERVICE_NAME
        );
        assert_eq!(
            hkdfguard_unwrap_dek(
                long_svc.as_ptr(),
                out.as_ptr(),
                64,
                out.as_mut_ptr(),
                &mut out_len
            ),
            status::INVALID_SERVICE_NAME
        );

        // Invalid UTF-8 service string (e.g. 0xFF, 0xFE)
        let invalid_utf8 = [0xFFu8, 0xFEu8, 0x00u8];
        assert_eq!(
            hkdfguard_wrap_dek(
                invalid_utf8.as_ptr() as *const c_char,
                dek.as_ptr(),
                32,
                out.as_mut_ptr(),
                &mut out_len
            ),
            status::INVALID_SERVICE_NAME
        );
        assert_eq!(
            hkdfguard_unwrap_dek(
                invalid_utf8.as_ptr() as *const c_char,
                out.as_ptr(),
                64,
                out.as_mut_ptr(),
                &mut out_len
            ),
            status::INVALID_SERVICE_NAME
        );
    }

    #[test]
    #[serial]
    fn unwrap_buffer_too_small_sets_required_length_and_zeroes() {
        with_isolated_ephemeral_provider(|| {
            let service = CString::new("com.company.orders").unwrap();
            create_kek_for_test(&service);
            let dek = [0x77u8; 32];
            let mut wrapped = [0u8; 512];
            let mut wrapped_len: c_int = 512;

            assert_eq!(
                hkdfguard_wrap_dek(
                    service.as_ptr(),
                    dek.as_ptr(),
                    32,
                    wrapped.as_mut_ptr(),
                    &mut wrapped_len
                ),
                status::OK
            );

            let mut tiny_out = [0xAAu8; 16];
            let mut tiny_out_len: c_int = 16;
            assert_eq!(
                hkdfguard_unwrap_dek(
                    service.as_ptr(),
                    wrapped.as_ptr(),
                    wrapped_len,
                    tiny_out.as_mut_ptr(),
                    &mut tiny_out_len
                ),
                status::BUFFER_TOO_SMALL
            );
            assert_eq!(tiny_out_len, 32);
            assert_eq!(tiny_out, [0u8; 16]);
        });
    }

    #[test]
    #[serial]
    fn boundary_service_lengths_round_trip() {
        with_isolated_ephemeral_provider(|| {
            let dek = [0x12u8; 32];

            // 1-byte service name
            let svc1 = CString::new("x").unwrap();
            create_kek_for_test(&svc1);
            let mut wrapped = [0u8; 512];
            let mut wrapped_len: c_int = 512;
            assert_eq!(
                hkdfguard_wrap_dek(
                    svc1.as_ptr(),
                    dek.as_ptr(),
                    32,
                    wrapped.as_mut_ptr(),
                    &mut wrapped_len
                ),
                status::OK
            );
            let mut out = [0u8; 32];
            let mut out_len: c_int = 32;
            assert_eq!(
                hkdfguard_unwrap_dek(
                    svc1.as_ptr(),
                    wrapped.as_ptr(),
                    wrapped_len,
                    out.as_mut_ptr(),
                    &mut out_len
                ),
                status::OK
            );
            assert_eq!(out, dek);

            // 128-byte service name (the new maximum)
            let svc128 = CString::new("s".repeat(128)).unwrap();
            create_kek_for_test(&svc128);
            let mut wrapped2 = [0u8; 512];
            let mut wrapped2_len: c_int = 512;
            assert_eq!(
                hkdfguard_wrap_dek(
                    svc128.as_ptr(),
                    dek.as_ptr(),
                    32,
                    wrapped2.as_mut_ptr(),
                    &mut wrapped2_len
                ),
                status::OK
            );
            let mut out2 = [0u8; 32];
            let mut out2_len: c_int = 32;
            assert_eq!(
                hkdfguard_unwrap_dek(
                    svc128.as_ptr(),
                    wrapped2.as_ptr(),
                    wrapped2_len,
                    out2.as_mut_ptr(),
                    &mut out2_len
                ),
                status::OK
            );
            assert_eq!(out2, dek);
        });
    }

    #[test]
    #[serial]
    fn service_name_over_128_bytes_is_invalid_service_name() {
        let dek = [0u8; 32];
        let mut out = [0u8; 512];
        let mut out_len: c_int = 512;

        let svc129 = CString::new("s".repeat(129)).unwrap();
        assert_eq!(
            hkdfguard_wrap_dek(svc129.as_ptr(), dek.as_ptr(), 32, out.as_mut_ptr(), &mut out_len),
            status::INVALID_SERVICE_NAME
        );
    }

    #[test]
    #[serial]
    fn service_name_rejects_non_alphanumeric_dot_characters() {
        let dek = [0u8; 32];
        let mut out = [0u8; 512];
        let mut out_len: c_int = 512;

        for bad in ["com_example.orders", "com example.orders", "com-example.orders", "com/example"] {
            let svc = CString::new(bad).unwrap();
            assert_eq!(
                hkdfguard_wrap_dek(svc.as_ptr(), dek.as_ptr(), 32, out.as_mut_ptr(), &mut out_len),
                status::INVALID_SERVICE_NAME,
                "should reject \"{bad}\""
            );
        }
    }

    #[test]
    fn service_name_rejects_leading_dot_and_consecutive_dots() {
        let dek = [0u8; 32];
        let mut out = [0u8; 512];
        let mut out_len: c_int = 512;
        let mut exists: c_int = 0;

        // Every entry point rejects these before any provider sees them.
        for bad in [".", "..", "...", ".hidden", ".com.example", "..parent", "com..example", "com.example..", "a...b"] {
            let svc = CString::new(bad).unwrap();
            assert_eq!(hkdfguard_create_kek(svc.as_ptr()), status::INVALID_SERVICE_NAME, "create_kek {bad:?}");
            assert_eq!(hkdfguard_kek_exists(svc.as_ptr(), &mut exists), status::INVALID_SERVICE_NAME, "kek_exists {bad:?}");
            assert_eq!(
                hkdfguard_wrap_dek(svc.as_ptr(), dek.as_ptr(), 32, out.as_mut_ptr(), &mut out_len),
                status::INVALID_SERVICE_NAME,
                "wrap {bad:?}"
            );
            let mut dek_out = [0u8; 32];
            let mut dek_out_len: c_int = 32;
            assert_eq!(
                hkdfguard_unwrap_dek(svc.as_ptr(), out.as_ptr(), 64, dek_out.as_mut_ptr(), &mut dek_out_len),
                status::INVALID_SERVICE_NAME,
                "unwrap {bad:?}"
            );
        }
    }

    #[test]
    #[serial]
    fn service_name_with_single_interior_and_trailing_dots_is_still_accepted() {
        // The new rules only forbid a leading dot and consecutive dots;
        // ordinary dotted names (and a single trailing dot) are unaffected.
        with_isolated_ephemeral_provider(|| {
            for ok in ["com.example.dottest", "a.b.c.d", "x", "com.example.trailing."] {
                let svc = CString::new(ok).unwrap();
                assert_eq!(hkdfguard_create_kek(svc.as_ptr()), status::OK, "{ok:?}");
            }
        });
    }

    #[test]
    #[serial]
    fn service_name_is_normalized_to_lowercase() {
        with_isolated_ephemeral_provider(|| {
            let dek = [0x55u8; 32];
            let mixed_case = CString::new("Com.Example.Orders").unwrap();
            create_kek_for_test(&mixed_case); // normalizes to lowercase internally, same as wrap/unwrap
            let mut wrapped = [0u8; 512];
            let mut wrapped_len: c_int = 512;
            assert_eq!(
                hkdfguard_wrap_dek(
                    mixed_case.as_ptr(),
                    dek.as_ptr(),
                    32,
                    wrapped.as_mut_ptr(),
                    &mut wrapped_len
                ),
                status::OK
            );

            // A different-case (but otherwise identical) service string
            // must unwrap the same payload -- proving both sides normalize
            // to the same canonical (lowercase) form.
            let lowercase = CString::new("com.example.orders").unwrap();
            let mut out = [0u8; 32];
            let mut out_len: c_int = 32;
            assert_eq!(
                hkdfguard_unwrap_dek(
                    lowercase.as_ptr(),
                    wrapped.as_ptr(),
                    wrapped_len,
                    out.as_mut_ptr(),
                    &mut out_len
                ),
                status::OK
            );
            assert_eq!(out, dek);

            // And a third, differently-cased variant of the very same name
            // must also unwrap it.
            let shouty_case = CString::new("COM.EXAMPLE.ORDERS").unwrap();
            let mut out2 = [0u8; 32];
            let mut out2_len: c_int = 32;
            assert_eq!(
                hkdfguard_unwrap_dek(
                    shouty_case.as_ptr(),
                    wrapped.as_ptr(),
                    wrapped_len,
                    out2.as_mut_ptr(),
                    &mut out2_len
                ),
                status::OK
            );
            assert_eq!(out2, dek);
        });
    }

    #[test]
    #[serial]
    fn create_kek_then_kek_exists_then_wrap_succeeds() {
        with_isolated_ephemeral_provider(|| {
            // A service name unique to this test: Ephemeral's key map is
            // process-global and never cleared between tests, so a
            // generic name another test also resolves via Ephemeral
            // could already exist by the time this "starts nonexistent"
            // assertion runs.
            let service = CString::new("com.company.orders.kekexiststest").unwrap();

            let mut exists: c_int = -1; // recognizable sentinel, must be overwritten
            assert_eq!(hkdfguard_kek_exists(service.as_ptr(), &mut exists), status::OK);
            assert_eq!(exists, 0);

            assert_eq!(hkdfguard_create_kek(service.as_ptr()), status::OK);

            assert_eq!(hkdfguard_kek_exists(service.as_ptr(), &mut exists), status::OK);
            assert_eq!(exists, 1);

            // hkdfguard_create_kek is idempotent: calling it again for a
            // service that already has one just confirms it, no error.
            assert_eq!(hkdfguard_create_kek(service.as_ptr()), status::OK);

            let dek = [0x66u8; 32];
            let mut wrapped = [0u8; 512];
            let mut wrapped_len: c_int = 512;
            assert_eq!(
                hkdfguard_wrap_dek(service.as_ptr(), dek.as_ptr(), 32, wrapped.as_mut_ptr(), &mut wrapped_len),
                status::OK
            );
        });
    }

    #[test]
    #[serial]
    fn wrap_before_create_kek_fails_with_kek_not_found() {
        with_isolated_ephemeral_provider(|| {
            let service = CString::new("com.company.unprovisioned").unwrap();
            let dek = [0x11u8; 32];
            let mut wrapped = [0u8; 512];
            let mut wrapped_len: c_int = 512;

            let rc = hkdfguard_wrap_dek(service.as_ptr(), dek.as_ptr(), 32, wrapped.as_mut_ptr(), &mut wrapped_len);
            assert_eq!(rc, status::KEK_NOT_FOUND);
        });
    }

    #[test]
    #[serial]
    fn unwrap_after_kek_rotation_fails_with_fingerprint_mismatch() {
        // external-secret, not Ephemeral, is what's rotated here: this
        // test needs key material something *outside* this process can
        // rewrite, and Ephemeral is in-memory only -- there's no file to
        // rotate out from under it. Pinned by policy, or a reachable
        // TPM/PKCS#11 device would win the chain and there would be
        // nothing for the rotation below to rotate.
        let _policy = policy::require_provider_policy_for_tests("external-secret");
        let ext_dir = tempfile::tempdir().unwrap();
        std::env::set_var("HKDFGUARD_EXTERNAL_SECRET_DIR", ext_dir.path());
        let service_str = "com.company.rotated";
        let secret_path = ext_dir.path().join(service_str);
        let service = CString::new(service_str).unwrap();

        let key_a = p256::SecretKey::random(&mut rand_core::OsRng);
        std::fs::write(&secret_path, key_a.to_bytes()).unwrap();
        // Owner-only, as the provider requires of a KEK file. The rotation
        // rewrite below preserves this mode, so it's set once.
        std::fs::set_permissions(&secret_path, <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600)).unwrap();
        create_kek_for_test(&service); // finds the pre-provisioned key; external-secret never creates one itself

        let dek = [0x33u8; 32];
        let mut wrapped = [0u8; 512];
        let mut wrapped_len: c_int = 512;
        assert_eq!(
            hkdfguard_wrap_dek(service.as_ptr(), dek.as_ptr(), 32, wrapped.as_mut_ptr(), &mut wrapped_len),
            status::OK
        );

        // Simulate an out-of-band KEK rotation: the deployment platform
        // rewrites the mounted secret file with a brand new, unrelated
        // key under the exact same service name.
        let key_b = p256::SecretKey::random(&mut rand_core::OsRng);
        std::fs::write(&secret_path, key_b.to_bytes()).unwrap();

        let mut out = [0xAAu8; 32]; // recognizable non-zero pattern
        let mut out_len: c_int = out.len() as c_int;
        let rc = hkdfguard_unwrap_dek(
            service.as_ptr(),
            wrapped.as_ptr(),
            wrapped_len,
            out.as_mut_ptr(),
            &mut out_len,
        );
        assert_eq!(rc, status::FINGERPRINT_MISMATCH);
        assert_eq!(rc, -16, "must match macOS's HKDFGuardStatus.fingerprintMismatch");
        assert_eq!(out, [0u8; 32], "output buffer must still be zeroed on failure");

        std::env::remove_var("HKDFGUARD_EXTERNAL_SECRET_DIR");
        std::env::remove_var("HKDFGUARD_POLICY_FILE");
    }

    #[test]
    fn unterminated_service_buffer_is_rejected_without_over_reading() {
        // Finding #13. A buffer of MAX_SERVICE_LEN + 1 non-NUL bytes and
        // *no* terminator at all. The old `CStr::from_ptr` would have read
        // past the end of this array looking for a zero byte; the bounded
        // scan reads exactly the 129 bytes that exist, finds no NUL, and
        // rejects. Under the old code this test would be undefined
        // behavior, which is precisely the regression it guards against.
        let unterminated = [b'a'; MAX_SERVICE_LEN + 1];
        let rc = hkdfguard_create_kek(unterminated.as_ptr() as *const c_char);
        assert_eq!(rc, status::INVALID_SERVICE_NAME);

        // And the boundary still behaves: exactly MAX_SERVICE_LEN bytes
        // plus a terminator is accepted by the parser (it may then fail
        // for provider reasons, but never as an invalid service name).
        let mut at_limit = [b'a'; MAX_SERVICE_LEN + 1];
        at_limit[MAX_SERVICE_LEN] = 0;
        assert!(cstr_to_service(at_limit.as_ptr() as *const c_char).is_ok());

        // One byte over, terminated: rejected by the length rule.
        let mut over = [b'a'; MAX_SERVICE_LEN + 2];
        over[MAX_SERVICE_LEN + 1] = 0;
        assert_eq!(
            cstr_to_service(over.as_ptr() as *const c_char).unwrap_err(),
            status::INVALID_SERVICE_NAME
        );
    }

    #[test]
    fn create_kek_and_kek_exists_null_service_is_invalid_service_name() {
        assert_eq!(hkdfguard_create_kek(std::ptr::null()), status::INVALID_SERVICE_NAME);

        let mut exists: c_int = 0;
        assert_eq!(
            hkdfguard_kek_exists(std::ptr::null(), &mut exists),
            status::INVALID_SERVICE_NAME
        );
    }

    #[test]
    #[serial]
    fn kek_exists_null_out_pointer_is_invalid_argument() {
        let service = CString::new("com.company.orders").unwrap();
        assert_eq!(
            hkdfguard_kek_exists(service.as_ptr(), std::ptr::null_mut()),
            status::INVALID_ARGUMENT
        );
    }
}
