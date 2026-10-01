//! Provider 2: PKCS#11 (used when TPM2 is unavailable).
//!
//! ```text
//!  ______________________________________________________________________
//! | HARDWARE/MODULE-DEPENDENT CODE                                        |
//! |                                                                        |
//! | Verified (see docker/): natively built against real `cryptoki` 0.6.2  |
//! | on Ubuntu 24.04 (x86_64 and aarch64), and the `#[ignore]`d tests pass |
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
//! All of it comes from the `[pkcs11]` table of the root-owned policy file.
//! The `HKDFGUARD_PKCS11_*` environment variables in brackets are honored
//! in debug builds only, for tests (see `crate::debug_only_env`).
//!
//! - `module` [`HKDFGUARD_PKCS11_MODULE`]: absolute path to the PKCS#11
//!   module. **Release builds use PKCS#11 only when this is set.** Debug
//!   builds fall back to common SoftHSM2 install paths; release builds
//!   don't, because SoftHSM2 is a software token that would otherwise be
//!   picked up -- and counted as hardware -- just for being installed. The
//!   (symlink-resolved) module file, its directory, and every directory
//!   above it must be owned by root and not writable by group or others
//!   (sticky ancestors excepted) -- see [`validate_module_path`]:
//!   the module is `dlopen`ed into this process.
//! - `token_label` / `token_serial`: which token to use, among initialized
//!   ones. Exactly one must match. With neither set, there must be exactly
//!   one initialized token. Slot numbers are not used in release builds
//!   because they can change across reboots and hot-plugging; the debug-only
//!   [`HKDFGUARD_PKCS11_SLOT`] index remains for tests.
//! - `pin_file` [`HKDFGUARD_PKCS11_PIN_FILE`]: the user-PIN file (default
//!   `/etc/hkdfguard/pkcs11.pin`). Owned by root, no access for others,
//!   group read allowed (`0400`, or `root:<service-group> 0440` for a
//!   non-root service), in directories only root can change; one
//!   trailing newline is ignored. The PIN itself is never read from the
//!   environment (`/proc/<pid>/environ` is readable by same-user processes
//!   and inherited by children); the retired `HKDFGUARD_PKCS11_PIN` is
//!   ignored with a warning.
//!
//! ## Design
//!
//! For each service, finds (or generates, if absent) a **non-extractable**
//! token-persistent EC P-256 key pair labelled `hkdfguard:<service>`
//! (`CKA_TOKEN=true`, `CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=false`,
//! `CKA_DERIVE=true`). ECDH is performed on-token via `CKM_ECDH1_DERIVE`
//! (`CKD_NULL` -- no token-side KDF; this crate does its own HKDF-SHA512
//! outside, per the shared protocol), which derives a session-local,
//! extractable generic-secret object holding the raw shared X-coordinate.
//! That value is read out, the temporary derived object is destroyed
//! immediately, and the raw bytes are wrapped in a zeroizing buffer before
//! returning -- the *persistent* private key never leaves the token.

use crate::error::{Error, Result}; // this crate's error type + `Result` alias
use crate::provider::{Backend, KekHandle, KekProvider, ProviderType, SharedSecret}; // traits/types this module implements
use elliptic_curve::sec1::ToEncodedPoint; // encodes our ephemeral public key into the raw bytes the token expects
use p256::PublicKey; // the caller's ephemeral public key type
use sha2::{Digest as ShaDigest, Sha256}; // used for the CKA_ID tag (aliased to avoid clashing with cryptoki's own naming)
use std::path::{Path, PathBuf}; // module-path validation and PIN-file location
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

// SEC1 uncompressed P-256 point: 1 tag byte (0x04) + 32-byte X + 32-byte Y.
const UNCOMPRESSED_POINT_LEN: usize = 65;

// Bundles the open session (there's nothing else to track: the module
// context is only needed to open it).
struct OpenSession {
    session: Session,
}

// Holds the shared, lazily-usable PKCS#11 session. `None` in `state` means
// no module/token/PIN was usable at construction time.
pub struct Pkcs11Provider {
    state: Arc<Mutex<Option<OpenSession>>>,
    // Set when PKCS#11 is configured but can't be used (see
    // `crate::provider::Backend::Refused`); every call then fails with it.
    refused: Option<String>,
}

impl Pkcs11Provider {
    pub fn new() -> Self {
        // try to set everything up once, at construction time
        let (state, refused) = match open_session() {
            Backend::Ready(open) => (Some(open), None),
            Backend::Absent => (None, None),
            Backend::Refused(reason) => {
                log::error!("hkdfguard: PKCS#11 refused: {reason}");
                (None, Some(reason))
            }
        };
        Pkcs11Provider { state: Arc::new(Mutex::new(state)), refused }
    }

    fn connected(&self) -> bool {
        self.state.lock().map(|guard| guard.is_some()).unwrap_or(false) // a poisoned lock counts as not connected
    }

    fn check_not_refused(&self) -> Result<()> {
        match &self.refused {
            Some(reason) => Err(Error::Provider(format!("PKCS#11 refused: {reason}"))),
            None => Ok(()),
        }
    }
}

impl Default for Pkcs11Provider {
    fn default() -> Self {
        Self::new()
    }
}

// Which module path(s) to try: the policy's `module`; else, in debug
// builds, HKDFGUARD_PKCS11_MODULE or the SoftHSM2 install paths. Empty in a
// release build with no `module` in policy -- PKCS#11 is then unavailable.
fn candidate_module_paths(from_policy: Option<PathBuf>, from_env: Option<std::ffi::OsString>) -> Vec<PathBuf> {
    if let Some(module) = from_policy {
        return vec![module];
    }
    if let Some(module) = from_env {
        return vec![PathBuf::from(module)];
    }
    if cfg!(debug_assertions) {
        return DEFAULT_MODULE_PATHS.iter().map(PathBuf::from).collect();
    }
    Vec::new()
}

/// Picks one token from the initialized tokens present, given as
/// `(label, serial)` pairs in slot order. With a label and/or serial
/// configured, exactly one token must match all that are set. Otherwise
/// the debug-only slot index is used if given, and failing that there must
/// be exactly one initialized token -- with several, guessing would make
/// which token holds the keys depend on enumeration order.
fn select_token(
    tokens: &[(String, String)],
    label: Option<&str>,
    serial: Option<&str>,
    debug_index: Option<&str>,
) -> std::result::Result<usize, String> {
    if label.is_some() || serial.is_some() {
        let matches: Vec<usize> = tokens
            .iter()
            .enumerate()
            .filter(|(_, (l, n))| label.is_none_or(|want| want == l) && serial.is_none_or(|want| want == n))
            .map(|(i, _)| i)
            .collect();
        return match matches.as_slice() {
            [one] => Ok(*one),
            [] => Err(format!("no initialized token matches pkcs11.token_label {label:?} / token_serial {serial:?}")),
            many => Err(format!(
                "{} tokens match pkcs11.token_label {label:?} / token_serial {serial:?}; set token_serial to choose one",
                many.len()
            )),
        };
    }
    if let Some(index) = debug_index {
        let i: usize = index.parse().map_err(|_| format!("HKDFGUARD_PKCS11_SLOT={index:?} is not an index"))?;
        return if i < tokens.len() { Ok(i) } else { Err(format!("HKDFGUARD_PKCS11_SLOT={i} is out of range")) };
    }
    match tokens.len() {
        1 => Ok(0),
        0 => Err("no initialized PKCS#11 token is present".to_string()),
        n => Err(format!("{n} initialized PKCS#11 tokens are present; set pkcs11.token_label (or token_serial) to choose one")),
    }
}

/// Checks a PKCS#11 module path before it's ever `dlopen`ed: it must be
/// absolute, and after resolving symlinks, the module file must be owned
/// by root and not writable by group or others, and so must its directory
/// and every directory above it (see [`crate::secure_file::check_dir_chain`]).
/// Returns the canonical (symlink-resolved) path -- the one that was
/// actually checked -- so that's exactly what gets loaded.
///
/// Loading a module runs its code inside this process. Checking only the
/// file and its immediate directory isn't enough: a non-root user who can
/// write to any ancestor can rename the module's directory away and put
/// their own in its place between this check and the `dlopen`. With the
/// whole chain root-controlled, nothing on the path can change in between.
fn validate_module_path(path: &Path) -> std::result::Result<PathBuf, String> {
    use crate::secure_file::{check_dir_chain, check_metadata, Owner, FORBID_GROUP_OTHER_WRITE};

    if !path.is_absolute() {
        return Err(format!("PKCS#11 module path {path:?} must be absolute"));
    }
    let canonical = std::fs::canonicalize(path).map_err(|e| format!("PKCS#11 module {path:?}: {e}"))?;

    let file_meta = std::fs::metadata(&canonical).map_err(|e| format!("PKCS#11 module {}: {e}", canonical.display()))?;
    check_metadata(&file_meta, Some(Owner::Root), FORBID_GROUP_OTHER_WRITE)
        .map_err(|e| format!("refusing to load PKCS#11 module {}: {e}", canonical.display()))?;

    let parent = canonical
        .parent()
        .ok_or_else(|| format!("PKCS#11 module {} has no parent directory", canonical.display()))?;
    check_dir_chain(parent, Owner::Root)
        .map_err(|e| format!("refusing to load PKCS#11 module {}: {e}", canonical.display()))?;

    Ok(canonical)
}

/// Default location of the PKCS#11 user-PIN file (overridable with
/// `HKDFGUARD_PKCS11_PIN_FILE`).
const DEFAULT_PIN_FILE: &str = "/etc/hkdfguard/pkcs11.pin";

/// Longest PIN file accepted -- far above any real PIN length, only here
/// to bound the one up-front allocation `SecretBuffer` makes.
const MAX_PIN_FILE_LEN: usize = 256;

fn pin_file_path(from_policy: Option<PathBuf>, from_env: Option<std::ffi::OsString>) -> PathBuf {
    from_policy
        .or_else(|| from_env.map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PIN_FILE))
}

/// Reads the PKCS#11 user PIN from `path`. The file must be a regular file
/// owned by root (see [`crate::secure_file::config_owner`]), readable by
/// nobody but its owner and -- since it is root's -- optionally its group,
/// so a non-root service reads it as `root:<service-group> 0440`. It must
/// not be one the service can write: a wrong PIN written into it would
/// burn an HSM login attempt on every call until the token locks the user
/// out. The directories it lives in are checked the same way. Symlinks are
/// followed (Kubernetes Secret volumes are symlinks) but the checks apply
/// to the file actually opened. One trailing `\n` (or `\r\n`) is stripped.
/// The raw file bytes live in a self-wiping `SecretBuffer` that is wiped
/// explicitly before this returns -- on every path -- and the PIN itself
/// comes back as an `AuthPin`, which zeroizes its own storage on drop.
fn read_pin_file(path: &Path) -> std::result::Result<AuthPin, std::io::Error> {
    use crate::secure_file::{check_location, config_owner, open_checked, FileRequirements, SecretBuffer, FORBID_GROUP_OTHER_ACCESS};
    use std::io::{Error as IoError, ErrorKind};

    let requirements = FileRequirements {
        owner: Some(config_owner()),
        forbidden_mode_bits: FORBID_GROUP_OTHER_ACCESS,
        follow_symlinks: true,
        allow_group_read_if_root_owned: true,
    };
    check_location(path, config_owner())?;
    let mut file = open_checked(path, &requirements)?;
    let mut raw = SecretBuffer::read_from(&mut file, MAX_PIN_FILE_LEN)?;

    let mut pin = raw.as_slice();
    if let Some(stripped) = pin.strip_suffix(b"\n") {
        pin = stripped.strip_suffix(b"\r").unwrap_or(stripped);
    }
    // Copy exactly the PIN bytes (no over-allocation, no growth) into the
    // String `AuthPin` takes ownership of, then wipe the file buffer
    // before anything can return -- including the error paths below.
    let result = if pin.is_empty() {
        Err(IoError::new(ErrorKind::InvalidData, "PIN file is empty"))
    } else {
        String::from_utf8(pin.to_vec())
            .map(AuthPin::new)
            .map_err(|e| {
                let mut rejected = e.into_bytes();
                zeroize::Zeroize::zeroize(&mut rejected); // the non-UTF-8 bytes are still PIN material
                IoError::new(ErrorKind::InvalidData, "PIN file is not valid UTF-8")
            })
    };
    raw.wipe();
    result
}

// Loads the PIN, loads the module, initializes the library, picks a slot,
// opens a read/write session, and logs in. `Absent` when PKCS#11 isn't
// configured on this host -- no module named (or, in debug builds, none of
// the SoftHSM2 defaults installed), or no PIN file. Once it is configured,
// every later failure is `Refused`: the HSM is meant to be used, so a
// module that won't load, a missing token, or a wrong PIN is an outage to
// surface, not a reason to wrap under a weaker provider.
fn open_session() -> Backend<OpenSession> {
    if std::env::var_os("HKDFGUARD_PKCS11_PIN").is_some() {
        log::warn!(
            "hkdfguard: HKDFGUARD_PKCS11_PIN is no longer supported and is ignored; put the PIN in a root-owned mode-0400 (or 0440, group = the service's group) file named by pkcs11.pin_file in the policy (default {DEFAULT_PIN_FILE}) instead"
        );
    }

    let settings = match crate::policy::pkcs11_settings() {
        Ok(s) => s,
        Err(e) => return Backend::Refused(e.to_string()),
    };
    // Read every debug-only variable up front, so a release build warns
    // about each one that is set even when it would not have been reached.
    let env_module = crate::debug_only_env("HKDFGUARD_PKCS11_MODULE");
    let env_pin_file = crate::debug_only_env("HKDFGUARD_PKCS11_PIN_FILE");
    let env_slot = crate::debug_only_env("HKDFGUARD_PKCS11_SLOT").map(|v| v.to_string_lossy().into_owned());

    let module_named = settings.module.is_some() || env_module.is_some();
    let modules = candidate_module_paths(settings.module.clone(), env_module);
    if modules.is_empty() {
        log::debug!("hkdfguard: no PKCS#11 module configured (pkcs11.module); PKCS#11 provider not used");
        return Backend::Absent; // the normal state on a host without an HSM configured
    }

    let pin_path = pin_file_path(settings.pin_file.clone(), env_pin_file);
    let pin = match read_pin_file(&pin_path) {
        Ok(pin) => pin,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Its directory is root-controlled (see `read_pin_file`), so
            // nobody else can make it absent.
            log::debug!("hkdfguard: no PKCS#11 PIN file at {}; PKCS#11 provider not used", pin_path.display());
            return Backend::Absent;
        }
        Err(e) => return Backend::Refused(format!("PIN file {}: {e}", pin_path.display())),
    };

    let pkcs11 = if module_named {
        let path = &modules[0];
        let checked = match validate_module_path(path) {
            Ok(checked) => checked,
            Err(reason) => return Backend::Refused(reason),
        };
        match Pkcs11::new(&checked) {
            Ok(pkcs11) => pkcs11,
            Err(e) => return Backend::Refused(format!("could not load module {}: {e}", checked.display())),
        }
    } else {
        // Debug builds only: the SoftHSM2 install-path search.
        let found = modules.into_iter().find_map(|path| match validate_module_path(&path) {
            Ok(checked) => Pkcs11::new(checked).ok(),
            Err(reason) => {
                if path.exists() {
                    log::warn!("hkdfguard: {reason}"); // only worth a warning if something is actually there being refused
                }
                None
            }
        });
        match found {
            Some(pkcs11) => pkcs11,
            None => return Backend::Absent,
        }
    };
    let refuse = |what: &str, e: &dyn std::fmt::Display| Backend::Refused(format!("{what}: {e}"));

    if let Err(e) = pkcs11.initialize(CInitializeArgs::OsThreads) {
        return refuse("C_Initialize failed", &e); // telling the module we may call it from multiple OS threads
    }

    // Only initialized tokens can hold keys; SoftHSM2, for one, always
    // presents an extra blank token alongside the real ones.
    let slots = match pkcs11.get_slots_with_token() {
        Ok(slots) => slots,
        Err(e) => return refuse("could not list slots", &e),
    };
    let mut candidates: Vec<(Slot, (String, String))> = Vec::new();
    for slot in slots {
        let info = match pkcs11.get_token_info(slot) {
            Ok(info) => info,
            Err(e) => return refuse("could not read token info", &e),
        };
        if info.token_initialized() {
            candidates.push((slot, (info.label().to_string(), info.serial_number().to_string())));
        }
    }
    let tokens: Vec<(String, String)> = candidates.iter().map(|(_, t)| t.clone()).collect();
    let slot: Slot = match select_token(
        &tokens,
        settings.token_label.as_deref(),
        settings.token_serial.as_deref(),
        env_slot.as_deref(),
    ) {
        Ok(i) => candidates[i].0,
        Err(reason) => return Backend::Refused(reason),
    };

    let session = match pkcs11.open_rw_session(slot) {
        Ok(session) => session, // read/write, since we may need to generate keys
        Err(e) => return refuse("could not open a session", &e),
    };
    // C_Login as the normal user role, required before key generation/derivation
    if let Err(e) = session.login(UserType::User, Some(&pin)) {
        return refuse("C_Login failed", &e);
    }
    drop(pin); // AuthPin zeroizes its storage on drop; don't keep the PIN around for the session's lifetime

    Backend::Ready(OpenSession { session })
}

// Handle type returned from `load_kek`; holds only the service name and a
// shared reference to the session -- the actual PKCS#11 key object is
// looked up (or created, if `create_if_missing` was true) lazily inside
// `ecdh`.
struct Pkcs11Handle {
    key_id: Vec<u8>,   // diagnostic-only tag embedded in the wrapped payload
    service: String,   // needed to (re)locate this service's key object by label
    create_if_missing: bool, // whether `ecdh` may generate a new key pair if none exists yet
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

        let private_key = find_key_pair(&open.session, &self.service)? // look for an existing key pair first
            .map(Ok)
            .unwrap_or_else(|| {
                if self.create_if_missing {
                    generate_key_pair(&open.session, &self.service).map(|(_public, private)| private) // none exists yet and creation was requested
                } else {
                    Err(Error::KeyNotProvisioned(
                        "no PKCS#11 KEK created yet for this service",
                    ))
                }
            })?;
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

    // Deliberately never creates anything (unlike `ecdh`'s own lookup),
    // even when `self.create_if_missing` is true: `generate_key_pair`
    // always produces a fresh, unrelated keypair, and if the private key
    // this handle's `ecdh` would use already exists (the only case this
    // method is ever actually reached in via `crypto::wrap`/`unwrap`,
    // which both resolve through `select_existing`/`load_kek(_, false)`),
    // its matching public object -- created in the very same
    // `generate_key_pair` call -- is guaranteed to exist too. Silently
    // generating a *different* pair here on a mismatch would desynchronize
    // the fingerprint from whatever private key `ecdh` actually ends up
    // using, so a missing public object is always reported as
    // `KeyNotProvisioned`, never papered over.
    fn public_key(&self) -> Result<PublicKey> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| Error::Provider("PKCS#11 session lock poisoned".into()))?;
        let open = guard
            .as_mut()
            .ok_or(Error::Provider("PKCS#11 session not available".into()))?;

        let public_handle = find_public_key(&open.session, &self.service)?.ok_or(
            Error::KeyNotProvisioned("no PKCS#11 KEK created yet for this service"),
        )?;

        let point_bytes = read_ec_point(&open.session, public_handle)?;
        parse_ec_point(&point_bytes)
    }
}

impl KekProvider for Pkcs11Provider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Pkcs11
    }

    fn probe(&self) -> bool {
        self.refused.is_some() || self.connected()
    }

    // Eager, side-effect-free existence check -- unlike `load_kek`, which
    // defers the actual PKCS#11 lookup to `ecdh` (see `Pkcs11Handle`'s doc
    // comment), this queries the token directly so the provider-selection
    // chain can decide whether this provider has the requested service's
    // key *before* attempting any ECDH.
    fn kek_exists(&self, service: &str) -> Result<bool> {
        self.check_not_refused()?;
        let mut guard = self
            .state
            .lock()
            .map_err(|_| Error::Provider("PKCS#11 session lock poisoned".into()))?;
        let open = guard
            .as_mut()
            .ok_or(Error::Provider("PKCS#11 session not available".into()))?;
        Ok(find_key_pair(&open.session, service)?.is_some())
    }

    fn load_kek(&self, service: &str, create_if_missing: bool) -> Result<Box<dyn KekHandle>> {
        self.check_not_refused()?;
        if !self.connected() {
            return Err(Error::Provider("PKCS#11 session not available".into()));
        }
        Ok(Box::new(Pkcs11Handle {
            key_id: format!("hkdfguard:{service}").into_bytes(),
            service: service.to_string(),
            create_if_missing,
            state: Arc::clone(&self.state), // cheap refcount bump, not a clone of the underlying session
        }))
    }
}

// The CKA_LABEL used to identify a service's key pair on the token.
fn key_label(service: &str) -> String {
    format!("hkdfguard:{service}")
}

// Looks up the service's private key object by label, without creating
// anything. `None` means no key pair has been generated for this service
// yet.
fn find_key_pair(session: &Session, service: &str) -> Result<Option<ObjectHandle>> {
    let label = key_label(service);

    let find_template = [
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::EC),
        Attribute::Label(label.into_bytes()),
    ];
    let found = session
        .find_objects(&find_template) // C_FindObjects: search the token for a matching private key
        .map_err(|e| Error::Provider(format!("PKCS#11 find_objects failed: {e}")))?;

    Ok(found.into_iter().next())
}

// Looks up the service's public key object by label, without creating
// anything -- the counterpart to `find_key_pair`, used only by
// `Pkcs11Handle::public_key` (the private key it pairs with is never
// extractable, so the fingerprint has to come from this object instead).
fn find_public_key(session: &Session, service: &str) -> Result<Option<ObjectHandle>> {
    let label = key_label(service);

    let find_template = [
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(KeyType::EC),
        Attribute::Label(label.into_bytes()),
    ];
    let found = session
        .find_objects(&find_template)
        .map_err(|e| Error::Provider(format!("PKCS#11 find_objects failed: {e}")))?;

    Ok(found.into_iter().next())
}

// Generates a new, non-extractable EC key pair on the token for `service`,
// returning (public, private) handles. Callers are responsible for having
// already checked (via `find_key_pair`) that one doesn't exist yet -- this
// always generates a fresh pair.
fn generate_key_pair(session: &Session, service: &str) -> Result<(ObjectHandle, ObjectHandle)> {
    let label = key_label(service);
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

    let (public, private) = session
        .generate_key_pair(
            &Mechanism::EccKeyPairGen, // C_GenerateKeyPair with the EC key pair generation mechanism
            &public_template,
            &private_template,
        )
        .map_err(|e| Error::Provider(format!("PKCS#11 EC key pair generation failed: {e}")))?;

    Ok((public, private))
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
            // Wrap every CKA_VALUE the moment it's taken out of the
            // attribute list, so one of an unexpected size is still
            // zeroed as it's dropped here rather than freed with the
            // derived secret still in it.
            let bytes = Zeroizing::new(bytes);
            if bytes.len() == expected_len {
                return Ok(bytes); // found a CKA_VALUE of the expected size
            }
        }
    }
    Err(Error::Provider(
        "PKCS#11 token did not return a CKA_VALUE for derived secret".into(), // shouldn't happen given how `derive_template` was built
    ))
}

// Reads the CKA_EC_POINT attribute off a public-key object -- unlike
// CKA_VALUE on a private key, this is never sensitive (it's the whole
// point of a public key), so no `Zeroizing` wrapper is needed here.
fn read_ec_point(session: &Session, handle: ObjectHandle) -> Result<Vec<u8>> {
    let attrs = session
        .get_attributes(handle, &[AttributeType::EcPoint]) // C_GetAttributeValue for CKA_EC_POINT
        .map_err(|e| Error::Provider(format!("PKCS#11 get_attributes (EC_POINT) failed: {e}")))?;

    for attr in attrs {
        if let Attribute::EcPoint(bytes) = attr {
            return Ok(bytes);
        }
    }
    Err(Error::Provider(
        "PKCS#11 token did not return a CKA_EC_POINT for the public key".into(),
    ))
}

// Parses a PKCS#11 CKA_EC_POINT attribute value into a `p256::PublicKey`.
// The PKCS#11 spec defines this as the ANSI X9.62 ECPoint encoding, which
// for an uncompressed point *is* the raw `0x04 || X || Y` bytes -- but some
// tokens/implementations additionally DER-wrap that in an OCTET STRING
// (tag 0x04, length 0x41 = 65), which happens to share its leading byte
// with the uncompressed-point marker, so length (65 vs 67) is what
// actually disambiguates the two rather than the leading byte.
fn parse_ec_point(bytes: &[u8]) -> Result<PublicKey> {
    let raw: &[u8] = match bytes.len() {
        UNCOMPRESSED_POINT_LEN => bytes,
        n if n == UNCOMPRESSED_POINT_LEN + 2
            && bytes[0] == 0x04
            && bytes[1] as usize == UNCOMPRESSED_POINT_LEN =>
        {
            &bytes[2..] // strip the outer DER OCTET STRING tag + length byte
        }
        n => {
            return Err(Error::Provider(format!(
                "PKCS#11 token returned an EC point of unexpected length {n}"
            )))
        }
    };
    PublicKey::from_sec1_bytes(raw)
        .map_err(|_| Error::Provider("PKCS#11 token returned an invalid EC point".into()))
}

#[cfg(test)]
mod tests {
    use super::*; // bring `Pkcs11Provider` etc. into scope
    use secrecy::ExposeSecret;
    use std::os::unix::fs::PermissionsExt;

    // In a private directory of its own: `$TMPDIR` itself is usually
    // `/tmp`, which anyone can write to, and the PIN's location is checked.
    struct PinFile {
        dir: tempfile::TempDir,
        path: PathBuf,
    }

    impl PinFile {
        fn path(&self) -> &Path {
            &self.path
        }
    }

    fn pin_file(contents: &[u8], mode: u32) -> PinFile {
        let dir = crate::secure_file::private_tempdir();
        let path = dir.path().join("pkcs11.pin");
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        PinFile { dir, path }
    }

    #[test]
    fn pin_file_in_a_directory_others_can_write_is_rejected() {
        let f = pin_file(b"1234\n", 0o600);
        std::fs::set_permissions(f.dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = read_pin_file(f.path()).expect_err("someone else could swap in a wrong PIN");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        std::fs::set_permissions(f.dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn pin_file_is_read_and_one_trailing_newline_stripped() {
        let f = pin_file(b"1234\n", 0o600);
        assert_eq!(read_pin_file(f.path()).unwrap().expose_secret(), "1234");

        let f = pin_file(b"5678\r\n", 0o400);
        assert_eq!(read_pin_file(f.path()).unwrap().expose_secret(), "5678");

        let f = pin_file(b"no-newline", 0o600);
        assert_eq!(read_pin_file(f.path()).unwrap().expose_secret(), "no-newline");
    }

    #[test]
    fn pin_file_readable_by_group_or_others_is_rejected() {
        // SAFETY: geteuid has no preconditions.
        let root = unsafe { libc::geteuid() } == 0;
        // 0640 is the supported layout for a *root-owned* PIN (group = the
        // service's group); on a file the service owns, it's a leak.
        let modes: &[u32] = if root { &[0o604, 0o644, 0o660] } else { &[0o640, 0o604, 0o644, 0o660] };
        for &mode in modes {
            let f = pin_file(b"1234\n", mode);
            let err = read_pin_file(f.path()).expect_err("must be rejected");
            assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "mode {mode:o}");
        }
    }

    #[test]
    fn empty_or_non_utf8_pin_file_is_rejected() {
        let f = pin_file(b"\n", 0o600);
        assert_eq!(read_pin_file(f.path()).err().unwrap().kind(), std::io::ErrorKind::InvalidData);

        let f = pin_file(&[0xFF, 0xFE, b'\n'], 0o600);
        assert_eq!(read_pin_file(f.path()).err().unwrap().kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn missing_pin_file_is_not_found() {
        let err = read_pin_file(Path::new("/nonexistent-hkdfguard-pin-file")).err().unwrap();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    fn tok(label: &str, serial: &str) -> (String, String) {
        (label.to_string(), serial.to_string())
    }

    #[test]
    fn a_configured_label_or_serial_must_match_exactly_one_token() {
        let tokens = [tok("prod-kek", "1111"), tok("staging", "2222"), tok("prod-kek", "3333")];
        assert_eq!(select_token(&tokens, Some("staging"), None, None), Ok(1));
        assert_eq!(select_token(&tokens, None, Some("3333"), None), Ok(2));
        assert_eq!(select_token(&tokens, Some("prod-kek"), Some("1111"), None), Ok(0));
        assert!(select_token(&tokens, Some("prod-kek"), None, None).is_err(), "two tokens share the label");
        assert!(select_token(&tokens, Some("missing"), None, None).is_err());
        assert!(select_token(&tokens, Some("staging"), Some("1111"), None).is_err(), "label and serial must both match");
        // A configured label beats the debug slot index.
        assert_eq!(select_token(&tokens, Some("staging"), None, Some("0")), Ok(1));
    }

    #[test]
    fn without_a_label_there_must_be_exactly_one_token() {
        assert_eq!(select_token(&[tok("only", "1")], None, None, None), Ok(0));
        assert!(select_token(&[], None, None, None).is_err());
        assert!(
            select_token(&[tok("a", "1"), tok("b", "2")], None, None, None).is_err(),
            "with several tokens, picking the first would make the key's home depend on enumeration order"
        );
        // The debug-only index still works for tests.
        assert_eq!(select_token(&[tok("a", "1"), tok("b", "2")], None, None, Some("1")), Ok(1));
        assert!(select_token(&[tok("a", "1")], None, None, Some("5")).is_err());
        assert!(select_token(&[tok("a", "1")], None, None, Some("x")).is_err());
    }

    #[test]
    fn module_candidates_come_from_policy_then_debug_only_sources() {
        let policy = Some(PathBuf::from("/opt/hsm/lib.so"));
        let env = Some(std::ffi::OsString::from("/usr/lib/other.so"));
        assert_eq!(candidate_module_paths(policy.clone(), env.clone()), vec![PathBuf::from("/opt/hsm/lib.so")]);
        assert_eq!(candidate_module_paths(None, env), vec![PathBuf::from("/usr/lib/other.so")]);
        // This test binary is a debug build: the SoftHSM2 search applies.
        // Release builds get an empty list here (no module => no PKCS#11);
        // the Docker suite checks that against the release library.
        assert_eq!(candidate_module_paths(None, None).len(), DEFAULT_MODULE_PATHS.len());
    }

    #[test]
    fn module_path_must_be_absolute() {
        assert!(validate_module_path(Path::new("libsofthsm2.so")).is_err());
        assert!(validate_module_path(Path::new("./libsofthsm2.so")).is_err());
    }

    #[test]
    fn module_path_owned_by_non_root_is_rejected() {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return; // as root, any temp file is root-owned, so there's nothing to reject
        }
        let f = pin_file(b"not really a module", 0o755);
        let err = validate_module_path(f.path()).unwrap_err();
        assert!(err.contains("refusing"), "unexpected error: {err}");
    }

    #[test]
    fn root_owned_system_binary_passes_path_validation() {
        // Validation only -- nothing is loaded. /bin/sh is root-owned,
        // 0755, in a root-owned 0755 directory on every Unix this builds on
        // (and canonicalizing through a merged-/usr symlink still lands in
        // a root-owned directory).
        let checked = validate_module_path(Path::new("/bin/sh")).unwrap();
        assert!(checked.is_absolute());
    }

    #[test]
    #[ignore = "requires a configured SoftHSM2 (or other PKCS#11) module + token"] // skipped by default; run explicitly with `-- --ignored`
    fn same_service_reuses_same_key_pair() {
        let provider = Pkcs11Provider::new();
        assert!(provider.probe(), "no PKCS#11 session available");

        let eph = p256::SecretKey::random(&mut rand_core::OsRng); // stand-in "caller" ephemeral key for this test
        let eph_pub = eph.public_key();

        let h1 = provider.load_kek("com.company.orders", true).unwrap(); // first call: generates the key pair on the token
        let h2 = provider.load_kek("com.company.orders", true).unwrap(); // second call: must find and reuse the same one
        assert_eq!(*h1.ecdh(&eph_pub).unwrap(), *h2.ecdh(&eph_pub).unwrap()); // same underlying key -> same shared secret

        // `public_key()` must report the exact key `ecdh` actually used --
        // verified independently, by doing ECDH from the ephemeral side
        // against the reported public key and checking it agrees with
        // `h1.ecdh` above.
        let reported_public = h1.public_key().unwrap();
        let via_reported = p256::ecdh::diffie_hellman(eph.to_nonzero_scalar(), reported_public.as_affine());
        assert_eq!(h1.ecdh(&eph_pub).unwrap().as_slice(), via_reported.raw_secret_bytes().as_slice());
    }

    /// The SoftHSM2 token label both test harnesses create --
    /// docker/entrypoint-test.sh and scripts/native-tpm-test.sh. Change all
    /// three together.
    const SOFTHSM_TEST_TOKEN_LABEL: &str = "hkdfguard-test";

    #[test]
    #[ignore = "requires a configured SoftHSM2 (or other PKCS#11) module + the harness token (SOFTHSM_TEST_TOKEN_LABEL)"]
    fn policy_selects_the_module_and_the_token_by_label() {
        // Both harnesses initialize a token labelled SOFTHSM_TEST_TOKEN_LABEL
        // and export the module path for debug builds; here the module comes
        // from policy instead, as in production.
        let module = std::env::var("HKDFGUARD_PKCS11_MODULE").expect("set by the test harness");
        let dir = crate::secure_file::private_tempdir();
        let path = dir.path().join("policy.toml");
        let policy_for = |label: &str| {
            format!("[selection]\nmode = \"require\"\nprovider = \"pkcs11\"\n[pkcs11]\nmodule = \"{module}\"\ntoken_label = \"{label}\"\n")
        };

        crate::secure_file::write_world_readable_for_tests(&path, policy_for(SOFTHSM_TEST_TOKEN_LABEL));
        std::env::set_var("HKDFGUARD_POLICY_FILE", &path);
        let matched = Pkcs11Provider::new().probe();

        crate::secure_file::write_world_readable_for_tests(&path, policy_for("no-such-token"));
        let unmatched = Pkcs11Provider::new();
        let unmatched_load = unmatched.load_kek("com.company.orders", false).err();
        std::env::remove_var("HKDFGUARD_POLICY_FILE");

        assert!(matched, "the token labelled {SOFTHSM_TEST_TOKEN_LABEL} must be selected");
        // Configured but unusable: refused -- present, so the chain stops
        // here, and failing every call -- never another token, and never
        // a quiet fall-through to a weaker provider.
        assert!(unmatched.probe(), "a configured PKCS#11 that can't be used is refused, not absent");
        match unmatched_load {
            Some(Error::Provider(msg)) => assert!(msg.contains("no-such-token"), "unexpected: {msg}"),
            other => panic!("a label that matches no token must fail the call, got {other:?}"),
        }
    }

    #[test]
    #[ignore = "requires a configured SoftHSM2 (or other PKCS#11) module + token"]
    fn token_accepts_hashed_payload_points() {
        // Same check as the TPM2 provider's own version: the
        // forgery-resistant protocol needs CKM_ECDH1_DERIVE against a
        // caller-supplied point hashed from the payload salt, so confirm
        // this module accepts such points rather than assuming. A module
        // that rejected them would make the construction unusable on
        // that HSM.
        let provider = Pkcs11Provider::new();
        assert!(provider.probe(), "no PKCS#11 session available");

        let h = crate::crypto::payload_ecdh_point(&[0x42u8; 32]).unwrap();

        let handle = provider.load_kek("com.company.orders", true).unwrap();
        let z1 = handle.ecdh(&h).unwrap();
        let z2 = handle.ecdh(&h).unwrap();
        assert_eq!(*z1, *z2, "ECDH against the same point must be repeatable for the same key");
        assert_ne!(z1.as_slice(), [0u8; 32], "shared secret must not be all zeroes");

        // A different service's key must yield a different Z against the
        // same point.
        let other = provider.load_kek("com.company.billing", true).unwrap();
        assert_ne!(*z1, *other.ecdh(&h).unwrap(), "different keys must yield different Z against the same point");

        // A different salt's point yields a different Z for the same key.
        let h2 = crate::crypto::payload_ecdh_point(&[0x43u8; 32]).unwrap();
        assert_ne!(*z1, *handle.ecdh(&h2).unwrap(), "different salts must yield different Z");
    }
}
