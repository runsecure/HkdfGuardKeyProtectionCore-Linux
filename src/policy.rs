//! Linux administrative key-selection policy: `/etc/hkdfguard/policy.toml`
//! (overridable with `HKDFGUARD_POLICY_FILE`), giving system administrators
//! control over which KEK providers this crate may use and how the
//! provider chain is selected -- functionally equivalent to HKDFGuard's
//! Windows registry-based policy, extended to Linux-specific providers
//! (TPM2, PKCS#11, an externally provisioned secret, and an in-memory
//! ephemeral key). There is deliberately no software-backed (PKCS#8-file)
//! provider on this platform, so `require: pkcs8` -- the Windows-parity
//! token the original design sketch used for that concept -- is not part
//! of this vocabulary; a deployment without TPM2/PKCS#11 hardware should
//! provision a KEK via `external-secret` instead.
//!
//! Design: policy decisions are expressed primarily in terms of a
//! [`KeyProtectionLevel`] (an assurance tier) rather than naming specific
//! provider technologies, so a future provider can slot into an existing
//! level (see [`ProviderType::protection_level`]) and immediately be
//! usable under `require-level`/`minimum_protection` policies without any
//! change to this schema. Only the `require` mode and `preferred_order`
//! name providers directly, since that's their whole point.
//!
//! Separation of concerns: this module owns policy *parsing and
//! evaluation* only -- it has no knowledge of `KekProvider`/`KekHandle`
//! (the actual provider implementations in `crate::provider`) and knows
//! nothing about *how* a provider works -- it only carries the settings
//! each provider reads from the policy (module path, PIN file, TCTI...).
//! Its central question: given the provider types compiled
//! into this build, which of them, in what order, does policy currently
//! allow?

use crate::error::{Error, Result};
use crate::provider::ProviderType;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

/// Location of the policy file. Every build that ships reads only this
/// path; every other piece of configuration (TPM, derivation secret,
/// secret mount, PKCS#11 module, token and PIN file) is named inside it.
#[cfg_attr(test, allow(dead_code))] // unit tests never read the real policy (see `policy_file_path`)
const DEFAULT_POLICY_FILE: &str = "/etc/hkdfguard/policy.toml";

/// Which policy file to read.
///
/// Builds that ship: always [`DEFAULT_POLICY_FILE`]. Nothing in the
/// environment can redirect it -- the environment is often set by
/// lower-trust configuration than the root-owned file, and whoever picks
/// the policy file picks the TPM, the secrets, and the HSM module loaded
/// into this process.
///
/// Test builds only:
/// - this crate's unit tests (`cfg(test)`): the policy of the innermost
///   live [`test_support::TestPolicy`]; else the harness's
///   `HKDFGUARD_POLICY_FILE`; else *no* policy, so a real
///   `/etc/hkdfguard` on a developer's machine never leaks into a test;
/// - the harnesses' out-of-process builds (`--cfg hkdfguard_test_paths`,
///   which no ordinary build setting can turn on, debug profile
///   included): `HKDFGUARD_POLICY_FILE`, else the default. Such a build
///   says so in its log.
fn policy_file_path() -> PathBuf {
    #[cfg(test)]
    {
        if let Some(path) = test_support::active_path() {
            return path;
        }
        std::env::var_os("HKDFGUARD_POLICY_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/nonexistent-hkdfguard-policy-for-unit-tests"))
    }
    #[cfg(all(not(test), hkdfguard_test_paths))]
    {
        static ANNOUNCED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        ANNOUNCED.get_or_init(|| {
            log::warn!(
                "hkdfguard: TEST BUILD (--cfg hkdfguard_test_paths): HKDFGUARD_POLICY_FILE is honored and \
                 configuration owned by this user is accepted; never deploy this library"
            );
        });
        std::env::var_os("HKDFGUARD_POLICY_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_POLICY_FILE))
    }
    #[cfg(not(any(test, hkdfguard_test_paths)))]
    {
        if std::env::var_os("HKDFGUARD_POLICY_FILE").is_some() {
            static WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
            WARNED.get_or_init(|| {
                log::warn!("hkdfguard: HKDFGUARD_POLICY_FILE is set but ignored: the policy is always {DEFAULT_POLICY_FILE}");
            });
        }
        PathBuf::from(DEFAULT_POLICY_FILE)
    }
}

/// Security assurance level a provider offers, independent of the specific
/// technology backing it (see [`ProviderType::protection_level`]). Declared
/// ascending, weakest first, so a derived [`Ord`] makes "at least this
/// strong" a plain `>=` comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyProtectionLevel {
    Ephemeral,
    Software,
    External,
    Hardware,
}

impl KeyProtectionLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyProtectionLevel::Ephemeral => "ephemeral",
            KeyProtectionLevel::Software => "software",
            KeyProtectionLevel::External => "external",
            KeyProtectionLevel::Hardware => "hardware",
        }
    }
}

impl ProviderType {
    /// This provider's assurance tier -- what policy decisions should
    /// generally be made against instead of the specific provider
    /// identity, so adding a new provider later doesn't require touching
    /// every existing `require-level`/`minimum_protection` policy.
    pub fn protection_level(&self) -> KeyProtectionLevel {
        match self {
            ProviderType::Tpm2 | ProviderType::Pkcs11 => KeyProtectionLevel::Hardware,
            ProviderType::ExternalSecret => KeyProtectionLevel::External,
            ProviderType::Ephemeral => KeyProtectionLevel::Ephemeral,
        }
    }

    /// The policy-file vocabulary's name for this provider (distinct from
    /// [`Self::as_str`], which is the log-message/legacy form) -- used in
    /// policy error messages so they read in the same terms the policy file uses.
    fn policy_name(&self) -> &'static str {
        match self {
            ProviderType::Tpm2 => "tpm2",
            ProviderType::Pkcs11 => "pkcs11",
            ProviderType::ExternalSecret => "external-secret",
            ProviderType::Ephemeral => "ephemeral",
        }
    }
}

// Manual (not derived) `Deserialize`: the policy vocabulary's provider
// names (`tpm2`, `pkcs11`, `external-secret`, `ephemeral`) don't match
// `ProviderType`'s own variant names 1:1 (the wire-format log names are
// upper-snake-case), so this is kept independent of that type's definition
// in `provider::mod` -- Rust's orphan rules allow a foreign trait
// (`serde::Deserialize`) to be implemented for a local type from any
// module in this crate.
//
// `pkcs8` is deliberately not a recognized token: this platform has no
// software-backed provider (see this module's own doc comment), so it
// falls through to the `other` arm below like any other unknown name.
impl<'de> Deserialize<'de> for ProviderType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "tpm2" => Ok(ProviderType::Tpm2),
            "pkcs11" => Ok(ProviderType::Pkcs11),
            "external-secret" => Ok(ProviderType::ExternalSecret),
            "ephemeral" => Ok(ProviderType::Ephemeral),
            other => Err(serde::de::Error::custom(format!(
                "unknown provider \"{other}\" (expected one of: tpm2, pkcs11, external-secret, ephemeral)"
            ))),
        }
    }
}

// ---------------------------------------------------------------------
// Raw (as-deserialized, unvalidated) policy-file schema.
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    #[serde(default)]
    key_requirements: KeyRequirements,
    selection: RawSelection,
    #[serde(default)]
    preferred_order: Vec<ProviderType>,
    #[serde(default)]
    startup_behavior: StartupBehavior,
    #[serde(default)]
    tpm: TpmPolicy,
    #[serde(default)]
    external_secret: ExternalSecretPolicy,
    #[serde(default)]
    pkcs11: Pkcs11Policy,
}

/// External-secret provider settings (`[external_secret]`).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalSecretPolicy {
    /// The directory holding `<service>` KEK files. When set, it is the
    /// only place looked at; when unset, the provider searches the
    /// conventional secret mounts.
    dir: Option<String>,
}

/// PKCS#11 provider settings (`[pkcs11]`).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pkcs11Policy {
    /// Absolute path of the PKCS#11 module to load. Every build uses
    /// PKCS#11 only when this is set: there is no default module search,
    /// since the commonly installed one (SoftHSM2) is a software token.
    module: Option<String>,
    /// Absolute path of the user-PIN file (default /etc/hkdfguard/pkcs11.pin).
    pin_file: Option<String>,
    /// Select the token by its CKA label (`CK_TOKEN_INFO.label`), and/or
    /// its serial number. Slot numbers aren't stable across reboots or
    /// hot-plugging; these are. Exactly one token must match.
    token_label: Option<String>,
    token_serial: Option<String>,
}

/// The PKCS#11 settings policy supplies, validated.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pkcs11Settings {
    pub module: Option<PathBuf>,
    pub pin_file: Option<PathBuf>,
    pub token_label: Option<String>,
    pub token_serial: Option<String>,
}

// A policy-supplied path must be absolute: a relative one would resolve
// against whatever directory the host application happens to run in.
fn absolute_path(field: &str, value: &str) -> Result<PathBuf> {
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(Error::Provider(format!("hkdfguard policy: {field} \"{value}\" must be an absolute path")));
    }
    Ok(path)
}

// PKCS#11 token fields are fixed-width, blank-padded: label 32 bytes,
// serial 16. A longer value can never match, so reject it as a typo.
fn token_field(field: &str, value: &str, max: usize) -> Result<String> {
    if value.is_empty() || value.len() > max {
        return Err(Error::Provider(format!(
            "hkdfguard policy: {field} must be 1..={max} bytes, got {}",
            value.len()
        )));
    }
    Ok(value.to_string())
}

/// TPM2-provider-specific administrative controls. Parsed and validated
/// on every build (so a policy file is portable across builds with and
/// without the `tpm2` feature) but only consulted by the TPM2 provider.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TpmPolicy {
    /// Refuse to use the TPM provider at all unless the derivation-secret
    /// file is present and trustworthy. Default `true`: without the secret
    /// the derivation depends only on the TPM seed and a public label, so
    /// any local process that can open the TPM reproduces every key.
    /// Setting it `false` allows running without one, with a warning.
    #[serde(default = "default_true")]
    require_derivation_secret: bool,
    /// Expected TPM Name, per service, as lowercase hex. When a service
    /// has an entry here, the Name the TPM reports for its key must match
    /// it exactly or the operation fails -- see
    /// [`pinned_tpm_name`] for why this, and not the
    /// self-consistency check, is the part that resists substitution.
    #[serde(default)]
    pinned_names: BTreeMap<String, String>,
    /// Make `pinned_names` the TPM provider's allowlist: a service with no
    /// pinned Name is treated as having no KEK (`kek_exists` is false,
    /// wrap/unwrap decline). Without this, the TPM derives a key for any
    /// service name on demand, so "provisioning" gates nothing. Default
    /// `false`, so existing deployments keep working until they pin.
    #[serde(default)]
    require_pinned_names: bool,
    /// Whether `TPM2_ECDH_ZGen` runs inside a salted, parameter-encrypted
    /// HMAC session, so the shared secret does not cross the TPM bus in
    /// cleartext. See [`SessionEncryption`].
    #[serde(default)]
    session_encryption: SessionEncryption,
    /// Expected TPM Name of the key that salts encrypted sessions, as
    /// lowercase hex. Without it, a bus-resident attacker can substitute
    /// their own salt key at `TPM2_ReadPublic` and decrypt the session
    /// (a full man-in-the-middle), so `session_encryption = "required"`
    /// refuses to load without one. Under `auto` it is optional and its
    /// absence is logged once: passive sniffing is still defeated.
    pinned_session_salt_key_name: Option<String>,
    /// Which TPM to talk to, as a tpm2-tss TCTI string:
    /// `device:/dev/tpmrm0` (the default when unset), `tabrmd:...`,
    /// `mssim:...` or `swtpm:...`. Set here, by root, because it decides
    /// whose TPM derives the keys: a TCTI pointed at an attacker-run
    /// simulator hands them a TPM whose seed they know.
    tcti: Option<String>,
    /// Absolute path of the derivation-secret file (default
    /// `/etc/hkdfguard/tpm.derivation-secret`).
    derivation_secret_file: Option<String>,
}

/// TCTI kinds tss-esapi can open; anything else is rejected at load time.
const TCTI_KINDS: &[&str] = &["device", "tabrmd", "mssim", "swtpm"];

// Checks that a policy TCTI names a supported kind. The rest of the string
// (device path, host/port) is parsed by the TPM provider, which treats a
// value it can't parse as "TPM unavailable", never as "use the default".
fn validate_tcti(tcti: &str) -> Result<()> {
    let kind = tcti.split(':').next().unwrap_or("");
    if TCTI_KINDS.contains(&kind) {
        return Ok(());
    }
    Err(Error::Provider(format!(
        "hkdfguard policy: tpm.tcti \"{tcti}\" must start with one of: {}",
        TCTI_KINDS.join(", ")
    )))
}

// Manual rather than derived: `require_derivation_secret` must default to
// true when the `[tpm]` table is absent, exactly as when it is present
// without the key.
impl Default for TpmPolicy {
    fn default() -> Self {
        TpmPolicy {
            require_derivation_secret: true,
            pinned_names: BTreeMap::new(),
            require_pinned_names: false,
            session_encryption: SessionEncryption::default(),
            pinned_session_salt_key_name: None,
            tcti: None,
            derivation_secret_file: None,
        }
    }
}

/// Policy for TPM session parameter encryption (`tpm.session_encryption`).
///
/// The threat this addresses is an interposer on a *discrete* TPM's LPC or
/// SPI bus reading `TPM2_ECDH_ZGen`'s response -- the shared secret -- in
/// cleartext. A firmware TPM (Intel PTT, AMD fTPM) or a virtual TPM has no
/// external bus, so encryption there is pure overhead with no security
/// return; the residual fTPM threats are inside the TPM's own trust
/// boundary, where transport encryption cannot help.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionEncryption {
    /// Always encrypt, and refuse the TPM unless the salt key's Name is
    /// pinned. For fleets with discrete TPMs, or when the manufacturer
    /// string can't be trusted.
    Required,
    /// Encrypt unless the TPM reports a manufacturer known to have no
    /// external bus (fTPM/vTPM vendors). Unknown vendors are encrypted --
    /// the decision only ever *skips* encryption for a known-internal TPM.
    /// The manufacturer is read over the bus being protected, so an active
    /// interposer can forge it: this defeats passive sniffing only. With
    /// `pinned_session_salt_key_name` set, `auto` always encrypts.
    #[default]
    Auto,
    /// Never encrypt. For test harnesses; not for production.
    Off,
}

/// Length of a SHA-256 TPM Name: the two-byte `TPM_ALG_SHA256` prefix
/// followed by the 32-byte digest of the marshalled public area.
const SHA256_TPM_NAME_LEN: usize = 2 + 32;

// Decodes a policy-supplied TPM Name and checks it is a SHA-256 Name.
fn parse_tpm_name(field: &str, hex: &str) -> Result<Vec<u8>> {
    let bytes = parse_hex(hex)
        .ok_or_else(|| Error::Provider(format!("hkdfguard policy: {field} is not valid hex")))?;
    if bytes.len() != SHA256_TPM_NAME_LEN {
        return Err(Error::Provider(format!(
            "hkdfguard policy: {field} is {} bytes, expected {SHA256_TPM_NAME_LEN} (a SHA-256 TPM Name)",
            bytes.len()
        )));
    }
    Ok(bytes)
}

// Decodes an even-length hex string. Returns `None` on any non-hex
// character or odd length.
fn parse_hex(s: &str) -> Option<Vec<u8>> {
    // Works on bytes, never on `&str` slices: slicing at an odd byte
    // offset panics if a multi-byte character straddles it, and a policy
    // file is not trusted to be ASCII. Digits are decoded one by one,
    // because `u8::from_str_radix` would also accept a leading `+`.
    let digit = |b: u8| (b as char).to_digit(16);
    let s = s.trim().as_bytes();
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return None;
    }
    let (pairs, _) = s.as_chunks::<2>(); // even length, so nothing is left over
    pairs.iter().map(|&[hi, lo]| Some((digit(hi)? << 4 | digit(lo)?) as u8)).collect()
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRequirements {
    minimum_protection: Option<KeyProtectionLevel>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSelection {
    mode: SelectionModeTag,
    provider: Option<ProviderType>,
    level: Option<KeyProtectionLevel>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum SelectionModeTag {
    Require,
    RequireLevel,
    Prefer,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartupBehavior {
    // Accepted for schema/Windows-policy-vocabulary compatibility, but
    // currently a no-op either way: this crate always fails closed (design
    // goal #6 -- "no automatic downgrades occur" is unconditional, not an
    // opt-in), so there's no non-fail-closed startup mode to switch off
    // yet. Kept as a real, validated field rather than silently accepted
    // so a future graceful-startup mode has somewhere to land without a
    // schema change.
    #[serde(default = "default_true")]
    #[allow(dead_code)]
    fail_if_requirement_unmet: bool,
    // Minimum wall-clock duration of every `hkdfguard_create_kek` and
    // `hkdfguard_kek_exists` call, in milliseconds (default
    // `DEFAULT_SETUP_MIN_DELAY_MS`; `0` disables the floor). See
    // `setup_min_delay` for what this is for.
    setup_min_delay_ms: Option<u64>,
}

fn default_true() -> bool {
    true
}

impl Default for StartupBehavior {
    fn default() -> Self {
        StartupBehavior {
            fail_if_requirement_unmet: true,
            setup_min_delay_ms: None,
        }
    }
}

/// Default floor on the duration of each setup call (`hkdfguard_create_kek`
/// / `hkdfguard_kek_exists`) when the policy doesn't say otherwise.
pub const DEFAULT_SETUP_MIN_DELAY_MS: u64 = 1_000;

/// Largest `setup_min_delay_ms` a policy may set. A root-controlled policy
/// could legitimately want a long floor, but a typo (one zero too many)
/// shouldn't be able to turn application startup into a multi-hour hang;
/// anything above this is rejected as a validation error rather than
/// honored.
pub const MAX_SETUP_MIN_DELAY_MS: u64 = 60_000;

// ---------------------------------------------------------------------
// Validated policy.
// ---------------------------------------------------------------------

/// A validated selection mode -- the parsed, cross-checked form of
/// [`RawSelection`] (e.g. `require` is guaranteed to carry a `provider`,
/// never a stray `level`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionMode {
    /// Only this exact provider may be used; no fallback.
    Require(ProviderType),
    /// Any provider at or above this assurance tier may be used.
    RequireLevel(KeyProtectionLevel),
    /// Try providers in preference order; first available wins.
    Prefer,
}

/// Trait-based abstraction over policy evaluation, so provider-selection
/// code (`provider::allowed_chain`) depends on this interface rather than
/// [`Policy`]'s concrete fields.
pub trait PolicyEvaluator {
    /// Given every provider type compiled into this build, in the default
    /// priority order, returns the subset policy currently allows, in the
    /// order they should be tried. An empty result (not an error) means
    /// the policy is well-formed but nothing compiled into this build
    /// currently qualifies -- callers should fail closed on that, exactly
    /// as they would on a chain that was merely unreachable at runtime.
    fn allowed_providers(&self, compiled: &[ProviderType]) -> Result<Vec<ProviderType>>;
}

/// A fully parsed and cross-validated policy file.
#[derive(Debug, Clone)]
pub struct Policy {
    selection: SelectionMode,
    minimum_protection: Option<KeyProtectionLevel>,
    preferred_order: Vec<ProviderType>,
    setup_min_delay: Duration,
    require_tpm_derivation_secret: bool,
    require_tpm_pinned_names: bool,
    /// Normalized service name -> expected TPM Name bytes.
    pinned_tpm_names: BTreeMap<String, Vec<u8>>,
    tpm_session_encryption: SessionEncryption,
    pinned_session_salt_key_name: Option<Vec<u8>>,
    tpm_tcti: Option<String>,
    tpm_derivation_secret_file: Option<PathBuf>,
    external_secret_dir: Option<PathBuf>,
    pkcs11: Pkcs11Settings,
}

impl Policy {
    /// Parses and validates a policy document from a string (the TOML
    /// text itself, not a path) -- kept separate from file I/O so tests
    /// can exercise every schema/validation rule without touching disk or
    /// environment variables.
    ///
    /// TOML rather than YAML: it has one way to write each value (no
    /// implicit `off`/`no` booleans, no anchors or aliases to expand), its
    /// parser is a maintained, Rust-native crate, and a misplaced key is a
    /// hard error here rather than a silent reinterpretation -- every
    /// table is `deny_unknown_fields`, so a top-level key written below a
    /// `[table]` header lands inside that table and is rejected.
    pub fn from_toml_str(doc: &str) -> Result<Policy> {
        let raw: PolicyFile = toml::from_str(doc)
            .map_err(|e| Error::Provider(format!("invalid hkdfguard policy: {e}")))?;
        Self::validate(raw)
    }

    fn validate(raw: PolicyFile) -> Result<Policy> {
        let selection = match raw.selection.mode {
            SelectionModeTag::Require => {
                let provider = raw.selection.provider.ok_or_else(|| {
                    Error::Provider(
                        "hkdfguard policy: selection.mode \"require\" needs a selection.provider"
                            .to_string(),
                    )
                })?;
                if raw.selection.level.is_some() {
                    return Err(Error::Provider(
                        "hkdfguard policy: selection.mode \"require\" must not also set selection.level"
                            .to_string(),
                    ));
                }
                SelectionMode::Require(provider)
            }
            SelectionModeTag::RequireLevel => {
                let level = raw.selection.level.ok_or_else(|| {
                    Error::Provider(
                        "hkdfguard policy: selection.mode \"require-level\" needs a selection.level"
                            .to_string(),
                    )
                })?;
                if raw.selection.provider.is_some() {
                    return Err(Error::Provider(
                        "hkdfguard policy: selection.mode \"require-level\" must not also set selection.provider"
                            .to_string(),
                    ));
                }
                SelectionMode::RequireLevel(level)
            }
            SelectionModeTag::Prefer => {
                if raw.selection.provider.is_some() || raw.selection.level.is_some() {
                    return Err(Error::Provider(
                        "hkdfguard policy: selection.mode \"prefer\" must not set selection.provider or selection.level"
                            .to_string(),
                    ));
                }
                SelectionMode::Prefer
            }
        };

        let minimum_protection = raw.key_requirements.minimum_protection;

        // A "require this exact provider" policy that names a provider
        // below the stated minimum protection is self-contradictory --
        // reject it now rather than let it silently produce an always-
        // empty allowed list at evaluation time.
        if let (SelectionMode::Require(p), Some(min)) = (selection, minimum_protection) {
            if p.protection_level() < min {
                return Err(Error::Provider(format!(
                    "hkdfguard policy: selection requires provider \"{}\" ({}), below key_requirements.minimum_protection ({})",
                    p.policy_name(),
                    p.protection_level().as_str(),
                    min.as_str()
                )));
            }
        }

        let mut seen = Vec::new();
        for p in &raw.preferred_order {
            if seen.contains(p) {
                return Err(Error::Provider(format!(
                    "hkdfguard policy: preferred_order lists \"{}\" more than once",
                    p.policy_name()
                )));
            }
            seen.push(*p);
        }

        let setup_min_delay_ms = raw
            .startup_behavior
            .setup_min_delay_ms
            .unwrap_or(DEFAULT_SETUP_MIN_DELAY_MS);
        if setup_min_delay_ms > MAX_SETUP_MIN_DELAY_MS {
            return Err(Error::Provider(format!(
                "hkdfguard policy: startup_behavior.setup_min_delay_ms is {setup_min_delay_ms}, above the {MAX_SETUP_MIN_DELAY_MS} ms maximum"
            )));
        }

        // Pinned TPM Names: decode and length-check every entry up front,
        // so a typo surfaces as a policy error at load time rather than as
        // a mysterious provider failure on the first wrap. Service keys go
        // through the same normalization the FFI layer applies, so a
        // policy written with a differently-cased name still matches.
        let mut pinned_tpm_names = BTreeMap::new();
        for (service, hex) in &raw.tpm.pinned_names {
            let bytes = parse_tpm_name(&format!("tpm.pinned_names[\"{service}\"]"), hex)?;
            if pinned_tpm_names
                .insert(crate::normalize_service(service), bytes)
                .is_some()
            {
                return Err(Error::Provider(format!(
                    "hkdfguard policy: tpm.pinned_names lists \"{service}\" more than once (names are compared case-insensitively)"
                )));
            }
        }

        let pinned_session_salt_key_name = raw
            .tpm
            .pinned_session_salt_key_name
            .as_deref()
            .map(|hex| parse_tpm_name("tpm.pinned_session_salt_key_name", hex))
            .transpose()?;
        // `required` without a pin is a false sense of security: the
        // session would be encrypted, but to a salt key an interposer can
        // substitute. Refuse the policy rather than honor half of it.
        if raw.tpm.session_encryption == SessionEncryption::Required
            && pinned_session_salt_key_name.is_none()
        {
            return Err(Error::Provider(
                "hkdfguard policy: tpm.session_encryption \"required\" needs tpm.pinned_session_salt_key_name; \
                 without a pinned salt key the encrypted session can be man-in-the-middled on the bus"
                    .to_string(),
            ));
        }

        if let Some(tcti) = &raw.tpm.tcti {
            validate_tcti(tcti)?;
        }
        let tpm_derivation_secret_file = raw
            .tpm
            .derivation_secret_file
            .as_deref()
            .map(|f| absolute_path("tpm.derivation_secret_file", f))
            .transpose()?;

        let external_secret_dir = raw
            .external_secret
            .dir
            .as_deref()
            .map(|d| absolute_path("external_secret.dir", d))
            .transpose()?;
        let pkcs11 = Pkcs11Settings {
            module: raw.pkcs11.module.as_deref().map(|m| absolute_path("pkcs11.module", m)).transpose()?,
            pin_file: raw.pkcs11.pin_file.as_deref().map(|f| absolute_path("pkcs11.pin_file", f)).transpose()?,
            token_label: raw.pkcs11.token_label.as_deref().map(|l| token_field("pkcs11.token_label", l, 32)).transpose()?,
            token_serial: raw.pkcs11.token_serial.as_deref().map(|n| token_field("pkcs11.token_serial", n, 16)).transpose()?,
        };

        Ok(Policy {
            selection,
            minimum_protection,
            preferred_order: raw.preferred_order,
            setup_min_delay: Duration::from_millis(setup_min_delay_ms),
            require_tpm_derivation_secret: raw.tpm.require_derivation_secret,
            require_tpm_pinned_names: raw.tpm.require_pinned_names,
            pinned_tpm_names,
            tpm_session_encryption: raw.tpm.session_encryption,
            pinned_session_salt_key_name,
            tpm_tcti: raw.tpm.tcti,
            tpm_derivation_secret_file,
            external_secret_dir,
            pkcs11,
        })
    }

    /// TPM session parameter-encryption mode (`tpm.session_encryption`).
    pub fn tpm_session_encryption(&self) -> SessionEncryption {
        self.tpm_session_encryption
    }

    /// The external-secret directory (`external_secret.dir`), if policy sets one.
    pub fn external_secret_dir(&self) -> Option<&std::path::Path> {
        self.external_secret_dir.as_deref()
    }

    /// The PKCS#11 settings (`[pkcs11]`).
    pub fn pkcs11(&self) -> &Pkcs11Settings {
        &self.pkcs11
    }

    /// The TCTI the TPM provider must use (`tpm.tcti`), if policy sets one.
    pub fn tpm_tcti(&self) -> Option<&str> {
        self.tpm_tcti.as_deref()
    }

    /// The derivation-secret file (`tpm.derivation_secret_file`), if policy sets one.
    pub fn tpm_derivation_secret_file(&self) -> Option<&std::path::Path> {
        self.tpm_derivation_secret_file.as_deref()
    }

    /// The administrator-pinned Name of the session salt key, if any.
    pub fn pinned_session_salt_key_name(&self) -> Option<&[u8]> {
        self.pinned_session_salt_key_name.as_deref()
    }

    /// The floor on how long each setup call (`hkdfguard_create_kek`,
    /// `hkdfguard_kek_exists`) takes -- see the module-level
    /// [`setup_min_delay`] for why it exists.
    pub fn setup_min_delay(&self) -> Duration {
        self.setup_min_delay
    }

    /// Whether the TPM provider must refuse to run without a
    /// derivation-secret file (`tpm.require_derivation_secret`).
    pub fn require_tpm_derivation_secret(&self) -> bool {
        self.require_tpm_derivation_secret
    }

    /// Whether the TPM provider treats only pinned services as provisioned
    /// (`tpm.require_pinned_names`).
    pub fn require_tpm_pinned_names(&self) -> bool {
        self.require_tpm_pinned_names
    }

    /// The administrator-pinned TPM Name for `service`, if policy sets one.
    pub fn pinned_tpm_name(&self, service: &str) -> Option<&[u8]> {
        self.pinned_tpm_names
            .get(&crate::normalize_service(service))
            .map(|v| v.as_slice())
    }

    /// Whether Ephemeral is explicitly named by this policy: either as the
    /// sole provider under `require`, or listed by name in
    /// `preferred_order`. This is the *only* way Ephemeral is ever
    /// reachable -- see [`PolicyEvaluator::allowed_providers`] -- since its
    /// keys live only in process memory and are permanently lost on
    /// restart; assuming it's disallowed unless an operator specifically
    /// named it is the safer default than an opt-out flag someone could
    /// forget to set (or that could default the wrong way in a future
    /// schema change).
    fn ephemeral_explicitly_listed(&self) -> bool {
        self.selection == SelectionMode::Require(ProviderType::Ephemeral)
            || self.preferred_order.contains(&ProviderType::Ephemeral)
    }

    // The order candidates are considered in before the mode/level/
    // minimum-protection/ephemeral filters below are applied: the
    // configured `preferred_order` (restricted to what's actually
    // compiled in, preserving its relative order), or -- if none was
    // given -- the default compiled-in priority order verbatim.
    fn candidate_order(&self, compiled: &[ProviderType]) -> Vec<ProviderType> {
        if self.preferred_order.is_empty() {
            compiled.to_vec()
        } else {
            self.preferred_order
                .iter()
                .copied()
                .filter(|p| compiled.contains(p))
                .collect()
        }
    }
}

impl PolicyEvaluator for Policy {
    fn allowed_providers(&self, compiled: &[ProviderType]) -> Result<Vec<ProviderType>> {
        let mut candidates = match self.selection {
            SelectionMode::Require(provider) => {
                if !compiled.contains(&provider) {
                    return Err(Error::Provider(format!(
                        "hkdfguard policy requires provider \"{}\", but it is not compiled into this build",
                        provider.policy_name()
                    )));
                }
                vec![provider]
            }
            SelectionMode::RequireLevel(level) => self
                .candidate_order(compiled)
                .into_iter()
                .filter(|p| p.protection_level() >= level)
                .collect(),
            SelectionMode::Prefer => self.candidate_order(compiled),
        };

        if let Some(min) = self.minimum_protection {
            candidates.retain(|p| p.protection_level() >= min);
        }

        // Ephemeral is dropped from every result unless the policy
        // explicitly named it -- see `ephemeral_explicitly_listed`'s doc
        // comment. This applies regardless of mode: a `require-level`
        // policy whose level happens to be low enough to admit Ephemeral
        // by tier still doesn't get it unless it's actually named.
        if !self.ephemeral_explicitly_listed() {
            candidates.retain(|p| *p != ProviderType::Ephemeral);
        }

        Ok(candidates)
    }
}

/// Largest policy file accepted. Far above any realistic policy; exists so
/// a huge (or endless) file can't be used to exhaust memory.
const MAX_POLICY_FILE_LEN: usize = 64 * 1024;

/// What the policy file must satisfy before it's trusted: owned by root
/// (see [`crate::secure_file::config_owner`]) and not writable by anyone
/// else -- a policy the service itself could edit wouldn't be a policy.
/// Symlinks are followed (e.g. Kubernetes ConfigMap mounts are symlinks),
/// but the checks apply to the file actually opened, not the link.
const POLICY_FILE_REQUIREMENTS: crate::secure_file::FileRequirements = crate::secure_file::FileRequirements {
    owner: Some(crate::secure_file::config_owner()),
    forbidden_mode_bits: crate::secure_file::FORBID_GROUP_OTHER_WRITE,
    follow_symlinks: true,
    allow_group_read_if_root_owned: false, // already allowed: only write bits are forbidden
};

/// Reads and parses the configured policy file, if one is present.
///
/// Returns:
/// - `None` **only** if no file exists at the configured path. Every
///   compiled-in provider except Ephemeral is then allowed, in the default
///   priority order (see `provider::allowed_chain`).
/// - `Some(Ok(policy))` if a policy file was found, passed its ownership
///   and permission checks, and is valid.
/// - `Some(Err(_))` in every other case -- the file exists but can't be
///   read (permission denied, it's a directory, an I/O error), is owned by
///   someone untrusted or writable by group/others, is too large, isn't
///   UTF-8, or is malformed or self-contradictory; or the directory it
///   lives in (or would live in) is one someone untrusted could change.
///   This **fails closed**: every wrap/unwrap/create/exists call fails
///   rather than falling back to the unrestricted default. Making the file
///   unreadable, or deleting it, must never be a way to switch policy off.
///
/// Re-read from disk on every call (no caching), so an operator can update
/// the policy without restarting the process.
pub fn load() -> Option<Result<Policy>> {
    let path = policy_file_path();
    let fail = |what: String| Some(Err(Error::Provider(format!("hkdfguard policy file {}: {what}", path.display()))));

    if let Err(e) = crate::secure_file::check_location(&path, crate::secure_file::config_owner()) {
        return fail(format!("refusing to trust its location ({e})"));
    }
    let mut file = match crate::secure_file::open_checked(&path, &POLICY_FILE_REQUIREMENTS) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => return fail(format!("refusing to use it ({e})")),
    };
    let contents = match crate::secure_file::SecretBuffer::read_from(&mut file, MAX_POLICY_FILE_LEN) {
        Ok(c) => c,
        Err(e) => return fail(format!("could not be read ({e})")),
    };
    let text = match std::str::from_utf8(contents.as_slice()) {
        Ok(t) => t,
        Err(_) => return fail("is not valid UTF-8".to_string()),
    };

    Some(Policy::from_toml_str(text).map_err(|e| match e {
        Error::Provider(msg) => Error::Provider(format!("{} ({})", msg, path.display())),
        other => other,
    }))
}

/// The floor on the wall-clock duration of every `hkdfguard_create_kek` and
/// `hkdfguard_kek_exists` call: [`DEFAULT_SETUP_MIN_DELAY_MS`] unless the
/// policy file sets `startup_behavior.setup_min_delay_ms`.
///
/// Those two calls are meant to run once per application startup, so
/// making each take at least a second costs nothing a caller should
/// notice and buys several things at once: it bounds how fast a buggy or
/// hot-looping caller can drive the TPM/HSM (each call is a fresh
/// connection plus a key derivation -- see `provider::construct_provider`),
/// bounds Ephemeral key-map growth to one entry per second, and turns the
/// two enumeration oracles (`kek_exists` for "which services have a key",
/// and by extension the fingerprint pre-check) into something impractical
/// at scale. It's a floor on *latency*, not just spacing between calls, so
/// "exists" and "doesn't exist" take the same time as well.
///
/// A policy file that exists but is invalid still yields the default here
/// -- the call that's being gated is about to fail closed on that same
/// policy anyway, and there's no reason to let a broken policy also remove
/// the floor. Read from disk on every call, like everything else in this
/// module.
pub(crate) fn setup_min_delay() -> Duration {
    match load() {
        Some(Ok(policy)) => policy.setup_min_delay(),
        Some(Err(_)) | None => Duration::from_millis(DEFAULT_SETUP_MIN_DELAY_MS),
    }
}

/// Whether the TPM2 provider may only be used with a derivation-secret
/// file present (`tpm.require_derivation_secret`).
///
/// `true` unless a valid policy explicitly sets it `false`: with no policy
/// file, with a policy that doesn't mention it, and with a policy file
/// that exists but is invalid (a broken policy must never be the thing
/// that relaxes a security control).
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(crate) fn require_tpm_derivation_secret() -> bool {
    match load() {
        Some(Ok(policy)) => policy.require_tpm_derivation_secret(),
        Some(Err(_)) | None => true,
    }
}

/// The administrator-pinned TPM Name for `service`, if any.
///
/// This is the part of Name checking that actually resists substitution.
/// A TPM Name is `nameAlg || H(publicArea)` -- a *public* function of the
/// public area -- so verifying that a reported Name matches its own
/// reported public area (which the TPM2 provider also does) only catches
/// a non-conformant stack or corruption, not an active man-in-the-middle,
/// who could simply recompute a matching Name. Comparing against a value
/// an administrator recorded out-of-band, in the root-owned policy file,
/// is what makes substitution detectable.
///
/// `Err` when a policy file exists but can't be trusted -- pinning must
/// fail closed rather than silently degrade to "nothing pinned".
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(crate) fn pinned_tpm_name(service: &str) -> Result<Option<Vec<u8>>> {
    match load() {
        Some(Ok(policy)) => Ok(policy.pinned_tpm_name(service).map(|n| n.to_vec())),
        Some(Err(e)) => Err(e),
        None => Ok(None),
    }
}

/// Whether the TPM provider only serves services whose Name is pinned
/// (`tpm.require_pinned_names`). No policy file → `false`. A policy file
/// that exists but is invalid → `true`: a broken policy must never be what
/// widens the set of services the TPM will serve.
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(crate) fn require_tpm_pinned_names() -> bool {
    match load() {
        Some(Ok(policy)) => policy.require_tpm_pinned_names(),
        Some(Err(_)) => true,
        None => false,
    }
}

/// TPM session parameter-encryption mode. No policy file → `Auto`. A
/// policy file that exists but is invalid → `Required` (fail closed: a
/// broken policy must never be what turns bus protection off).
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(crate) fn tpm_session_encryption() -> SessionEncryption {
    match load() {
        Some(Ok(policy)) => policy.tpm_session_encryption(),
        Some(Err(_)) => SessionEncryption::Required,
        None => SessionEncryption::Auto,
    }
}

/// The TCTI policy requires (`tpm.tcti`), if any. `Err` on a policy file
/// that exists but can't be trusted: the TPM is then unavailable rather
/// than opened at a default the administrator may have meant to avoid.
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(crate) fn tpm_tcti() -> Result<Option<String>> {
    match load() {
        Some(Ok(policy)) => Ok(policy.tpm_tcti().map(str::to_owned)),
        Some(Err(e)) => Err(e),
        None => Ok(None),
    }
}

/// The derivation-secret file policy names (`tpm.derivation_secret_file`),
/// if any. `Err` on a policy file that exists but can't be trusted.
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(crate) fn tpm_derivation_secret_file() -> Result<Option<PathBuf>> {
    match load() {
        Some(Ok(policy)) => Ok(policy.tpm_derivation_secret_file().map(std::path::Path::to_path_buf)),
        Some(Err(e)) => Err(e),
        None => Ok(None),
    }
}

/// The external-secret directory policy requires (`external_secret.dir`),
/// if any. `Err` on a policy file that exists but can't be trusted, so the
/// provider is unavailable rather than searching the default mounts.
#[cfg_attr(not(feature = "external-secret"), allow(dead_code))]
pub(crate) fn external_secret_dir() -> Result<Option<PathBuf>> {
    match load() {
        Some(Ok(policy)) => Ok(policy.external_secret_dir().map(std::path::Path::to_path_buf)),
        Some(Err(e)) => Err(e),
        None => Ok(None),
    }
}

/// The PKCS#11 settings from policy (all unset with no policy file). `Err`
/// on a policy file that exists but can't be trusted.
#[cfg_attr(not(feature = "pkcs11"), allow(dead_code))]
pub(crate) fn pkcs11_settings() -> Result<Pkcs11Settings> {
    match load() {
        Some(Ok(policy)) => Ok(policy.pkcs11().clone()),
        Some(Err(e)) => Err(e),
        None => Ok(Pkcs11Settings::default()),
    }
}

/// The pinned session-salt-key Name, if policy sets one. `Err` on a
/// policy file that exists but can't be trusted -- pinning fails closed.
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(crate) fn pinned_session_salt_key_name() -> Result<Option<Vec<u8>>> {
    match load() {
        Some(Ok(policy)) => Ok(policy.pinned_session_salt_key_name().map(|n| n.to_vec())),
        Some(Err(e)) => Err(e),
        None => Ok(None),
    }
}

/// Test-only: a policy that explicitly names Ephemeral in
/// `preferred_order` (alongside `external-secret`, so tests that also need
/// that provider to remain a candidate still get it) -- the same explicit
/// naming a real deployment needs, since with no policy at all (or one that
/// never names it) Ephemeral is excluded (see `provider::allowed_chain` and
/// [`Policy::ephemeral_explicitly_listed`]). In force while the returned
/// guard lives.
#[cfg(test)]
pub(crate) fn allow_ephemeral_policy_for_tests() -> test_support::TestPolicy {
    test_support::TestPolicy::write("preferred_order = [\"external-secret\", \"ephemeral\"]\n[selection]\nmode = \"prefer\"\n")
}

/// Test-only: a policy pinning provider selection to `provider` (the policy
/// vocabulary's name, e.g. `external-secret`), in force while the returned
/// guard lives.
///
/// Any test whose subject is one *specific* provider must pin it this
/// way rather than relying on stronger providers being absent. With the
/// `tpm2` or `pkcs11` features compiled in and a real (or simulated)
/// device reachable, the priority chain selects TPM2/PKCS#11 first, and
/// a test that assumed external-secret would win either fails or -- much
/// worse -- silently stops exercising the thing it is named after. That
/// is exactly what happened to the rotation and provider-identity tests
/// the first time the suite ran under `--features tpm2` against swtpm.
#[cfg(test)]
pub(crate) fn require_provider_policy_for_tests(provider: &str) -> test_support::TestPolicy {
    test_support::TestPolicy::write(&format!("[selection]\nmode = \"require\"\nprovider = \"{provider}\"\n"))
}

/// Per-test policy files. See [`TestPolicy`].
#[cfg(test)]
pub(crate) mod test_support {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    /// Tables a layered policy merges key by key; every other top-level key
    /// (`[selection]` above all) is replaced whole, so a test's selection is
    /// never a blend of its own and the harness's.
    const MERGED_TABLES: &[&str] = &["tpm", "pkcs11", "external_secret"];

    struct Layer {
        path: PathBuf,
        /// `None`: this layer is "no policy file at all".
        table: Option<toml::Table>,
    }

    /// Live `TestPolicy` layers, innermost last. Tests that touch policy
    /// are `#[serial]`, so one stack serves the whole test binary.
    static LAYERS: Mutex<Vec<Layer>> = Mutex::new(Vec::new());

    fn layers() -> std::sync::MutexGuard<'static, Vec<Layer>> {
        LAYERS.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(super) fn active_path() -> Option<PathBuf> {
        layers().last().map(|l| l.path.clone())
    }

    // What a new layer is merged onto: the innermost live layer, or with
    // none, the harness's policy (HKDFGUARD_POLICY_FILE: which TPM, which
    // derivation secret, which PKCS#11 token this machine's test run uses).
    fn base() -> toml::Table {
        if let Some(layer) = layers().last() {
            return layer.table.clone().unwrap_or_default();
        }
        std::env::var_os("HKDFGUARD_POLICY_FILE")
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|text| text.parse::<toml::Table>().expect("the harness policy (HKDFGUARD_POLICY_FILE) is not valid TOML"))
            .unwrap_or_default()
    }

    /// A real policy file for the duration of one test: written into a
    /// private temp directory, read by the library through exactly the
    /// production path (ownership, location, and parse checks included),
    /// and removed -- with the library pointed back at whatever was in
    /// force before -- when the guard drops. Guards nest; drop them in
    /// reverse order of creation, as Rust does for locals.
    pub(crate) struct TestPolicy {
        _dir: tempfile::TempDir, // removed, with the policy file in it, when the guard drops
        depth: usize,
    }

    impl TestPolicy {
        /// `doc` layered over the policy already in force: the tables in
        /// `MERGED_TABLES` merge key by key, `doc` winning; any other
        /// top-level key `doc` sets replaces the old one whole. With no
        /// `[selection]` anywhere, `mode = "prefer"` is added, which selects
        /// exactly as having no policy file does.
        pub(crate) fn write(doc: &str) -> Self {
            let mut merged = base();
            let layer: toml::Table = doc.parse().unwrap_or_else(|e| panic!("TestPolicy::write: invalid TOML ({e}); use TestPolicy::exact for a malformed policy:\n{doc}"));
            for (key, value) in layer {
                match (merged.get_mut(&key), value) {
                    (Some(toml::Value::Table(old)), toml::Value::Table(new)) if MERGED_TABLES.contains(&key.as_str()) => old.extend(new),
                    (_, value) => {
                        merged.insert(key, value);
                    }
                }
            }
            if !merged.contains_key("selection") {
                let mut selection = toml::Table::new();
                selection.insert("mode".into(), toml::Value::String("prefer".into()));
                merged.insert("selection".into(), toml::Value::Table(selection));
            }
            let text = toml::to_string(&merged).expect("a merged policy serializes");
            Self::push(&text, Some(merged))
        }

        /// Exactly `contents`, merged with nothing -- for malformed,
        /// oversized, or otherwise deliberately broken policies.
        pub(crate) fn exact(contents: impl AsRef<[u8]>) -> Self {
            Self::push(contents, None)
        }

        /// Whatever is at `path` -- for tests of how the loader treats a
        /// directory, an unreadable file, or a file they manage themselves.
        pub(crate) fn at(path: &Path) -> Self {
            Self::stack(crate::secure_file::private_tempdir(), Layer { path: path.to_path_buf(), table: None })
        }

        /// No policy file at all.
        pub(crate) fn absent() -> Self {
            let dir = crate::secure_file::private_tempdir();
            let path = dir.path().join("no-policy.toml");
            Self::stack(dir, Layer { path, table: None })
        }

        fn push(contents: impl AsRef<[u8]>, table: Option<toml::Table>) -> Self {
            let dir = crate::secure_file::private_tempdir();
            let path = dir.path().join("policy.toml");
            crate::secure_file::write_world_readable_for_tests(&path, contents);
            Self::stack(dir, Layer { path, table: table.or(Some(toml::Table::new())) })
        }

        fn stack(dir: tempfile::TempDir, layer: Layer) -> Self {
            let mut layers = layers();
            layers.push(layer);
            TestPolicy { _dir: dir, depth: layers.len() }
        }
    }

    /// Points the external-secret provider at `dir` (`external_secret.dir`),
    /// layered over the policy in force.
    pub(crate) fn secret_mount(dir: &Path) -> TestPolicy {
        TestPolicy::write(&format!("[external_secret]\ndir = \"{}\"\n", dir.display()))
    }

    impl Drop for TestPolicy {
        fn drop(&mut self) {
            let mut layers = layers();
            // Out-of-order drops can only come from a guard kept beyond its
            // scope; unwinding everything above it keeps the stack sane.
            layers.truncate(self.depth - 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_support::TestPolicy;

    fn compiled(types: &[ProviderType]) -> Vec<ProviderType> {
        types.to_vec()
    }

    // ---- KeyProtectionLevel / ProviderType mapping ----

    #[test]
    fn protection_level_ordering_is_ascending() {
        assert!(KeyProtectionLevel::Ephemeral < KeyProtectionLevel::Software);
        assert!(KeyProtectionLevel::Software < KeyProtectionLevel::External);
        assert!(KeyProtectionLevel::External < KeyProtectionLevel::Hardware);
    }

    #[test]
    fn provider_protection_level_mapping() {
        assert_eq!(ProviderType::Tpm2.protection_level(), KeyProtectionLevel::Hardware);
        assert_eq!(ProviderType::Pkcs11.protection_level(), KeyProtectionLevel::Hardware);
        assert_eq!(ProviderType::ExternalSecret.protection_level(), KeyProtectionLevel::External);
        assert_eq!(ProviderType::Ephemeral.protection_level(), KeyProtectionLevel::Ephemeral);
    }

    #[test]
    fn provider_names_parse_per_policy_vocabulary() {
        let doc = "preferred_order = [\"tpm2\", \"pkcs11\", \"external-secret\", \"ephemeral\"]\n[selection]\nmode = \"prefer\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        assert_eq!(
            policy.preferred_order,
            vec![
                ProviderType::Tpm2,
                ProviderType::Pkcs11,
                ProviderType::ExternalSecret,
                ProviderType::Ephemeral,
            ]
        );
    }

    #[test]
    fn unknown_provider_name_is_rejected() {
        let doc = "[selection]\nmode = \"require\"\nprovider = \"quantum-vault\"\n";
        assert!(Policy::from_toml_str(doc).is_err());
    }

    // ---- Require mode ----

    #[test]
    fn require_tpm_success() {
        let doc = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        let allowed = policy
            .allowed_providers(&compiled(&[ProviderType::Tpm2, ProviderType::ExternalSecret, ProviderType::Ephemeral]))
            .unwrap();
        assert_eq!(allowed, vec![ProviderType::Tpm2]);
    }

    #[test]
    fn require_tpm_failure_when_not_compiled_in() {
        let doc = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        // TPM2 simply isn't part of this build -- policy must refuse to
        // silently substitute anything else.
        let err = policy
            .allowed_providers(&compiled(&[ProviderType::ExternalSecret, ProviderType::Ephemeral]))
            .unwrap_err();
        assert!(matches!(err, Error::Provider(_)));
    }

    // ---- Require-level mode ----

    #[test]
    fn require_hardware_success_via_tpm() {
        let doc = "[selection]\nmode = \"require-level\"\nlevel = \"hardware\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        let allowed = policy
            .allowed_providers(&compiled(&[ProviderType::Tpm2, ProviderType::ExternalSecret]))
            .unwrap();
        assert_eq!(allowed, vec![ProviderType::Tpm2]);
    }

    #[test]
    fn require_hardware_success_via_pkcs11() {
        let doc = "[selection]\nmode = \"require-level\"\nlevel = \"hardware\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        let allowed = policy
            .allowed_providers(&compiled(&[ProviderType::Pkcs11, ProviderType::ExternalSecret]))
            .unwrap();
        assert_eq!(allowed, vec![ProviderType::Pkcs11]);
    }

    #[test]
    fn require_hardware_failure_with_only_external_secret() {
        let doc = "[selection]\nmode = \"require-level\"\nlevel = \"hardware\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        // Not an Err here (the policy itself is fine) -- an empty allowed
        // list, which is what makes the actual selection chain fail
        // closed downstream.
        let allowed = policy
            .allowed_providers(&compiled(&[ProviderType::ExternalSecret, ProviderType::Ephemeral]))
            .unwrap();
        assert_eq!(allowed, Vec::<ProviderType>::new());
    }

    #[test]
    fn require_level_accepts_both_hardware_providers_together() {
        let doc = "[selection]\nmode = \"require-level\"\nlevel = \"hardware\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        let allowed = policy
            .allowed_providers(&compiled(&[
                ProviderType::Tpm2,
                ProviderType::Pkcs11,
                ProviderType::ExternalSecret,
                ProviderType::Ephemeral,
            ]))
            .unwrap();
        assert_eq!(allowed, vec![ProviderType::Tpm2, ProviderType::Pkcs11]);
    }

    // ---- Prefer mode ----

    #[test]
    fn prefer_mode_fallback_ordering() {
        let doc = "preferred_order = [\"tpm2\", \"pkcs11\", \"external-secret\", \"ephemeral\"]\n[selection]\nmode = \"prefer\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        // Only ephemeral and external-secret are actually compiled into
        // this build; the allowed order must still reflect
        // preferred_order's relative ordering, not the default
        // all_providers() order.
        let allowed = policy
            .allowed_providers(&compiled(&[ProviderType::Ephemeral, ProviderType::ExternalSecret]))
            .unwrap();
        assert_eq!(allowed, vec![ProviderType::ExternalSecret, ProviderType::Ephemeral]);
    }

    #[test]
    fn prefer_mode_without_preferred_order_uses_default_compiled_order() {
        // Deliberately uses two non-Ephemeral providers: this test is
        // about the fallback-to-compiled-order behavior specifically, kept
        // separate from Ephemeral's own always-excluded-unless-named rule
        // (covered by `ephemeral_disallowed_by_default_even_without_preferred_order`).
        let doc = "[selection]\nmode = \"prefer\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        let allowed = policy
            .allowed_providers(&compiled(&[ProviderType::Tpm2, ProviderType::ExternalSecret]))
            .unwrap();
        assert_eq!(allowed, vec![ProviderType::Tpm2, ProviderType::ExternalSecret]);
    }

    // ---- Minimum protection ----

    #[test]
    fn minimum_protection_enforcement() {
        let doc = "[key_requirements]\nminimum_protection = \"external\"\n[selection]\nmode = \"prefer\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        let allowed = policy
            .allowed_providers(&compiled(&[
                ProviderType::ExternalSecret,
                ProviderType::Ephemeral,
            ]))
            .unwrap();
        assert_eq!(allowed, vec![ProviderType::ExternalSecret]);
    }

    #[test]
    fn minimum_protection_external_rejects_ephemeral_only_build() {
        let doc = "[key_requirements]\nminimum_protection = \"external\"\n[selection]\nmode = \"prefer\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        let allowed = policy.allowed_providers(&compiled(&[ProviderType::Ephemeral])).unwrap();
        assert_eq!(allowed, Vec::<ProviderType>::new());
    }

    // ---- Ephemeral / container policy ----

    #[test]
    fn ephemeral_disallowed_by_default() {
        let doc = "[selection]\nmode = \"prefer\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        let allowed = policy
            .allowed_providers(&compiled(&[ProviderType::ExternalSecret, ProviderType::Ephemeral]))
            .unwrap();
        assert_eq!(allowed, vec![ProviderType::ExternalSecret]);
    }

    #[test]
    fn ephemeral_allowed_when_explicitly_named() {
        let doc = "preferred_order = [\"external-secret\", \"ephemeral\"]\n[selection]\nmode = \"prefer\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        let allowed = policy
            .allowed_providers(&compiled(&[ProviderType::ExternalSecret, ProviderType::Ephemeral]))
            .unwrap();
        assert_eq!(allowed, vec![ProviderType::ExternalSecret, ProviderType::Ephemeral]);
    }

    #[test]
    fn container_policy_is_not_a_policy_table() {
        // `max_ephemeral_lifetime_seconds` was once accepted and validated
        // but never enforced -- a setting that read as a limit and did
        // nothing. The table is gone, so a policy that sets it fails to
        // load instead of implying a control that doesn't exist.
        // (Ephemeral keys already live only as long as the process; its
        // gate is `preferred_order` naming it, see
        // `Policy::ephemeral_explicitly_listed`.)
        for doc in [
            "[selection]\nmode = \"prefer\"\n[container_policy]\nmax_ephemeral_lifetime_seconds = 3600\n",
            "[selection]\nmode = \"prefer\"\n[container_policy]\nallow_ephemeral = true\n",
        ] {
            let err = Policy::from_toml_str(doc).expect_err(doc);
            assert!(err.to_string().contains("container_policy"), "unexpected error: {err}");
        }
    }

    // ---- Invalid configuration rejection ----

    #[test]
    fn invalid_configuration_rejection() {
        let cases = [
            // require without a provider
            "[selection]\nmode = \"require\"\n",
            // require-level without a level
            "[selection]\nmode = \"require-level\"\n",
            // require with a stray level field
            "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\nlevel = \"hardware\"\n",
            // require-level with a stray provider field
            "[selection]\nmode = \"require-level\"\nlevel = \"hardware\"\nprovider = \"tpm2\"\n",
            // prefer with a stray provider field
            "[selection]\nmode = \"prefer\"\nprovider = \"tpm2\"\n",
            // unknown selection mode
            "[selection]\nmode = \"strongly-suggest\"\n",
            // unknown top-level field (typo)
            "preferred_ordr = [\"tpm2\"]\n[selection]\nmode = \"prefer\"\n",
            // duplicate entries in preferred_order
            "preferred_order = [\"tpm2\", \"tpm2\"]\n[selection]\nmode = \"prefer\"\n",
            // the removed [container_policy] table (see
            // container_policy_is_not_a_policy_table)
            "[selection]\nmode = \"prefer\"\n[container_policy]\nmax_ephemeral_lifetime_seconds = 3600\n",
            // require a provider below the stated minimum protection
            "[key_requirements]\nminimum_protection = \"hardware\"\n[selection]\nmode = \"require\"\nprovider = \"external-secret\"\n",
            // not valid TOML at all
            "not = [valid, toml",
            // a top-level key written below a table header belongs to that
            // table in TOML -- here `selection.preferred_order` -- and must
            // be rejected, not silently dropped
            "[selection]\nmode = \"prefer\"\npreferred_order = [\"tpm2\"]\n",
            // a duplicate key
            "[selection]\nmode = \"prefer\"\nmode = \"require\"\n",
            // missing the required `selection` section entirely
            "[key_requirements]\nminimum_protection = \"hardware\"\n",
        ];
        for (i, doc) in cases.iter().enumerate() {
            assert!(Policy::from_toml_str(doc).is_err(), "case {i} should have been rejected: {doc}");
        }
    }

    #[test]
    fn require_ephemeral_succeeds_since_naming_it_under_require_is_itself_explicit() {
        let doc = "[selection]\nmode = \"require\"\nprovider = \"ephemeral\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        let allowed = policy.allowed_providers(&compiled(&[ProviderType::Ephemeral])).unwrap();
        assert_eq!(allowed, vec![ProviderType::Ephemeral]);
    }

    #[test]
    fn require_level_does_not_admit_ephemeral_even_when_its_tier_qualifies() {
        // require-level: ephemeral means "ephemeral tier or above", i.e.
        // every provider -- but Ephemeral itself is still excluded unless
        // separately named in preferred_order, since qualifying by tier
        // is not the same as being explicitly listed.
        let doc = "[selection]\nmode = \"require-level\"\nlevel = \"ephemeral\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        let allowed = policy
            .allowed_providers(&compiled(&[ProviderType::ExternalSecret, ProviderType::Ephemeral]))
            .unwrap();
        assert_eq!(allowed, vec![ProviderType::ExternalSecret]);

        // Naming it in preferred_order admits it, same as `prefer` mode.
        let doc_named = "preferred_order = [\"ephemeral\", \"external-secret\"]\n[selection]\nmode = \"require-level\"\nlevel = \"ephemeral\"\n";
        let policy_named = Policy::from_toml_str(doc_named).unwrap();
        let allowed_named = policy_named
            .allowed_providers(&compiled(&[ProviderType::ExternalSecret, ProviderType::Ephemeral]))
            .unwrap();
        assert_eq!(allowed_named, vec![ProviderType::Ephemeral, ProviderType::ExternalSecret]);
    }

    // ---- startup_behavior.setup_min_delay_ms ----

    #[test]
    fn setup_min_delay_defaults_to_one_second_when_absent() {
        let doc = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        assert_eq!(policy.setup_min_delay(), Duration::from_millis(DEFAULT_SETUP_MIN_DELAY_MS));

        // Also when startup_behavior is present but doesn't mention it.
        let doc = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[startup_behavior]\nfail_if_requirement_unmet = true\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        assert_eq!(policy.setup_min_delay(), Duration::from_millis(DEFAULT_SETUP_MIN_DELAY_MS));
    }

    #[test]
    fn setup_min_delay_is_read_from_the_policy() {
        let doc = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[startup_behavior]\nsetup_min_delay_ms = 2500\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        assert_eq!(policy.setup_min_delay(), Duration::from_millis(2500));
    }

    #[test]
    fn setup_min_delay_can_be_disabled_with_zero() {
        let doc = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[startup_behavior]\nsetup_min_delay_ms = 0\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        assert_eq!(policy.setup_min_delay(), Duration::ZERO);
    }

    #[test]
    fn setup_min_delay_above_the_cap_is_rejected() {
        let doc = format!(
            "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[startup_behavior]\nsetup_min_delay_ms = {}\n",
            MAX_SETUP_MIN_DELAY_MS + 1
        );
        assert!(Policy::from_toml_str(&doc).is_err());

        // ...and the cap itself is still accepted.
        let doc = format!(
            "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[startup_behavior]\nsetup_min_delay_ms = {MAX_SETUP_MIN_DELAY_MS}\n"
        );
        assert_eq!(
            Policy::from_toml_str(&doc).unwrap().setup_min_delay(),
            Duration::from_millis(MAX_SETUP_MIN_DELAY_MS)
        );
    }

    #[test]
    fn setup_min_delay_rejects_negative_and_non_integer_values() {
        for bad in ["-1", "1.5", "\"1000\"", "fast"] {
            let doc = format!("[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[startup_behavior]\nsetup_min_delay_ms = {bad}\n");
            assert!(Policy::from_toml_str(&doc).is_err(), "{bad} should not parse as a delay");
        }
    }

    #[test]
    #[serial_test::serial]
    fn setup_min_delay_helper_uses_the_default_without_a_policy_file() {
        let _no_policy = TestPolicy::absent();
        let delay = setup_min_delay();
        assert_eq!(delay, Duration::from_millis(DEFAULT_SETUP_MIN_DELAY_MS));
    }

    #[test]
    #[serial_test::serial]
    fn setup_min_delay_helper_reads_the_configured_file() {
        let _policy = TestPolicy::write("[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[startup_behavior]\nsetup_min_delay_ms = 42\n");
        let delay = setup_min_delay();
        assert_eq!(delay, Duration::from_millis(42));
    }

    #[test]
    #[serial_test::serial]
    fn setup_min_delay_helper_keeps_the_default_when_the_policy_is_broken() {
        // A malformed policy must not become a way to remove the floor
        // (the gated call fails closed on the same policy regardless).
        let _policy = TestPolicy::exact("[selection]\nmode = \"require\"\n[startup_behavior]\nsetup_min_delay_ms = 0\n");
        let delay = setup_min_delay();
        assert_eq!(delay, Duration::from_millis(DEFAULT_SETUP_MIN_DELAY_MS));
    }

    // ---- tpm.require_derivation_secret / tpm.pinned_names ----

    const A_NAME: &str = "000b0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    #[test]
    fn tpm_section_defaults_to_requiring_the_secret_and_no_pins() {
        let base = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n";
        let policy = Policy::from_toml_str(base).unwrap();
        assert!(policy.require_tpm_derivation_secret(), "required by default with no [tpm] table");
        assert!(!policy.require_tpm_pinned_names(), "the allowlist must be opt-in");
        assert_eq!(policy.pinned_tpm_name("com.company.orders"), None);

        // A [tpm] table that doesn't mention it gets the same default.
        let doc = format!("{base}[tpm]\nsession_encryption = \"auto\"\n");
        assert!(Policy::from_toml_str(&doc).unwrap().require_tpm_derivation_secret());

        // Only an explicit `false` turns it off.
        let doc = format!("{base}[tpm]\nrequire_derivation_secret = false\n");
        assert!(!Policy::from_toml_str(&doc).unwrap().require_tpm_derivation_secret());
    }

    #[test]
    fn tpm_require_pinned_names_is_read() {
        let doc = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nrequire_pinned_names = true\n";
        assert!(Policy::from_toml_str(doc).unwrap().require_tpm_pinned_names());
    }

    #[test]
    fn require_pinned_names_with_no_pins_is_a_valid_policy() {
        // The first step of rolling the allowlist out: turn it on, then run
        // `provision` for each service to learn the Name to pin. Every TPM
        // service is refused until then, which is the point.
        let doc = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nrequire_pinned_names = true\n";
        let policy = Policy::from_toml_str(doc).unwrap();
        assert!(policy.require_tpm_pinned_names());
        assert_eq!(policy.pinned_tpm_name("com.company.orders"), None);
    }

    #[test]
    fn tpm_require_derivation_secret_is_read() {
        let doc = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nrequire_derivation_secret = true\n";
        assert!(Policy::from_toml_str(doc).unwrap().require_tpm_derivation_secret());
    }

    #[test]
    fn pinned_name_is_decoded_and_matched_case_insensitively() {
        let doc = format!(
            "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm.pinned_names]\n\"com.company.Orders\" = \"{A_NAME}\"\n"
        );
        let policy = Policy::from_toml_str(&doc).unwrap();

        let pinned = policy.pinned_tpm_name("com.company.orders").expect("pin should be present");
        assert_eq!(pinned.len(), SHA256_TPM_NAME_LEN);
        assert_eq!(&pinned[..2], &[0x00, 0x0B], "the TPM_ALG_SHA256 prefix must survive decoding");
        assert_eq!(pinned[2], 0x01);
        assert_eq!(pinned[SHA256_TPM_NAME_LEN - 1], 0x20);

        // The policy key was written with a capital O; lookup normalizes.
        assert_eq!(policy.pinned_tpm_name("COM.COMPANY.ORDERS"), Some(pinned));
        // An unpinned service stays unpinned.
        assert_eq!(policy.pinned_tpm_name("com.company.billing"), None);
    }

    #[test]
    fn pinned_name_rejects_bad_hex_and_wrong_length() {
        for bad in [
            "nothex",                    // not hex at all
            "000b01",                    // hex, but far too short
            "000b0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021", // one byte too long
            "000b0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2",    // odd length
        ] {
            let doc = format!(
                "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm.pinned_names]\n\"com.company.orders\" = \"{bad}\"\n"
            );
            assert!(
                Policy::from_toml_str(&doc).is_err(),
                "{bad} must be rejected as a pinned TPM Name"
            );
        }
    }

    #[test]
    fn pinned_names_reject_an_unquoted_dotted_service_name() {
        // In TOML an unquoted `com.company.orders = ...` is a dotted key --
        // nested tables `com` -> `company` -> `orders` -- not one key
        // containing dots. That must fail to parse rather than quietly pin
        // nothing, which would leave the service unpinned (and, under
        // require_pinned_names, unprovisioned) with no error to say why.
        let doc = format!(
            "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm.pinned_names]\ncom.company.orders = \"{A_NAME}\"\n"
        );
        assert!(Policy::from_toml_str(&doc).is_err(), "an unquoted dotted key must be rejected");

        let quoted = format!(
            "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm.pinned_names]\n\"com.company.orders\" = \"{A_NAME}\"\n"
        );
        assert!(Policy::from_toml_str(&quoted).unwrap().pinned_tpm_name("com.company.orders").is_some());
    }

    #[test]
    fn pinned_names_reject_a_duplicate_after_normalization() {
        let doc = format!(
            "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm.pinned_names]\n\"com.company.orders\" = \"{A_NAME}\"\n\"com.company.ORDERS\" = \"{A_NAME}\"\n"
        );
        assert!(Policy::from_toml_str(&doc).is_err(), "two keys differing only in case must be rejected");
    }

    #[test]
    fn tpm_tcti_is_read_and_validated() {
        let base = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n";
        assert_eq!(Policy::from_toml_str(base).unwrap().tpm_tcti(), None, "unset by default");

        for ok in ["device:/dev/tpmrm0", "device", "tabrmd:bus_type=system", "mssim:host=localhost,port=2321", "swtpm:port=2321"] {
            let doc = format!("{base}[tpm]\ntcti = \"{ok}\"\n");
            assert_eq!(Policy::from_toml_str(&doc).unwrap().tpm_tcti(), Some(ok), "{ok}");
        }
        for bad in ["", "libtss2-tcti-evil.so", "/tmp/evil.so", "cmd:sh", "devices:/dev/tpm0"] {
            let doc = format!("{base}[tpm]\ntcti = \"{bad}\"\n");
            assert!(Policy::from_toml_str(&doc).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn external_secret_and_pkcs11_sections_are_read_and_validated() {
        let base = "[selection]\nmode = \"prefer\"\n";
        let policy = Policy::from_toml_str(base).unwrap();
        assert_eq!(policy.external_secret_dir(), None);
        assert_eq!(policy.pkcs11(), &Pkcs11Settings::default());

        let doc = format!(
            "{base}[external_secret]\ndir = \"/srv/secrets/hkdfguard\"\n\
             [pkcs11]\nmodule = \"/usr/lib/vendor/libhsm.so\"\npin_file = \"/etc/hkdfguard/hsm.pin\"\n\
             token_label = \"prod-kek\"\ntoken_serial = \"0123456789abcdef\"\n"
        );
        let policy = Policy::from_toml_str(&doc).unwrap();
        assert_eq!(policy.external_secret_dir(), Some(std::path::Path::new("/srv/secrets/hkdfguard")));
        assert_eq!(
            policy.pkcs11(),
            &Pkcs11Settings {
                module: Some(PathBuf::from("/usr/lib/vendor/libhsm.so")),
                pin_file: Some(PathBuf::from("/etc/hkdfguard/hsm.pin")),
                token_label: Some("prod-kek".into()),
                token_serial: Some("0123456789abcdef".into()),
            }
        );

        for bad in [
            "[external_secret]\ndir = \"relative/dir\"\n",
            "[pkcs11]\nmodule = \"libsofthsm2.so\"\n",
            "[pkcs11]\npin_file = \"pkcs11.pin\"\n",
            "[pkcs11]\ntoken_label = \"\"\n",
            "[pkcs11]\ntoken_label = \"this label is far too long for a pkcs11 token\"\n",
            "[pkcs11]\ntoken_serial = \"0123456789abcdef0\"\n",
            "[pkcs11]\nslot = 0\n",
            "[external_secret]\npath = \"/x\"\n",
        ] {
            assert!(Policy::from_toml_str(&format!("{base}{bad}")).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn unknown_key_in_the_tpm_section_is_rejected() {
        let doc = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nrequire_drivation_secret = true\n"; // typo
        assert!(Policy::from_toml_str(doc).is_err());
    }

    #[test]
    #[serial_test::serial]
    fn tpm_helpers_without_a_policy_file() {
        let _no_policy = TestPolicy::absent();
        let required = require_tpm_derivation_secret();
        let allowlist = require_tpm_pinned_names();
        let pinned = pinned_tpm_name("com.company.orders");
        assert!(required, "the derivation secret is required by default, policy or not");
        assert!(!allowlist, "no policy must not silently make the TPM refuse every service");
        assert_eq!(pinned.unwrap(), None);
    }

    #[test]
    #[serial_test::serial]
    fn tpm_helpers_fail_closed_on_a_broken_policy() {
        // A policy that can't be parsed must not be the reason a security
        // control is skipped: requiring becomes true, and pinning errors
        // rather than reporting "nothing pinned".
        let _policy = TestPolicy::exact("[selection]\nmode = \"require\"\n"); // missing `provider`
        let required = require_tpm_derivation_secret();
        let allowlist = require_tpm_pinned_names();
        let pinned = pinned_tpm_name("com.company.orders");
        assert!(required, "a broken policy must fail closed to requiring the secret");
        assert!(allowlist, "a broken policy must fail closed to the allowlist");
        assert!(pinned.is_err(), "a broken policy must not report 'nothing pinned'");
    }

    #[test]
    #[serial_test::serial]
    fn tpm_helpers_read_the_configured_file() {
        let _policy = TestPolicy::write(&format!("[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nrequire_derivation_secret = true\n[tpm.pinned_names]\n\"com.company.orders\" = \"{A_NAME}\"\n"));
        let required = require_tpm_derivation_secret();
        let pinned = pinned_tpm_name("com.company.orders");
        let unpinned = pinned_tpm_name("com.company.billing");

        assert!(required);
        assert_eq!(pinned.unwrap().unwrap().len(), SHA256_TPM_NAME_LEN);
        assert_eq!(unpinned.unwrap(), None);
    }

    #[test]
    fn a_non_ascii_pinned_name_is_a_policy_error_not_a_panic() {
        // 68 bytes, even, with a two-byte character straddling the first
        // two-byte step: the old `&str`-slicing decoder panicked here.
        let name = format!("a{}0", "é".repeat(33));
        for doc in [
            format!("[selection]\nmode = \"prefer\"\n[tpm]\npinned_session_salt_key_name = \"{name}\"\n"),
            format!("[selection]\nmode = \"prefer\"\n[tpm.pinned_names]\n\"com.company.orders\" = \"{name}\"\n"),
        ] {
            let err = Policy::from_toml_str(&doc).expect_err("a non-hex Name must be refused");
            assert!(err.to_string().contains("not valid hex"), "unexpected error: {err}");
        }
    }

    #[test]
    fn parse_hex_round_trips_and_rejects_malformed_input() {
        assert_eq!(parse_hex("00ff10").unwrap(), vec![0x00, 0xff, 0x10]);
        assert_eq!(parse_hex("00FF10").unwrap(), vec![0x00, 0xff, 0x10], "uppercase hex must decode");
        assert_eq!(parse_hex("  00ff10  ").unwrap(), vec![0x00, 0xff, 0x10], "surrounding whitespace is trimmed");
        assert!(parse_hex("").is_none());
        assert!(parse_hex("0").is_none());
        assert!(parse_hex("0g").is_none());
        assert!(parse_hex("00 ff").is_none(), "interior whitespace is not hex");
        assert!(parse_hex("+f").is_none(), "a sign is not a hex digit");
        // Non-ASCII must be refused, not panic: "aé0" is four bytes, and
        // a two-byte step lands inside the "é".
        for non_ascii in ["aé0", "é0", "€0", "00ｆｆ"] {
            assert!(parse_hex(non_ascii).is_none(), "{non_ascii:?}");
        }
    }

    // ---- tpm.session_encryption / tpm.pinned_session_salt_key_name ----

    #[test]
    fn session_encryption_defaults_to_auto_with_no_pin() {
        let policy = Policy::from_toml_str("[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n").unwrap();
        assert_eq!(policy.tpm_session_encryption(), SessionEncryption::Auto);
        assert_eq!(policy.pinned_session_salt_key_name(), None);
    }

    #[test]
    fn session_encryption_modes_parse() {
        for (text, expected) in [
            ("auto", SessionEncryption::Auto),
            ("off", SessionEncryption::Off),
        ] {
            let doc = format!("[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nsession_encryption = \"{text}\"\n");
            assert_eq!(Policy::from_toml_str(&doc).unwrap().tpm_session_encryption(), expected, "{text}");
        }
        let doc = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nsession_encryption = \"sometimes\"\n";
        assert!(Policy::from_toml_str(doc).is_err(), "unknown mode must be rejected");
    }

    #[test]
    fn required_session_encryption_needs_a_pinned_salt_key() {
        let without_pin = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nsession_encryption = \"required\"\n";
        assert!(
            Policy::from_toml_str(without_pin).is_err(),
            "required without a pinned salt key is a MITM-able session and must be refused"
        );

        let with_pin = format!(
            "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nsession_encryption = \"required\"\npinned_session_salt_key_name = \"{A_NAME}\"\n"
        );
        let policy = Policy::from_toml_str(&with_pin).unwrap();
        assert_eq!(policy.tpm_session_encryption(), SessionEncryption::Required);
        assert_eq!(policy.pinned_session_salt_key_name().unwrap().len(), SHA256_TPM_NAME_LEN);
    }

    #[test]
    fn pinned_salt_key_name_is_validated_like_other_names() {
        for bad in ["nothex", "000b01"] {
            let doc = format!(
                "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\npinned_session_salt_key_name = \"{bad}\"\n"
            );
            assert!(Policy::from_toml_str(&doc).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    #[serial_test::serial]
    fn session_encryption_helpers_fail_closed() {
        // No policy: auto, nothing pinned.
        let _no_policy = TestPolicy::absent();
        let mode = tpm_session_encryption();
        let pin = pinned_session_salt_key_name();
        assert_eq!(mode, SessionEncryption::Auto);
        assert_eq!(pin.unwrap(), None);

        // Broken policy: required (never "off"), and pinning errors.
        let _policy = TestPolicy::exact("[selection]\nmode = \"require\"\n[tpm]\nsession_encryption = \"off\"\n");
        let mode = tpm_session_encryption();
        let pin = pinned_session_salt_key_name();
        assert_eq!(mode, SessionEncryption::Required, "a broken policy must not turn bus protection off");
        assert!(pin.is_err());
    }

    // ---- load() / file-path behavior ----

    #[test]
    #[serial_test::serial]
    fn load_returns_none_when_no_policy_file_is_configured() {
        let _no_policy = TestPolicy::absent();
        assert!(load().is_none());
    }

    #[test]
    #[serial_test::serial]
    fn load_reads_and_validates_the_configured_file() {
        let _policy = TestPolicy::write("[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n");

        match load() {
            Some(Ok(policy)) => {
                assert_eq!(policy.selection, SelectionMode::Require(ProviderType::Tpm2));
            }
            other => panic!("expected Some(Ok(_)), got {other:?}"),
        }

    }

    #[test]
    #[serial_test::serial]
    fn load_fails_closed_on_a_malformed_file() {
        let _policy = TestPolicy::exact("[selection]\nmode = \"require\"\n"); // missing required `provider`

        match load() {
            Some(Err(_)) => {}
            other => panic!("expected Some(Err(_)), got {other:?}"),
        }

    }

    // Points the policy at `path` and asserts load() fails closed
    // (Some(Err)) rather than treating the file as absent (None).
    fn assert_load_fails_closed(path: &std::path::Path, why: &str) {
        let _policy = TestPolicy::at(path);
        let result = load();
        match result {
            Some(Err(_)) => {}
            other => panic!("{why}: expected Some(Err(_)) (fail closed), got {other:?}"),
        }
    }

    #[test]
    #[serial_test::serial]
    fn load_fails_closed_on_an_unreadable_file() {
        if crate::secure_file::skip_as_root() {
            return; // root can read a mode-000 file, so this scenario can't be set up
        }
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::secure_file::private_tempdir();
        let path = dir.path().join("policy.toml");
        std::fs::write(&path, "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert_load_fails_closed(&path, "a present-but-unreadable policy must not disable policy");
    }

    #[test]
    #[serial_test::serial]
    fn load_fails_closed_when_path_is_a_directory() {
        let dir = crate::secure_file::private_tempdir();
        assert_load_fails_closed(dir.path(), "a directory at the policy path must not disable policy");
    }

    #[test]
    #[serial_test::serial]
    fn load_fails_closed_on_a_group_or_world_writable_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::secure_file::private_tempdir();
        let path = dir.path().join("policy.toml");
        std::fs::write(&path, "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n").unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert_load_fails_closed(&path, "a group-writable policy must be rejected");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o646)).unwrap();
        assert_load_fails_closed(&path, "a world-writable policy must be rejected");
    }

    #[test]
    #[serial_test::serial]
    fn load_fails_closed_when_others_could_replace_or_delete_the_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::secure_file::private_tempdir();
        let path = dir.path().join("policy.toml");
        crate::secure_file::write_world_readable_for_tests(&path, "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_load_fails_closed(&path, "a policy in a world-writable directory could be swapped out");

        // Absent is "no policy" only where nobody untrusted could have deleted it.
        std::fs::remove_file(&path).unwrap();
        assert_load_fails_closed(&path, "deleting the policy must not be a way to switch it off");

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let _policy = TestPolicy::at(&path);
        let absent = load();
        assert!(absent.is_none(), "in a trusted directory, a missing policy is just no policy");
    }

    #[test]
    #[serial_test::serial]
    fn load_fails_closed_on_an_oversized_file() {
        let dir = crate::secure_file::private_tempdir();
        let path = dir.path().join("policy.toml");
        crate::secure_file::write_world_readable_for_tests(&path, vec![b'#'; MAX_POLICY_FILE_LEN + 1]);
        assert_load_fails_closed(&path, "an oversized policy must be rejected, not truncated");
    }
}
