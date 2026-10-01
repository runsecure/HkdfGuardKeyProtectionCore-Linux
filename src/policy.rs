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
//! nothing about *how* a provider works (module paths, PINs, slots --
//! those stay in each provider's own `HKDFGUARD_*` environment variables).
//! It answers exactly one question: given the provider types compiled
//! into this build, which of them, in what order, does policy currently
//! allow?

use crate::error::{Error, Result};
use crate::provider::ProviderType;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

/// Location of the policy file. Release builds read only this path; debug
/// builds (tests, development) may redirect it with `HKDFGUARD_POLICY_FILE`
/// -- see [`crate::debug_only_env`] for why that is debug-only.
const DEFAULT_POLICY_FILE: &str = "/etc/hkdfguard/policy.toml";

fn policy_file_path() -> PathBuf {
    crate::debug_only_env("HKDFGUARD_POLICY_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_POLICY_FILE))
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
    container_policy: ContainerPolicy,
    #[serde(default)]
    tpm: TpmPolicy,
}

/// TPM2-provider-specific administrative controls. Parsed and validated
/// on every build (so a policy file is portable across builds with and
/// without the `tpm2` feature) but only consulted by the TPM2 provider.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct TpmPolicy {
    /// Refuse to use the TPM provider at all unless the derivation-secret
    /// file is present and trustworthy. Default `false`, which means "mix
    /// the secret into the key derivation if the file is there, otherwise
    /// derive from the TPM seed and service label alone" -- so enabling
    /// the secret on an existing deployment doesn't silently become
    /// mandatory everywhere.
    #[serde(default)]
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
    let s = s.trim();
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
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

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContainerPolicy {
    // Accepted and validated (must be positive if present), but not
    // enforced by an internal expiry timer: this crate's ephemeral
    // provider already ties key lifetime to the process lifetime, which
    // for a container *is* the natural bound this field is asking for.
    // Surfaced here (rather than rejected as an unknown field) so it can
    // be read by orchestration tooling and so a real timer-based rotation
    // has a validated place to read from later, without a schema change.
    max_ephemeral_lifetime_seconds: Option<u64>,
}

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

        if let Some(0) = raw.container_policy.max_ephemeral_lifetime_seconds {
            return Err(Error::Provider(
                "hkdfguard policy: container_policy.max_ephemeral_lifetime_seconds must be positive"
                    .to_string(),
            ));
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
        })
    }

    /// TPM session parameter-encryption mode (`tpm.session_encryption`).
    pub fn tpm_session_encryption(&self) -> SessionEncryption {
        self.tpm_session_encryption
    }

    /// The TCTI the TPM provider must use (`tpm.tcti`), if policy sets one.
    pub fn tpm_tcti(&self) -> Option<&str> {
        self.tpm_tcti.as_deref()
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

/// What the policy file must satisfy before it's trusted: owned by root or
/// by this process's own user, and not writable by anyone else -- a
/// policy anyone else could edit wouldn't be a policy. Symlinks are
/// followed (e.g. Kubernetes ConfigMap mounts are symlinks), but the
/// checks apply to the file actually opened, not the link.
const POLICY_FILE_REQUIREMENTS: crate::secure_file::FileRequirements = crate::secure_file::FileRequirements {
    owner: Some(crate::secure_file::Owner::RootOrCurrentUser),
    forbidden_mode_bits: crate::secure_file::FORBID_GROUP_OTHER_WRITE,
    follow_symlinks: true,
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
///   UTF-8, or is malformed or self-contradictory. This **fails closed**:
///   every wrap/unwrap/create/exists call fails rather than falling back
///   to the unrestricted default. Making the file unreadable must never be
///   a way to switch policy off.
///
/// Re-read from disk on every call (no caching), so an operator can update
/// the policy without restarting the process.
pub fn load() -> Option<Result<Policy>> {
    let path = policy_file_path();
    let fail = |what: String| Some(Err(Error::Provider(format!("hkdfguard policy file {}: {what}", path.display()))));

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
/// Defaults to `false` with no policy file -- the secret is an opt-in
/// hardening step, and defaulting it on would make every TPM deployment
/// that hasn't provisioned one stop working. A policy file that exists
/// but is *invalid* returns `true`, because a broken policy must never be
/// the thing that relaxes a security control (the surrounding operation
/// fails closed on that same policy anyway).
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(crate) fn require_tpm_derivation_secret() -> bool {
    match load() {
        Some(Ok(policy)) => policy.require_tpm_derivation_secret(),
        Some(Err(_)) => true,
        None => false,
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

/// Test-only: writes a policy that explicitly names Ephemeral in
/// `preferred_order` (alongside `external-secret`, so tests that also
/// need that provider to remain a candidate still get it) and points
/// `HKDFGUARD_POLICY_FILE` at it -- the same explicit naming a real
/// deployment now needs, since with no policy at all (or a policy that
/// never names it) Ephemeral is excluded (see `provider::allowed_chain`
/// and [`Policy::ephemeral_explicitly_listed`]). The returned `TempDir`
/// owns the file; keep it alive for as long as the policy should apply.
#[cfg(test)]
pub(crate) fn allow_ephemeral_policy_for_tests() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.toml");
    crate::secure_file::write_world_readable_for_tests(
        &path,
        "preferred_order = [\"external-secret\", \"ephemeral\"]\n[selection]\nmode = \"prefer\"\n",
    );
    std::env::set_var("HKDFGUARD_POLICY_FILE", &path);
    dir
}

/// Test-only: writes a policy pinning provider selection to `provider`
/// (the policy vocabulary's name, e.g. `external-secret`) and points
/// `HKDFGUARD_POLICY_FILE` at it. The returned `TempDir` owns the file;
/// keep it alive for as long as the policy should apply.
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
pub(crate) fn require_provider_policy_for_tests(provider: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.toml");
    crate::secure_file::write_world_readable_for_tests(
        &path,
        format!("[selection]\nmode = \"require\"\nprovider = \"{provider}\"\n"),
    );
    std::env::set_var("HKDFGUARD_POLICY_FILE", &path);
    dir
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn container_policy_accepts_a_positive_max_lifetime() {
        let doc = "[selection]\nmode = \"prefer\"\n[container_policy]\nmax_ephemeral_lifetime_seconds = 3600\n";
        assert!(Policy::from_toml_str(doc).is_ok());
    }

    #[test]
    fn container_policy_rejects_zero_max_lifetime() {
        let doc = "[selection]\nmode = \"prefer\"\n[container_policy]\nmax_ephemeral_lifetime_seconds = 0\n";
        assert!(Policy::from_toml_str(doc).is_err());
    }

    #[test]
    fn container_policy_rejects_the_removed_allow_ephemeral_field() {
        // Confirms the tightened schema: `allow_ephemeral` is no longer a
        // recognized field (Ephemeral's gate is now `preferred_order`
        // naming it explicitly -- see `Policy::ephemeral_explicitly_listed`),
        // so a policy still written in the old style fails closed instead
        // of silently doing nothing.
        let doc = "[selection]\nmode = \"prefer\"\n[container_policy]\nallow_ephemeral = true\n";
        assert!(Policy::from_toml_str(doc).is_err());
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
            // the removed allow_ephemeral field (see
            // container_policy_rejects_the_removed_allow_ephemeral_field)
            "[selection]\nmode = \"prefer\"\n[container_policy]\nallow_ephemeral = true\n",
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
        std::env::set_var("HKDFGUARD_POLICY_FILE", "/nonexistent-hkdfguard-policy-for-tests");
        let delay = setup_min_delay();
        std::env::remove_var("HKDFGUARD_POLICY_FILE");
        assert_eq!(delay, Duration::from_millis(DEFAULT_SETUP_MIN_DELAY_MS));
    }

    #[test]
    #[serial_test::serial]
    fn setup_min_delay_helper_reads_the_configured_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        crate::secure_file::write_world_readable_for_tests(&path, "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[startup_behavior]\nsetup_min_delay_ms = 42\n");
        std::env::set_var("HKDFGUARD_POLICY_FILE", &path);
        let delay = setup_min_delay();
        std::env::remove_var("HKDFGUARD_POLICY_FILE");
        assert_eq!(delay, Duration::from_millis(42));
    }

    #[test]
    #[serial_test::serial]
    fn setup_min_delay_helper_keeps_the_default_when_the_policy_is_broken() {
        // A malformed policy must not become a way to remove the floor
        // (the gated call fails closed on the same policy regardless).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        crate::secure_file::write_world_readable_for_tests(&path, "[selection]\nmode = \"require\"\n[startup_behavior]\nsetup_min_delay_ms = 0\n");
        std::env::set_var("HKDFGUARD_POLICY_FILE", &path);
        let delay = setup_min_delay();
        std::env::remove_var("HKDFGUARD_POLICY_FILE");
        assert_eq!(delay, Duration::from_millis(DEFAULT_SETUP_MIN_DELAY_MS));
    }

    // ---- tpm.require_derivation_secret / tpm.pinned_names ----

    const A_NAME: &str = "000b0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    #[test]
    fn tpm_section_defaults_to_no_requirement_and_no_pins() {
        let policy = Policy::from_toml_str("[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n").unwrap();
        assert!(!policy.require_tpm_derivation_secret());
        assert!(!policy.require_tpm_pinned_names(), "the allowlist must be opt-in");
        assert_eq!(policy.pinned_tpm_name("com.company.orders"), None);
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
    fn unknown_key_in_the_tpm_section_is_rejected() {
        let doc = "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nrequire_drivation_secret = true\n"; // typo
        assert!(Policy::from_toml_str(doc).is_err());
    }

    #[test]
    #[serial_test::serial]
    fn tpm_helpers_default_permissively_without_a_policy_file() {
        std::env::set_var("HKDFGUARD_POLICY_FILE", "/nonexistent-hkdfguard-policy-for-tests");
        let required = require_tpm_derivation_secret();
        let allowlist = require_tpm_pinned_names();
        let pinned = pinned_tpm_name("com.company.orders");
        std::env::remove_var("HKDFGUARD_POLICY_FILE");
        assert!(!required, "no policy must not silently mandate a derivation secret");
        assert!(!allowlist, "no policy must not silently make the TPM refuse every service");
        assert_eq!(pinned.unwrap(), None);
    }

    #[test]
    #[serial_test::serial]
    fn tpm_helpers_fail_closed_on_a_broken_policy() {
        // A policy that can't be parsed must not be the reason a security
        // control is skipped: requiring becomes true, and pinning errors
        // rather than reporting "nothing pinned".
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        crate::secure_file::write_world_readable_for_tests(&path, "[selection]\nmode = \"require\"\n"); // missing `provider`
        std::env::set_var("HKDFGUARD_POLICY_FILE", &path);
        let required = require_tpm_derivation_secret();
        let allowlist = require_tpm_pinned_names();
        let pinned = pinned_tpm_name("com.company.orders");
        std::env::remove_var("HKDFGUARD_POLICY_FILE");
        assert!(required, "a broken policy must fail closed to requiring the secret");
        assert!(allowlist, "a broken policy must fail closed to the allowlist");
        assert!(pinned.is_err(), "a broken policy must not report 'nothing pinned'");
    }

    #[test]
    #[serial_test::serial]
    fn tpm_helpers_read_the_configured_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        crate::secure_file::write_world_readable_for_tests(
            &path,
            format!("[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n[tpm]\nrequire_derivation_secret = true\n[tpm.pinned_names]\n\"com.company.orders\" = \"{A_NAME}\"\n"),
        );
        std::env::set_var("HKDFGUARD_POLICY_FILE", &path);
        let required = require_tpm_derivation_secret();
        let pinned = pinned_tpm_name("com.company.orders");
        let unpinned = pinned_tpm_name("com.company.billing");
        std::env::remove_var("HKDFGUARD_POLICY_FILE");

        assert!(required);
        assert_eq!(pinned.unwrap().unwrap().len(), SHA256_TPM_NAME_LEN);
        assert_eq!(unpinned.unwrap(), None);
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
        std::env::set_var("HKDFGUARD_POLICY_FILE", "/nonexistent-hkdfguard-policy-for-tests");
        let mode = tpm_session_encryption();
        let pin = pinned_session_salt_key_name();
        std::env::remove_var("HKDFGUARD_POLICY_FILE");
        assert_eq!(mode, SessionEncryption::Auto);
        assert_eq!(pin.unwrap(), None);

        // Broken policy: required (never "off"), and pinning errors.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        crate::secure_file::write_world_readable_for_tests(&path, "[selection]\nmode = \"require\"\n[tpm]\nsession_encryption = \"off\"\n");
        std::env::set_var("HKDFGUARD_POLICY_FILE", &path);
        let mode = tpm_session_encryption();
        let pin = pinned_session_salt_key_name();
        std::env::remove_var("HKDFGUARD_POLICY_FILE");
        assert_eq!(mode, SessionEncryption::Required, "a broken policy must not turn bus protection off");
        assert!(pin.is_err());
    }

    // ---- load() / file-path behavior ----

    #[test]
    #[serial_test::serial]
    fn load_returns_none_when_no_policy_file_is_configured() {
        std::env::set_var("HKDFGUARD_POLICY_FILE", "/nonexistent-hkdfguard-policy-for-tests");
        assert!(load().is_none());
        std::env::remove_var("HKDFGUARD_POLICY_FILE");
    }

    #[test]
    #[serial_test::serial]
    fn load_reads_and_validates_the_configured_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        crate::secure_file::write_world_readable_for_tests(&path, "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n");
        std::env::set_var("HKDFGUARD_POLICY_FILE", &path);

        match load() {
            Some(Ok(policy)) => {
                assert_eq!(policy.selection, SelectionMode::Require(ProviderType::Tpm2));
            }
            other => panic!("expected Some(Ok(_)), got {other:?}"),
        }

        std::env::remove_var("HKDFGUARD_POLICY_FILE");
    }

    #[test]
    #[serial_test::serial]
    fn load_fails_closed_on_a_malformed_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        crate::secure_file::write_world_readable_for_tests(&path, "[selection]\nmode = \"require\"\n"); // missing required `provider`
        std::env::set_var("HKDFGUARD_POLICY_FILE", &path);

        match load() {
            Some(Err(_)) => {}
            other => panic!("expected Some(Err(_)), got {other:?}"),
        }

        std::env::remove_var("HKDFGUARD_POLICY_FILE");
    }

    // Points HKDFGUARD_POLICY_FILE at `path` and asserts load() fails
    // closed (Some(Err)) rather than treating the file as absent (None).
    fn assert_load_fails_closed(path: &std::path::Path, why: &str) {
        std::env::set_var("HKDFGUARD_POLICY_FILE", path);
        let result = load();
        std::env::remove_var("HKDFGUARD_POLICY_FILE");
        match result {
            Some(Err(_)) => {}
            other => panic!("{why}: expected Some(Err(_)) (fail closed), got {other:?}"),
        }
    }

    #[test]
    #[serial_test::serial]
    fn load_fails_closed_on_an_unreadable_file() {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return; // root can read a mode-000 file, so this scenario can't be set up
        }
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        std::fs::write(&path, "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert_load_fails_closed(&path, "a present-but-unreadable policy must not disable policy");
    }

    #[test]
    #[serial_test::serial]
    fn load_fails_closed_when_path_is_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        assert_load_fails_closed(dir.path(), "a directory at the policy path must not disable policy");
    }

    #[test]
    #[serial_test::serial]
    fn load_fails_closed_on_a_group_or_world_writable_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        std::fs::write(&path, "[selection]\nmode = \"require\"\nprovider = \"tpm2\"\n").unwrap();

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert_load_fails_closed(&path, "a group-writable policy must be rejected");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o646)).unwrap();
        assert_load_fails_closed(&path, "a world-writable policy must be rejected");
    }

    #[test]
    #[serial_test::serial]
    fn load_fails_closed_on_an_oversized_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        crate::secure_file::write_world_readable_for_tests(&path, vec![b'#'; MAX_POLICY_FILE_LEN + 1]);
        assert_load_fails_closed(&path, "an oversized policy must be rejected, not truncated");
    }
}
