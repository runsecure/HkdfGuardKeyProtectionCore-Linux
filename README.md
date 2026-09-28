# KeyProtectionCore-Linux (HKDFGuard)

Linux implementation of HKDFGuard: a stable C ABI for wrapping/unwrapping
32-byte Data Encryption Keys (DEKs) under a persistent, per-service Key
Encryption Key (KEK), using the strongest KEK backing available on the
host. Same cryptographic protocol and `service`-based key identity as the
macOS Secure Enclave and Windows TPM/CNG implementations of HKDFGuard.

```
ECDH (P-256, fixed point)  ->  HKDF-SHA512  ->  AES-256-GCM
```

A wrapped payload can only be **created** and **opened** on the host that
holds the KEK. The wrapping key is `ECDH(KEK_priv, H)` for a fixed P-256
point `H` with no known discrete log, so producing a valid payload
requires the KEK's private key — which never leaves the TPM, HSM, or
root-owned secret file.

This is deliberately *not* ECIES. An ephemeral-key scheme would let
anyone holding the KEK's public key (not a secret — on a TPM, anyone who
can reach the device can recompute it) derive the same wrapping key and
mint a payload that unwraps to a DEK of their choosing. See
[`src/crypto.rs`](src/crypto.rs) for the full rationale, and note the
consequence: a build server **cannot** pre-wrap a DEK for a host. DEKs
are delivered to the host and wrapped there.

Wire format version 3. Every byte of a payload except the ciphertext is
bound into both the AEAD's associated data and the HKDF `info`, so the
`provider_type` tag and the KEK fingerprint are authenticated rather
than merely present.

## Quick start

```sh
scripts/build-release.sh
```

Runs `cargo build --release`, which produces
`target/release/libHkdfGuardKeyProtectionLinux.{so,dylib}` (dynamic) and
`libHkdfGuardKeyProtectionLinux.a` (static) -- the `[lib] name` in
`Cargo.toml` controls that output name directly, and Cargo has no way to
produce a name containing dots. The script's one additional step copies the
dynamic library to `target/release/HkdfGuard.Kms.Linux.v1.{so,dylib}` --
this project's actual release artifact name, matching the
`HkdfGuard.Kms.<platform>.v1` convention its Windows (CMake `OUTPUT_NAME`)
and macOS (Xcode `PRODUCT_NAME`) builds apply natively. A plain
`cargo build --release` still works for local iteration; just link against
`libHkdfGuardKeyProtectionLinux` directly in that case. The C header
(`include/hkdfguard.h`) and exported C symbols (`hkdfguard_wrap_dek`,
`hkdfguard_unwrap_dek`, `hkdfguard_generate_and_wrap_dek`) are unaffected
either way and keep their existing names.

```c
#include "hkdfguard.h"

uint8_t dek[32] = { ... };
uint8_t wrapped[512];
int wrapped_len = sizeof(wrapped);
hkdfguard_wrap_dek("com.company.orders", dek, 32, wrapped, &wrapped_len);

uint8_t recovered[32];
int recovered_len = sizeof(recovered);
hkdfguard_unwrap_dek("com.company.orders", wrapped, wrapped_len, recovered, &recovered_len);
```

`hkdfguard_generate_and_wrap_dek` generates its own cryptographically random
32-byte DEK (via the OS CSPRNG) and wraps it in one call, for callers minting
a brand new Ephemeral Data Protection Key -- the plaintext DEK never crosses
back out to the caller; it's zeroed internally the moment it's wrapped.
Recover it later via `hkdfguard_unwrap_dek` on the resulting payload, with
the same `service`:

```c
uint8_t wrapped[512];
int wrapped_len = sizeof(wrapped);
hkdfguard_generate_and_wrap_dek("com.company.orders", wrapped, &wrapped_len);
```

See [`examples/wrap_unwrap.c`](examples/wrap_unwrap.c) for a complete,
buildable example, and [`include/hkdfguard.h`](include/hkdfguard.h) for the
full API contract (status codes, buffer sizing, safety requirements).

## Provider chain

Every `hkdfguard_wrap_dek` call tries providers in this order and uses the
first one that is available *and* can produce a key for the requested
`service`; `hkdfguard_unwrap_dek` always uses the exact provider that
originally wrapped the payload (recorded in the payload itself, never in
`service`):

| # | Provider | Module | Feature flag | Built by default |
|---|----------|--------|---------------|-------------------|
| 1 | TPM2 | [`src/provider/tpm2.rs`](src/provider/tpm2.rs) | `tpm2` | no |
| 2 | PKCS#11 | [`src/provider/pkcs11.rs`](src/provider/pkcs11.rs) | `pkcs11` | no |
| 3 | External Secret | [`src/provider/external_secret.rs`](src/provider/external_secret.rs) | `external-secret` | yes |
| 4 | Ephemeral | [`src/provider/ephemeral.rs`](src/provider/ephemeral.rs) | `ephemeral` | yes |

There is deliberately no software-backed (locally-generated,
filesystem-encrypted-at-rest) provider: a deployment without TPM2 or
PKCS#11 hardware is expected to provision a KEK via external-secret
instead.

Ephemeral is compiled in by default but **never used unless a policy file
explicitly names it** -- either as the sole provider under `require`, or
by name in `preferred_order` (e.g. `preferred_order: [external-secret,
ephemeral]`). Qualifying by assurance tier under `require-level` is not
enough on its own; it must be named. Its keys live only in process
memory, so every DEK wrapped under one is lost on restart; without a
policy (or a policy that never names it), a missing secret mount or
unavailable TPM makes `hkdfguard_create_kek` fail rather than silently
degrade to it.

The policy file (`/etc/hkdfguard/policy.yaml`, or `HKDFGUARD_POLICY_FILE`)
must be owned by root or by the process's own user and not writable by
group or others. Only a *missing* file means "no policy"; a file that
exists but is unreadable, too broadly writable, or malformed makes every
operation fail closed.

### Setup calls are deliberately slow

`hkdfguard_create_kek` and `hkdfguard_kek_exists` are meant to run once
per application startup, so each takes **at least one second** of
wall-clock time whatever its outcome (found, not found, or error), and
they are serialized with each other across threads. This bounds how fast
a buggy or hot-looping caller can drive the TPM/HSM (every call is a
fresh connection plus a key derivation), caps Ephemeral key-map growth,
and makes `kek_exists` useless as a fast "which services have a key"
oracle. Argument errors (bad pointer, invalid service name) still return
immediately since they never reach a provider. The library logs a warning
once a process has made more than 10 setup calls.

The floor is set by the policy file and can be tuned per host (up to
60 000 ms; `0` disables it):

```yaml
startup_behavior:
  setup_min_delay_ms: 1000   # default when absent
```

A policy file that is present but invalid keeps the 1 s default (the
gated call fails closed on that same policy anyway). There is no
environment-variable override.

### Hardening the TPM key

By default the TPM provider derives each service's KEK with a
deterministic `TPM2_CreatePrimary` from the TPM's own primary seed plus a
per-service label. That makes the key unexportable and machine-bound, but
it also means **any process that can open `/dev/tpmrm0` can issue the
same command and reproduce the same key.** An `authValue` cannot fix
that, because the authValue is not an input to the derivation — an
attacker simply re-derives the key with an authValue of their own.

Two optional controls close that gap:

**1. A host derivation secret.** Provision a root-owned secret and the
derived key depends on the TPM seed *and* a file the attacker must also
be able to read:

```sh
install -d -m 0700 /etc/hkdfguard
( umask 077; head -c 32 /dev/urandom > /etc/hkdfguard/tpm.derivation-secret )
```

The file's bytes are used exactly as they are on disk — no newline
trimming, because any trimming rule would silently change the derived key
for a secret ending in that byte. A file that is present but
untrustworthy (wrong owner, group/other-accessible, a symlink, empty,
oversized) is a hard error, never silently ignored.

> **This changes the KEK.** Adding, removing, or altering the secret
> derives a different key, so DEKs wrapped beforehand will fail their
> fingerprint check (`-16`) rather than decrypt. Provision it before
> wrapping anything you need to keep. There is currently no rewrap API.

The secret is folded into the `TPM2_CreatePrimary` template's `unique`
field, which is the TPM's designed channel for influencing primary
derivation. (`inSensitive.data` would be the more obvious choice and does
not work: for an asymmetric key the TPM requires
`TPMA_OBJECT.sensitiveDataOrigin` to be SET, and clearing it to supply
sensitive data fails with `TPM_RC_ATTRIBUTES` — confirmed against swtpm.)

Because a TPM that ignored the extra input would leave the secret looking
configured while protecting nothing, the provider verifies empirically —
once per process — that the secret actually changes the derived key, and
refuses to use the TPM at all if it doesn't.

**2. Pinned TPM Names.** Record the Name your TPM reports for a service
and the provider will refuse any key whose Name differs. Unlike the
provider's own Name self-consistency check (which only catches a
non-conformant stack, since a Name is a public function of the public
area that anyone could recompute), this compares against a value held in
the root-owned policy file, so substitution is detectable.

```yaml
tpm:
  require_derivation_secret: true      # refuse the TPM without the secret file
  pinned_names:
    com.company.orders: "000b<64 hex chars>"
```

Get the value to pin from `tpm2_readpublic` on the object, or from the
`-16`/mismatch diagnostic the provider logs. `require_derivation_secret`
defaults to `false` so that enabling the secret on one host doesn't
silently make it mandatory fleet-wide; set it `true` once every host has
one. Both settings fail closed: a policy file that exists but can't be
parsed is treated as requiring the secret, and pinning errors rather than
reporting "nothing pinned".

Neither control addresses TPM *bus* exposure (an interposer on a discrete
TPM's LPC/SPI bus can still read the ECDH result in cleartext); that
needs salted, parameter-encrypted sessions, which this provider does not
yet use.

Callers never see which provider is active. Every provider implements the
identical `ECDH -> HKDF-SHA512 -> AES-256-GCM` protocol
([`src/crypto.rs`](src/crypto.rs)); the only difference is where the
persistent P-256 KEK's private key lives and who performs the ECDH.

### Build & verification matrix

All of the below has actually been run, in Docker on Debian bookworm/aarch64
(`docker/run-tests.sh` -- see that section below), not just reasoned about:

| Feature | Builds on macOS (this repo's dev env) | Builds & links natively on Linux | Hardware/module test |
|---|---|---|---|
| `external-secret`, `ephemeral` (default) | yes | yes -- verified | unit tests pass; full wrap/unwrap round trip through the compiled C ABI (`examples/wrap_unwrap.c`) verified |
| `pkcs11` | yes (build-only; no module to talk to) | yes -- verified, linked against real `cryptoki` 0.6.2 + `libsofthsm2.so` | `#[ignore]`d test passed against a real SoftHSM2 token: `C_GenerateKeyPair` + `CKM_ECDH1_DERIVE` executed for real, same key reproduced deterministically |
| `tpm2` | **no** -- `tss-esapi-sys` ships pregenerated bindings only for specific Linux target tuples and hard-fails on macOS/aarch64 | yes -- verified, linked against real `libtss2-esys` 3.2.1 | `#[ignore]`d test passed against a real `swtpm` instance: `TPM2_CreatePrimary` + `TPM2_ECDH_ZGen` executed for real, same key reproduced deterministically |

Neither hardware provider has been exercised against a physical TPM chip,
an fTPM, or a hardware HSM/YubiHSM -- only their software-simulated
equivalents (`swtpm`, SoftHSM2). Re-test against your actual production
hardware before depending on it.

Run the ignored hardware/module tests yourself once you have the real backend:

```sh
cargo test --features tpm2 -- --ignored     # needs a TPM or swtpm, on Linux
cargo test --features pkcs11 -- --ignored   # needs SoftHSM2 or another PKCS#11 module
```

### Testing in Docker (recommended if you're not already on Linux)

```sh
docker/run-tests.sh
```

Builds a real Linux environment with `tpm2-tss`, `swtpm`, and `SoftHSM2`
and runs the full matrix above end-to-end, including a real link against
`libtss2-esys` and the PKCS#11 loader and both `#[ignore]`d hardware
tests. This has been run successfully end-to-end (Debian bookworm/aarch64):
all 21 default-feature tests, a real link against `tpm2,pkcs11`, the
swtpm-backed TPM2 test, the SoftHSM2-backed PKCS#11 test, and the C ABI
round trip all passed. See [`docker/README.md`](docker/README.md).

## Initializing a wrapped key (`hkdfguard-v1-initialize`)

Because a wrapped payload can only be produced on the host that holds the
KEK, a deployment pipeline delivers the *plaintext* DEK to the host and
wraps it there. This CLI is that step.

The DEK is base64 of exactly 32 bytes, and is read from stdin or a file —
never from a command-line argument or an environment variable, both of
which are readable by any process running as the same user
(`/proc/<pid>/cmdline`, `/proc/<pid>/environ`).

```sh
# stdin -- printf is a shell builtin, so the DEK never reaches any argv
printf '%s' "$DEK_B64" | hkdfguard-v1-initialize /var/lib/app/key.bin \
    --service-name com.company.orders --dek-stdin

# file -- a Kubernetes/Vault secret mount, or a systemd credential
hkdfguard-v1-initialize /var/lib/app/key.bin \
    --service-name com.company.orders \
    --dek-file "$CREDENTIALS_DIRECTORY/dek"
```

A `--dek-file` must be a regular file, not a symlink, owned by root or by
the invoking user, with no group or other access (e.g. `0400`/`0600`) — the
same rules the library applies to the PKCS#11 PIN and the TPM derivation
secret. One trailing newline is ignored on both paths. Add `--force` to
replace an existing key file (the old contents are overwritten in place
before removal).

> The remaining exposure is upstream of this tool: don't put the DEK in an
> environment variable, and don't pipe it with an `echo` that resolves to
> `/bin/echo` (argv again). `printf` as a shell builtin is safe.

## Configuration

| Env var | Used by | Purpose |
|---|---|---|
| `HKDFGUARD_EXTERNAL_SECRET_DIR` | External Secret | Override the mount directory searched for `<dir>/<service>` secret files (default: first of `/var/run/secrets/hkdfguard`, `/run/secrets/hkdfguard`, `/vault/secrets/hkdfguard`, `/mnt/secrets-store/hkdfguard` that exists) |
| `HKDFGUARD_PKCS11_MODULE` | PKCS#11 | Absolute path to the PKCS#11 module `.so` (default: common SoftHSM2 install paths). The resolved file and its directory must be root-owned and not group/other-writable, or the module is refused. |
| `HKDFGUARD_PKCS11_SLOT` | PKCS#11 | Slot index (default: first slot with a token present) |
| `HKDFGUARD_PKCS11_PIN_FILE` | PKCS#11 | Path to a file holding the user PIN (default: `/etc/hkdfguard/pkcs11.pin`). Must be owned by root or the process's user with no group/other access (e.g. `0600`). The former `HKDFGUARD_PKCS11_PIN` env var is no longer read. |
| `HKDFGUARD_POLICY_FILE` | Policy | Override the policy file path (default: `/etc/hkdfguard/policy.yaml`) |
| `HKDFGUARD_TPM_DERIVATION_SECRET_FILE` | TPM2 | Path to the optional host secret mixed into TPM key derivation (default: `/etc/hkdfguard/tpm.derivation-secret`). Must be owned by root or this process's user with no group/other access (e.g. `0600`), and must not be a symlink. See "Hardening the TPM key" below. |
| `TPM2TOOLS_TCTI` / `TCTI` / `TEST_TCTI` | TPM2 | Standard `tpm2-tools`-style TCTI selector (e.g. `device:/dev/tpmrm0`, `swtpm:host=localhost,port=2321`); falls back to `device:/dev/tpmrm0` if unset |

## Design decisions worth knowing

- **Wire format is hand-rolled, not `serde`+`bincode`.** The wrapped
  payload ([`src/payload.rs`](src/payload.rs)) is a security-critical,
  cross-language, cross-version format the macOS and Windows
  implementations must also be able to parse; every field width and order
  is pinned explicitly rather than left to a serialization library's
  derive output.
- **Pure-Rust crypto (`p256`/`hkdf`/`aes-gcm`), not OpenSSL**, for the
  protocol itself. No system OpenSSL version skew across distros, trivial
  static linking (`libHkdfGuardKeyProtectionLinux.a`), and RustCrypto's P-256/HKDF-SHA512/
  AES-256-GCM implementations satisfy the mandated algorithm list exactly.
  TPM2 and PKCS#11 still, necessarily, link against their respective
  native libraries.
- **TPM2 KEKs are deterministic `CreatePrimary` outputs, not persistent
  handles.** Rather than using `EvictControl` to persist a child key into
  the TPM's limited persistent-handle range (which needs an owner-auth
  session and a local `service -> handle number` mapping to protect and
  never lose), each service's KEK is produced by `TPM2_CreatePrimary`
  with the public template's `unique` field set to
  `SHA-256(service)`. `CreatePrimary` is deterministic for a fixed
  hierarchy/template, so this reproduces the exact same key on demand from
  the TPM's own internal primary seed -- no persistent-handle bookkeeping,
  no exhaustion risk, nothing to lose. See the module doc in
  [`src/provider/tpm2.rs`](src/provider/tpm2.rs) for the full rationale
  and why this is not the kind of "derive a KEK from a machine
  fingerprint" construction the spec prohibits (the secret input is the
  TPM's seed; `service` is only a public domain-separation label, exactly
  like it already is for HKDF `info`).
- **The external-secret provider never creates keys, only loads them**,
  and declines per-service (not globally) when nothing is provisioned for
  a given `service` -- the wrap-time selection chain falls through to
  Ephemeral for that one service rather than failing the whole operation.
- **Unwrap always uses the provider recorded in the payload**, not
  whichever provider is currently strongest. If they differ, a migration
  hint is logged (see Logging below) so operators know it's time to
  re-wrap onto the stronger provider.

## Security properties

- **No Rust type, TPM handle, OpenSSL structure, or PKCS#11 object crosses
  the C ABI.** Only `int`/`uint8_t*`/`char*`.
- **No panic ever unwinds across the ABI.** Every exported function is
  wrapped in `catch_unwind`; a caught panic returns `HKDFGUARD_ERR_INTERNAL_ERROR`.
- **DEK plaintext is stack-only, never heap, during wrap/unwrap.**
  `crypto.rs` uses `AeadInPlace::{encrypt,decrypt}_in_place_detached` on a
  stack-allocated `[u8; 32]` instead of the more convenient
  `Aead::{encrypt,decrypt}`, which internally allocates a heap `Vec<u8>`
  for exactly this data.
- **Private key material never leaves the TPM or the PKCS#11 token.**
  `Tpm2Handle`/`Pkcs11Handle` hold no key bytes at all -- only a service
  name and a session handle; `ecdh()` asks the device/token to compute the
  shared point and only the (non-reversible) result crosses back.
- **Every other point a secret transits a heap buffer is explicitly
  zeroized**, not left to an incidental `Drop`: the ECDH shared secret and
  derived AES key (`Zeroizing<[u8; 32]>` throughout), the raw bytes read
  from a PKCS#11 token attribute, and the external-secret provider's
  mounted secret-file bytes.
- **On any `hkdfguard_unwrap_dek` failure, the caller's entire declared
  output buffer is zeroed** before returning -- no partial or stale key
  material is ever left behind.
- **KEKs are always cryptographically random**, generated by the provider
  (TPM RNG, PKCS#11 token RNG, or `OsRng`) -- never derived from hostname,
  machine ID, MAC address, container ID, or any other host fingerprint.
  The one necessary exception is the Ephemeral provider, whose whole
  design requires keeping generated keys in a heap-resident map for the
  life of the process; those keys still zeroize on drop
  (`elliptic_curve::SecretKey` implements `ZeroizeOnDrop`), but by
  definition can't be stack-only across calls.
- **Logging** (via the `log` crate) covers provider selection, provider
  initialization, migration events, and error codes -- never DEKs, KEKs,
  shared secrets, HKDF output, plaintext, or ciphertext.

## Layout

```
src/
  lib.rs                    C ABI: hkdfguard_wrap_dek / hkdfguard_unwrap_dek /
                             hkdfguard_generate_and_wrap_dek
  error.rs                  Internal error type <-> C status codes
  payload.rs                Wrapped-payload wire format
  crypto.rs                 ECDH -> HKDF-SHA512 -> AES-256-GCM protocol
  provider/
    mod.rs                  KekProvider/KekHandle traits, selection chain
    tpm2.rs                 Provider 1 (feature `tpm2`)
    pkcs11.rs                Provider 2 (feature `pkcs11`)
    external_secret.rs      Provider 3 (feature `external-secret`, default)
    ephemeral.rs             Provider 4 (feature `ephemeral`, default)
include/hkdfguard.h          C header
examples/wrap_unwrap.c       Minimal C consumer
scripts/build-release.sh     cargo build --release, then renames the output
                              to HkdfGuard.Kms.Linux.v1.{so,dylib}
```
