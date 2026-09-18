# KeyProtectionCore-Linux (HKDFGuard)

Linux implementation of HKDFGuard: a stable C ABI for wrapping/unwrapping
32-byte Data Encryption Keys (DEKs) under a persistent, per-service Key
Encryption Key (KEK), using the strongest KEK backing available on the
host. Same cryptographic protocol and `service`-based key identity as the
macOS Secure Enclave and Windows TPM/CNG implementations of HKDFGuard.

```
ECDH (P-256)  ->  HKDF-SHA256  ->  AES-256-GCM
```

## Quick start

```sh
cargo build --release
```

Produces `target/release/libhkdfguard.{so,dylib}` (dynamic) and
`libhkdfguard.a` (static), plus the C header at `include/hkdfguard.h`.

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
| 4 | Software | [`src/provider/software.rs`](src/provider/software.rs) | `software` | yes |
| 5 | Ephemeral | [`src/provider/ephemeral.rs`](src/provider/ephemeral.rs) | `ephemeral` | yes |

Callers never see which provider is active. Every provider implements the
identical `ECDH -> HKDF-SHA256 -> AES-256-GCM` protocol
([`src/crypto.rs`](src/crypto.rs)); the only difference is where the
persistent P-256 KEK's private key lives and who performs the ECDH.

### Build & verification matrix

All of the below has actually been run, in Docker on Debian bookworm/aarch64
(`docker/run-tests.sh` -- see that section below), not just reasoned about:

| Feature | Builds on macOS (this repo's dev env) | Builds & links natively on Linux | Hardware/module test |
|---|---|---|---|
| `software`, `external-secret`, `ephemeral` (default) | yes | yes -- verified | 21/21 unit tests pass; full wrap/unwrap round trip through the compiled C ABI (`examples/wrap_unwrap.c`) verified |
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

## Configuration

| Env var | Used by | Purpose |
|---|---|---|
| `HKDFGUARD_SOFTWARE_DIR` | Software | Override the KEK storage directory (default: `/var/lib/hkdfguard` if running as root, else `$XDG_CONFIG_HOME/hkdfguard`) |
| `HKDFGUARD_EXTERNAL_SECRET_DIR` | External Secret | Override the mount directory searched for `<dir>/<service>` secret files (default: first of `/var/run/secrets/hkdfguard`, `/run/secrets/hkdfguard`, `/vault/secrets/hkdfguard`, `/mnt/secrets-store/hkdfguard` that exists) |
| `HKDFGUARD_PKCS11_MODULE` | PKCS#11 | Path to the PKCS#11 module `.so` (default: common SoftHSM2 install paths) |
| `HKDFGUARD_PKCS11_SLOT` | PKCS#11 | Slot index (default: first slot with a token present) |
| `HKDFGUARD_PKCS11_PIN` | PKCS#11 | User PIN for login |
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
  static linking (`libhkdfguard.a`), and RustCrypto's P-256/HKDF-SHA256/
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
  Software for that one service rather than failing the whole operation.
- **Unwrap always uses the provider recorded in the payload**, not
  whichever provider is currently strongest. If they differ, a migration
  hint is logged (see Logging below) so operators know it's time to
  re-wrap onto the stronger provider.
- **Software KEKs are encrypted at rest** (AES-256-GCM under a locally-held
  vault key, `0600`/`0700` permissions) but the vault key lives on the same
  filesystem -- this is priority 4 for a reason; see the module doc in
  [`src/provider/software.rs`](src/provider/software.rs) for the explicit
  threat-model caveat.

## Security properties

- **No Rust type, TPM handle, OpenSSL structure, or PKCS#11 object crosses
  the C ABI.** Only `int`/`uint8_t*`/`char*`.
- **No panic ever unwinds across the ABI.** Every exported function is
  wrapped in `catch_unwind`; a caught panic returns `HKDFGUARD_ERR_INTERNAL_ERROR`.
- **DEK plaintext is stack-only, never heap, during wrap/unwrap.**
  `crypto.rs` uses `AeadInPlace::{encrypt,decrypt}_in_place_detached` on a
  stack-allocated `[u8; 32]` instead of the more convenient
  `Aead::{encrypt,decrypt}`, which internally allocates a heap `Vec<u8>`
  for exactly this data. The same technique protects the software
  provider's on-disk private-key encryption/decryption
  ([`src/provider/software.rs`](src/provider/software.rs)).
- **Private key material never leaves the TPM or the PKCS#11 token.**
  `Tpm2Handle`/`Pkcs11Handle` hold no key bytes at all -- only a service
  name and a session handle; `ecdh()` asks the device/token to compute the
  shared point and only the (non-reversible) result crosses back.
- **Every other point a secret transits a heap buffer is explicitly
  zeroized**, not left to an incidental `Drop`: the ECDH shared secret and
  derived AES key (`Zeroizing<[u8; 32]>` throughout), the raw bytes read
  from a PKCS#11 token attribute, the software provider's vault key and
  decrypted DER as read off disk, and the external-secret provider's
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
  lib.rs                    C ABI: hkdfguard_wrap_dek / hkdfguard_unwrap_dek
  error.rs                  Internal error type <-> C status codes
  payload.rs                Wrapped-payload wire format
  crypto.rs                 ECDH -> HKDF-SHA256 -> AES-256-GCM protocol
  provider/
    mod.rs                  KekProvider/KekHandle traits, selection chain
    tpm2.rs                 Provider 1 (feature `tpm2`)
    pkcs11.rs                Provider 2 (feature `pkcs11`)
    external_secret.rs      Provider 3 (feature `external-secret`, default)
    software.rs             Provider 4 (feature `software`, default)
    ephemeral.rs             Provider 5 (feature `ephemeral`, default)
include/hkdfguard.h          C header
examples/wrap_unwrap.c       Minimal C consumer
```
