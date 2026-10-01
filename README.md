# KeyProtectionCore-Linux (HKDFGuard)

Linux implementation of HKDFGuard: a stable C ABI for wrapping/unwrapping
32-byte Data Encryption Keys (DEKs) under a persistent, per-service Key
Encryption Key (KEK), using the strongest KEK backing available on the
host. Same cryptographic protocol and `service`-based key identity as the
macOS Secure Enclave and Windows TPM/CNG implementations of HKDFGuard.

```
ECDH (P-256, per-payload hashed point)  ->  HKDF-SHA512  ->  AES-256-GCM
```

A wrapped payload can only be **created** and **opened** on the host that
holds the KEK. The wrapping key is `ECDH(KEK_priv, H_salt)`, where
`H_salt` is a P-256 point hashed from the payload's random 32-byte salt
(try-and-increment; no one knows the discrete log of a hash output), so
producing a valid payload requires the KEK's private key — which never
leaves the TPM, HSM, or root-owned secret file. Because the point is
different for every payload, so is the raw ECDH secret `Z`: capturing
one `Z` (core dump, swap, a discrete TPM's bus) opens exactly that one
payload, not every payload the service has ever wrapped.

This is deliberately *not* ECIES. An ephemeral-key scheme would let
anyone holding the KEK's public key (not a secret — on a TPM, anyone who
can reach the device can recompute it) derive the same wrapping key and
mint a payload that unwraps to a DEK of their choosing. See
[`src/crypto.rs`](src/crypto.rs) for the full rationale, and note the
consequence: a build server **cannot** pre-wrap a DEK for a host. DEKs
are delivered to the host and wrapped there.

Wire format version 1. Every byte of a payload except the ciphertext is
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
(`include/hkdfguard.h`) and exported C symbols (`hkdfguard_create_kek`,
`hkdfguard_kek_exists`, `hkdfguard_wrap_dek`, `hkdfguard_unwrap_dek`,
`hkdfguard_generate_and_wrap_dek`) are unaffected either way and keep
their existing names.

```c
#include "hkdfguard.h"

/* Once, at startup: make sure the service has a KEK. This is the only
 * call that creates one -- wrap never does -- and it is deliberately
 * slow (see "Setup calls are deliberately slow"). Idempotent. */
hkdfguard_create_kek("com.company.orders");

uint8_t dek[32] = { ... };
uint8_t wrapped[512];
int wrapped_len = sizeof(wrapped);
hkdfguard_wrap_dek("com.company.orders", dek, 32, wrapped, &wrapped_len);

uint8_t recovered[32];
int recovered_len = sizeof(recovered);
hkdfguard_unwrap_dek("com.company.orders", wrapped, wrapped_len, recovered, &recovered_len);
```

`hkdfguard_wrap_dek` and `hkdfguard_generate_and_wrap_dek` return
`HKDFGUARD_ERR_KEK_NOT_FOUND` (`-9`) if `hkdfguard_create_kek` has never
succeeded for that `service`; `hkdfguard_kek_exists` reports whether it
has, without creating anything.

`hkdfguard_generate_and_wrap_dek` generates its own cryptographically random
32-byte DEK (via the OS CSPRNG) and wraps it in one call, for callers minting
a brand new DEK -- the plaintext never crosses back out to the caller; it's
zeroed internally the moment it's wrapped. Recover it later via
`hkdfguard_unwrap_dek` on the resulting payload, with the same `service`:

```c
uint8_t wrapped[512];
int wrapped_len = sizeof(wrapped);
hkdfguard_generate_and_wrap_dek("com.company.orders", wrapped, &wrapped_len);
```

See [`examples/wrap_unwrap.c`](examples/wrap_unwrap.c) for a complete,
buildable example, and [`include/hkdfguard.h`](include/hkdfguard.h) for the
full API contract (status codes, buffer sizing, safety requirements).

## Provider chain

`hkdfguard_create_kek` walks the policy-allowed providers in this order and
creates the `service`'s KEK on the first one that is available.
`hkdfguard_wrap_dek` walks the same order but only ever *loads*: it uses
the first provider that already holds a KEK for `service`, and never
creates one. `hkdfguard_unwrap_dek` always uses the exact provider that
originally wrapped the payload (recorded -- and authenticated -- in the
payload itself, never in `service`). Providers are constructed fresh on
every call; nothing is cached or kept open between calls.

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

Get the values to pin from the TPM itself with the two operator-helper
tests (see "Testing on a native Linux TPM" below; `scripts/native-tpm-test.sh`
runs them for you). They go through the production derivation, so a pin
learned *before* provisioning a derivation secret will not match after --
provision the secret first, then pin. `require_derivation_secret`
defaults to `false` so that enabling the secret on one host doesn't
silently make it mandatory fleet-wide; set it `true` once every host has
one. Both settings fail closed: a policy file that exists but can't be
parsed is treated as requiring the secret, and pinning errors rather than
reporting "nothing pinned".

**3. Session parameter encryption (bus protection).** On a *discrete*
TPM — a separate chip on the LPC/SPI bus — an interposer can read
`TPM2_ECDH_ZGen`'s response, the shared secret, in cleartext. Each
response opens one payload (the per-payload hashed point keeps a
captured `Z` from opening any other), but an interposer that stays on
the bus captures every subsequent one. The provider can run that command inside
a salted HMAC session with parameter encryption (TPM 2.0 Part 1 §19.6;
the cryptography is tpm2-tss's ESAPI, not this crate's), so the secret
crosses the bus AES-128-CFB encrypted.

```yaml
tpm:
  session_encryption: auto            # auto (default) | required | off
  pinned_session_salt_key_name: "000b<64 hex chars>"
```

`auto` reads `TPM_PT_MANUFACTURER` and skips encryption only for TPMs
positively known to have no external bus (Intel PTT, AMD fTPM, Qualcomm,
Hyper-V/VMware/Google vTPMs, swtpm) — there is nothing to sniff inside an
SoC or a hypervisor, and the residual fTPM threats sit inside the TPM's
own trust boundary where transport encryption can't help. Unknown
vendors are encrypted. `required` always encrypts and **refuses to load
without a pinned salt-key Name**: an unsalted session's key is derivable
from bus-visible nonces, and even a salted one can be man-in-the-middled
if the attacker substitutes their own salt key at `TPM2_ReadPublic`, so
the pin is what makes `required` mean something. Under `auto` the pin is
optional (passive sniffing is still defeated) and its absence is logged
once. The salt key is a deterministic primary with a fixed label, so its
Name is stable and pinnable; it carries no derivation secret and protects
nothing by itself.

> **Known limitation on discrete TPMs:** parameter encryption covers only
> a command's *first* parameter, and `TPM2_CreatePrimary`'s first
> parameter is `inSensitive`, not `inPublic`. The derivation-secret-derived
> `unique` label therefore still crosses the bus in cleartext when the
> service key is re-created, and an interposer that captures it can
> re-derive the key. On a discrete TPM the derivation secret protects
> against software attackers only. Closing that needs a persisted,
> parent-encrypted key blob (`TPM2_Create` + `TPM2_Load`) instead of a
> derived primary.

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
| `pkcs11` | yes (build-only; no module to talk to) | yes -- verified, linked against real `cryptoki` 0.6.2 + `libsofthsm2.so` | `#[ignore]`d tests pass against a real SoftHSM2 token: `C_GenerateKeyPair` + `CKM_ECDH1_DERIVE` executed for real, same key reproduced deterministically, and `CKM_ECDH1_DERIVE` against hashed per-payload points accepted |
| `tpm2` | **no** -- `tss-esapi-sys` ships pregenerated bindings only for specific Linux target tuples and hard-fails on macOS/aarch64 | yes -- verified, linked against real `libtss2-esys` 3.2.1 | The `#[ignore]`d conformance suite passes against a real `swtpm` instance: `TPM2_CreatePrimary` determinism and per-service uniqueness, the client-side Name formula matching the TPM's own, `TPM2_ECDH_ZGen` against hashed per-payload points, the derivation secret genuinely changing the derived key, and salted/parameter-encrypted sessions producing the same `Z` as plain ones. The same suite, plus the reboot-persistence check, has also been run via `scripts/native-tpm-test.sh` against real firmware TPMs: **Intel PTT** and **AMD fTPM** |

The TPM provider has been verified against `swtpm` and against two real
firmware TPMs, Intel PTT and AMD fTPM. It has **not** been exercised
against a discrete TPM chip (e.g. Infineon or Nuvoton) or against a
hardware HSM/YubiHSM -- the PKCS#11 provider has only ever been run
against SoftHSM2. `scripts/native-tpm-test.sh` (next section) exists
precisely so you can run the same matrix on your own hardware, including
a discrete chip, before depending on it.

Run the ignored hardware/module tests yourself once you have the real backend:

```sh
cargo test --features tpm2 -- --ignored     # needs a TPM or swtpm, on Linux
cargo test --features pkcs11 -- --ignored   # needs SoftHSM2 or another PKCS#11 module
```

### Testing on a native Linux TPM (Intel PTT / AMD fTPM / discrete)

Docker proves the code against `swtpm`. This repo's maintainers have run
the scripts below to completion, including reboot persistence, on real
**Intel PTT** and **AMD fTPM** firmware TPMs. A **discrete** TPM (e.g.
Infineon, Nuvoton) has not yet been tested -- the code path exists (see
the known limitation on parameter encryption below) but is unverified
against real discrete hardware. To prove it against the hardware you
will actually deploy on:

```sh
scripts/native-tpm-preflight.sh   # read-only: device access, tpm2-tools, libtss2-esys, vendor
scripts/native-tpm-test.sh        # the full matrix, on the real TPM
```

The preflight identifies the TPM from `TPM2_PT_MANUFACTURER` and tells you
what `tpm.session_encryption: auto` will decide on it (skip for an
fTPM/vTPM, encrypt for a discrete chip). The full run then does everything
`docker/entrypoint-test.sh` does, against the real device: the
conformance suite (determinism, Name formula, the fixed ECDH point,
encrypted-session correctness), the same suite again with a derivation
secret provisioned, a C ABI round trip with the KEK on the TPM under both
`auto` and a fully pinned `required` policy, and the CLI-to-C-consumer
cross-process check. It learns the Names to pin from the TPM itself via
two operator-helper tests (run them directly to get values for your own
policy):

```sh
cargo test --features tpm2 --lib print_session_salt_key_name_for_pinning -- --ignored --nocapture
HKDFGUARD_PIN_SERVICE=com.company.orders \
cargo test --features tpm2 --lib print_service_key_name_for_pinning -- --ignored --nocapture
```

Nothing under `/etc/hkdfguard` is touched and no state is left on the
TPM. On a discrete chip one fTPM-specific assertion is skipped (the
mechanism it exercises still runs).

The one property `swtpm` can only approximate is survival of a real
reboot. For that:

```sh
scripts/native-tpm-test.sh reboot capture   # wraps a DEK on the TPM and saves state
# reboot the machine
scripts/native-tpm-test.sh reboot verify    # the same KEK must re-derive and unwrap it
```

### Testing in Docker (recommended if you're not already on Linux)

```sh
docker/run-tests.sh
```

Builds a real Linux environment with `tpm2-tss`, `swtpm`, and `SoftHSM2`
and runs the full matrix end-to-end, in this order: the default-feature
unit, CLI, and integration tests; a real link against `libtss2-esys` and
the PKCS#11 loader; the `tpm2`-feature unit tests; the `#[ignore]`d TPM
conformance suite against swtpm; the `#[ignore]`d PKCS#11 tests against a
fresh SoftHSM2 token; a C ABI round trip through the release `.so`; and the
CLI flow (`provision`, then `wrap` via stdin and `--dek-file`, with the
retired `--dek` and an unprovisioned `wrap` both asserted to be refused)
unwrapped by a separate C consumer. Every change in this repo is expected
to pass it. See [`docker/README.md`](docker/README.md).

## External-secret file requirements

For the external-secret provider the mounted file *is* the KEK private
key, so it is held to the same standard as the PKCS#11 PIN and the TPM
derivation secret. `<mount>/<service>` must:

- be **owned by root or by the process's user**, with **no group or other
  access** — `0400` or `0600`;
- be a **regular file** (not a directory, device, or FIFO);
- **resolve to a path inside the mount.** Symlinks are followed —
  Kubernetes Secret volumes present every key as a symlink into `..data/`,
  and refusing that would refuse the most common delivery mechanism — but
  only while the resolution stays within the mount directory. A link
  leading anywhere else is refused.

A file that is present but fails a check is reported as an **error**,
never as "not provisioned": a misconfigured mount must not silently fall
through to a weaker provider. `hkdfguard_kek_exists` surfaces it the same
way.

Every common mechanism meets the mode requirement with one setting:

| Mechanism | Setting |
|---|---|
| Kubernetes `Secret` volume | `defaultMode: 0400` on the volume (files are root-owned) |
| Vault Agent template/sink | `perms = "0400"` |
| Docker Swarm secret | `mode: 0400` (the default `0444` is refused) |
| CSI Secrets Store | `defaultMode`/file permission in the `SecretProviderClass` |
| systemd `LoadCredential=` | already `0400`, root-owned — works as-is |

> **Kubernetes `fsGroup` caveat:** setting `fsGroup` on the pod can add
> group-read to secret files even with `defaultMode: 0400`, which the
> provider refuses. Either leave `fsGroup` unset for the secret volume,
> or use `fsGroupChangePolicy: OnRootMismatch` with an owner that matches
> the process's user.

## Initializing a wrapped key (`hkdfguard-v1-initialize`)

Because a wrapped payload can only be produced on the host that holds the
KEK, a deployment pipeline delivers the *plaintext* DEK to the host and
wraps it there. This CLI is that step, in two deliberately separate
commands:

```sh
# 1. Once, at deployment time: ensure the service has a KEK. This is the
#    only command that makes the (deliberately slow) setup calls.
hkdfguard-v1-initialize provision --service-name com.company.orders

# 2. Wrap a DEK under it. Never creates a KEK: if none is provisioned it
#    fails and names the command above.
printf '%s' "$DEK_B64" | hkdfguard-v1-initialize wrap \
    --key-file-path /var/lib/app/key.bin \
    --service-name com.company.orders --dek-stdin

# ...or from a file: a Kubernetes/Vault secret mount, or a systemd credential
hkdfguard-v1-initialize wrap \
    --key-file-path /var/lib/app/key.bin \
    --service-name com.company.orders \
    --dek-file "$CREDENTIALS_DIRECTORY/dek"
```

`provision` is idempotent: it checks first and reports "already
provisioned" without touching an existing KEK. On a TPM the KEK is derived
on demand, so it always reports present; for `external-secret` the mounted
file *is* the provisioning; only Ephemeral actually creates anything.

The DEK is base64 of exactly 32 bytes, read from stdin or a file — never
from a command-line argument or an environment variable, both of which are
readable by any process running as the same user (`/proc/<pid>/cmdline`,
`/proc/<pid>/environ`). `printf` is a shell builtin, so the DEK never
reaches any argv.

`wrap --force` completes the wrap in memory *before* it securely
overwrites and replaces the existing key file, so a wrap that fails — no
KEK, provider unavailable, bad input — never destroys the key file that
was already there.

A `--dek-file` must be a regular file, not a symlink, owned by root or by
the invoking user, with no group or other access (e.g. `0400`/`0600`) — the
same rules the library applies to the PKCS#11 PIN and the TPM derivation
secret. One trailing newline is ignored on both paths.

> The remaining exposure is upstream of this tool: don't put the DEK in an
> environment variable, and don't pipe it with an `echo` that resolves to
> `/bin/echo` (argv again). `printf` as a shell builtin is safe.

## Configuration

| Env var | Used by | Purpose |
|---|---|---|
| `HKDFGUARD_EXTERNAL_SECRET_DIR` | External Secret | Override the mount directory searched for `<dir>/<service>` secret files (default: first of `/var/run/secrets/hkdfguard`, `/run/secrets/hkdfguard`, `/vault/secrets/hkdfguard`, `/mnt/secrets-store/hkdfguard` that exists). Each file must be owner-only (`0400`/`0600`), owned by root or the process's user, and resolve to a path inside the mount — see "External-secret file requirements". |
| `HKDFGUARD_PKCS11_MODULE` | PKCS#11 | Absolute path to the PKCS#11 module `.so` (default: common SoftHSM2 install paths). The resolved file and its directory must be root-owned and not group/other-writable, or the module is refused. |
| `HKDFGUARD_PKCS11_SLOT` | PKCS#11 | Slot index (default: first slot with a token present) |
| `HKDFGUARD_PKCS11_PIN_FILE` | PKCS#11 | Path to a file holding the user PIN (default: `/etc/hkdfguard/pkcs11.pin`). Must be owned by root or the process's user with no group/other access (e.g. `0600`). The former `HKDFGUARD_PKCS11_PIN` env var is no longer read. |
| `HKDFGUARD_POLICY_FILE` | Policy | Override the policy file path (default: `/etc/hkdfguard/policy.yaml`) |
| `HKDFGUARD_TPM_DERIVATION_SECRET_FILE` | TPM2 | Path to the optional host secret mixed into TPM key derivation (default: `/etc/hkdfguard/tpm.derivation-secret`). Must be owned by root or this process's user with no group/other access (e.g. `0600`), and must not be a symlink. See "Hardening the TPM key" above. |
| `TPM2TOOLS_TCTI` / `TCTI` / `TEST_TCTI` | TPM2 | Standard `tpm2-tools`-style TCTI selector (e.g. `device:/dev/tpmrm0`, `swtpm:host=localhost,port=2321`); falls back to `device:/dev/tpmrm0` if unset |

Secrets are never read from environment variables (`/proc/<pid>/environ`
is readable by same-user processes and inherited by children); every
secret above is a file path, and every such file is checked on the opened
descriptor for ownership, mode, and type before its contents are trusted.

### Policy file reference

Everything the policy file (`/etc/hkdfguard/policy.yaml`) accepts, in one
place. Unknown keys are rejected. Every field is optional except
`selection`; the values shown are the defaults where one exists.

```yaml
key_requirements:
  minimum_protection: external      # ephemeral | software | external | hardware; providers below this tier are excluded

selection:
  mode: prefer                      # require | require-level | prefer
  provider: tpm2                    # with `require`: exactly this provider (tpm2 | pkcs11 | external-secret | ephemeral)
  level: hardware                   # with `require-level`: any provider at this tier or above

preferred_order:                    # with `prefer`: try in this order; omitted providers are excluded.
  - tpm2                            # This is also the ONLY way Ephemeral is ever used: it must be named here
  - pkcs11                          # (or be the `require` provider). With no policy file at all, the order is
  - external-secret                 # tpm2, pkcs11, external-secret -- and never ephemeral.

startup_behavior:
  setup_min_delay_ms: 1000          # floor on create_kek/kek_exists latency; 0 disables, max 60000
  fail_if_requirement_unmet: true   # accepted for schema parity; the library always fails closed regardless

container_policy:
  max_ephemeral_lifetime_seconds: 3600   # accepted and validated (> 0); not enforced by an internal timer

tpm:
  require_derivation_secret: false  # refuse the TPM without /etc/hkdfguard/tpm.derivation-secret
  pinned_names:                     # per-service expected TPM Name; refuse any other key
    com.company.orders: "000b<64 hex>"
  session_encryption: auto          # auto | required | off  (see "Session parameter encryption")
  pinned_session_salt_key_name: "000b<64 hex>"   # mandatory under `required`
```

The file must be owned by root or by the process's user and not writable
by group or others. Only a *missing* file means "no policy"; a present but
unreadable, too-broadly-writable, or malformed file makes every operation
fail closed -- and resolves each hardening knob to its strictest setting
(`session_encryption: required`, derivation secret required) rather than
its default.

## Design decisions worth knowing

- **Wire format is hand-rolled, not `serde`+`bincode`.** The wrapped
  payload ([`src/payload.rs`](src/payload.rs)) is security-critical: it
  is the AAD input as well as the on-disk layout, so every field width
  and order is pinned explicitly rather than left to a serialization
  library's derive output, which could silently change across a
  dependency bump. 
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
  with the public template's `unique` field set to a hash of the service
  name -- and, once provisioned, of the host derivation secret (see
  "Hardening the TPM key"). `CreatePrimary` is deterministic for a fixed
  hierarchy/template, so this reproduces the exact same key on demand from
  the TPM's own internal primary seed -- no persistent-handle bookkeeping,
  no exhaustion risk, nothing to lose. See the module doc in
  [`src/provider/tpm2.rs`](src/provider/tpm2.rs) for the full rationale
  and why this is not the kind of "derive a KEK from a machine
  fingerprint" construction the spec prohibits (the secret input is the
  TPM's seed; `service` is only a public domain-separation label, exactly
  like it already is for HKDF `info`). The consequence worth knowing: on a
  TPM every service's KEK "already exists" the moment the TPM is
  reachable, so `hkdfguard_kek_exists` is always true there and
  `provision` always reports already-provisioned.
- **The external-secret provider never creates keys, only loads them**,
  and declines per-service (not globally) when nothing is provisioned for
  a given `service`. `hkdfguard_create_kek` then continues down the
  policy-allowed chain; if nothing there can create one -- and Ephemeral
  is never a candidate unless the policy names it -- the call fails with
  `HKDFGUARD_ERR_PROVIDER_UNAVAILABLE` rather than quietly producing a key
  that would be lost on restart.
- **Nothing is cached between calls.** Providers are constructed fresh on
  every call and dropped after it; there are no standing TPM or PKCS#11
  sessions, no memoized provider selection, and the policy file is re-read
  from disk each time. The only per-process state is a handful of facts
  about the *hardware* (the TPM conformance verdict, whether it honors the
  derivation secret, and its manufacturer) that cannot change underneath a
  running process. This is deliberate: the most secret parts of the system
  are re-authenticated on every use rather than held open.
- **Unwrap always uses the provider recorded in the payload**, not
  whichever provider is currently strongest -- and that provider tag is
  authenticated, so it cannot be steered. If it differs from what policy
  would pick today, a debug-level migration hint is logged so operators
  know it's time to re-wrap onto the stronger provider.

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
  name and a connection; `ecdh()` asks the device/token to compute the
  shared point and only the (non-reversible) result crosses back.
- **Every secret file is checked on its opened descriptor, never by path.**
  The policy file, the PKCS#11 PIN, the TPM derivation secret, an
  external-secret KEK, and the CLI's `--dek-file` all go through the same
  discipline (`src/secure_file.rs`): open, then `fstat` the descriptor for
  regular-file type, ownership, and mode, so nothing can be swapped between
  the check and the read. Secret contents are read into a single fixed
  allocation that is never grown (so no partially-filled buffer is ever
  freed un-wiped) and zeroed on every exit path.
- **Service names can never name a file outside their mount.** The C ABI
  rejects a `service` that starts with `.` or contains `..`, and the
  external-secret provider enforces the same rule again where the name
  becomes a path -- plus a containment check that any symlink it follows
  resolves inside the mount directory.
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
  lib.rs                    C ABI: hkdfguard_create_kek / hkdfguard_kek_exists /
                             hkdfguard_wrap_dek / hkdfguard_unwrap_dek /
                             hkdfguard_generate_and_wrap_dek; the setup-call gate
  error.rs                  Internal error type <-> C status codes
  payload.rs                Wrapped-payload wire format (version 1)
  crypto.rs                 ECDH(H_salt) -> HKDF-SHA512 -> AES-256-GCM protocol; salt-to-point hashing
  policy.rs                 /etc/hkdfguard/policy.yaml parsing and evaluation
  secure_file.rs            Descriptor-checked secret-file reads, self-wiping buffer
  provider/
    mod.rs                  KekProvider/KekHandle traits, selection chain
    tpm2.rs                 Provider 1 (feature `tpm2`): derivation secret, Name
                             pinning, session encryption, conformance suite
    pkcs11.rs                Provider 2 (feature `pkcs11`)
    external_secret.rs      Provider 3 (feature `external-secret`, default)
    ephemeral.rs             Provider 4 (feature `ephemeral`, default)
  bin/
    hkdfguard-v1-initialize.rs   CLI: `provision` and `wrap`
include/hkdfguard.h          C header
examples/
  wrap_unwrap.c              Minimal C consumer (create_kek -> wrap -> unwrap)
  cli_unwrap_check.c         Unwraps a CLI-written key file through the .so
tests/
  cli_initialize_round_trip.rs   Drives the CLI as a real subprocess
scripts/
  build-release.sh           cargo build --release, then renames the output
                              to HkdfGuard.Kms.Linux.v1.{so,dylib}
  native-tpm-preflight.sh    Read-only check of a real Linux TPM host
  native-tpm-test.sh         Full matrix on a real TPM; `reboot capture|verify`
  tpm-reboot-test.sh         swtpm-restart approximation of reboot persistence
docker/                      Dockerfile + entrypoint running the full matrix
                              against swtpm and SoftHSM2 (run-tests.sh)
```
