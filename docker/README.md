# Running HKDFGuard's tests in Docker

This crate's TPM2 and PKCS#11 providers can't be built or tested on the
macOS machine this repo's core was written on (`tss-esapi-sys` only ships
pregenerated bindings for specific Linux target tuples, and there's no TPM
or PKCS#11 module to talk to). This directory gives you a real Linux
environment with `tpm2-tss`, `swtpm` (a software TPM2 simulator), and
`SoftHSM2` (a software PKCS#11 token) so every provider can actually be
built, linked, and exercised end-to-end.

## Run everything

```sh
docker/run-tests.sh
```

This builds the image and runs [`entrypoint-test.sh`](entrypoint-test.sh),
which:

1. `cargo build` / `cargo test` with the default features (software,
   external-secret, ephemeral) -- 21 unit/integration tests.
2. `cargo build --features tpm2,pkcs11` -- confirms this crate actually
   *links* against real `libtss2-esys` and the PKCS#11 loader (only
   type-checking, not linking, could be verified outside Docker).
3. Starts `swtpm`, sends `TPM2_Startup`, and runs the `#[ignore]`d TPM2
   test against it.
4. Initializes a `SoftHSM2` token and runs the `#[ignore]`d PKCS#11 test
   against it.
5. Builds `libHkdfGuardKeyProtectionLinux.so` in release mode and runs
   [`examples/wrap_unwrap.c`](../examples/wrap_unwrap.c) against it.

Exits non-zero (and stops at the failing section) if anything fails.

## Interactive use

```sh
docker build -t hkdfguard-test -f docker/Dockerfile .
docker run --rm -it --entrypoint bash hkdfguard-test
```

From there you have a full Linux Rust toolchain plus `tpm2-tools`,
`swtpm`, and `softhsm2-util` to explore manually, e.g.:

```sh
# start swtpm + TPM2_Startup, then:
cargo test --features tpm2 -- --ignored --test-threads=1

# init a SoftHSM2 token, then:
cargo test --features pkcs11 -- --ignored --test-threads=1
```

(see the corresponding sections of `entrypoint-test.sh` for the exact
commands).

## Testing against a real hardware TPM instead of swtpm

If the Docker host has a real TPM2 device, pass it through instead of
relying on the container's `swtpm`:

```sh
docker run --rm --device=/dev/tpmrm0 \
    -e TCTI=device:/dev/tpmrm0 \
    --entrypoint bash hkdfguard-test
```

then run `cargo test --features tpm2 -- --ignored --test-threads=1`
inside. Note this gives the container access to the host's real TPM state
-- keys it creates are real and persist in TPM NV/derivation state exactly
as they would outside Docker.
