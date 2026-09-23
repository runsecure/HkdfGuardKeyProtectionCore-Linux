# Running HKDFGuard's tests and builds in Docker

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
   external-secret, ephemeral) -- unit tests plus the CLI integration tests
   in [`tests/cli_initialize_round_trip.rs`](../tests/cli_initialize_round_trip.rs),
   which drive the `hkdfguard-v1-initialize` binary as a real subprocess.
2. `cargo build --features tpm2,pkcs11` -- confirms this crate actually
   *links* against real `libtss2-esys` and the PKCS#11 loader (only
   type-checking, not linking, could be verified outside Docker).
3. Starts `swtpm`, sends `TPM2_Startup`, and runs the `#[ignore]`d TPM2
   test against it.
4. Initializes a `SoftHSM2` token and runs the `#[ignore]`d PKCS#11 test
   against it.
5. Builds `libHkdfGuardKeyProtectionLinux.so` in release mode and runs
   [`examples/wrap_unwrap.c`](../examples/wrap_unwrap.c) against it.
6. Runs `hkdfguard-v1-initialize` (release build) to wrap a fresh random
   DEK to a file, then runs
   [`examples/cli_unwrap_check.c`](../examples/cli_unwrap_check.c), which
   loads `libHkdfGuardKeyProtectionLinux.so` dynamically and confirms it
   unwraps that file back to the exact same DEK -- proving the CLI's
   output isn't tied to being read back by the same (statically-linked)
   binary that wrote it.

Exits non-zero (and stops at the failing section) if anything fails.

## Build a distributable release

```sh
docker/build-dist.sh
```

Builds two images -- `linux/amd64` and `linux/arm64` -- from the same
`docker/Dockerfile` `run-tests.sh` uses (the non-native one runs under
QEMU emulation, transparently on a normal Docker Desktop install), and
runs [`entrypoint-build.sh`](entrypoint-build.sh) inside each, which:

1. Runs `cargo test` (default features), then `cargo test --all-features`
   -- a fast sanity gate (unit/integration tests, plus confirming the
   all-features build actually links against `libtss2-esys` and the
   PKCS#11 loader) rather than the full swtpm/SoftHSM2 hardware matrix
   above; run `docker/run-tests.sh` separately before a real release if you
   want that stronger guarantee.
2. Runs `cargo build --release --all-features`, so the distributed library
   supports every KEK provider (TPM2, PKCS#11, external secret, software,
   ephemeral), not just the ones enabled by default.
3. Copies `libHkdfGuardKeyProtectionLinux.so`,
   `libHkdfGuardKeyProtectionLinux.a`, the `hkdfguard-v1-initialize` CLI
   binary, and `include/hkdfguard.h` into `/dist` inside the container,
   which `build-dist.sh` bind-mounts to `dist/linux-amd64` or
   `dist/linux-arm64` on the host respectively -- so each architecture's
   four files land in its own subdirectory once the script finishes:

   ```
   dist/
     linux-amd64/
       hkdfguard-v1-initialize
       hkdfguard.h
       libHkdfGuardKeyProtectionLinux.a
       libHkdfGuardKeyProtectionLinux.so
     linux-arm64/
       hkdfguard-v1-initialize
       hkdfguard.h
       libHkdfGuardKeyProtectionLinux.a
       libHkdfGuardKeyProtectionLinux.so
   ```

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
