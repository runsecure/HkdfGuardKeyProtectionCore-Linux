/*
 * Verifies that a wrapped-key file produced by the hkdfguard-v1-initialize
 * CLI tool (which links this crate's Rust code statically, as an rlib)
 * unwraps cleanly through libHkdfGuardKeyProtectionLinux.so loaded
 * dynamically here -- proving the wrapped payload's wire format is truly
 * consumer-independent, not an artifact of both sides sharing one binary.
 *
 * Usage: cli_unwrap_check <wrapped-file> <service> <expected-dek-file>
 *   <wrapped-file>       output of `hkdfguard-v1-initialize`
 *   <service>            the exact "<service-name>.<material-identifier>"
 *                         string the CLI wrapped it under
 *   <expected-dek-file>  the original 32 raw DEK bytes given to the CLI
 *                         (before base64-encoding for --dek)
 *
 * Build (after `cargo build --release`):
 *   cc -I../include cli_unwrap_check.c -L../target/release \
 *       -lHkdfGuardKeyProtectionLinux -o cli_unwrap_check
 *   LD_LIBRARY_PATH=../target/release ./cli_unwrap_check \
 *       <wrapped-file> <service> <expected-dek-file>
 */

#include <stdio.h>
#include <string.h>
#include "hkdfguard.h"

static long read_file(const char* path, uint8_t* buf, long max_len) {
    FILE* f = fopen(path, "rb");
    if (!f) {
        perror("fopen");
        return -1;
    }
    long n = (long)fread(buf, 1, (size_t)max_len, f);
    fclose(f);
    return n;
}

int main(int argc, char** argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s <wrapped-file> <service> <expected-dek-file>\n", argv[0]);
        return 2;
    }
    const char* wrapped_path = argv[1];
    const char* service = argv[2];
    const char* expected_dek_path = argv[3];

    uint8_t wrapped[1024];
    long wrapped_len = read_file(wrapped_path, wrapped, (long)sizeof(wrapped));
    if (wrapped_len <= 0) {
        fprintf(stderr, "failed to read wrapped file %s\n", wrapped_path);
        return 1;
    }

    uint8_t expected_dek[HKDFGUARD_DEK_LEN];
    long expected_len = read_file(expected_dek_path, expected_dek, (long)sizeof(expected_dek));
    if (expected_len != HKDFGUARD_DEK_LEN) {
        fprintf(stderr, "expected DEK file must be exactly %d bytes, got %ld\n", HKDFGUARD_DEK_LEN, expected_len);
        return 1;
    }

    uint8_t recovered[HKDFGUARD_DEK_LEN];
    int recovered_len = sizeof(recovered);
    int rc = hkdfguard_unwrap_dek(service, wrapped, (int)wrapped_len, recovered, &recovered_len);
    if (rc != HKDFGUARD_OK) {
        fprintf(stderr, "hkdfguard_unwrap_dek failed: %d\n", rc);
        return 1;
    }

    if (recovered_len != HKDFGUARD_DEK_LEN || memcmp(recovered, expected_dek, HKDFGUARD_DEK_LEN) != 0) {
        fprintf(stderr, "unwrapped DEK does not match the original --dek input\n");
        return 1;
    }

    printf("CLI-wrapped key unwraps cleanly via libHkdfGuardKeyProtectionLinux.so (service \"%s\")\n", service);
    return 0;
}
