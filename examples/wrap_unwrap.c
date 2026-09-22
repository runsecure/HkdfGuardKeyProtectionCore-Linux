/*
 * Minimal C consumer of the HKDFGuard C ABI.
 *
 * Build (after `cargo build --release`):
 *   cc -I../include wrap_unwrap.c -L../target/release -lHkdfGuardKeyProtectionLinux -o wrap_unwrap
 *   LD_LIBRARY_PATH=../target/release ./wrap_unwrap
 */

#include <stdio.h>
#include <string.h>
#include "hkdfguard.h"

int main(void) {
    const char* service = "com.company.orders";
    uint8_t dek[HKDFGUARD_DEK_LEN];
    for (int i = 0; i < HKDFGUARD_DEK_LEN; i++) {
        dek[i] = (uint8_t)i;
    }

    uint8_t wrapped[512];
    int wrapped_len = sizeof(wrapped);

    int rc = hkdfguard_wrap_dek(service, dek, HKDFGUARD_DEK_LEN, wrapped, &wrapped_len);
    if (rc != HKDFGUARD_OK) {
        fprintf(stderr, "wrap failed: %d\n", rc);
        return 1;
    }
    printf("wrapped %d bytes\n", wrapped_len);

    uint8_t recovered[HKDFGUARD_DEK_LEN];
    int recovered_len = sizeof(recovered);
    rc = hkdfguard_unwrap_dek(service, wrapped, wrapped_len, recovered, &recovered_len);
    if (rc != HKDFGUARD_OK) {
        fprintf(stderr, "unwrap failed: %d\n", rc);
        return 1;
    }

    if (recovered_len != HKDFGUARD_DEK_LEN || memcmp(dek, recovered, HKDFGUARD_DEK_LEN) != 0) {
        fprintf(stderr, "round trip mismatch\n");
        return 1;
    }

    printf("round trip OK\n");

    /* hkdfguard_generate_and_wrap_dek: for an Ephemeral Data Protection Key
     * where the caller doesn't need (or want) to see the plaintext DEK
     * itself -- it generates the random DEK internally and hands back only
     * the wrapped payload. */
    uint8_t ephemeral_wrapped[512];
    int ephemeral_wrapped_len = sizeof(ephemeral_wrapped);
    rc = hkdfguard_generate_and_wrap_dek(service, ephemeral_wrapped, &ephemeral_wrapped_len);
    if (rc != HKDFGUARD_OK) {
        fprintf(stderr, "generate_and_wrap failed: %d\n", rc);
        return 1;
    }
    printf("generated and wrapped %d bytes\n", ephemeral_wrapped_len);

    return 0;
}
