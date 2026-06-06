#ifndef UDP_SECURE_SHA1_UTIL_H
#define UDP_SECURE_SHA1_UTIL_H

#include <stddef.h>
#include <stdint.h>

#define SHA1_DIGEST_LENGTH 20
#define SHA1_HEX_LENGTH 40

typedef struct {
    uint32_t state[5];
    uint64_t bit_count;
    uint8_t buffer[64];
    size_t buffer_len;
} Sha1Context;

void sha1_init(Sha1Context *ctx);
void sha1_update(Sha1Context *ctx, const uint8_t *data, size_t len);
void sha1_final(Sha1Context *ctx, uint8_t digest[SHA1_DIGEST_LENGTH]);
int sha1_file(const char *path, uint8_t digest[SHA1_DIGEST_LENGTH]);
void sha1_to_hex(const uint8_t digest[SHA1_DIGEST_LENGTH], char out[SHA1_HEX_LENGTH + 1]);

#endif
