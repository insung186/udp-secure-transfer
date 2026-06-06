#include "sha1_util.h"

#include <stdio.h>
#include <string.h>

static uint32_t rotl32(uint32_t value, unsigned bits) {
    return (value << bits) | (value >> (32U - bits));
}

static void sha1_transform(Sha1Context *ctx, const uint8_t block[64]) {
    uint32_t w[80];
    uint32_t a, b, c, d, e;
    size_t i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               (uint32_t)block[i * 4 + 3];
    }
    for (i = 16; i < 80; i++) {
        w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];

    for (i = 0; i < 80; i++) {
        uint32_t f;
        uint32_t k;
        uint32_t temp;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5a827999U;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ed9eba1U;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdcU;
        } else {
            f = b ^ c ^ d;
            k = 0xca62c1d6U;
        }
        temp = rotl32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl32(b, 30);
        b = a;
        a = temp;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

void sha1_init(Sha1Context *ctx) {
    ctx->state[0] = 0x67452301U;
    ctx->state[1] = 0xefcdab89U;
    ctx->state[2] = 0x98badcfeU;
    ctx->state[3] = 0x10325476U;
    ctx->state[4] = 0xc3d2e1f0U;
    ctx->bit_count = 0;
    ctx->buffer_len = 0;
}

void sha1_update(Sha1Context *ctx, const uint8_t *data, size_t len) {
    size_t copy_len;
    if (!ctx || (!data && len > 0)) {
        return;
    }
    ctx->bit_count += (uint64_t)len * 8U;
    while (len > 0) {
        copy_len = 64U - ctx->buffer_len;
        if (copy_len > len) {
            copy_len = len;
        }
        memcpy(ctx->buffer + ctx->buffer_len, data, copy_len);
        ctx->buffer_len += copy_len;
        data += copy_len;
        len -= copy_len;
        if (ctx->buffer_len == 64U) {
            sha1_transform(ctx, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }
}

void sha1_final(Sha1Context *ctx, uint8_t digest[SHA1_DIGEST_LENGTH]) {
    uint64_t bit_count = ctx->bit_count;
    size_t i;
    uint8_t one = 0x80;
    uint8_t zero = 0x00;
    uint8_t length_bytes[8];

    sha1_update(ctx, &one, 1);
    while (ctx->buffer_len != 56U) {
        sha1_update(ctx, &zero, 1);
    }
    for (i = 0; i < 8; i++) {
        length_bytes[7 - i] = (uint8_t)((bit_count >> (i * 8)) & 0xffU);
    }
    sha1_update(ctx, length_bytes, sizeof(length_bytes));

    for (i = 0; i < 5; i++) {
        digest[i * 4] = (uint8_t)((ctx->state[i] >> 24) & 0xffU);
        digest[i * 4 + 1] = (uint8_t)((ctx->state[i] >> 16) & 0xffU);
        digest[i * 4 + 2] = (uint8_t)((ctx->state[i] >> 8) & 0xffU);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i] & 0xffU);
    }
    memset(ctx, 0, sizeof(*ctx));
}

int sha1_file(const char *path, uint8_t digest[SHA1_DIGEST_LENGTH]) {
    FILE *fp;
    Sha1Context ctx;
    uint8_t buf[4096];
    size_t n;

    fp = fopen(path, "rb");
    if (!fp) {
        return -1;
    }
    sha1_init(&ctx);
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        sha1_update(&ctx, buf, n);
    }
    if (ferror(fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    sha1_final(&ctx, digest);
    return 0;
}

void sha1_to_hex(const uint8_t digest[SHA1_DIGEST_LENGTH], char out[SHA1_HEX_LENGTH + 1]) {
    static const char hex[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < SHA1_DIGEST_LENGTH; i++) {
        out[i * 2] = hex[(digest[i] >> 4) & 0x0f];
        out[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    out[SHA1_HEX_LENGTH] = '\0';
}
