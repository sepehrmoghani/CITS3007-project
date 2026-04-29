#include "bun_utils.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>


// -----------------------------------------------------------------------------
// Overflow-safe arithmetic helpers
// -----------------------------------------------------------------------------
bool bun_u64_add(uint64_t a, uint64_t b, uint64_t *out) {
#if defined(__has_builtin)
#  if __has_builtin(__builtin_add_overflow)
    uint64_t tmp;
    if (__builtin_add_overflow(a, b, &tmp)) {
    if (out != NULL) *out = UINT64_MAX;
    return false;
    }
    if (out != NULL) *out = tmp;
    return true;
#  endif
#endif
    // Portable fallback.
    if (a > UINT64_MAX - b) {
    if (out != NULL) *out = UINT64_MAX;
    return false;
    }
    if (out != NULL) *out = a + b;
    return true;
}

bool bun_u64_mul(uint64_t a, uint64_t b, uint64_t *out) {
#if defined(__has_builtin)
#  if __has_builtin(__builtin_mul_overflow)
    uint64_t tmp;
    if (__builtin_mul_overflow(a, b, &tmp)) {
    if (out != NULL) *out = UINT64_MAX;
    return false;
    }
    if (out != NULL) *out = tmp;
    return true;
#  endif
#endif
    if (a != 0 && b > UINT64_MAX / a) {
    if (out != NULL) *out = UINT64_MAX;
    return false;
    }
    if (out != NULL) *out = a * b;
    return true;
}

bool bun_ranges_disjoint(uint64_t a_off, uint64_t a_size,
                            uint64_t b_off, uint64_t b_size) {
    // Zero-length ranges never overlap anything.
    if (a_size == 0 || b_size == 0) {
    return true;
    }
    uint64_t a_end, b_end;
    if (!bun_u64_add(a_off, a_size, &a_end)) return false;
    if (!bun_u64_add(b_off, b_size, &b_end)) return false;
    return (a_end <= b_off) || (b_end <= a_off);
}


bool check_range_within_file(u64 offset, u64 size, long file_size) {
    u64 end = 0u;
    if (file_size < 0) {
        return false;
    }
    if (!bun_u64_add(offset, size, &end)) {
        return false;
    }
    return end <= (u64)file_size;
}



u16 read_u16_le(const u8 *buf, size_t offset) {
    return (u16)((u16)buf[offset] |
                 ((u16)buf[offset + 1u] << 8));
}



u32 read_u32_le(const u8 *buf, size_t offset) {
    return (u32)((u32)buf[offset] |
                 ((u32)buf[offset + 1u] << 8) |
                 ((u32)buf[offset + 2u] << 16) |
                 ((u32)buf[offset + 3u] << 24));
}



u64 read_u64_le(const u8 *buf, size_t offset) {
    return (u64)((u64)buf[offset] |
                 ((u64)buf[offset + 1u] << 8) |
                 ((u64)buf[offset + 2u] << 16) |
                 ((u64)buf[offset + 3u] << 24) |
                 ((u64)buf[offset + 4u] << 32) |
                 ((u64)buf[offset + 5u] << 40) |
                 ((u64)buf[offset + 6u] << 48) |
                 ((u64)buf[offset + 7u] << 56));
}




bun_result_t decompress_rle(const u8 *input, u64 input_size, u8 *output, u64 expected_size) {
    u64 out_pos = 0u;
    u64 i = 0u;

    if ((input_size % 2u) != 0u) {
        return BUN_MALFORMED;
    }

    while (i < input_size) {
        u8 count = input[i];
        u8 value = input[i + 1u];
        u64 j;

        if (count == 0u) {
            return BUN_MALFORMED;
        }
        if (out_pos > expected_size || (u64)count > expected_size - out_pos) {
            return BUN_MALFORMED;
        }

        for (j = 0u; j < (u64)count; j++) {
            if (output != NULL) {
                output[out_pos] = value;
            }
            out_pos++;
        }
        i += 2u;
    }

    return out_pos == expected_size ? BUN_OK : BUN_MALFORMED;
}




void add_error(BunParseContext *ctx, bun_result_t code, const char *fmt, ...) {
    va_list args;

    if (ctx == NULL) {
        return;
    }

    if (code == BUN_MALFORMED) {
        ctx->saw_malformed = 1;
    } else if (code == BUN_UNSUPPORTED) {
        ctx->saw_unsupported = 1;
    }

    if (ctx->error_count >= MAX_ERRORS) {
        return;
    }

    va_start(args, fmt);
    (void)vsnprintf(ctx->errors[ctx->error_count], MAX_ERROR_LEN, fmt, args);
    va_end(args);
    ctx->error_count++;
}
