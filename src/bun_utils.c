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

/*



 * -----------------------

 * Verifies that a byte range lies completely within the bounds of the file.

 *

 * Parameters:

 *   offset     - starting byte position

 *   size       - length of the range

 *   file_size  - total file size

 *

 * The function checks:

 *   1. file_size is non-negative

 *   2. offset + size does not overflow (using bun_u64_add)

 *   3. offset + size <= file_size

 *

 * Returns:

 *   1 if the range is valid and within the file bounds

 *   0 otherwise

 *

 * This prevents reading beyond the end of the file, which could lead

 * to undefined behaviour or security vulnerabilities.

 */

int check_range_within_file(u64 offset, u64 size, long file_size) {
    u64 end = 0u;
    if (file_size < 0) {
        return 0;
    }
    if (!bun_u64_add(offset, size, &end)) {
        return 0;
    }
    return end <= (u64)file_size;
}


/*

 * -----------
 * Reads a 16-bit unsigned integer from a byte buffer in little-endian format.
 *
 * The least significant byte is stored first in memory.
 *
 * Example:
 *   bytes: [0x34, 0x12] → value = 0x1234
 *
 * This is used to decode fields from the BUN file format,
 * which stores all multi-byte integers in little-endian order.
 */

u16 read_u16_le(const u8 *buf, size_t offset) {
    return (u16)((u16)buf[offset] |
                 ((u16)buf[offset + 1u] << 8));
}


/*
 * -----------
 * Reads a 32-bit unsigned integer from a byte buffer in little-endian format.
 *
 * Combines four consecutive bytes into a single u32 value,
 * with the least significant byte at the lowest address.
 *
 * Example:
 *   bytes: [0x78, 0x56, 0x34, 0x12] → value = 0x12345678
 *
 * Used for decoding header and asset record fields from the file.
 */

u32 read_u32_le(const u8 *buf, size_t offset) {
    return (u32)((u32)buf[offset] |
                 ((u32)buf[offset + 1u] << 8) |
                 ((u32)buf[offset + 2u] << 16) |
                 ((u32)buf[offset + 3u] << 24));
}


/*

 * -----------
 * Reads a 64-bit unsigned integer from a byte buffer in little-endian format.
 *
 * Combines eight consecutive bytes into a single u64 value.
 *
 * This is required for decoding large offsets and sizes in the BUN format,
 * such as section offsets and data sizes.
 */

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


/*

 * --------------
 * Decompresses data encoded using Run-Length Encoding (RLE).
 *
 * The input consists of (count, value) byte pairs:
 *   count  number of repetitions
 *   value  byte to repeat
 *
 * Example:
 *   [3, 'A']  "AAA"
 *
 * Parameters:
 *   input          - pointer to compressed data
 *   input_size     - size of compressed data (must be even)
 *   output         - destination buffer (may be NULL if only validating)
 *   expected_size  - expected size after decompression
 *
 * Checks performed:
 *
 * 1. input_size must be even (pairs of count/value)
 * 2. count must not be zero
 * 3. decompressed size must not exceed expected_size
 * 4. final decompressed size must equal expected_size
 *
 * If output is non-NULL, decompressed bytes are written to it.
 *
 * Returns:
 *   BUN_OK if decompression is valid and matches expected size
 *   BUN_MALFORMED otherwise
 *
 * This function ensures RLE data is structurally valid and prevents
 * buffer overflows or incorrect decoding.
 */

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


/*

 * ---------
 * Records an error message in the parser context.
 *
 * Parameters:
 *   ctx   - parser context
 *   code  - error type (BUN_MALFORMED or BUN_UNSUPPORTED)
 *   fmt   - printf-style format string for the error message
 *   ...   - additional arguments for formatting
 *
 * Behaviour:
 *
 * 1. Updates context flags:
 *    - Sets ctx->saw_malformed if code is BUN_MALFORMED
 *    - Sets ctx->saw_unsupported if code is BUN_UNSUPPORTED
 *
 * 2. Updates ctx->worst_error using bun_context_result()
 *
 * 3. Stores a formatted error message in ctx->errors[],
 *    provided the maximum error limit has not been reached.
 *
 * 4. Increments ctx->error_count
 *
 * This allows the parser to:
 *   - collect multiple errors safely
 *   - report all detected issues
 *   - determine the final exit code after parsing
 *
 * If the maximum number of errors is reached, additional errors are ignored.
 */

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
    ctx->worst_error = bun_context_result(ctx);

    if (ctx->error_count >= MAX_ERRORS) {
        return;
    }

    va_start(args, fmt);
    (void)vsnprintf(ctx->errors[ctx->error_count], MAX_ERROR_LEN, fmt, args);
    va_end(args);
    ctx->error_count++;
}
