#include "bun_utils.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <limits.h>


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
 *   true if the range is valid and within the file bounds
 *   false otherwise
 *
 * This prevents reading beyond the end of the file, which could lead
 * to undefined behaviour or security vulnerabilities.
 */

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
 * 2. Stores a formatted error message in ctx->errors[],
 *    provided the maximum error limit has not been reached.
 *
 * 3. Increments ctx->error_count
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

    if (ctx->error_count >= MAX_ERRORS) {
        return;
    }

    va_start(args, fmt);
    (void)vsnprintf(ctx->errors[ctx->error_count], MAX_ERROR_LEN, fmt, args);
    va_end(args);
    ctx->error_count++;
}


size_t rle_decode_prefix(const u8 *input,
                                size_t input_len,
                                u8 *output,
                                size_t output_cap) {
  size_t out_pos = 0u;

  for (size_t i = 0u; i + 1u < input_len && out_pos < output_cap; i += 2u) {
    u8 count = input[i];
    u8 value = input[i + 1u];
    u8 j;

    if (count == 0u) {
      break;
    }
    for (j = 0u; j < count && out_pos < output_cap; j++) {
      output[out_pos++] = value;
    }
  }
  return out_pos;
}


int seek_u64(FILE *file, u64 offset) {
  if (file == NULL || offset > (u64)LONG_MAX) {
    return -1;
  }
  return fseek(file, (long)offset, SEEK_SET);
}


bool name_range_safe(const BunHeader *header, const BunAssetRecord *rec) {
  u64 end = 0u;
  return rec->name_length > 0u
      && bun_u64_add((u64)rec->name_offset, (u64)rec->name_length, &end)
      && end <= header->string_table_size;
}


bool data_range_safe(const BunHeader *header, const BunAssetRecord *rec) {
  u64 end = 0u;
  return bun_u64_add(rec->data_offset, rec->data_size, &end)
      && end <= header->data_section_size;
}
