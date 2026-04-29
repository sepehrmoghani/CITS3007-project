// Group 22:
// Name:                     Student Num:    Github Username:
// Rayan Ramaprasad          24227537        24227537
// Abinandh Radhakrishnan    23689813        abxsnxper
// Campbell Henderson        24278297        phyric1
// Sepehr Moghani Pilehroud  23642415        sepehrmoghani
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
