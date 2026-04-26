#ifndef BUN_UTILS_H
#define BUN_UTILS_H


//Compiler uses the #include to literally paste the content of bun.h into the bun_utils.h file before compiling.
#include "bun.h"

/**
 * Safely compute a + b for u64 values.
 *
 * @param a First operand
 * @param b Second operand
 * @param out Pointer to store result
 * @return 1 if successful, 0 if overflow occurred
 *
 * Prevents integer overflow when performing bounds checks like:
 *   offset + size <= file_size
 */
int safe_add_u64(u64 a, u64 b, u64 *out);

/**
 * Safely compute a * b for u64 values.
 *
 * @param a First operand
 * @param b Second operand
 * @param out Pointer to store result
 * @return 1 if successful, 0 if overflow occurred
 *
 * Used for computing sizes such as:
 *   asset_count * BUN_ASSET_RECORD_SIZE
 */
int safe_mul_u64(u64 a, u64 b, u64 *out);

/**
 * Check whether a byte range lies fully within a file.
 *
 * @param offset Start of range
 * @param size Length of range
 * @param file_size Total file size
 * @return 1 if valid, 0 otherwise
 *
 * Internally uses safe_add_u64 to avoid overflow.
 */
int check_range_within_file(u64 offset, u64 size, long file_size);

u16 read_u16_le(const u8 *buf, size_t offset);
u32 read_u32_le(const u8 *buf, size_t offset);
u64 read_u64_le(const u8 *buf, size_t offset);


/**
 * Decompress RLE-encoded data.
 *
 * @param input Pointer to compressed data
 * @param input_size Size of compressed data in bytes
 * @param output Buffer for decompressed data
 * @param expected_size Expected size after decompression
 * @return BUN_OK on success, BUN_MALFORMED if invalid encoding
 *
 * Validates:
 * - input_size is even (pairs of count/value)
 * - count != 0 for all pairs
 * - output size matches expected_size exactly
 *
 * Does NOT allocate memory; caller must provide output buffer.
 */

bun_result_t decompress_rle(const u8 *input, u64 input_size, u8 *output, u64 expected_size);


/**
 * Record a parsing or validation error in the parse context.
 *
 * @param ctx  Pointer to the active BunParseContext
 * @param code Error classification (BUN_MALFORMED or BUN_UNSUPPORTED)
 * @param fmt  printf-style format string describing the error
 * @param ...  Additional arguments corresponding to the format string
 *
 * Formats a human-readable error message and appends it to the
 * context's internal error list, up to a fixed maximum number of stored
 * errors.
 *
 * Also updates ctx->worst_error to reflect the most severe
 * error encountered so far.
 *
 * If the maximum number of errors has already been reached, the new
 * error is silently discarded to prevent buffer overflow.
 *
 * This function does not perform any I/O; error messages must be
 * printed by another function.
 */
void add_error(BunParseContext *ctx, bun_result_t code, const char *fmt, ...);

#endif
