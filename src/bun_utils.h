#ifndef BUN_UTILS_H
#define BUN_UTILS_H


//Compiler uses the #include to literally paste the content of bun.h into the bun_utils.h file before compiling.
#include "bun.h"
#include <stdbool.h>

// -----------------------------------------------------------------------------
// Overflow-safe arithmetic helpers.
//
// These are shared by Members 1 and 3 (for layout validation) and exposed
// here so tests can exercise them directly without pulling in parser state.
// -----------------------------------------------------------------------------


/**
 * Compute `a + b` with overflow detection. Returns true on success and
 * writes the result to *out; returns false on overflow (out is set to
 * UINT64_MAX as a safety measure, so callers that ignore the return value
 * will at least not silently read a small wrapped value).
 */
bool bun_u64_add(uint64_t a, uint64_t b, uint64_t *out);


/**
 * Compute `a * b` with overflow detection. Same contract as bun_u64_add.
 */
bool bun_u64_mul(uint64_t a, uint64_t b, uint64_t *out);


/**
 * Return true iff [a_off, a_off + a_size) and [b_off, b_off + b_size) are
 * disjoint, treating zero-length ranges as "touching but not overlapping"
 * (so they never conflict). Overflow in a_off + a_size or b_off + b_size
 * is treated as overlap (the caller should have validated bounds already
 * but this is defensive).
 */
bool bun_ranges_disjoint(uint64_t a_off, uint64_t a_size,
                         uint64_t b_off, uint64_t b_size);

/**
 * Check whether a byte range lies fully within a file.
 *
 * @param offset Start of range
 * @param size Length of range
 * @param file_size Total file size
 * @return true if valid, false otherwise
 *
 * Internally uses safe_add_u64 to avoid overflow.
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
bool check_range_within_file(u64 offset, u64 size, long file_size);


/* -----------
* Reads a 16-bit unsigned integer from a byte buffer in little-endian format.
*
* The least significant byte is stored first in memory.
*
* Example:
*   bytes: [0x34, 0x12] , value = 0x1234
*
* This is used to decode fields from the BUN file format,
* which stores all multi-byte integers in little-endian order.
*/
u16 read_u16_le(const u8 *buf, size_t offset);


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
u32 read_u32_le(const u8 *buf, size_t offset);


/*
 * -----------
 * Reads a 64-bit unsigned integer from a byte buffer in little-endian format.
 *
 * Combines eight consecutive bytes into a single u64 value.
 *
 * This is required for decoding large offsets and sizes in the BUN format,
 * such as section offsets and data sizes.
 */
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
 *
 * If the maximum number of errors has already been reached, the new
 * error is silently discarded to prevent buffer overflow.
 *
 * This function does not perform any I/O; error messages must be
 * printed by another function.
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
void add_error(BunParseContext *ctx, bun_result_t code, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

#endif
