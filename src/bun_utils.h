#ifndef BUN_UTILS_H
#define BUN_UTILS_H

#include "bun.h"
#include <stdbool.h>

// -----------------------------------------------------------------------------
// Overflow-safe arithmetic helpers.
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
 */
bool check_range_within_file(u64 offset, u64 size, long file_size);


/* -----------
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
 */
void add_error(BunParseContext *ctx, bun_result_t code, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));


int seek_u64(FILE *file, u64 offset);


bool name_range_safe(const BunHeader *header, const BunAssetRecord *rec);


bool data_range_safe(const BunHeader *header, const BunAssetRecord *rec);


size_t rle_decode_prefix(const u8 *input,
                                size_t input_len,
                                u8 *output,
                                size_t output_cap);
#endif
