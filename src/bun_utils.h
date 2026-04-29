// Group 22:
// Name:                     Student Num:    Github Username:
// Rayan Ramaprasad          24227537        24227537
// Abinandh Radhakrishnan    23689813        abxsnxper
// Campbell Henderson        24278297        phyric1
// Sepehr Moghani Pilehroud  23642415        sepehrmoghani
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


/**
* @brief Seek to a 64-bit file offset.
*
* Positions the file stream at the given offset using fseek().
* Ensures the offset is representable as a long before seeking.
*
* Returns -1 if the file pointer is NULL or the offset exceeds
* LONG_MAX, otherwise returns the result of fseek().
*
* @param file    Open file stream.
* @param offset  Target byte offset from start of file.
* @return 0 on success, non-zero on failure.
*/
int seek_u64(FILE *file, u64 offset);


/**
 * @brief Validate that an asset name lies within the string table.
 *
 * Checks that the name has non-zero length and that
 * name_offset + name_length does not overflow and remains within
 * the string table bounds.
 *
 * Uses bun_u64_add() to safely detect overflow.
 *
 * @param header  Parsed BUN header.
 * @param rec     Asset record containing name metadata.
 * @return true if the name range is valid, false otherwise.
 */
bool name_range_safe(const BunHeader *header, const BunAssetRecord *rec);


/**
 * @brief Validate that an asset payload lies within the data section.
 *
 * Ensures data_offset + data_size does not overflow and stays within
 * the bounds of the data section.
 *
 * Uses bun_u64_add() to safely detect overflow.
 *
 * @param header  Parsed BUN header.
 * @param rec     Asset record containing payload metadata.
 * @return true if the data range is valid, false otherwise.
 */
bool data_range_safe(const BunHeader *header, const BunAssetRecord *rec);


/**
 * @brief Decode a prefix of RLE-compressed data.
 *
 * Interprets input as (count, value) byte pairs and writes decoded
 * output up to output_cap bytes.
 *
 * Stops decoding when:
 *  - input is exhausted,
 *  - output buffer is full, or
 *  - a zero count is encountered.
 *
 * @param input        RLE-compressed input buffer.
 * @param input_len    Length of input in bytes.
 * @param output       Output buffer for decoded data.
 * @param output_cap   Maximum bytes to write to output.
 * @return Number of bytes written to output.
 */
size_t rle_decode_prefix(const u8 *input,
                                size_t input_len,
                                u8 *output,
                                size_t output_cap);
#endif
