// Group 22:
// Name:                     Student Num:    Github Username:
// Rayan Ramaprasad          24227537        24227537
// Abinandh Radhakrishnan    23689813        abxsnxper
// Campbell Henderson        24278297        phyric1
// Sepehr Moghani Pilehroud  23642415        sepehrmoghani
#ifndef BUN_VALIDATE_H
#define BUN_VALIDATE_H

#include "bun.h"
#include <stdbool.h>

typedef struct {
    u64 offset;
    u64 size;
    const char *name;
} Section;

/**
 * Validate basic header fields.
 *
 * @param h Pointer to header
 * @return BUN_OK, BUN_MALFORMED, or BUN_UNSUPPORTED
 *
 * Checks:
 * - magic number matches BUN_MAGIC
 * - version is supported (1.0)
 */
 //Checks the Magic, If wrong, the file is malformed.
//Checks the version, If wrong, the file is unsupported.
bun_result_t validate_header_basic(BunParseContext *ctx, const BunHeader *h);


/**
 * Validate header offsets and section layout.
 *
 * @param h Pointer to header
 * @param file_size Total file size in bytes
 * @return BUN_OK or BUN_MALFORMED
 *
 * Checks:
 * - offsets and sizes are divisible by 4
 * - sections lie fully within file bounds
 * - no sections overlap
 */
 //Section Layout IS SEEN.
//1. Alignment: These must be divisible by 4: asset_table_offset,string_table_offset,string_table_size,data_section_offset,data_section_size. 2. Asset table size: It calculates: asset_table_size = asset_count * 48 using safe multiplication.
//3. Sections inside file: offset + size <= file_size for header, asset entry table, string table,data section. 4. No overlap: header vs asset table, header vs string table, header vs data,asset table vs string table,asset table vs data,string table vs data. If any overlap, malformed.
bun_result_t validate_header_offsets(BunParseContext *ctx, const BunHeader *h);


/**
 * Validate a single asset record.
 *
 * @param rec Asset record to validate
 * @param header File header (for section bounds)
 * @return BUN_OK, BUN_MALFORMED, or BUN_UNSUPPORTED
 *
 * Checks:
 * - name lies within string table
 * - data lies within data section
 * - compression rules are followed
 * - flags contain only supported bits
 * - checksum handling rules
 * ---------------------
 * Validates a single asset record against the BUN specification.
 *
 * This function performs structural and security checks to ensure that
 * the asset record does not reference invalid or unsafe regions of the file.
 *
 * Checks performed:
 *
 * 1. Name bounds:
 *    Ensures that name_offset + name_length does not exceed the size
 *    of the string table. Prevents reading outside the string table.
 *
 * 2. Data bounds:
 *    Ensures that data_offset + data_size does not exceed the size
 *    of the data section. Prevents reading outside the data section.
 *
 * 3. Flags validation:
 *    Verifies that only supported flag bits are set (ENCRYPTED and EXECUTABLE).
 *    Any unknown flag bits result in BUN_UNSUPPORTED.
 *
 * 4. Checksum validation:
 *    If checksum is non-zero, the parser reports BUN_UNSUPPORTED,
 *    since CRC validation is not implemented.
 *
 * 5. Compression validation:
 *    Delegates compression-specific checks (e.g. RLE, zlib, unknown types)
 *    to validate_compression().
 *
 * Errors are recorded using add_error(), and the final result is derived
 * from the context using bun_context_result().
 */
bun_result_t validate_asset_record(BunParseContext *ctx, const BunAssetRecord *rec, const BunHeader *header, u32 index);


/**
 * Validate an asset name from the string table.
 *
 * @param ctx Parse context (file access)
 * @param header File header
 * @param rec Asset record containing name info
 * @return BUN_OK or BUN_MALFORMED
 *
 * Checks:
 * - name_length > 0
 * - characters are printable ASCII (0x20–0x7E)
 * -------------------
 * Validates the name of an asset stored in the string table.
 *
 * This function ensures that asset names are well-formed and safe to read.
 *
 * Checks performed:
 *
 * 1. Non-empty name:
 *    Ensures that name_length > 0. Empty names are not allowed.
 *
 * 2. Absolute offset calculation:
 *    Computes the absolute file offset of the name by adding
 *    string_table_offset and name_offset. Uses bun_u64_add()
 *    to prevent integer overflow.
 *
 * 3. File access:
 *    Seeks to the calculated position in the file using fseek().
 *    If the seek fails, the file is considered malformed.
 *
 * 4. Printable ASCII validation:
 *    Reads each byte of the name and verifies that it lies within
 *    the printable ASCII range (0x20 to 0x7E).
 *
 *    Any non-printable character results in BUN_MALFORMED.
 *
 * Errors are recorded in the parser context and do not immediately
 * stop execution, allowing detection of multiple issues where safe.
 */
bun_result_t validate_asset_name(BunParseContext *ctx, const BunHeader *header, const BunAssetRecord *rec, u32 index);


/**
 * Validate compression-related fields in an asset record.
 *
 * @param rec Asset record
 * @return BUN_OK, BUN_MALFORMED, or BUN_UNSUPPORTED
 *
 * Checks:
 * - supported compression types (0, 1)
 * - RLE data size is even
 * - uncompressed_size rules are satisfied
 * --------------------
 * Validates the compression scheme and associated data for an asset.
 *
 * This function ensures that compression fields follow the BUN specification
 * and that compressed data is structurally valid and safe to process.
 *
 * Checks performed:
 *
 * 1. No compression (compression = 0):
 *    Ensures that uncompressed_size is 0. Any non-zero value is malformed.
 *
 * 2. Unsupported compression (zlib):
 *    If compression type is zlib (value = 2), reports BUN_UNSUPPORTED,
 *    as this parser does not implement zlib decompression.
 *
 * 3. Unknown compression:
 *    Any compression value other than NONE or RLE is treated as unsupported.
 *
 * 4. RLE compression validation (compression = 1):
 *
 *    a. Even data size:
 *       RLE data must consist of (count, byte) pairs, so data_size must be even.
 *
 *    b. Absolute offset calculation:
 *       Computes the absolute data offset using data_section_offset + data_offset.
 *       Uses bun_u64_add() to prevent overflow.
 *
 *    c. File access:
 *       Seeks to the RLE data position. Failure results in a malformed file.
 *
 *    d. RLE decoding checks:
 *       - Reads pairs of (count, value)
 *       - Ensures count != 0 (zero-count is invalid)
 *       - Accumulates expanded size using bun_u64_add()
 *
 *    e. Size verification:
 *       Ensures that the total expanded size matches uncompressed_size.
 *
 * Any violation results in BUN_MALFORMED or BUN_UNSUPPORTED as appropriate.
 *
 * Errors are recorded using add_error(), and processing continues where safe.
 */
bun_result_t validate_compression(BunParseContext *ctx, const BunHeader *header, const BunAssetRecord *rec, u32 index);

#endif
