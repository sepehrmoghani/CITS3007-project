#ifndef BUN_VALIDATE_H
#define BUN_VALIDATE_H

#include "bun.h"


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
 */
bun_result_t validate_compression(BunParseContext *ctx, const BunHeader *header, const BunAssetRecord *rec, u32 index);

#endif
