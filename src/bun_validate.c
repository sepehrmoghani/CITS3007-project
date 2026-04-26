//This file checks.
//Validates BUN Spec.
#include "bun_validate.h"
#include "bun_utils.h"

#include <inttypes.h>
#include <stdio.h>

#define PRINTABLE_ASCII_MIN 0x20u
#define PRINTABLE_ASCII_MAX 0x7Eu

typedef struct {
    u64 offset;
    u64 size;
    const char *name;
} Section;


//Private helpers.

//function 1
//Checks whether a number is divisible by 4.
//Used because BUN section offsets/sizes must be 4-byte aligned.

static int is_aligned4(u64 n) {
    return (n % 4u) == 0u;
}

//function 2
//Calculates: section end = offset + size.
//But safely using:safe_add_u64(...). So if offset + size overflows, it fails instead of wrapping around.
static int section_end(Section s, u64 *end) {
    return safe_add_u64(s.offset, s.size, end);
}

//function 3 
//Checks whether two sections overlap.
//Returns 1 if they overlap.

static int sections_overlap(Section a, Section b) {
    u64 a_end = 0u;
    u64 b_end = 0u;

    if (!section_end(a, &a_end) || !section_end(b, &b_end)) {
        return 1;
    }
    return !(a_end <= b.offset || b_end <= a.offset);
}

//function 4
//Checks the Magic, If wrong, the file is malformed.
//Checks the version, If wrong, the file is unsupported.


bun_result_t validate_header_basic(BunParseContext *ctx, const BunHeader *h) {
    if (h->magic != BUN_MAGIC) {
        add_error(ctx, BUN_MALFORMED,
                  "invalid magic: expected 0x%08" PRIX32 ", got 0x%08" PRIX32,
                  (u32)BUN_MAGIC, h->magic);
    }

    if (h->version_major != (u16)BUN_VERSION_MAJOR || h->version_minor != (u16)BUN_VERSION_MINOR) {
        add_error(ctx, BUN_UNSUPPORTED,
                  "unsupported version: got %" PRIu16 ".%" PRIu16 ", expected %u.%u",
                  h->version_major, h->version_minor,
                  (unsigned)BUN_VERSION_MAJOR, (unsigned)BUN_VERSION_MINOR);
    }

    return bun_context_result(ctx);
}

//function 5
//Section Layout IS SEEN.
//1. Alignment: These must be divisible by 4: asset_table_offset,string_table_offset,string_table_size,data_section_offset,data_section_size. 2. Asset table size: It calculates: asset_table_size = asset_count * 48 using safe multiplication.   
//3. Sections inside file: offset + size <= file_size for header, asset entry table, string table,data section. 4. No overlap: header vs asset table, header vs string table, header vs data,asset table vs string table,asset table vs data,string table vs data. If any overlap, malformed.
bun_result_t validate_header_offsets(BunParseContext *ctx, const BunHeader *h) {
    u64 asset_table_size = 0u;
    Section sections[4];
    size_t i;
    size_t j;

    if (!is_aligned4(h->asset_table_offset)) {
        add_error(ctx, BUN_MALFORMED, "asset_table_offset (%" PRIu64 ") is not 4-byte aligned", h->asset_table_offset);
    }
    if (!is_aligned4(h->string_table_offset)) {
        add_error(ctx, BUN_MALFORMED, "string_table_offset (%" PRIu64 ") is not 4-byte aligned", h->string_table_offset);
    }
    if (!is_aligned4(h->string_table_size)) {
        add_error(ctx, BUN_MALFORMED, "string_table_size (%" PRIu64 ") is not divisible by 4", h->string_table_size);
    }
    if (!is_aligned4(h->data_section_offset)) {
        add_error(ctx, BUN_MALFORMED, "data_section_offset (%" PRIu64 ") is not 4-byte aligned", h->data_section_offset);
    }
    if (!is_aligned4(h->data_section_size)) {
        add_error(ctx, BUN_MALFORMED, "data_section_size (%" PRIu64 ") is not divisible by 4", h->data_section_size);
    }

    if (!safe_mul_u64((u64)h->asset_count, (u64)BUN_ASSET_RECORD_SIZE, &asset_table_size)) {
        add_error(ctx, BUN_MALFORMED, "asset table size overflow: asset_count=%" PRIu32, h->asset_count);
        asset_table_size = UINT64_MAX;
    }

    sections[0] = (Section){0u, (u64)BUN_HEADER_SIZE, "header"};
    sections[1] = (Section){h->asset_table_offset, asset_table_size, "asset entry table"};
    sections[2] = (Section){h->string_table_offset, h->string_table_size, "string table"};
    sections[3] = (Section){h->data_section_offset, h->data_section_size, "data section"};

    for (i = 0u; i < 4u; i++) {
        u64 end = 0u;
        if (!section_end(sections[i], &end)) {
            add_error(ctx, BUN_MALFORMED, "%s end offset overflows u64", sections[i].name);
        } else if (!check_range_within_file(sections[i].offset, sections[i].size, ctx->file_size)) {
            add_error(ctx, BUN_MALFORMED,
                      "%s outside file bounds: offset=%" PRIu64 ", size=%" PRIu64 ", file_size=%ld",
                      sections[i].name, sections[i].offset, sections[i].size, ctx->file_size);
        }
    }

    for (i = 0u; i < 4u; i++) {
        for (j = i + 1u; j < 4u; j++) {
            if (sections_overlap(sections[i], sections[j])) {
                add_error(ctx, BUN_MALFORMED, "%s overlaps %s", sections[i].name, sections[j].name);
            }
        }
    }

    return bun_context_result(ctx);
}

//function 6
/*

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


bun_result_t validate_asset_record(BunParseContext *ctx, const BunAssetRecord *rec, const BunHeader *header, u32 index) {
    u64 name_end = 0u;
    u64 data_end = 0u;

    if (!safe_add_u64((u64)rec->name_offset, (u64)rec->name_length, &name_end) || name_end > header->string_table_size) {
        add_error(ctx, BUN_MALFORMED,
                  "asset %" PRIu32 " name range outside string table: offset=%" PRIu32 ", length=%" PRIu32 ", string_table_size=%" PRIu64,
                  index, rec->name_offset, rec->name_length, header->string_table_size);
    }

    if (!safe_add_u64(rec->data_offset, rec->data_size, &data_end) || data_end > header->data_section_size) {
        add_error(ctx, BUN_MALFORMED,
                  "asset %" PRIu32 " data range outside data section: offset=%" PRIu64 ", size=%" PRIu64 ", data_section_size=%" PRIu64,
                  index, rec->data_offset, rec->data_size, header->data_section_size);
    }

    if ((rec->flags & ~BUN_ALLOWED_FLAGS) != 0u) {
        add_error(ctx, BUN_UNSUPPORTED,
                  "asset %" PRIu32 " has unsupported flag bits: 0x%08" PRIX32,
                  index, rec->flags & ~BUN_ALLOWED_FLAGS);
    }

    if (rec->checksum != 0u) {
        add_error(ctx, BUN_UNSUPPORTED,
                  "asset %" PRIu32 " has non-zero checksum 0x%08" PRIX32 " but CRC validation is not implemented",
                  index, rec->checksum);
    }

    (void)validate_compression(ctx, header, rec, index);
    return bun_context_result(ctx);
}

//function 7
/*

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
 *    string_table_offset and name_offset. Uses safe_add_u64()
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


bun_result_t validate_asset_name(BunParseContext *ctx, const BunHeader *header, const BunAssetRecord *rec, u32 index) {
    u64 absolute = 0u;
    u32 i;

    if (rec->name_length == 0u) {
        add_error(ctx, BUN_MALFORMED, "asset %" PRIu32 " has empty name", index);
        return bun_context_result(ctx);
    }

    if (!safe_add_u64(header->string_table_offset, (u64)rec->name_offset, &absolute)) {
        add_error(ctx, BUN_MALFORMED, "asset %" PRIu32 " name absolute offset overflows", index);
        return bun_context_result(ctx);
    }

    if (fseek(ctx->file, (long)absolute, SEEK_SET) != 0) {
        add_error(ctx, BUN_MALFORMED, "asset %" PRIu32 " name seek failed", index);
        return bun_context_result(ctx);
    }

    for (i = 0u; i < rec->name_length; i++) {
        int ch = fgetc(ctx->file);
        if (ch == EOF) {
            add_error(ctx, BUN_MALFORMED, "asset %" PRIu32 " name read failed", index);
            break;
        }
        if ((unsigned)ch < PRINTABLE_ASCII_MIN || (unsigned)ch > PRINTABLE_ASCII_MAX) {
            add_error(ctx, BUN_MALFORMED,
                      "asset %" PRIu32 " name contains non-printable byte 0x%02X at name offset %" PRIu32,
                      index, (unsigned)ch, i);
            break;
        }
    }

    return bun_context_result(ctx);
}

//function 8
/*

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
 *       Uses safe_add_u64() to prevent overflow.
 *
 *    c. File access:
 *       Seeks to the RLE data position. Failure results in a malformed file.
 *
 *    d. RLE decoding checks:
 *       - Reads pairs of (count, value)
 *       - Ensures count != 0 (zero-count is invalid)
 *       - Accumulates expanded size using safe_add_u64()
 *
 *    e. Size verification:
 *       Ensures that the total expanded size matches uncompressed_size.
 *
 * Any violation results in BUN_MALFORMED or BUN_UNSUPPORTED as appropriate.
 *
 * Errors are recorded using add_error(), and processing continues where safe.
 */


bun_result_t validate_compression(BunParseContext *ctx, const BunHeader *header, const BunAssetRecord *rec, u32 index) {
    u64 absolute = 0u;
    u64 expanded = 0u;
    u64 pos;

    if (rec->compression == BUN_COMPRESSION_NONE) {
        if (rec->uncompressed_size != 0u) {
            add_error(ctx, BUN_MALFORMED,
                      "asset %" PRIu32 " uses no compression but uncompressed_size is %" PRIu64 " not 0",
                      index, rec->uncompressed_size);
        }
        return bun_context_result(ctx);
    }

    if (rec->compression == BUN_COMPRESSION_ZLIB) {
        add_error(ctx, BUN_UNSUPPORTED, "asset %" PRIu32 " uses unsupported zlib compression", index);
        return bun_context_result(ctx);
    }

    if (rec->compression != BUN_COMPRESSION_RLE) {
        add_error(ctx, BUN_UNSUPPORTED,
                  "asset %" PRIu32 " uses unknown compression value %" PRIu32,
                  index, rec->compression);
        return bun_context_result(ctx);
    }

    if ((rec->data_size % 2u) != 0u) {
        add_error(ctx, BUN_MALFORMED,
                  "asset %" PRIu32 " RLE data size is odd: %" PRIu64,
                  index, rec->data_size);
        return bun_context_result(ctx);
    }

    if (!safe_add_u64(header->data_section_offset, rec->data_offset, &absolute)) {
        add_error(ctx, BUN_MALFORMED, "asset %" PRIu32 " data absolute offset overflows", index);
        return bun_context_result(ctx);
    }

    if (fseek(ctx->file, (long)absolute, SEEK_SET) != 0) {
        add_error(ctx, BUN_MALFORMED, "asset %" PRIu32 " RLE data seek failed", index);
        return bun_context_result(ctx);
    }

    for (pos = 0u; pos < rec->data_size; pos += 2u) {
        int count = fgetc(ctx->file);
        int value = fgetc(ctx->file);
        (void)value;
        if (count == EOF || value == EOF) {
            add_error(ctx, BUN_MALFORMED, "asset %" PRIu32 " RLE data read failed", index);
            return bun_context_result(ctx);
        }
        if (count == 0) {
            add_error(ctx, BUN_MALFORMED,
                      "asset %" PRIu32 " RLE pair at data byte %" PRIu64 " has zero count",
                      index, pos);
            return bun_context_result(ctx);
        }
        if (!safe_add_u64(expanded, (u64)(unsigned)count, &expanded)) {
            add_error(ctx, BUN_MALFORMED, "asset %" PRIu32 " RLE expanded size overflows", index);
            return bun_context_result(ctx);
        }
    }

    if (expanded != rec->uncompressed_size) {
        add_error(ctx, BUN_MALFORMED,
                  "asset %" PRIu32 " RLE expands to %" PRIu64 " bytes, expected %" PRIu64,
                  index, expanded, rec->uncompressed_size);
    }

    return bun_context_result(ctx);
}
