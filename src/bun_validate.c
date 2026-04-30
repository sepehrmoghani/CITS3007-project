// Group 22:
// Name:                     Student Num:    Github Username:
// Rayan Ramaprasad          24227537        24227537
// Abinandh Radhakrishnan    23689813        abxsnxper
// Campbell Henderson        24278297        phyric1
// Sepehr Moghani Pilehroud  23642415        sepehrmoghani
#include "bun_validate.h"
#include "bun_utils.h"

#include <inttypes.h>
#include <stdio.h>

#define PRINTABLE_ASCII_MIN 0x20u
#define PRINTABLE_ASCII_MAX 0x7Eu


//Private helpers.

//function 1
//Checks whether a number is divisible by 4.
//Used because BUN section offsets/sizes must be 4-byte aligned.

static int is_aligned4(u64 n) {
    return (n % 4u) == 0u;
}

//function 2
//Calculates: section end = offset + size.
//But safely using:bun_u64_add(...). So if offset + size overflows, it fails instead of wrapping around.
static int section_end(Section s, u64 *end) {
    return bun_u64_add(s.offset, s.size, end);
}

//function 3
//Checks whether two sections overlap.
//Returns true if they overlap.

static bool sections_overlap(Section a, Section b) {
    u64 a_end = 0u;
    u64 b_end = 0u;

    if (!section_end(a, &a_end) || !section_end(b, &b_end)) {
        return true;
    }
    return !(a_end <= b.offset || b_end <= a.offset);
}

//function 4

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

    if (!bun_u64_mul((u64)h->asset_count, (u64)BUN_ASSET_RECORD_SIZE, &asset_table_size)) {
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
bun_result_t validate_asset_record(BunParseContext *ctx, const BunAssetRecord *rec, const BunHeader *header, u32 index) {
    u64 name_end = 0u;
    u64 data_end = 0u;

    if (rec->name_length == 0u) {
        add_error(ctx, BUN_MALFORMED, "asset %" PRIu32 " has empty name", index);
    } else if (!bun_u64_add((u64)rec->name_offset, (u64)rec->name_length, &name_end) || name_end > header->string_table_size) {
        add_error(ctx, BUN_MALFORMED,
                  "asset %" PRIu32 " name range outside string table: offset=%" PRIu32 ", length=%" PRIu32 ", string_table_size=%" PRIu64,
                  index, rec->name_offset, rec->name_length, header->string_table_size);
    }

    if (!bun_u64_add(rec->data_offset, rec->data_size, &data_end) || data_end > header->data_section_size) {
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
bun_result_t validate_asset_name(BunParseContext *ctx, const BunHeader *header, const BunAssetRecord *rec, u32 index) {
    u64 absolute = 0u;
    u32 i;

    if (rec->name_length == 0u) {
        add_error(ctx, BUN_MALFORMED, "asset %" PRIu32 " has empty name", index);
        return bun_context_result(ctx);
    }

    if (!bun_u64_add(header->string_table_offset, (u64)rec->name_offset, &absolute)) {
        add_error(ctx, BUN_MALFORMED, "asset %" PRIu32 " name absolute offset overflows", index);
        return bun_context_result(ctx);
    }

    if (seek_u64(ctx->file, absolute) != 0) {
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
bun_result_t validate_compression(BunParseContext *ctx, const BunHeader *header, const BunAssetRecord *rec, u32 index) {
    u64 absolute = 0u;
    u64 expanded = 0u;

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

    if (!bun_u64_add(header->data_section_offset, rec->data_offset, &absolute)) {
        add_error(ctx, BUN_MALFORMED, "asset %" PRIu32 " data absolute offset overflows", index);
        return bun_context_result(ctx);
    }

    if (seek_u64(ctx->file, absolute) != 0) {
        add_error(ctx, BUN_MALFORMED, "asset %" PRIu32 " RLE data seek failed", index);
        return bun_context_result(ctx);
    }

    uint8_t buffer[4096];

    size_t remaining = rec->data_size;
    u64 global_pos = 0u;

    while (remaining > 0) {
        size_t to_read = sizeof(buffer);
        if (to_read > remaining) {
            to_read = remaining;
        }

        size_t bytes_read = fread(buffer, 1, to_read, ctx->file);

        if (bytes_read != to_read) {
            add_error(ctx, BUN_MALFORMED,
                      "asset %" PRIu32 " RLE data read failed",
                      index);
            return bun_context_result(ctx);
        }

        for (size_t i = 0; i < bytes_read; i += 2) {

            uint8_t count = buffer[i];
            uint8_t value = buffer[i + 1];
            (void)value;

            if (count == 0) {
                add_error(ctx, BUN_MALFORMED,
                          "asset %" PRIu32 " RLE pair at byte %" PRIu64 " has zero count",
                          index, global_pos + (u64)i);
                return bun_context_result(ctx);
            }

            if (!bun_u64_add(expanded, (uint64_t)count, &expanded)) {
                add_error(ctx, BUN_MALFORMED,
                          "asset %" PRIu32 " RLE expanded size overflows",
                          index);
                return bun_context_result(ctx);
            }
        }

        global_pos += (u64)bytes_read;
        remaining -= bytes_read;
    }

    if (expanded != rec->uncompressed_size) {
        add_error(ctx, BUN_MALFORMED,
                  "asset %" PRIu32 " RLE expands to %" PRIu64 " bytes, expected %" PRIu64,
                  index, expanded, rec->uncompressed_size);
    }

    return bun_context_result(ctx);
}
