#include "bun.h"
#include "bun_utils.h"
#include "bun_validate.h"
#include "bun_output.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>


//It does not contain all validation itself. It calls validation functions from bun_validate.h.
//This converts 48 raw bytes from the file into a BunAssetRecord.
//So it is decoding the binary asset record from little-endian format.
//Because it is static, only bun_parse.c can use it.
static BunAssetRecord read_asset_record_from_buf(const u8 *buf) {
    BunAssetRecord rec;
    rec.name_offset = read_u32_le(buf, 0u);
    rec.name_length = read_u32_le(buf, 4u);
    rec.data_offset = read_u64_le(buf, 8u);
    rec.data_size = read_u64_le(buf, 16u);
    rec.uncompressed_size = read_u64_le(buf, 24u);
    rec.compression = read_u32_le(buf, 32u);
    rec.type = read_u32_le(buf, 36u);
    rec.checksum = read_u32_le(buf, 40u);
    rec.flags = read_u32_le(buf, 44u);
    return rec;
}

//The following functions are stored in the header bun.h and are called throughout multiple files for checks, as defined here in bun_parse.c below.

//This decides the current overall parser result.
//So if any malformed error was recorded, final result is 1. If no malformed error but unsupported was recorded, final result is 2.
//The parser collects errors instead of stopping immediately.
bun_result_t bun_context_result(const BunParseContext *ctx) {
    if (ctx == NULL) {
        return BUN_ERR_INTERNAL;
    }
    if (ctx->saw_malformed) {
        return BUN_MALFORMED;
    }
    if (ctx->saw_unsupported) {
        return BUN_UNSUPPORTED;
    }
    return BUN_OK;
}


//Step 1

//This opens the file and prepares the context. It does: 1. checks arguments are not NULL, 2. clears the context with memset,3. opens file using: fopen(path, "rb");,
//4. seeks to the end: fseek(ctx->file, 0, SEEK_END);, 5. gets file size: ctx->file_size = ftell(ctx->file); and 6. seeks back to the start: fseek(ctx->file, 0, SEEK_SET);.
//So after this function, ctx stores: the open file, the file size and initial parser state.
bun_result_t bun_open(const char *path, BunParseContext *ctx) {
    if (path == NULL || ctx == NULL) {
        return BUN_ERR_INTERNAL;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->worst_error = BUN_OK;

    ctx->file = fopen(path, "rb");
    if (ctx->file == NULL) {
        return BUN_ERR_IO;
    }

    if (fseek(ctx->file, 0, SEEK_END) != 0) {
        (void)fclose(ctx->file);
        ctx->file = NULL;
        return BUN_ERR_IO;
    }

    ctx->file_size = ftell(ctx->file);
    if (ctx->file_size < 0) {
        (void)fclose(ctx->file);
        ctx->file = NULL;
        return BUN_ERR_IO;
    }

    if (fseek(ctx->file, 0, SEEK_SET) != 0) {
        (void)fclose(ctx->file);
        ctx->file = NULL;
        return BUN_ERR_IO;
    }

    return BUN_OK;
}


//Step 2

//This reads and validates the BUN header.
//It first checks: if (ctx == NULL || ctx->file == NULL || header == NULL) Then clears the header.
//Then checks if file is at least 60 bytes: if (ctx->file_size < (long)BUN_HEADER_SIZE).
//Then reads 60 bytes: fread(buf, 1u, BUN_HEADER_SIZE, ctx->file).
//Then decodes all header fields.
//Then it marks: ctx->header_loaded = 1;.
//Then it calls validation from bun_validate.h, validate_header_basic and validate_header_offsets are defined in bun_validate.c.


bun_result_t bun_parse_header(BunParseContext *ctx, BunHeader *header) {
    u8 buf[BUN_HEADER_SIZE];

    if (ctx == NULL || ctx->file == NULL || header == NULL) {
        return BUN_ERR_INTERNAL;
    }

    memset(header, 0, sizeof(*header));
    ctx->header_loaded = 0;

    if (ctx->file_size < (long)BUN_HEADER_SIZE) {
        add_error(ctx, BUN_MALFORMED,
                  "file too small for BUN header: size=%ld, required=%u",
                  ctx->file_size, (unsigned)BUN_HEADER_SIZE);
        return bun_context_result(ctx);
    }

    if (fseek(ctx->file, 0, SEEK_SET) != 0) {
        return BUN_ERR_IO;
    }

    if (fread(buf, 1u, BUN_HEADER_SIZE, ctx->file) != BUN_HEADER_SIZE) {
        return BUN_ERR_IO;
    }

    header->magic = read_u32_le(buf, 0u);
    header->version_major = read_u16_le(buf, 4u);
    header->version_minor = read_u16_le(buf, 6u);
    header->asset_count = read_u32_le(buf, 8u);
    header->asset_table_offset = read_u64_le(buf, 12u);
    header->string_table_offset = read_u64_le(buf, 20u);
    header->string_table_size = read_u64_le(buf, 28u);
    header->data_section_offset = read_u64_le(buf, 36u);
    header->data_section_size = read_u64_le(buf, 44u);
    header->reserved = read_u64_le(buf, 52u);
    ctx->header_loaded = 1;

    (void)validate_header_basic(ctx, header);
    (void)validate_header_offsets(ctx, header);

    return bun_context_result(ctx);
}

//bun_result_t bun_parse_assets(BunParseContext *ctx, const BunHeader *header) This reads every asset record from the asset table.
//It first seeks to the asset table: fseek(ctx->file, (long)header->asset_table_offset, SEEK_SET).
//Then loops through each asset: for (i = 0u; i < header->asset_count; i++).
//For each asset: 1. read 48 bytes, 2. decode the record with: rec = read_asset_record_from_buf(buf);,
//3. print it: bun_print_asset_record(stdout, &rec, i);, 4. validate the record: validate_asset_record(ctx, &rec, header, i);.
//5. if the parser is not already malformed, validate the actual name bytes: validate_asset_name(ctx, header, &rec, i);.
//    read asset records and     validate them safely.




bun_result_t bun_parse_assets(BunParseContext *ctx, const BunHeader *header) {
    u32 i;

    if (ctx == NULL || ctx->file == NULL || header == NULL) {
        return BUN_ERR_INTERNAL;
    }

    if (fseek(ctx->file, (long)header->asset_table_offset, SEEK_SET) != 0) {
        return BUN_ERR_IO;
    }

    for (i = 0u; i < header->asset_count; i++) {
        u8 buf[BUN_ASSET_RECORD_SIZE];
        BunAssetRecord rec;

        if (fread(buf, 1u, BUN_ASSET_RECORD_SIZE, ctx->file) != BUN_ASSET_RECORD_SIZE) {
            add_error(ctx, BUN_MALFORMED, "could not read asset record %" PRIu32, i);
            return bun_context_result(ctx);
        }

        rec = read_asset_record_from_buf(buf);
        bun_print_asset_record(stdout, &rec, i);

        (void)validate_asset_record(ctx, &rec, header, i);

        /* Only read the name/data if the ranges looked safe enough. */
        //If there is already a malformed error, the code avoids doing unsafe seeks into name/data regions.
        //But be aware: if asset 0 is malformed, this may skip name validation for later assets too because ctx remains malformed. That is safe, but it may,
        //report fewer errors than possible. That is acceptable because the brief says report as many as can be safely detected.

        if (bun_context_result(ctx) != BUN_MALFORMED) {
            (void)validate_asset_name(ctx, header, &rec, i);
        } else {
            /* Continue reading records but avoid unsafe seeks for broken ranges. */
            if (fseek(ctx->file, (long)(header->asset_table_offset + ((u64)i + 1u) * BUN_ASSET_RECORD_SIZE), SEEK_SET) != 0) {
                return BUN_ERR_IO;
            }
        }
    }

    return bun_context_result(ctx);
}

//This closes the open file.
//It checks:    context is not NULL and     file is not already closed.
//Then:fclose(ctx->file);ctx->file = NULL;prevents leaving files open.
bun_result_t bun_close(BunParseContext *ctx) {
    if (ctx == NULL) {
        return BUN_ERR_INTERNAL;
    }
    if (ctx->file == NULL) {
        return BUN_OK;
    }
    if (fclose(ctx->file) != 0) {
        ctx->file = NULL;
        return BUN_ERR_IO;
    }
    ctx->file = NULL;
    return BUN_OK;
}
