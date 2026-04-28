#include "bun.h"
#include "bun_output.h"
#include "bun_utils.h"
#include "bun_validate.h"

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAYLOAD_SNIPPET_BYTES 64u
#define NAME_SNIPPET_BYTES 60u

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

static int seek_u64(FILE *file, u64 offset) {
  if (file == NULL || offset > (u64)LONG_MAX) {
    return -1;
  }
  return fseek(file, (long)offset, SEEK_SET);
}

static bool name_range_safe(const BunHeader *header, const BunAssetRecord *rec) {
  u64 end = 0u;
  return rec->name_length > 0u
      && bun_u64_add((u64)rec->name_offset, (u64)rec->name_length, &end)
      && end <= header->string_table_size;
}

static bool data_range_safe(const BunHeader *header, const BunAssetRecord *rec) {
  u64 end = 0u;
  return bun_u64_add(rec->data_offset, rec->data_size, &end)
      && end <= header->data_section_size;
}

static void print_asset_name_snippet(BunParseContext *ctx,
                                     const BunHeader *header,
                                     const BunAssetRecord *rec) {
  u64 absolute = 0u;
  size_t want;
  u8 buf[NAME_SNIPPET_BYTES];

  fputs("name: ", stdout);
  if (!name_range_safe(header, rec)
      || !bun_u64_add(header->string_table_offset, (u64)rec->name_offset, &absolute)
      || seek_u64(ctx->file, absolute) != 0) {
    fputs("<not safely readable>\n", stdout);
    return;
  }

  want = rec->name_length < NAME_SNIPPET_BYTES ? (size_t)rec->name_length : NAME_SNIPPET_BYTES;
  if (want > 0u && fread(buf, 1u, want, ctx->file) != want) {
    fputs("<read failed>\n", stdout);
    return;
  }

  fputc('"', stdout);
  (void)bun_print_escaped(stdout, buf, (size_t)rec->name_length, NAME_SNIPPET_BYTES);
  fputs("\"\n", stdout);
}

static size_t rle_decode_prefix(const u8 *input,
                                size_t input_len,
                                u8 *output,
                                size_t output_cap) {
  size_t out_pos = 0u;
  size_t i;

  for (i = 0u; i + 1u < input_len && out_pos < output_cap; i += 2u) {
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

static void print_asset_payload_snippet(BunParseContext *ctx,
                                        const BunHeader *header,
                                        const BunAssetRecord *rec) {
  u64 absolute = 0u;
  size_t want;
  u8 input[PAYLOAD_SNIPPET_BYTES * 2u];
  u8 decoded[PAYLOAD_SNIPPET_BYTES];

  fputs("payload snippet:\n", stdout);
  if (!data_range_safe(header, rec)
      || !bun_u64_add(header->data_section_offset, rec->data_offset, &absolute)
      || seek_u64(ctx->file, absolute) != 0) {
    fputs("  <not safely readable>\n", stdout);
    return;
  }

  if (rec->data_size == 0u) {
    fputs("  (empty)\n", stdout);
    return;
  }

  if (rec->compression == BUN_COMPRESSION_RLE) {
    want = rec->data_size < sizeof(input) ? (size_t)rec->data_size : sizeof(input);
    if (fread(input, 1u, want, ctx->file) != want) {
      fputs("  <read failed>\n", stdout);
      return;
    }
    want = rle_decode_prefix(input, want, decoded, sizeof(decoded));
    bun_print_payload_snippet(stdout, decoded, want, PAYLOAD_SNIPPET_BYTES);
    return;
  }

  if (rec->compression != BUN_COMPRESSION_NONE) {
    fputs("  <unsupported compression; raw payload not displayed>\n", stdout);
    return;
  }

  want = rec->data_size < PAYLOAD_SNIPPET_BYTES ? (size_t)rec->data_size : PAYLOAD_SNIPPET_BYTES;
  if (fread(input, 1u, want, ctx->file) != want) {
    fputs("  <read failed>\n", stdout);
    return;
  }
  bun_print_payload_snippet(stdout, input, want, PAYLOAD_SNIPPET_BYTES);
}

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

bun_result_t bun_open(const char *path, BunParseContext *ctx) {
  if (path == NULL || ctx == NULL) {
    return BUN_ERR_INTERNAL;
  }

  memset(ctx, 0, sizeof(*ctx));

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

bun_result_t bun_parse_assets(BunParseContext *ctx, const BunHeader *header) {
  u32 i;

  if (ctx == NULL || ctx->file == NULL || header == NULL) {
    return BUN_ERR_INTERNAL;
  }

  if (seek_u64(ctx->file, header->asset_table_offset) != 0) {
    return BUN_ERR_IO;
  }

  for (i = 0u; i < header->asset_count; i++) {
    u8 buf[BUN_ASSET_RECORD_SIZE];
    BunAssetRecord rec;
    u64 next_record = 0u;

    if (fread(buf, 1u, BUN_ASSET_RECORD_SIZE, ctx->file) != BUN_ASSET_RECORD_SIZE) {
      add_error(ctx, BUN_MALFORMED, "could not read asset record %" PRIu32, i);
      return bun_context_result(ctx);
    }

    rec = read_asset_record_from_buf(buf);
    bun_print_asset_record(stdout, &rec, i);
    print_asset_name_snippet(ctx, header, &rec);
    print_asset_payload_snippet(ctx, header, &rec);

    (void)validate_asset_record(ctx, &rec, header, i);
    if (name_range_safe(header, &rec)) {
      (void)validate_asset_name(ctx, header, &rec, i);
    }

    if (!bun_u64_mul((u64)i + 1u, (u64)BUN_ASSET_RECORD_SIZE, &next_record)
        || !bun_u64_add(header->asset_table_offset, next_record, &next_record)
        || seek_u64(ctx->file, next_record) != 0) {
      return BUN_ERR_IO;
    }
  }

  return bun_context_result(ctx);
}

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
