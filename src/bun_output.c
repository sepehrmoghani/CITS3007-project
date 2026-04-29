// Group 22:
// Name:                     Student Num:    Github Username:
// Rayan Ramaprasad          24227537        24227537
// Abinandh Radhakrishnan    23689813        abxsnxper
// Campbell Henderson        24278297        phyric1
// Sepehr Moghani Pilehroud  23642415        sepehrmoghani
#include "bun_output.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#define PAYLOAD_SNIPPET_BYTES 64u
#define NAME_SNIPPET_BYTES 60u

// -----------------------------------------------------------------------------
// Printability
// -----------------------------------------------------------------------------

bool bun_is_printable_ascii(const unsigned char *buf, size_t len) {
  if (buf == NULL) {
    return len == 0;
  }
  for (size_t i = 0; i < len; ++i) {
    unsigned char c = buf[i];
    bool ok = (c >= 0x20 && c <= 0x7E)
           || c == 0x09   // tab
           || c == 0x0A   // LF
           || c == 0x0D;  // CR
    if (!ok) {
      return false;
    }
  }
  return true;
}


// -----------------------------------------------------------------------------
// Escaped / snippet output
// -----------------------------------------------------------------------------

size_t bun_print_escaped(FILE *out, const unsigned char *buf, size_t len,
                         size_t max_len) {
  if (out == NULL) {
    return 0;
  }
  size_t n = len < max_len ? len : max_len;
  for (size_t i = 0; i < n; ++i) {
    unsigned char c = buf[i];
    if (c >= 0x20 && c <= 0x7E && c != '\\') {
      fputc((int)c, out);
    } else if (c == '\\') {
      fputs("\\\\", out);
    } else if (c == '\n') {
      fputs("\\n", out);
    } else if (c == '\t') {
      fputs("\\t", out);
    } else if (c == '\r') {
      fputs("\\r", out);
    } else {
      fprintf(out, "\\x%02x", (unsigned)c);
    }
  }
  if (len > max_len) {
    fputs("...", out);
  }
  return n;
}

void bun_hex_dump(FILE *out, const unsigned char *buf, size_t len,
                  size_t max_bytes) {
  if (out == NULL || buf == NULL) {
    return;
  }
  size_t n = len < max_bytes ? len : max_bytes;
  for (size_t i = 0; i < n; i += 16) {
    fprintf(out, "  %06zx  ", i);

    // hex column
    for (size_t j = 0; j < 16; ++j) {
      if (i + j < n) {
        fprintf(out, "%02x ", (unsigned)buf[i + j]);
      } else {
        fputs("   ", out);
      }
      if (j == 7) {
        fputc(' ', out);
      }
    }

    fputc('|', out);
    for (size_t j = 0; j < 16 && i + j < n; ++j) {
      unsigned char c = buf[i + j];
      fputc((c >= 0x20 && c <= 0x7E) ? (int)c : '.', out);
    }
    fputs("|\n", out);
  }
  if (len > max_bytes) {
    fprintf(out, "  ... (%zu more bytes omitted)\n", len - max_bytes);
  }
}

void bun_print_payload_snippet(FILE *out, const unsigned char *buf,
                               size_t len, size_t max_bytes) {
  if (out == NULL || buf == NULL || len == 0) {
    if (out != NULL) {
      fputs("  (empty)\n", out);
    }
    return;
  }
  size_t sniff = len < 64 ? len : 64;
  if (bun_is_printable_ascii(buf, sniff)) {
    fputs("  text: \"", out);
    bun_print_escaped(out, buf, len, max_bytes);
    fputs("\"\n", out);
  } else {
    fputs("  hex:\n", out);
    bun_hex_dump(out, buf, len, max_bytes);
  }
}


void bun_print_header(FILE *out, const BunHeader *header) {
    if (out == NULL || header == NULL) {
        return;
    }

    fprintf(out, "BUN Header\n");
    fprintf(out, "----------\n");
    fprintf(out, "magic: 0x%08" PRIX32 "\n", header->magic);
    fprintf(out, "version_major: %" PRIu16 "\n", header->version_major);
    fprintf(out, "version_minor: %" PRIu16 "\n", header->version_minor);
    fprintf(out, "asset_count: %" PRIu32 "\n", header->asset_count);
    fprintf(out, "asset_table_offset: %" PRIu64 "\n", header->asset_table_offset);
    fprintf(out, "string_table_offset: %" PRIu64 "\n", header->string_table_offset);
    fprintf(out, "string_table_size: %" PRIu64 "\n", header->string_table_size);
    fprintf(out, "data_section_offset: %" PRIu64 "\n", header->data_section_offset);
    fprintf(out, "data_section_size: %" PRIu64 "\n", header->data_section_size);
    fprintf(out, "reserved: %" PRIu64 "\n", header->reserved);
}


void bun_print_asset_record(FILE *out, const BunAssetRecord *rec, u32 index) {
    if (out == NULL || rec == NULL) {
        return;
    }

    fprintf(out, "\nAsset Record %" PRIu32 "\n", index);
    fprintf(out, "--------------\n");
    fprintf(out, "name_offset: %" PRIu32 "\n", rec->name_offset);
    fprintf(out, "name_length: %" PRIu32 "\n", rec->name_length);
    fprintf(out, "data_offset: %" PRIu64 "\n", rec->data_offset);
    fprintf(out, "data_size: %" PRIu64 "\n", rec->data_size);
    fprintf(out, "uncompressed_size: %" PRIu64 "\n", rec->uncompressed_size);
    fprintf(out, "compression: %" PRIu32 "\n", rec->compression);
    fprintf(out, "type: %" PRIu32 "\n", rec->type);
    fprintf(out, "checksum: 0x%08" PRIX32 "\n", rec->checksum);
    fprintf(out, "flags: 0x%08" PRIX32 "\n", rec->flags);
}


void bun_print_errors(FILE *out, const BunParseContext *ctx) {
    if (out == NULL || ctx == NULL) {
        return;
    }

    fprintf(stderr, "\nERRORS\n----------\n");
    for (int i = 0; i < ctx->error_count; i++) {
        fprintf(out, "%s\n", ctx->errors[i]);
    }
}


void print_asset_name_snippet(BunParseContext *ctx,
                                     const BunHeader *header,
                                     const BunAssetRecord *rec) {
  u64 absolute = 0u;
  u8 buf[NAME_SNIPPET_BYTES];

  fputs("name: ", stdout);
  if (!name_range_safe(header, rec)
      || !bun_u64_add(header->string_table_offset, (u64)rec->name_offset, &absolute)
      || seek_u64(ctx->file, absolute) != 0) {
    fputs("<not safely readable>\n", stdout);
    return;
  }

  size_t want = rec->name_length < NAME_SNIPPET_BYTES ? (size_t)rec->name_length : NAME_SNIPPET_BYTES;
  if (want > 0u && fread(buf, 1u, want, ctx->file) != want) {
    fputs("<read failed>\n", stdout);
    return;
  }

  fputc('"', stdout);
  (void)bun_print_escaped(stdout, buf, (size_t)rec->name_length, NAME_SNIPPET_BYTES);
  fputs("\"\n", stdout);
}


void print_asset_payload_snippet(BunParseContext *ctx,
                                        const BunHeader *header,
                                        const BunAssetRecord *rec) {
  u64 absolute = 0u;
  size_t want;
  u8 input[PAYLOAD_SNIPPET_BYTES * 2u];

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
    u8 decoded[PAYLOAD_SNIPPET_BYTES];
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
