// Group 22:
// Name:                     Student Num:    Github Username:
// Rayan Ramaprasad          24227537        24227537
// Abinandh Radhakrishnan    23689813        abxsnxper
// Campbell Henderson        24278297        phyric1
// Sepehr Moghani Pilehroud  23642415        sepehrmoghani

#ifndef BUN_OUTPUT_H
#define BUN_OUTPUT_H


// -----------------------------------------------------------------------------
// bun_output - human-readable rendering helpers for the bun parser CLI.
//
// These are pure helpers (no static state) used by main.c when rendering the
// header + asset records to stdout. Keeping them separate makes them unit-
// testable without depending on the file parsing path.
//
// Author: Group 22, Member 4.
// -----------------------------------------------------------------------------
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "bun.h"
#include "bun_utils.h"


// Default prefix length: the brief asks for "approximately the first 60
// characters or bytes" when rendering long names / payloads.
#define BUN_OUTPUT_SNIPPET_LEN 60


/**
 * Return true iff every byte in `buf[0..len)` is a printable ASCII character
 * (0x20-0x7E) or common whitespace (0x09 tab, 0x0A LF, 0x0D CR).
 *
 * An empty buffer (len == 0) is considered printable.
 *
 * The `tab/LF/CR` allowance is intended for the *payload* printability test;
 * asset *names* in the BUN spec are stricter (0x20-0x7E only). Use
 * bun_name_is_printable() for name validation.
 */
bool bun_is_printable_ascii(const unsigned char *buf, size_t len);


/**
 * Write up to `max_len` characters of `buf` to `out`, escaping any byte that
 * is not a printable ASCII character as `\xHH`. Always safe to call even if
 * buf contains NULs. Returns the number of *source* bytes consumed (always
 * min(len, max_len)).
 *
 * Intended for safely displaying asset names, which are untrusted input.
 */
size_t bun_print_escaped(FILE *out, const unsigned char *buf, size_t len,
                         size_t max_len);


/**
 * Write a classic "hex + ASCII" dump of `buf[0..len)` to `out`, up to
 * `max_bytes` source bytes. The format is 16 bytes per line:
 *
 *     000000  48 65 6c 6c 6f 2c 20 42  55 4e 20 77 6f 72 6c 64  |Hello, BUN world|
 *
 * If `len > max_bytes`, an ellipsis line "  ... (N more bytes omitted)" is
 * printed after the last full line.
 */
void bun_hex_dump(FILE *out, const unsigned char *buf, size_t len,
                  size_t max_bytes);


/**
 * Write a payload snippet to `out`. If the first min(len, sniff_len) bytes
 * look printable, prints an escaped text snippet; otherwise falls back to
 * bun_hex_dump(). Caps output at `max_bytes` source bytes.
 *
 * This is the helper Member 2 should call from the "print asset records"
 * loop.
 */
void bun_print_payload_snippet(FILE *out, const unsigned char *buf,
                               size_t len, size_t max_bytes);


//Prints the decoded header to Stdout or anyother filestream that gets passed.
//Nothing is validated only printed.
void bun_print_header(FILE *out, const BunHeader *header);


//Prints one asset record.
//Name Offset, Name Length, Data Offset, Data Size, Compression, Type, Checksum, Flags.
void bun_print_asset_record(FILE *out, const BunAssetRecord *rec, u32 index);


//All stored errors are printed.
//If errors are added the function displays them.
void bun_print_errors(FILE *out, const BunParseContext *ctx);


void print_asset_payload_snippet(BunParseContext *ctx,
                                        const BunHeader *header,
                                        const BunAssetRecord *rec);


void print_asset_name_snippet(BunParseContext *ctx,
                                     const BunHeader *header,
                                     const BunAssetRecord *rec);

#endif
