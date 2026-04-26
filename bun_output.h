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
 * Return true iff every byte in `buf[0..len)` is in the BUN-name range
 * (0x20-0x7E inclusive) AND len > 0. This matches BUN spec section 5.
 */
bool bun_name_is_printable(const unsigned char *buf, size_t len);

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

// -----------------------------------------------------------------------------
// Overflow-safe arithmetic helpers.
//
// These are shared by Members 1 and 3 (for layout validation) and exposed
// here so tests can exercise them directly without pulling in parser state.
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

#endif // BUN_OUTPUT_H
