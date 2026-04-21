// -----------------------------------------------------------------------------
// bun_output - implementation.
//
// See bun_output.h for API documentation.
//
// Author: Group 22, Member 4.
// -----------------------------------------------------------------------------

#include "bun_output.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

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

bool bun_name_is_printable(const unsigned char *buf, size_t len) {
  if (len == 0 || buf == NULL) {
    return false;
  }
  for (size_t i = 0; i < len; ++i) {
    unsigned char c = buf[i];
    if (c < 0x20 || c > 0x7E) {
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

// -----------------------------------------------------------------------------
// Overflow-safe arithmetic helpers
// -----------------------------------------------------------------------------

bool bun_u64_add(uint64_t a, uint64_t b, uint64_t *out) {
#if defined(__has_builtin)
#  if __has_builtin(__builtin_add_overflow)
  uint64_t tmp;
  if (__builtin_add_overflow(a, b, &tmp)) {
    if (out != NULL) *out = UINT64_MAX;
    return false;
  }
  if (out != NULL) *out = tmp;
  return true;
#  endif
#endif
  // Portable fallback.
  if (a > UINT64_MAX - b) {
    if (out != NULL) *out = UINT64_MAX;
    return false;
  }
  if (out != NULL) *out = a + b;
  return true;
}

bool bun_u64_mul(uint64_t a, uint64_t b, uint64_t *out) {
#if defined(__has_builtin)
#  if __has_builtin(__builtin_mul_overflow)
  uint64_t tmp;
  if (__builtin_mul_overflow(a, b, &tmp)) {
    if (out != NULL) *out = UINT64_MAX;
    return false;
  }
  if (out != NULL) *out = tmp;
  return true;
#  endif
#endif
  if (a != 0 && b > UINT64_MAX / a) {
    if (out != NULL) *out = UINT64_MAX;
    return false;
  }
  if (out != NULL) *out = a * b;
  return true;
}

bool bun_ranges_disjoint(uint64_t a_off, uint64_t a_size,
                         uint64_t b_off, uint64_t b_size) {
  // Zero-length ranges never overlap anything.
  if (a_size == 0 || b_size == 0) {
    return true;
  }
  uint64_t a_end, b_end;
  if (!bun_u64_add(a_off, a_size, &a_end)) return false;
  if (!bun_u64_add(b_off, b_size, &b_end)) return false;
  return (a_end <= b_off) || (b_end <= a_off);
}
