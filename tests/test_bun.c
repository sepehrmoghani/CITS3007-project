// -----------------------------------------------------------------------------
// test_bun.c - libcheck unit tests for the bun parser.
//
// Coverage:
//   - Output helpers from bun_output.{c,h}      (complete - passes now)
//   - Overflow-safe arithmetic helpers          (complete - passes now)
//   - Header parsing via bun_parse_header()     (uses valid + invalid fixtures)
//   - Asset parsing via bun_parse_assets()      (uses valid fixtures)
//
// Conventions:
//   - Each behaviour gets its own START_TEST block (no shared state).
//   - Fixtures are looked up relative to the project root, which is the CWD
//     when `make test` is invoked (see the Makefile rule).
//   - Test names are test_<area>_<case>.
// -----------------------------------------------------------------------------

#define _POSIX_C_SOURCE 200809L
#include "bun.h"
#include "bun_output.h"
#include "bun_utils.h"

#include <check.h>

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

static void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "fatal error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    abort();
}

// Resolve a fixture path relative to the project root.
static const char *fixture(const char *rel) {
    static char path[512];
    int r = snprintf(path, sizeof(path), "tests/fixtures/%s", rel);
    if (r < 0 || (size_t)r >= sizeof(path)) {
        die("fixture path too long: %s", rel);
    }
    return path;
}

// Open a fixture and assert bun_open succeeded. Returns the context.
static BunParseContext open_fixture(const char *rel) {
    BunParseContext ctx = {0};
    bun_result_t r = bun_open(fixture(rel), &ctx);
    ck_assert_msg(r == BUN_OK,
                  "bun_open(%s) returned %d (expected BUN_OK)", rel, r);
    return ctx;
}

// -----------------------------------------------------------------------------
// Output helpers: is_printable_ascii
// -----------------------------------------------------------------------------

START_TEST(test_output_printable_empty) {
    ck_assert(bun_is_printable_ascii(NULL, 0));
    ck_assert(bun_is_printable_ascii((const unsigned char*)"", 0));
}
END_TEST

START_TEST(test_output_printable_plain_text) {
    const unsigned char *s = (const unsigned char *)"Hello, world!\n";
    ck_assert(bun_is_printable_ascii(s, strlen((const char *)s)));
}
END_TEST

START_TEST(test_output_printable_rejects_high_bytes) {
    unsigned char s[] = { 0x41, 0xFF, 0x42 };
    ck_assert(!bun_is_printable_ascii(s, sizeof(s)));
}
END_TEST

START_TEST(test_output_printable_rejects_nul) {
    unsigned char s[] = { 0x41, 0x00, 0x42 };
    ck_assert(!bun_is_printable_ascii(s, sizeof(s)));
}
END_TEST


// -----------------------------------------------------------------------------
// Output helpers: escaped printing
// -----------------------------------------------------------------------------

START_TEST(test_output_print_escaped_plain) {
    char buf[64] = {0};
    FILE *f = fmemopen(buf, sizeof(buf), "w");
    ck_assert_ptr_ne(f,NULL);
    bun_print_escaped(f, (const unsigned char *)"hi", 2, 60);
    fflush(f);
    fclose(f);
    ck_assert_str_eq(buf, "hi");
}
END_TEST

START_TEST(test_output_print_escaped_hex) {
    char buf[64] = {0};
    FILE *f = fmemopen(buf, sizeof(buf), "w");
    ck_assert_ptr_ne(f,NULL);
    const unsigned char src[] = { 'a', 0x01, 'b' };
    bun_print_escaped(f, src, 3, 60);
    fflush(f);
    fclose(f);
    ck_assert_str_eq(buf, "a\\x01b");
}
END_TEST

START_TEST(test_output_print_escaped_truncates) {
    char buf[64] = {0};
    FILE *f = fmemopen(buf, sizeof(buf), "w");
    ck_assert_ptr_ne(f,NULL);
    const unsigned char src[] = "0123456789";
    bun_print_escaped(f, src, 10, 4);
    fflush(f);
    fclose(f);
    ck_assert_str_eq(buf, "0123...");
}
END_TEST

// -----------------------------------------------------------------------------
// Overflow helpers
// -----------------------------------------------------------------------------

START_TEST(test_overflow_add_ok) {
    uint64_t out = 0;
    ck_assert(bun_u64_add(1, 2, &out));
    ck_assert_uint_eq(out, 3);
}
END_TEST

START_TEST(test_overflow_add_detects) {
    uint64_t out = 0;
    ck_assert(!bun_u64_add(UINT64_MAX, 1, &out));
    ck_assert_uint_eq(out, UINT64_MAX);
}
END_TEST

START_TEST(test_overflow_mul_detects) {
    uint64_t out = 0;
    ck_assert(!bun_u64_mul(UINT64_MAX, 2, &out));
    ck_assert_uint_eq(out, UINT64_MAX);
}
END_TEST



// -----------------------------------------------------------------------------
// Header parsing - valid fixtures
// -----------------------------------------------------------------------------

START_TEST(test_header_valid_empty) {
    BunParseContext ctx = open_fixture("valid/01-empty.bun");
    BunHeader h = {0};
    ck_assert_int_eq(bun_parse_header(&ctx, &h), BUN_OK);
    ck_assert_uint_eq(h.magic, BUN_MAGIC);
    ck_assert_uint_eq(h.version_major, 1);
    ck_assert_uint_eq(h.version_minor, 0);
    ck_assert_uint_eq(h.asset_count, 0);
    bun_close(&ctx);
}
END_TEST

START_TEST(test_header_valid_single_uncompressed) {
    BunParseContext ctx = open_fixture("valid/02-single-uncompressed.bun");
    BunHeader h = {0};
    ck_assert_int_eq(bun_parse_header(&ctx, &h), BUN_OK);
    ck_assert_uint_eq(h.asset_count, 1);
    bun_close(&ctx);
}
END_TEST

START_TEST(test_header_valid_reserved_ignored) {
    // reserved field is non-zero; spec says parser must still accept.
    BunParseContext ctx = open_fixture("valid/08-reserved-nonzero.bun");
    BunHeader h = {0};
    ck_assert_int_eq(bun_parse_header(&ctx, &h), BUN_OK);
    bun_close(&ctx);
}
END_TEST

// -----------------------------------------------------------------------------
// Header parsing - malformed / unsupported
// -----------------------------------------------------------------------------

START_TEST(test_header_bad_magic_is_malformed) {
    BunParseContext ctx = open_fixture("invalid/01-bad-magic.bun");
    BunHeader h = {0};
    ck_assert_int_eq(bun_parse_header(&ctx, &h), BUN_MALFORMED);
    bun_close(&ctx);
}
END_TEST

START_TEST(test_header_truncated_is_malformed) {
    BunParseContext ctx = open_fixture("invalid/02-truncated-header.bun");
    BunHeader h = {0};
    ck_assert_int_eq(bun_parse_header(&ctx, &h), BUN_MALFORMED);
    bun_close(&ctx);
}
END_TEST

START_TEST(test_header_unaligned_offset_is_malformed) {
    BunParseContext ctx = open_fixture("invalid/04-unaligned-offset.bun");
    BunHeader h = {0};
    ck_assert_int_eq(bun_parse_header(&ctx, &h), BUN_MALFORMED);
    bun_close(&ctx);
}
END_TEST

START_TEST(test_header_bad_version_major_is_unsupported) {
    BunParseContext ctx = open_fixture("invalid/20-bad-version-major.bun");
    BunHeader h = {0};
    ck_assert_int_eq(bun_parse_header(&ctx, &h), BUN_UNSUPPORTED);
    bun_close(&ctx);
}
END_TEST

START_TEST(test_header_bad_version_minor_is_unsupported) {
    BunParseContext ctx = open_fixture("invalid/21-bad-version-minor.bun");
    BunHeader h = {0};
    ck_assert_int_eq(bun_parse_header(&ctx, &h), BUN_UNSUPPORTED);
    bun_close(&ctx);
}
END_TEST

// -----------------------------------------------------------------------------
// Asset parsing - valid fixtures
// -----------------------------------------------------------------------------

START_TEST(test_assets_valid_multiple) {
    BunParseContext ctx = open_fixture("valid/03-multiple-assets.bun");
    BunHeader h = {0};
    ck_assert_int_eq(bun_parse_header(&ctx, &h), BUN_OK);
    ck_assert_int_eq(bun_parse_assets(&ctx, &h), BUN_OK);
    bun_close(&ctx);
}
END_TEST

START_TEST(test_assets_valid_rle) {
    BunParseContext ctx = open_fixture("valid/04-rle-compressed.bun");
    BunHeader h = {0};
    ck_assert_int_eq(bun_parse_header(&ctx, &h), BUN_OK);
    ck_assert_int_eq(bun_parse_assets(&ctx, &h), BUN_OK);
    bun_close(&ctx);
}
END_TEST

// -----------------------------------------------------------------------------
// Asset parsing - malformed / unsupported
// -----------------------------------------------------------------------------

START_TEST(test_assets_overlap_is_malformed) {
    BunParseContext ctx = open_fixture("invalid/06-overlapping-sections.bun");
    BunHeader h = {0};
    bun_result_t r = bun_parse_header(&ctx, &h);
    if (r == BUN_OK) {
        r = bun_parse_assets(&ctx, &h);
    }
    ck_assert_int_eq(r, BUN_MALFORMED);
    bun_close(&ctx);
}
END_TEST

START_TEST(test_assets_name_oob_is_malformed) {
    BunParseContext ctx = open_fixture("invalid/08-name-out-of-string-table.bun");
    BunHeader h = {0};
    bun_result_t r = bun_parse_header(&ctx, &h);
    if (r == BUN_OK) r = bun_parse_assets(&ctx, &h);
    ck_assert_int_eq(r, BUN_MALFORMED);
    bun_close(&ctx);
}
END_TEST

START_TEST(test_assets_nonprintable_name_is_malformed) {
    BunParseContext ctx = open_fixture("invalid/10-nonprintable-name.bun");
    BunHeader h = {0};
    bun_result_t r = bun_parse_header(&ctx, &h);
    if (r == BUN_OK) r = bun_parse_assets(&ctx, &h);
    ck_assert_int_eq(r, BUN_MALFORMED);
    bun_close(&ctx);
}
END_TEST

START_TEST(test_assets_rle_odd_is_malformed) {
    BunParseContext ctx = open_fixture("invalid/12-rle-odd-size.bun");
    BunHeader h = {0};
    bun_result_t r = bun_parse_header(&ctx, &h);
    if (r == BUN_OK) r = bun_parse_assets(&ctx, &h);
    ck_assert_int_eq(r, BUN_MALFORMED);
    bun_close(&ctx);
}
END_TEST

START_TEST(test_assets_rle_zero_count_is_malformed) {
    BunParseContext ctx = open_fixture("invalid/13-rle-zero-count.bun");
    BunHeader h = {0};
    bun_result_t r = bun_parse_header(&ctx, &h);
    if (r == BUN_OK) r = bun_parse_assets(&ctx, &h);
    ck_assert_int_eq(r, BUN_MALFORMED);
    bun_close(&ctx);
}
END_TEST

START_TEST(test_assets_zlib_is_unsupported) {
    BunParseContext ctx = open_fixture("invalid/22-compression-zlib.bun");
    BunHeader h = {0};
    bun_result_t r = bun_parse_header(&ctx, &h);
    if (r == BUN_OK) r = bun_parse_assets(&ctx, &h);
    ck_assert_int_eq(r, BUN_UNSUPPORTED);
    bun_close(&ctx);
}
END_TEST

START_TEST(test_assets_checksum_nonzero_is_unsupported) {
    BunParseContext ctx = open_fixture("invalid/24-checksum-nonzero.bun");
    BunHeader h = {0};
    bun_result_t r = bun_parse_header(&ctx, &h);
    if (r == BUN_OK) r = bun_parse_assets(&ctx, &h);
    ck_assert_int_eq(r, BUN_UNSUPPORTED);
    bun_close(&ctx);
}
END_TEST

START_TEST(test_assets_unknown_flag_is_unsupported) {
    BunParseContext ctx = open_fixture("invalid/25-unknown-flag.bun");
    BunHeader h = {0};
    bun_result_t r = bun_parse_header(&ctx, &h);
    if (r == BUN_OK) r = bun_parse_assets(&ctx, &h);
    ck_assert_int_eq(r, BUN_UNSUPPORTED);
    bun_close(&ctx);
}
END_TEST

// -----------------------------------------------------------------------------
// I/O path - missing file
// -----------------------------------------------------------------------------

START_TEST(test_io_missing_file) {
    BunParseContext ctx = {0};
    bun_result_t r = bun_open("tests/fixtures/does-not-exist.bun", &ctx);
    ck_assert_int_eq(r, BUN_ERR_IO);
}
END_TEST

// -----------------------------------------------------------------------------
// Suite assembly
// -----------------------------------------------------------------------------

static Suite *bun_suite(void) {
    Suite *s = suite_create("bun");

    TCase *tc_out = tcase_create("output-helpers");
    tcase_add_test(tc_out, test_output_printable_empty);
    tcase_add_test(tc_out, test_output_printable_plain_text);
    tcase_add_test(tc_out, test_output_printable_rejects_high_bytes);
    tcase_add_test(tc_out, test_output_printable_rejects_nul);
    tcase_add_test(tc_out, test_output_print_escaped_plain);
    tcase_add_test(tc_out, test_output_print_escaped_hex);
    tcase_add_test(tc_out, test_output_print_escaped_truncates);
    suite_add_tcase(s, tc_out);

    TCase *tc_ov = tcase_create("overflow-helpers");
    tcase_add_test(tc_ov, test_overflow_add_ok);
    tcase_add_test(tc_ov, test_overflow_add_detects);
    tcase_add_test(tc_ov, test_overflow_mul_detects);
    suite_add_tcase(s, tc_ov);

    TCase *tc_hdr = tcase_create("header");
    tcase_add_test(tc_hdr, test_header_valid_empty);
    tcase_add_test(tc_hdr, test_header_valid_single_uncompressed);
    tcase_add_test(tc_hdr, test_header_valid_reserved_ignored);
    tcase_add_test(tc_hdr, test_header_bad_magic_is_malformed);
    tcase_add_test(tc_hdr, test_header_truncated_is_malformed);
    tcase_add_test(tc_hdr, test_header_unaligned_offset_is_malformed);
    tcase_add_test(tc_hdr, test_header_bad_version_major_is_unsupported);
    tcase_add_test(tc_hdr, test_header_bad_version_minor_is_unsupported);
    suite_add_tcase(s, tc_hdr);

    TCase *tc_a = tcase_create("assets");
    tcase_add_test(tc_a, test_assets_valid_multiple);
    tcase_add_test(tc_a, test_assets_valid_rle);
    tcase_add_test(tc_a, test_assets_overlap_is_malformed);
    tcase_add_test(tc_a, test_assets_name_oob_is_malformed);
    tcase_add_test(tc_a, test_assets_nonprintable_name_is_malformed);
    tcase_add_test(tc_a, test_assets_rle_odd_is_malformed);
    tcase_add_test(tc_a, test_assets_rle_zero_count_is_malformed);
    tcase_add_test(tc_a, test_assets_zlib_is_unsupported);
    tcase_add_test(tc_a, test_assets_checksum_nonzero_is_unsupported);
    tcase_add_test(tc_a, test_assets_unknown_flag_is_unsupported);
    suite_add_tcase(s, tc_a);

    TCase *tc_io = tcase_create("io");
    tcase_add_test(tc_io, test_io_missing_file);
    suite_add_tcase(s, tc_io);

    return s;
}

int main(void) {
    Suite   *s  = bun_suite();
    SRunner *sr = srunner_create(s);

    // CK_NORMAL: only failures printed. Use CK_VERBOSE while developing.
    srunner_run_all(sr, CK_NORMAL);
    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
