#include <stdarg.h>
#include "bun.h"

static int safe_add_u64(u64 a, u64 b, u64 *out);

static int safe_mul_u64(u64 a, u64 b, u64 *out);

static int check_range_within_file(u64 offset, u64 size, long file_size);

static bun_result_t decompress_rle(const u8 *input, u64 input_size, u8 *output, u64 expected_size);

static void add_error(BunParseContext *ctx, bun_result_t code, const char *fmt, ...) {
    if (code > ctx->worst_error) {
        ctx->worst_error = code;
    }

    if (ctx->error_count >= MAX_ERRORS) {
        return;
    }

    if (ctx->error_count == MAX_ERRORS - 1) {
        snprintf(ctx->errors[ctx->error_count],
                 MAX_ERROR_LEN,
                 "... additional errors not displayed");
        ctx->error_count++;
        return;
    }

    va_list args;
    va_start(args, fmt);
    vsnprintf(ctx->errors[ctx->error_count],
              MAX_ERROR_LEN,
              fmt,
              args);
    va_end(args);
    ctx->error_count++;
}
