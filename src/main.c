// Group 22:
// Name:                     Student Num:    Github Username:
// Rayan Ramaprasad          24227537        24227537
// Abinandh Radhakrishnan    23689813        abxsnxper
// Campbell Henderson        24278297        phyric1
// Sepehr Moghani Pilehroud  23642415        sepehrmoghani
#include "bun.h"
#include "bun_output.h"
#include <stdio.h>


/*
 * -----------
 * Prints the correct command-line usage for the parser.
 *
 * This is called when the user provides the wrong number of arguments.
 *
 * Expected usage:
 *   ./bun_parser <file.bun>
 *
 * The message is printed to stderr because incorrect usage is an error.
 */
static void print_usage(const char *progname) {
    fprintf(stderr, "Usage: %s <file.bun>\n", progname);
}


/*
 * main
 * ----
 * Entry point for the bun_parser executable.
 *
 * This function controls the overall program flow:
 *
 *   1. Checks command-line arguments.
 *   2. Opens the requested .bun file.
 *   3. Parses and validates the BUN header.
 *   4. Prints the header if it was safely loaded.
 *   5. Parses asset records if the header was valid.
 *   6. Prints any malformed/unsupported error messages.
 *   7. Closes the file.
 *   8. Returns the correct exit code.
 *
 * Exit codes:
 *   BUN_OK            - file parsed successfully
 *   BUN_MALFORMED     - file violates the BUN specification
 *   BUN_UNSUPPORTED   - file uses unsupported BUN features
 *   BUN_ERR_USAGE     - incorrect command-line usage
 *   BUN_ERR_IO        - file open/read/seek/close error
 *   BUN_ERR_INTERNAL  - internal parser misuse or unexpected state
 */
int main(int argc, char *argv[]) {
    const char *path;
    BunParseContext ctx;
    BunHeader header;
    bun_result_t result;
    bun_result_t close_result;

    if (argc != 2) {
        print_usage(argv[0]);
        return BUN_ERR_USAGE;
    }

    path = argv[1];
    result = bun_open(path, &ctx);
    if (result != BUN_OK) {
        fprintf(stderr, "Error: could not open or read '%s'\n", path);
        return (int)result;
    }

    result = bun_parse_header(&ctx, &header);

    if (ctx.header_loaded) {
        bun_print_header(stdout, &header);
    }

    if (result == BUN_OK) {
        result = bun_parse_assets(&ctx, &header);
    }

    if (result == BUN_MALFORMED || result == BUN_UNSUPPORTED) {
        bun_print_errors(stderr, &ctx);
    } else if (result == BUN_ERR_IO) {
        fprintf(stderr, "----------\nError: I/O failure while processing '%s'\n", path);
    } else if (result == BUN_ERR_INTERNAL) {
        fprintf(stderr, "----------\nError: internal parser error\n");
    }

    close_result = bun_close(&ctx);
    if (close_result != BUN_OK && result == BUN_OK) {
        result = close_result;
    }

    return (int)result;
}
