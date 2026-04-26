//This file controls flow.
//Compiler uses the #include to literally paste the content of bun.h into the main.c file before compiling.
#include "bun.h"

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

    /*

     * The parser expects exactly one argument: the path to a .bun file.

     * If the argument count is wrong, print usage and return a usage error.

     */

    if (argc != 2) {
        print_usage(argv[0]);
        return BUN_ERR_USAGE;
    }

    /*

     * Store the input path and open the file.

     * bun_open() also initializes the parser context and records file size.

     */

    path = argv[1];
    result = bun_open(path, &ctx);
    if (result != BUN_OK) {
        fprintf(stderr, "Error: could not open or read '%s'\n", path);
        return result;
    }


    /*

     * Parse the BUN header.

     * This reads the fixed-size header, decodes its fields, and performs

     * header/layout validation such as magic, version, bounds, and overlap checks.

     */

    result = bun_parse_header(&ctx, &header);




    /*

     * If a full header was successfully read from disk, print it even if

     * validation later found problems. This satisfies the requirement to show

     * as much of an invalid file as can be safely displayed.

     */

    if (ctx.header_loaded) {
        bun_print_header(stdout, &header);
    }


    /*

     * Only continue to asset parsing if the header and file layout are valid.

     * This avoids unsafe seeks or reads based on invalid section offsets.

     */

    if (result == BUN_OK) {
        result = bun_parse_assets(&ctx, &header);
    }


    /*

     * Print any errors collected during parsing.

     * Malformed and unsupported BUN-format errors are printed from the parser

     * context. Non-format errors such as I/O or internal errors get direct messages.

     */

    if (result == BUN_MALFORMED || result == BUN_UNSUPPORTED) {
        bun_print_errors(stderr, &ctx);
    } else if (result == BUN_ERR_IO) {
        fprintf(stderr, "Error: I/O failure while processing '%s'\n", path);
    } else if (result == BUN_ERR_INTERNAL) {
        fprintf(stderr, "Error: internal parser error\n");
    }



     /*

     * Always close the file before exiting.

     * If parsing succeeded but closing failed, return the close error instead.

     */
    
    close_result = bun_close(&ctx);
    if (close_result != BUN_OK && result == BUN_OK) {
        result = close_result;
    }


    /*

     * Return the final parser result as the program exit code.

     */

    return result;
}
