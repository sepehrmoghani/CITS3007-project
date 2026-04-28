# BUN Parser Completion Report

## Summary of completed work

This update integrates the remaining parser, validation, output, testing, and documentation work into the existing CITS3007 BUN parser project. The code still follows the existing layout: `main.c` handles CLI flow, `bun_parse.c` handles binary parsing and safe output, `bun_validate.c` handles specification checks, `bun_utils.c` contains endian/integer helpers, and `bun_output.c` contains human-readable output helpers.

## Member 1 - Core file parser

Added and verified the main parser flow:

- Opens the input file in binary mode and determines file size.
- Reads the fixed 60-byte BUN header without relying on struct padding.
- Decodes all multi-byte fields manually as little-endian.
- Validates section offsets, sizes, bounds, and overlap before asset parsing.
- Uses documented exit codes: `0` OK, `1` malformed, `2` unsupported, `3` usage error, `4` I/O error, and `5` internal error.

## Member 2 - Asset parsing and decompression

Completed asset handling:

- Reads each 48-byte asset record from the asset table.
- Decodes all asset fields manually from little-endian bytes.
- Prints all asset record fields.
- Reads and prints a safe escaped asset-name snippet from the string table.
- Reads and prints a bounded payload snippet from the data section.
- Supports `compression = 0` for raw payload display.
- Supports `compression = 1` by validating RLE structure and printing a decoded prefix.
- Returns `BUN_UNSUPPORTED` for zlib, unknown compression values, non-zero checksums, and unknown flags.

## Member 3 - Validation and security checks

Added/confirmed safe validation checks:

- Magic number validation.
- Version validation.
- 4-byte alignment checks for section offsets and sizes.
- File-bounds checks for all declared sections.
- Non-overlap checks for header, asset table, string table, and data section.
- Asset name range validation.
- Asset data range validation.
- Empty-name detection.
- Printable ASCII validation for names.
- RLE odd-size detection.
- RLE zero-count detection.
- RLE expanded-size mismatch detection.
- Integer-overflow-safe arithmetic through `bun_u64_add` and `bun_u64_mul`.
- Bounded snippet buffers so large files are not loaded fully into memory.

## Member 4 - Testing and report work

The project already contained a good fixture and test structure. This update preserved it and verified the end-to-end tests.

Command run:

```sh
make clean
make all
./tests/run_e2e.sh
```

Result:

```text
E2E summary: 31 passed, 0 failed
```

The full `make test` target depends on Python fixture generation and libcheck. The end-to-end test suite was run after generating fixtures and confirmed all valid and invalid fixture exit codes.

## Important implementation decisions

- The parser does not use C struct reads for on-disk data, because the BUN specification says the disk layout has no padding and all multi-byte integers are little-endian.
- The parser validates section layout before using offsets from the file.
- Asset names and payloads are printed only as short snippets to avoid huge memory usage.
- For RLE payload output, the parser decodes only a bounded prefix for display, while validation still checks the full compressed stream.
- Unsupported features are deliberately reported rather than silently ignored.

## Files changed most significantly

- `src/bun_parse.c`: completed safe asset parsing, asset-name output, payload-snippet output, RLE prefix decoding, and safer per-record flow.
- `src/bun_validate.c`: added empty-name detection at the asset-record validation level and confirmed malformed/unsupported checks.
- `tests/make_fixtures.py`: kept the generated fixture setup and ensured fixture scripts remain executable in the packaged project.
- `report/changes_report.md`: this short implementation report.

## Security discussion

A BUN file is untrusted binary input. In a game client that automatically downloads BUN files, risks include buffer overflows, integer wraparound, oversized memory allocation, malicious compressed data, path-like malicious names, parser crashes, and denial-of-service through huge files or huge asset counts. This implementation reduces those risks by using bounded reads, manual endian decoding, integer-overflow checks, range checks before seeking, safe printable output, and explicit unsupported-feature handling.

Recommended future improvements:

- Add cryptographic signatures for downloaded BUN files.
- Add a maximum asset count and maximum displayed/decompressed asset size policy.
- Add CRC-32 validation if the checksum field is to be supported.
- Fuzz test the parser with AFL++ or libFuzzer.
- Run CI with AddressSanitizer and UndefinedBehaviorSanitizer enabled.

## Tools and libraries

- C11 standard library only for the parser executable.
- GCC with strict warning flags through the Makefile.
- Shell end-to-end tests through `tests/run_e2e.sh`.
- Python fixture generator supplied with the project.

