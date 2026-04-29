# CITS3007 Phase 1 - Group 22 - `bun_parser`

A C11 parser for the BUN (Binary UNified assets) container format, written
for CITS3007 Secure Coding (Semester 1, 2026).

Repository: <https://github.com/sepehrmoghani/CITS3007-project>

## Group 22

| Role (primary)                | Name | Student # | GitHub |
|-------------------------------|------|-----------|--------|
| Member 1 - File structure     | _TBD_ | _TBD_   | _TBD_  |
| Member 2 - Asset parsing      | _TBD_ | _TBD_   | _TBD_  |
| Member 3 - Compression/sec.   | _TBD_ | _TBD_   | _TBD_  |
| Member 4 - Testing + report   | Sepehr Moghani | 23642415 | `sepehrmoghani` |

(Replace the `_TBD_` cells before submission.)

## Building

Requires the CITS3007 SDE (Ubuntu 22 with `gcc`, `make`, `libcheck`):

```bash
sudo apt-get install check   # one-off
make all                     # produces ./bun_parser
```

## Usage

```bash
./bun_parser path/to/file.bun
```

Exit codes (see the report for the full list):

| Code | Meaning                                     |
|------|---------------------------------------------|
| 0    | `BUN_OK` - file parsed successfully         |
| 1    | `BUN_MALFORMED` - spec violation found      |
| 2    | `BUN_UNSUPPORTED` - valid but uses zlib, CRC, or unknown flag |
| 3-10 | I/O and argument errors (see report)        |

## Testing

```bash
make fixtures        # generate tests/fixtures/{valid,invalid}/*.bun
make test            # libcheck unit tests + end-to-end exit-code tests
make asan            # rebuild with AddressSanitizer / UBSan
make memcheck        # large-file RSS budget test
```

See [HACKING.md](HACKING.md) for coding standards and workflow.
