# HACKING.md - `bun_parser` contributor guide

This document is the single source of truth for coding standards, build
and test workflow, and repository conventions for Group 22's CITS3007
Phase 1 project. If anything here conflicts with the brief or the spec,
the brief/spec wins - please open a PR to fix this file.

## Repository layout

```
.
├── bun.h                       # Public API, on-disk format constants
├── bun_parse.c                 # Parser + validator (no I/O to stdout/stderr)
├── bun_output.c / .h           # Output helpers (escaped print, hex dump),
│                               # overflow-safe u64 arithmetic, range checks
├── main.c                      # CLI entry point, argument parsing, stdout/stderr
├── Makefile                    # all / test / asan / fixtures / memcheck / clean
├── bunfile_generator.py        # Supplied reference fixture generator (do not edit)
├── submission_sanity_checker.py# Supplied submission checker (do not edit)
├── setup.sh                    # Supplied SDE setup helper (do not edit)
├── tests/
│   ├── test_bun.c              # libcheck unit tests (5 TCases)
│   ├── make_fixtures.py        # Generates tests/fixtures/{valid,invalid}/*.bun
│   ├── make_large_fixture.py   # Streaming generator for the RSS budget test
│   ├── run_e2e.sh              # Exit-code test driver using expectations.tsv
│   ├── memcheck_large.sh       # RSS budget assertion (50 MiB default)
│   └── fixtures/               # Machine-generated; re-run `make fixtures`
│       ├── valid/              # Files that must exit 0 (BUN_OK)
│       ├── invalid/            # Files that must exit 1 (malformed) or 2 (unsupported)
│       └── expectations.tsv    # <relpath>\t<expected_exit>
├── report/
│   └── report.md               # Pandoc-ready report skeleton -> report.pdf
├── README.md                   # Short user-facing summary
└── HACKING.md                  # This file
```

## Build and test

Target platform is the CITS3007 SDE (Ubuntu 22, `gcc`, `make`, `libcheck`).

```bash
sudo apt-get install check    # once, on the SDE
make all                      # builds ./bun_parser
make test                     # libcheck unit tests + end-to-end exit-code tests
make asan                     # rebuild with AddressSanitizer + UBSan and re-run
make fixtures                 # (re)generate tests/fixtures/*
make memcheck                 # RSS budget test against a large (>100 MiB) file
make sanity                   # runs submission_sanity_checker.py against a .zip
make clean                    # remove build artifacts and generated fixtures
make help                     # lists all targets
```

Warning set is non-negotiable:

```
-std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wconversion
-Wstrict-prototypes -Wformat=2 -Wwrite-strings -Wpointer-arith
-Wcast-align -Wno-unused-parameter
```

The sanitizer build adds `-fsanitize=address,undefined -fno-omit-frame-pointer
-g -O1`. **All PRs must compile cleanly under both the strict build and the
sanitizer build**, and `make test` must pass on both.

## Git workflow

- `main` is protected. Do not push directly.
- Work on a feature branch per member / per feature:
  `m1-header-parse`, `m2-assets`, `m3-compression`, `member4-testing-report`.
- Open a PR against `main`. At least one other group member must review.
- Squash-merge when green. Keep the squashed commit message informative.
- Rebase your feature branch on `main` before opening the PR; don't merge
  `main` into feature branches.

### Commit messages

Prefix commits with the area of the tree they touch:

```
parse:   validate asset table bounds (#12)
output:  add hex dump fallback for non-printable payloads
tests:   add fixture 11-empty-name (BUN_MALFORMED)
report:  fill section 4.1 (ASan findings) with commit refs
build:   bump -Wformat to =2, pin to C11
```

Every commit that fixes a sanitizer / analyzer finding should reference the
issue number in the commit message, because the report's "Tools used"
section needs concrete before/after commit pairs.

## Coding style

- **Language:** C11 only. No GNU extensions except documented uses of
  `__builtin_add_overflow` / `__builtin_mul_overflow`, which are guarded
  by `__has_builtin` with a portable fallback.
- **Indent:** 2 spaces, no tabs.
- **Braces:** K&R (`if (x) {`, closing brace on its own line).
- **Line length:** 100 columns. Break long function signatures one
  parameter per line.
- **Naming:**
  - Functions: `snake_case`, public API prefixed `bun_`
    (e.g. `bun_parse_header`, `bun_print_escaped`).
  - Types: `UpperCamelCase` (`BunHeader`, `BunParseContext`).
  - Constants / enums: `SCREAMING_SNAKE_CASE` with `BUN_` prefix
    (`BUN_HEADER_SIZE`, `BUN_OK`).
  - Locals: short `snake_case`.
- **Headers:** `#pragma once` is banned; use include guards
  `BUN_<NAME>_H` to be conservative.
- **Includes:** system headers first, then project headers; alphabetised
  within each group.
- **`static`:** every function and every file-scope variable that is
  not part of a public API must be `static`.
- **`const`:** apply liberally to pointer parameters that are not modified.

## Memory and integer safety

- **No whole-file slurp.** `bun_parser` must handle files larger than
  available RAM (the brief's 638 MiB sample is the reference). Read
  the 60-byte header into a fixed stack buffer, the 48-byte asset
  records one at a time, and stream payload through a bounded output
  buffer. The RSS budget is **50 MiB** regardless of input size;
  `make memcheck` enforces this.
- **No heap allocation proportional to `asset_count`, `name_length`,
  `data_size`, or `uncompressed_size`.** All of these come from the
  attacker and may be huge.
- **All arithmetic on attacker-controlled u32/u64 fields goes through
  `bun_u64_add` / `bun_u64_mul`** (declared in `bun_output.h`). Never
  write `a + b` where `a` and `b` came from the file. Widen u32 values
  to u64 *before* adding, as the spec requires.
- **All byte-range checks go through `bun_ranges_disjoint`** for
  overlap, and through the u64 helpers for upper-bound checks
  (e.g. `base + size <= file_size`).
- On any overflow or out-of-bounds result, return `BUN_MALFORMED` and
  emit a violation line; do not crash, do not read past the buffer.

## Error reporting

Violations are written to `stderr`, one per line, in this exact format:

```
bun_parser: <path>: <byte-offset>: <message>
```

- `<path>` is the path as given on the command line, not a canonicalised
  form.
- `<byte-offset>` is the decimal offset in the file at which the
  violation was detected (not the offset *of* the violation, which
  may be outside the file).
- `<message>` is a short lowercase sentence without a trailing period.

Parser functions return a `BunResult` code and record violations into the
`BunParseContext`. They do not call `fprintf` directly. `main.c` drains
the context at the end and prints.

## Output format (stdout)

The human-readable summary has two blocks:

1. **Header block** - every header field, one per line,
   `key: value` with `value` rendered safely (escaped if it came from
   disk).
2. **Asset records block** - one block per record, indented, with
   `name`, offsets, sizes, flags, compression scheme, and a
   **truncated** payload snippet.

Payload snippets are rendered via `bun_print_payload_snippet`, which
picks text (escaped) vs hex dump based on the first 64 bytes. `name`
values go through `bun_print_escaped` with a cap of `BUN_OUTPUT_SNIPPET_LEN`
bytes.

`bun_parse.c` is **not** allowed to write to stdout or stderr; only
`main.c` does that. This keeps the unit tests independent of output
layout.

## Untrusted-input rules (the 30-second summary)

1. Every byte on disk is adversarial.
2. Check for overflow before using a value in a size calculation.
3. Check bounds before reading.
4. Check alignment (4-byte) before accepting a section offset/size.
5. Check overlap between the three non-header sections.
6. Check printability before rendering a name.
7. Cap output length (snippet for payloads, `BUN_OUTPUT_SNIPPET_LEN`
   for names) before writing to stdout.
8. When in doubt, `BUN_MALFORMED`.

## Tests

`tests/test_bun.c` is a libcheck suite with these TCases:

| TCase               | What it covers                                           |
|---------------------|----------------------------------------------------------|
| `output-helpers`    | `bun_is_printable_ascii`, `bun_name_is_printable`,       |
|                     | `bun_print_escaped` truncation and escaping              |
| `overflow-helpers`  | `bun_u64_add`/`mul` overflow, `bun_ranges_disjoint`      |
| `header`            | Valid + malformed + unsupported header fixtures          |
| `assets`            | Asset-table bounds, overlap, name printability,          |
|                     | RLE malformed, zlib/checksum/flag -> BUN_UNSUPPORTED     |
| `io`                | Missing file, unreadable file                            |

End-to-end tests live in `tests/run_e2e.sh`; they drive the built
binary against every file in `tests/fixtures/` and compare the exit
code to `tests/fixtures/expectations.tsv`.

Fixtures are machine-generated by `tests/make_fixtures.py` which calls
into the supplied `bunfile_generator.py`. Do not hand-edit fixtures;
regenerate.

## Definition of done (per PR)

- [ ] `make all` compiles with zero warnings under the strict flag set.
- [ ] `make asan` compiles and `make test` passes under ASan+UBSan.
- [ ] `make test` passes (libcheck + e2e).
- [ ] If parsing logic changed, `make memcheck` passes on a >100 MiB
      fixture.
- [ ] New code paths have test coverage; new spec-violation handling
      has a fixture + an `expectations.tsv` entry.
- [ ] Every commit that fixes a sanitizer / analyzer finding is
      referenced in `report/report.md` section 4 before merge.
- [ ] PR description links to the relevant spec section(s).

## Pointers to the brief and spec

- `docs/brief.md` - task description, deliverables, grading rubric.
- `docs/spec.md`  - BUN format specification. The section numbers
  referenced throughout the code comments (e.g. "per spec 5.1 note 1")
  point at this file.

When the brief and the code disagree, the brief wins, and this repo
is wrong. Open an issue.
