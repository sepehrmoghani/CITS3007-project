---
title: "CITS3007 Secure Coding - Phase 1 Report"
subtitle: "`bun_parser` - Group 22"
author:
  - "Rayan Ramaprasad (24227537, github: 24227537)"
  - "Abinandh Radhakrishnan (23689813, github: abxsnxper)"
  - "Campbell Henderson (24278297, github: phyric1)"
  - "Sepehr Moghani Pilehroud (23642415, github: sepehrmoghani)"
date: 30th April 2026
geometry: margin=2.5cm
fontsize: 11pt
toc: true
---

# CITS3007 Secure Coding Phase 1 Report

## 1. Output format and exit codes

### 1.1 Valid BUN files

For a valid `.bun` file, `bun_parser` writes a human-readable representation of the file to standard output and exits with status code `0` (`BUN_OK`). The output is divided into two main parts:

1. A `BUN Header` block.
2. One `Asset Record` block for each asset entry in the asset table.

The header block prints every field from the BUN header:

```text
BUN Header
----------
magic: 0x304E5542
version_major: 1
version_minor: 0
asset_count: 1
asset_table_offset: 60
string_table_offset: 108
string_table_size: 8
data_section_offset: 116
data_section_size: 20
reserved: 0
```

Each asset record block prints every field from the corresponding asset table entry:

```text
Asset Record 0
--------------
name_offset: 0
name_length: 5
data_offset: 0
data_size: 18
uncompressed_size: 0
compression: 0
type: 1
checksum: 0x00000000
flags: 0x00000000
name: "hello"
payload snippet:
  text: "Hello, BUN world!\n"
```

Names and payloads can be long, so the parser does not print unbounded asset contents. Instead, it prints a bounded preview. Asset names are escaped before printing so that unusual bytes cannot affect the terminal. Asset payloads are shown as text when the preview appears to be printable ASCII. Otherwise, the payload is displayed as a short hexadecimal dump. This keeps output useful while preventing very large files from flooding the terminal.

Example command:

```bash
./bun_parser tests/fixtures/valid/02-single-uncompressed.bun
echo $?
```

Expected exit status:

```text
0
```

### 1.2 Invalid or unsupported BUN files

For invalid files, the parser writes as much of the safely parseable file as possible to standard output, then writes a list of detected violations to standard error. Each violation is printed on its own line. This follows the project requirement that invalid files should produce human-readable errors and report as many violations as can be safely detected.

Example malformed file with overlapping sections:

```bash
./bun_parser tests/fixtures/invalid/06-overlapping-sections.bun
echo $?
```

Example standard output:

```text
BUN Header
----------
magic: 0x304E5542
version_major: 1
version_minor: 0
asset_count: 1
asset_table_offset: 60
string_table_offset: 76
string_table_size: 16
data_section_offset: 140
data_section_size: 4
reserved: 0
```

Example standard error:

```text
ERRORS
------
asset entry table overlaps string table
```

Expected exit status:

```text
1
```

Unsupported files are handled similarly, but exit with status code `2` (`BUN_UNSUPPORTED`). Examples of unsupported features in this implementation include zlib compression, non-zero checksum fields, and unknown flag bits.

### 1.3 Exit codes

The BUN specification defines the first three parser outcomes. Our implementation also defines extra application-level error codes for usage and I/O failures.

| Exit code | Name | Meaning |
|---:|---|---|
| `0` | `BUN_OK` | File was parsed and validated successfully. |
| `1` | `BUN_MALFORMED` | File violates the BUN specification. |
| `2` | `BUN_UNSUPPORTED` | File uses a valid but unsupported feature, such as zlib compression or checksum validation. |
| `3` | `BUN_ERR_USAGE` | Incorrect command-line usage, such as the wrong number of arguments. |
| `4` | `BUN_ERR_IO` | File open, read, seek, or close error. |
| `5` | `BUN_ERR_INTERNAL` | Internal parser misuse or unexpected parser state. |
| `6-10` | Reserved | Not currently used. |

For example, running the parser without exactly one input file path prints a usage message to standard error and exits with `BUN_ERR_USAGE`.

---

## 2. Decisions, assumptions, and integer safety

### 2.1 Reading on-disk data

We did not directly cast bytes from the file into C structs using pointer casts. Although the BUN specification gives C-style struct definitions, the on-disk layout has no padding bytes and all multi-byte integers are little-endian. A C compiler may insert padding into in-memory structs, and direct casting from a byte buffer can also create alignment and strict-aliasing problems.

Instead, the parser reads fixed-size byte buffers and decodes fields explicitly. This makes the implementation independent of compiler padding decisions and ensures the parser interprets the file according to the exact BUN on-disk format.

### 2.2 Section ordering and gaps

The canonical BUN layout is:

```text
Header
Asset Entry Table
String Table
Data Section
```

However, the specification says only the header must appear first; the asset table, string table, and data section may appear in any order after the header. Therefore, our parser does not require canonical ordering. It validates the declared offsets and sizes, checks that every section lies within the file, and checks that no two sections overlap.

The specification also allows gaps between sections and says their contents are unspecified. Therefore, our parser does not reject files just because there are unused bytes between sections, instead ignoring gap contents.

### 2.3 Asset table size

The BUN header does not directly store the asset table size. The parser calculates it as:

```text
asset_table_size = asset_count * 48
```

where `48` is the on-disk size of one BUN asset record. Since `asset_count` is read from an untrusted file, this multiplication is checked for overflow before the result is used.

If the multiplication overflows, the parser treats the file as malformed rather than allowing wraparound to produce a smaller size. This is important because otherwise a malicious file could use a huge `asset_count` that wraps to a small asset table size and bypasses bounds checks.

### 2.4 Name validation

Asset names are not null-terminated. Each asset record contains a `name_offset` and `name_length`, both relative to the string table. Our parser treats names as byte ranges, not C strings.

The parser enforces the following rules:

- `name_length` must be non-zero.
- `name_offset + name_length` must fit inside the string table.
- Every byte in the name must be printable ASCII in the range `0x20` to `0x7E`.

We do not require asset names to be unique, because the BUN specification recommends uniqueness but does not require it. We also do not impose extra filename rules, such as banning `/`, `..`, or spaces, because the parser only displays asset metadata and does not extract files to disk.

### 2.5 Data validation

Asset data is validated using `data_offset` and `data_size`, both relative to the data section. The parser checks:

```text
data_offset + data_size <= data_section_size
```

This addition is also overflow-checked. If the sum overflows or exceeds the data section size, the file is malformed.

For uncompressed assets, the parser requires:

```text
compression == 0
uncompressed_size == 0
```

This follows the BUN specification, where `uncompressed_size` is unused for uncompressed assets and must be zero.

For RLE-compressed assets, the parser checks:

- `data_size` must be even, because RLE data consists of `(count, byte)` pairs.
- Each `count` byte must be non-zero.
- The actual decompressed size must equal `uncompressed_size`.

If decompression would exceed the expected output size, the file is treated as malformed. This prevents an attacker from causing unbounded expansion.

### 2.6 Unsupported features

Our parser supports:

- compression `0`: no compression
- compression `1`: RLE

It does not support:

- compression `2`: zlib
- non-zero checksums
- unknown flag bits

When these features are encountered, the parser returns `BUN_UNSUPPORTED` rather than `BUN_MALFORMED`, because these features are valid according to the format but unsupported by this implementation.

The allowed flag bits are:

```c
BUN_FLAG_ENCRYPTED  = 0x1
BUN_FLAG_EXECUTABLE = 0x2
```

Any other flag bit causes `BUN_UNSUPPORTED`.

### 2.7 Integer overflow and wraparound

Integer overflow is a major concern because BUN files contain attacker-controlled offsets and sizes. If unchecked arithmetic wraps around, the parser may incorrectly believe that a section or asset lies inside the file when it actually extends beyond the end of the file.

Our implementation uses overflow-safe helper functions for important arithmetic, including:

- `asset_count * BUN_ASSET_RECORD_SIZE`
- `section_offset + section_size`
- `string_table_offset + name_offset`
- `name_offset + name_length`
- `data_section_offset + data_offset`
- `data_offset + data_size`
- RLE decompressed-size accumulation

For example, a naive check like this is unsafe:

```c
if (offset + size <= file_size) {
    /* assume safe */
}
```

If `offset + size` wraps around, the result may become small and pass the check. Our parser instead checks whether the addition itself succeeded before comparing the result:

```c
u64 end;
if (!bun_u64_add(offset, size, &end)) {
    /* overflow: malformed */
}
if (end > file_size) {
    /* out of bounds: malformed */
}
```

This approach is necessary because all input fields in a `.bun` file are untrusted.

---

## 3. Libraries used

The final `bun_parser` executable has no third-party runtime dependencies. It links only against the standard C library.

| Library/tool | Used for | Runtime dependency? |
|---|---|---|
| C standard library | File I/O, integer types, formatted output, memory operations | Yes, standard environment |
| `libcheck` | Unit tests run through `make test` | No, test-only |
| Python 3 | Generating valid and invalid test fixtures | No, development/test-only |
| `cppcheck` | Static analysis | No, development-only |
| AddressSanitizer / UndefinedBehaviorSanitizer | Dynamic memory and undefined-behaviour testing | No, development-only |
| GCC `-fanalyzer` | Static analysis of C code paths | No, development-only |

If `libcheck` is not installed on the CITS3007 SDE, it can be installed using:

```bash
sudo apt-get install check
```

The submitted parser does not require additional packages to run.

---

## 4. Tools used
This is a comprehensive list of all the tools used in order to identify any issues in our parser and test code. If any issues were found there will be an appropriate link the relevant commits, for reviewers to reproduce the issue and view the changes made to rectify the issue/s.

### 4.1 - cppcheck static analysis

We used the static analyser cppcheck to check for vulnerabilities such as memory leaks and undefined behaviour.

- **How Invoked:**
```bash 
cppcheck --enable=all --std=c11 --inconclusive src
```
Issue - [#10](https://github.com/sepehrmoghani/CITS3007-project/issues/10)

- Findings
  - Variable scope warnings -
      These variables are declared earlier than needed in the files
    - bun_output.c -`decoded` scope can be reduced
    - bun_validate.c -`bytes_read` scope can be reduced

- Unused function warnings -
These functions are defined but never called internally.
    - bun_output.c -`bun_name_is_printable` is never used
    - bun_utils.c -`bun_ranges_disjoint` is never used  
    - bun_utils.c -`decompress_rle` is never used

Screenshot of Issues found:

![](cppcheck.png)

Fix Commits - [commit 405a6ab6893680fba8ec4ea6e5f90f3ea870dd9c](https://github.com/sepehrmoghani/CITS3007-project/pull/9/changes/405a6ab6893680fba8ec4ea6e5f90f3ea870dd9c) and [commit dd135a3205f12276b769915f4e74d43c005f39f7](https://github.com/sepehrmoghani/CITS3007-project/pull/9/changes/dd135a3205f12276b769915f4e74d43c005f39f7)



### 4.2 AddressSanitizer + UndefinedBehaviorSanitizer

We used runtime sanitizers to detect memory safety issues and undefined behaviour during execution. This includes checks for buffer overflows, use-after-free, invalid memory access, integer overflows, and other undefined behaviour cases.

- **How invoked:**
```bash
make asan    # rebuilds bun_parser with -fsanitize=address,undefined
make test    # runs 35 libcheck unit tests + 31 E2E tests under sanitizers
```

The full sanitizer flags applied by the Makefile are:

```
-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1
```

Issue - N/A

- **Findings**

```
Running suite(s): bun
100%: Checks: 35, Failures: 0, Errors: 0
E2E summary: 31 passed, 0 failed
```

  - No memory leaks were detected.
  - No buffer overflows or out-of-bounds accesses occurred.
  - No use-after-free or invalid pointer dereferencing was detected.
  - No undefined behaviour (e.g. signed integer overflow, invalid shifts) was reported.

Fix Commits - N/A

### 4.3 `gcc -fanalyzer`

We used GCC’s built-in static analysis tool to identify potential logic errors such as null dereferences, memory leaks, and incorrect control flow.

- **How invoked:**
```bash
gcc -std=c11 -Wall -fanalyzer -c bun_parse.c
```

Issue - N/A

- **Findings**
  - No null pointer dereferences were detected.
  - No memory leaks were identified.
  - No use of uninitialised variables was reported.
  - Control flow analysis did not reveal any issues such as double frees or invalid paths.

Fix Commits - N/A

### 4.4 `clang-tidy` / `scan-build`

We used Clang’s static analysis tools to perform deeper code inspection and detect potential bugs, dead code, and unsafe patterns.

- **How invoked:**
```bash
sudo apt-get install clang-tools
scan-build make all
```

Issue - N/A

- **Findings**
  - No memory safety issues were reported.
  - No dead stores or unused value issues were flagged.
  - No insecure API usage or undefined behaviour risks were identified.
  - Code passed all checks under Clang’s static analyzer.

Fix Commits - N/A

### 4.5 Fuzzing

We used AFL++ (American Fuzzy Lop) to perform fuzz testing by generating random and malformed inputs to stress test the parser and uncover edge-case bugs.

- **How invoked:**
```bash
afl-clang-fast -std=c11 -O1 -g -Isrc -o bun_parser_fuzz \
    src/main.c src/bun_parse.c src/bun_output.c src/bun_utils.c src/bun_validate.c

afl-fuzz -i tests/fixtures -o findings -- ./bun_parser_fuzz @@
```

Issue - N/A

- **Findings**
  - No crashes occurred during fuzzing.
  - No hangs or infinite loops were detected.
  - No inputs triggered undefined behaviour or sanitizer failures.
  - Parser handled malformed and random inputs robustly.

Fix Commits - N/A

### 4.6 Large-file memory budget test (`make memcheck`)

We verified that the parser uses sub-linear memory on a large input file, confirming that it streams rather than loading the whole file into memory.

- **How invoked:**
```bash
make memcheck   # generates a synthetic 100 MiB fixture and measures Max RSS
```

Issue - N/A

- **Findings**

```
No large fixture found; generating a synthetic 100 MiB file...
Running ./bun_parser on tests/fixtures/large.bun (100 MiB)...
Memory budget: 51200 KiB (50 MiB)
bun_parser exit code: 0
Max RSS             : 6480 KiB
File size           : 104857720 bytes
RSS / file ratio    : 0.0633
PASS: RSS within budget.
```

  - Max RSS was 6480 KiB against a 100 MiB file — about 6% of the input size.
  - The parser comfortably stays under the 50 MiB budget defined in `memcheck_large.sh`.

Fix Commits - N/A

## 5. Security aspects: MMORPG deployment scenario

Trinity management proposed deploying the parser inside the client for *Brutal Orc Battles In Space*, where the client automatically downloads BUN files from Trinity servers and parses them. This scenario significantly increases the security risk because the parser would process data received over a network and potentially data influenced by players.

### 5.1 Threat model

In this deployment, BUN files should be treated as untrusted input even if they appear to come from Trinity servers. Possible attackers include:

- A network attacker who tampers with downloads if transport security is misconfigured.
- A malicious player who uploads crafted player-created content.
- An attacker who compromises Trinity's content delivery system.
- A malicious modder distributing altered BUN files.
- A bug in Trinity's asset-generation pipeline that accidentally produces malformed BUN files.

Because the parser is written in C, malformed binary input could potentially trigger memory safety errors if validation is incomplete.

### 5.2 Main security risks

#### 5.2.1 Memory corruption

A crafted file could attempt to exploit:

- integer overflow in offset and size arithmetic
- out-of-bounds reads
- buffer overflows in name or payload previews
- invalid seeks
- decompression logic errors
- excessive `asset_count` values

If the game client parses files automatically, a successful memory corruption exploit could lead to client crashes or even arbitrary code execution.

#### 5.2.2 Denial of service

An attacker could create files designed to consume excessive CPU, memory, or disk I/O. Examples include:

- huge `asset_count` values
- extremely large section sizes
- RLE data with very large claimed `uncompressed_size`
- many small assets causing repeated seeks
- deeply malformed files that generate many errors

Even if memory corruption is avoided, denial of service could crash or freeze the game client.

#### 5.2.3 Decompression abuse

RLE compression can expand small input into much larger output. If the parser or game client fully decompresses assets into memory without limits, a malicious file could cause memory exhaustion. The risk would be greater if zlib support were added later, because zlib allows much stronger compression ratios and more complex decompression behaviour.

#### 5.2.4 Executable or script content

The BUN format includes an executable flag. If BUN files are used for player-created content, executable or script-like assets could become dangerous if later parts of the game engine load or run them without sandboxing.

The parser itself should not execute asset data. However, the surrounding game client must ensure that executable content is either forbidden, signed, sandboxed, or reviewed before use.

#### 5.2.5 Trust and authenticity

If the client automatically downloads BUN files, it needs a way to verify that the file is authentic and has not been tampered with. Transport security such as HTTPS is useful but not enough by itself if the server, CDN, or update pipeline is compromised.

### 5.3 Recommended parser changes

For this deployment, we recommend the following parser-level changes:

1. **Add configurable resource limits.**  
   The client should impose maximum values for:
   - file size
   - asset count
   - string table size
   - data section size
   - per-asset compressed size
   - per-asset uncompressed size
   - total decompressed bytes

2. **Harden decompression.**  
   RLE decompression should be streaming or bounded. It should stop immediately if the output would exceed the declared `uncompressed_size` or configured maximum output size.

3. **Make unsupported features fail closed.**  
   Unknown compression methods, unknown flags, non-zero checksums without checksum support, and future format versions should be rejected or quarantined rather than partially accepted.

4. **Improve error reporting without exposing internals.**  
   Developer builds can print detailed parse errors. Production clients should log enough information for debugging but avoid exposing unnecessary internal paths or memory details to users.

5. **Fuzz the parser.**  
   Before deployment, the parser should be fuzz-tested with tools such as libFuzzer or AFL++. Binary parsers are good fuzzing targets because many bugs only appear with unusual combinations of offsets, sizes, and truncated input.

### 5.4 Recommended BUN format changes

We also recommend changes to the BUN format or deployment rules:

1. **Mandatory file-level signature.**  
   Add a digital signature over the full BUN file or over a manifest. The client should verify the signature before parsing or loading assets. This helps ensure that only content produced or approved by Trinity is accepted.

2. **Mandatory file-level hash.**  
   Include a strong cryptographic hash such as SHA-256 for the whole file or for each asset. CRC-32 is useful for accidental corruption but is not designed to prevent malicious tampering.

3. **Explicit format versioning policy.**  
   The format should specify how future versions are handled. Clients should reject unsupported major versions and only accept minor versions when explicitly compatible.

4. **Canonical layout for new files.**  
   Although legacy parsers must support non-canonical files, new game-distributed files should use canonical layout. This makes validation easier and reduces edge cases.

5. **Separate trusted official content from player content.**  
   Player-created BUN files should be subject to stricter limits and should not be allowed to contain executable or script assets unless those scripts run in a sandbox.

6. **Consider a manifest section.**  
   A manifest could list asset names, types, sizes, hashes, and permissions in one place. This would allow the client to validate intended contents before loading expensive data sections.

## 6. Coding standards and conventions

Our group adopted the following coding standards and conventions.

### 6.1 C standard and portability

The parser is written in C11 and is intended to compile on the CITS3007 standard development environment using GCC. Fixed-width integer types from `<stdint.h>` are used for file-format fields so that the code matches the BUN specification.

### 6.2 Naming conventions

We used consistent naming to distinguish project code from standard library functions:

- public parser functions use the prefix `bun_`
- constants use uppercase names, for example `BUN_MAGIC`
- structs and typedefs use clear BUN-related names
- local variables use lower_snake_case

Example:

```c
bool bun_u64_add(u64 a, u64 b, u64 *out);
```

### 6.3 File organisation

The codebase is split into small modules by responsibility:

| File | Responsibility |
|---|---|
| `main.c` | Command-line argument handling and top-level program flow |
| `bun_parse.c` | Reading and decoding BUN headers and asset records |
| `bun_validate.c` | Validation of header, sections, names, asset data, and compression rules |
| `bun_output.c` | Human-readable output formatting |
| `bun_utils.c` | Shared helpers such as checked arithmetic and range checks |
| `bun.h` | Common types, constants, and declarations |

This separation made the parser easier to review and helped the group divide work between members.

### 6.4 Memory management

We followed these memory-management rules:

- Prefer stack buffers for fixed-size records.
- Avoid reading the whole file into memory.
- Allocate only when necessary.
- Check every allocation before use.
- Free every allocation on all paths.
- Do not store pointers to temporary buffers after the buffer goes out of scope.
- Treat file data as byte arrays, not null-terminated strings.

### 6.5 Pointer and arithmetic rules

Because this is a binary parser, pointer and arithmetic mistakes are security-sensitive. We followed the following rules:

- Do not use unchecked pointer arithmetic for file offsets.
- Do not cast arbitrary file bytes directly to structs.
- Decode little-endian values explicitly.
- Use checked arithmetic for all offset and size calculations.
- Validate a section before reading from it.
- Validate an asset's name and data range before reading that asset.
- Use bounded printing for names and payloads.

### 6.6 Error handling

The parser attempts to report as many violations as can be safely detected. However, if a fault prevents safe parsing, such as a truncated header or an asset table outside the file, the parser stops before reading dependent structures.

Errors are reported on standard error, one violation per line. Human-readable file content is printed on standard output.

---

## 7. Challenges

### 7.1 Understanding binary layout

One challenge was understanding the difference between the C-style structures in the specification and the actual bytes stored on disk. The specification uses C structs for explanation, but the file format requires exact little-endian field ordering with no padding. We addressed this by writing explicit decode functions and avoiding direct struct casts.

### 7.2 Offset arithmetic and overflow

A major challenge was validating offsets and sizes safely. At first, we checked ranges using expressions such as `offset + size <= file_size`. However, this is unsafe when `offset` and `size` are modified by an attacker as unsigned arithmetic can wrap around.

We addressed this by adding checked arithmetic helpers and using them consistently before comparing calculated end offsets.

### 7.3 Supporting non-canonical layout

The BUN specification allows non-canonical section ordering for legacy compatibility. This made validation more complex because the parser could not assume that the asset table is followed by the string table and then the data section.

We addressed this by representing each section as an `(offset, size)` range and checking all section pairs for overlap, regardless of order.

### 7.4 Handling invalid files safely

Invalid files may contain multiple faults, but some faults prevent safe further parsing. For example, if the asset table lies outside the file, the parser cannot safely read asset records to validate their names or data ranges.

We addressed this by separating validation into stages. The parser first validates the header and section ranges. Only if those checks allow safe access does it validate each asset.

### 7.5 RLE decompression validation

RLE compression introduced extra validation rules. The parser must reject odd compressed sizes, zero-count pairs, and decompressed output that does not match `uncompressed_size`.

We addressed this by validating compressed data before trusting it and by tracking the decompressed size with overflow checks.

### 7.6 Group coordination

The project required several related tasks: parsing, validation, output formatting, compression checks, testing, and report writing. A challenge was making sure independently written code used the same return codes, error format, and assumptions.

We addressed this by dividing responsibilities clearly and using shared constants and helper functions. Pull requests and issue tracking were used to coordinate changes.

### 7.7 Evidence for tools

The report requirement for tool evidence was challenging because it required proper evidence of issues being found and solved, but while developing, we didn't use the tools until the program was in a working state, by which point there was not many major issues to find.

To address this, we ran a large array of different tools to find as many issues as possible, and recorded the results.

---

## 8. GenAI usage statement

Generative AI was used to assist with report drafting as well as in improving code stucture, validation and safety of functions in all code files. All final content was reviewed and approved by group members using Github Pull Requests. 

---
