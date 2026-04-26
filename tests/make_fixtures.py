#!/usr/bin/env python3
"""
make_fixtures.py - Generate the full set of valid and malformed .bun test
fixtures used by the Group 22 test suite.

Output layout:
    tests/fixtures/valid/*.bun
    tests/fixtures/invalid/*.bun

Each invalid file exercises exactly one spec violation; the filename encodes
the defect (matches the naming convention used by the sample files supplied
on Moodle).

Re-uses the low-level writers from ../bunfile_generator.py so the on-disk
format stays in sync with the authoritative reference writer.

Author: Group 22, Member 4.
"""

from __future__ import annotations

import io
import os
import struct
import sys
from contextlib import redirect_stdout
from pathlib import Path

# Make the in-tree generator importable.
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import bunfile_generator as gen  # noqa: E402

FIX_ROOT    = HERE / "fixtures"
VALID_DIR   = FIX_ROOT / "valid"
INVALID_DIR = FIX_ROOT / "invalid"

HEADER_SIZE = gen.HEADER_SIZE   # 60
RECORD_SIZE = gen.RECORD_SIZE   # 48

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def _align4(n: int) -> int:
    return (n + 3) & ~3

def _write(path: Path, build):
    """Run `build(file_object)` while silencing the noisy prints in
    bunfile_generator.py. Writes to path.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    buf = io.BytesIO()
    with redirect_stdout(io.StringIO()):
        build(buf)
    path.write_bytes(buf.getvalue())
    print(f"  wrote {path.relative_to(ROOT)} ({path.stat().st_size} bytes)")

def _simple_valid(
    f,
    *,
    assets,              # list of (name: bytes, payload: bytes, compression, uncompressed_size, asset_type, checksum, flags)
    magic=gen.BUN_MAGIC,
    version_major=1,
    version_minor=0,
    reserved=0,
    canonical=True,
):
    """Build a canonical (header, asset-table, string-table, data) file with
    one record per asset. All offsets/sizes are 4-aligned. Defaults to
    writing a structurally valid file; pass magic/version/reserved overrides
    to break specific fields.
    """
    asset_count = len(assets)

    # Compute offsets.
    asset_table_offset  = _align4(HEADER_SIZE)
    string_table_offset = _align4(asset_table_offset + asset_count * RECORD_SIZE)
    # Pack names back-to-back.
    names_concat = b"".join(a[0] for a in assets)
    string_table_size = _align4(len(names_concat)) if names_concat else 0
    data_section_offset = _align4(string_table_offset + string_table_size)
    # Pack payloads back-to-back.
    payloads_concat = b"".join(a[1] for a in assets)
    data_section_size = _align4(len(payloads_concat)) if payloads_concat else 0

    gen.write_header(
        f,
        magic               = magic,
        version_major       = version_major,
        version_minor       = version_minor,
        asset_count         = asset_count,
        asset_table_offset  = asset_table_offset,
        string_table_offset = string_table_offset,
        string_table_size   = string_table_size,
        data_section_offset = data_section_offset,
        data_section_size   = data_section_size,
        reserved            = reserved,
    )

    # Pad to asset table.
    gen.write_padding(f, asset_table_offset - HEADER_SIZE, "hdr->at")

    # Emit records.
    name_cursor = 0
    data_cursor = 0
    for (name, payload, compression, uncomp_size, asset_type, checksum, flags) in assets:
        gen.write_asset_record(
            f,
            name_offset       = name_cursor,
            name_length       = len(name),
            data_offset       = data_cursor,
            data_size         = len(payload),
            uncompressed_size = uncomp_size,
            compression       = compression,
            asset_type        = asset_type,
            checksum          = checksum,
            flags             = flags,
        )
        name_cursor += len(name)
        data_cursor += len(payload)

    # Pad to string table.
    here = asset_table_offset + asset_count * RECORD_SIZE
    gen.write_padding(f, string_table_offset - here, "at->st")

    # Write string table.
    f.write(names_concat)
    gen.write_padding(f, string_table_size - len(names_concat), "st pad")

    # Pad to data section.
    here = string_table_offset + string_table_size
    gen.write_padding(f, data_section_offset - here, "st->ds")

    # Write data section.
    f.write(payloads_concat)
    gen.write_padding(f, data_section_size - len(payloads_concat), "ds pad")


def _rle_encode(raw: bytes) -> bytes:
    """Simple RLE: emit (count, byte) pairs, count capped at 255."""
    out = bytearray()
    i = 0
    while i < len(raw):
        b = raw[i]
        run = 1
        while run < 255 and i + run < len(raw) and raw[i + run] == b:
            run += 1
        out.append(run)
        out.append(b)
        i += run
    return bytes(out)


# A single short RLE payload we can reuse: 8 copies of 'A'.
RLE_RAW_A = b"A" * 8
RLE_ENCODED_A = _rle_encode(RLE_RAW_A)  # two bytes: 08 41


# -----------------------------------------------------------------------------
# Valid fixtures
# -----------------------------------------------------------------------------

def valid_01_empty(f):
    """Valid file with zero assets."""
    _simple_valid(f, assets=[])

def valid_02_single_uncompressed(f):
    """One asset, no compression. The textbook example."""
    _simple_valid(f, assets=[
        (b"hello", b"Hello, BUN world!\n", 0, 0, 1, 0, 0),
    ])

def valid_03_multiple_assets(f):
    """Three assets of different types and sizes."""
    _simple_valid(f, assets=[
        (b"texture/grass.rgb", b"\x00\x80\x00" * 16, 0, 0, 1, 0, 0),
        (b"audio/click.raw",   b"\x10\x20\x30\x40" * 8, 0, 0, 2, 0, 0),
        (b"script/init.lua",   b"print('hi')\n", 0, 0, 3, 0, 0),
    ])

def valid_04_rle_compressed(f):
    """One asset compressed with RLE (compression=1)."""
    _simple_valid(f, assets=[
        (b"rle-blob", RLE_ENCODED_A, 1, len(RLE_RAW_A), 1, 0, 0),
    ])

def valid_05_flag_executable(f):
    """Asset with the BUN_FLAG_EXECUTABLE bit set."""
    _simple_valid(f, assets=[
        (b"bin/launcher", b"MZ\x90\x00", 0, 0, 1, 0, 0x2),
    ])

def valid_06_flag_encrypted(f):
    """Asset with the BUN_FLAG_ENCRYPTED bit set."""
    _simple_valid(f, assets=[
        (b"vault/secret", b"\x00\x01\x02\x03", 0, 0, 1, 0, 0x1),
    ])

def valid_07_max_printable_name(f):
    """Asset whose name covers the full printable-ASCII range."""
    # 0x20-0x7E inclusive = 95 chars
    name = bytes(range(0x20, 0x7F))
    _simple_valid(f, assets=[
        (name, b"payload", 0, 0, 0, 0, 0),
    ])

def valid_08_reserved_nonzero(f):
    """Reserved field set to a non-zero value. The spec says reserved is
    ignored by current parsers - so this MUST still parse as valid."""
    _simple_valid(f, assets=[
        (b"r", b"x", 0, 0, 0, 0, 0),
    ], reserved=0xDEADBEEFCAFEBABE)

def valid_09_empty_payload(f):
    """Asset with a zero-byte payload - allowed by the spec."""
    _simple_valid(f, assets=[
        (b"empty", b"", 0, 0, 0, 0, 0),
    ])

def valid_10_non_canonical_section_order(f):
    """Permitted by the spec (section 1): header first, then any order for
    the other sections. Here we place data section *before* string table."""
    # Hand-built so we can reorder.
    name    = b"swap"
    payload = b"DATA!"
    asset_count = 1

    header_off         = 0
    asset_table_offset = _align4(HEADER_SIZE)
    data_section_offset = _align4(asset_table_offset + asset_count * RECORD_SIZE)
    data_section_size   = _align4(len(payload))
    string_table_offset = _align4(data_section_offset + data_section_size)
    string_table_size   = _align4(len(name))

    gen.write_header(
        f,
        magic=gen.BUN_MAGIC, version_major=1, version_minor=0,
        asset_count=asset_count,
        asset_table_offset=asset_table_offset,
        string_table_offset=string_table_offset,
        string_table_size=string_table_size,
        data_section_offset=data_section_offset,
        data_section_size=data_section_size,
        reserved=0,
    )
    gen.write_padding(f, asset_table_offset - HEADER_SIZE, "pad")
    gen.write_asset_record(
        f, name_offset=0, name_length=len(name),
        data_offset=0, data_size=len(payload),
        uncompressed_size=0, compression=0, asset_type=0, checksum=0, flags=0,
    )
    # Pad to data section.
    here = asset_table_offset + asset_count * RECORD_SIZE
    gen.write_padding(f, data_section_offset - here, "pad")
    f.write(payload)
    gen.write_padding(f, data_section_size - len(payload), "pad")
    # Pad to string table.
    here = data_section_offset + data_section_size
    gen.write_padding(f, string_table_offset - here, "pad")
    f.write(name)
    gen.write_padding(f, string_table_size - len(name), "pad")


# -----------------------------------------------------------------------------
# Invalid fixtures
# -----------------------------------------------------------------------------

# Malformed (BUN_MALFORMED = 1)

def invalid_01_bad_magic(f):
    """Magic number is wrong."""
    _simple_valid(f, assets=[(b"x", b"y", 0, 0, 0, 0, 0)], magic=0xDEADBEEF)

def invalid_02_truncated_header(f):
    """File is shorter than the 60-byte header."""
    f.write(b"BUN0" + b"\x00" * 20)  # only 24 bytes total

def invalid_03_truncated_file(f):
    """Declared data section extends past EOF."""
    # Claim 1000 bytes of data, but only write 20 bytes total after header.
    asset_table_offset = _align4(HEADER_SIZE)
    string_table_offset = _align4(asset_table_offset + 48)
    gen.write_header(
        f, asset_count=1,
        asset_table_offset=asset_table_offset,
        string_table_offset=string_table_offset,
        string_table_size=4,
        data_section_offset=_align4(string_table_offset + 4),
        data_section_size=1000,  # lie!
    )
    gen.write_padding(f, asset_table_offset - HEADER_SIZE, "pad")
    gen.write_asset_record(
        f, name_offset=0, name_length=1,
        data_offset=0, data_size=4,
        uncompressed_size=0, compression=0,
        asset_type=0, checksum=0, flags=0,
    )
    # Write a tiny amount more, then stop early.
    f.write(b"hi\x00\x00")   # string table
    f.write(b"ABCD")          # claimed 4 bytes of data; header claims 1000

def invalid_04_unaligned_offset(f):
    """asset_table_offset is not divisible by 4."""
    gen.write_header(
        f, asset_count=0,
        asset_table_offset=61,  # not divisible by 4
        string_table_offset=64,
        string_table_size=0,
        data_section_offset=64,
        data_section_size=0,
    )

def invalid_05_unaligned_size(f):
    """string_table_size is not divisible by 4."""
    gen.write_header(
        f, asset_count=0,
        asset_table_offset=60,
        string_table_offset=60,
        string_table_size=3,   # bad
        data_section_offset=64,
        data_section_size=0,
    )
    gen.write_padding(f, 3, "pad")  # so sections at least lie within file

def invalid_06_overlapping_sections(f):
    """String table overlaps asset entry table."""
    asset_count = 1
    asset_table_offset = _align4(HEADER_SIZE)
    # Place string table *inside* the asset table.
    string_table_offset = asset_table_offset + 16
    string_table_size   = 16
    data_section_offset = _align4(asset_table_offset + asset_count * RECORD_SIZE + 32)
    data_section_size   = 4

    gen.write_header(
        f, asset_count=asset_count,
        asset_table_offset=asset_table_offset,
        string_table_offset=string_table_offset,
        string_table_size=string_table_size,
        data_section_offset=data_section_offset,
        data_section_size=data_section_size,
    )
    gen.write_padding(f, asset_table_offset - HEADER_SIZE, "pad")
    # Write just enough bytes that declared sections lie within file.
    f.write(b"\x00" * (data_section_offset + data_section_size - asset_table_offset))

def invalid_07_asset_count_overflow(f):
    """asset_count is large enough that asset_count * 48 overflows u64.
    A non-overflow-safe parser will read garbage past EOF or die."""
    # Pick a value such that N * 48 > 2^64 but N fits in u32.
    # 2^32 - 1 = 4294967295; * 48 = 206158430160 < 2^64 -> that doesn't overflow.
    # So we can't overflow u64 with u32 * 48. The real bug hunt here is
    # asset_count * 48 > file_size. Use a huge asset_count.
    gen.write_header(
        f, asset_count=0xFFFFFFFF,
        asset_table_offset=60,
        string_table_offset=60,
        string_table_size=0,
        data_section_offset=60,
        data_section_size=0,
    )
    gen.write_padding(f, 4, "pad")

def invalid_08_name_out_of_string_table(f):
    """Asset name_offset + name_length exceeds string_table_size."""
    asset_table_offset = _align4(HEADER_SIZE)
    string_table_offset = _align4(asset_table_offset + RECORD_SIZE)
    string_table_size = 4
    data_section_offset = _align4(string_table_offset + string_table_size)
    gen.write_header(
        f, asset_count=1,
        asset_table_offset=asset_table_offset,
        string_table_offset=string_table_offset,
        string_table_size=string_table_size,
        data_section_offset=data_section_offset,
        data_section_size=4,
    )
    gen.write_padding(f, asset_table_offset - HEADER_SIZE, "pad")
    gen.write_asset_record(
        f, name_offset=2, name_length=10,   # 2+10 > 4
        data_offset=0, data_size=1,
        uncompressed_size=0, compression=0, asset_type=0, checksum=0, flags=0,
    )
    f.write(b"abcd")
    f.write(b"XXXX")

def invalid_09_data_out_of_data_section(f):
    """Asset data_offset + data_size exceeds data_section_size."""
    asset_table_offset = _align4(HEADER_SIZE)
    string_table_offset = _align4(asset_table_offset + RECORD_SIZE)
    data_section_offset = _align4(string_table_offset + 4)
    gen.write_header(
        f, asset_count=1,
        asset_table_offset=asset_table_offset,
        string_table_offset=string_table_offset,
        string_table_size=4,
        data_section_offset=data_section_offset,
        data_section_size=4,
    )
    gen.write_padding(f, asset_table_offset - HEADER_SIZE, "pad")
    gen.write_asset_record(
        f, name_offset=0, name_length=1,
        data_offset=2, data_size=10,   # 2+10 > 4
        uncompressed_size=0, compression=0, asset_type=0, checksum=0, flags=0,
    )
    f.write(b"abcd")
    f.write(b"WXYZ")

def invalid_10_nonprintable_name(f):
    """Asset name contains a non-printable byte (0x01)."""
    name = b"bad\x01name"
    _simple_valid(f, assets=[(name, b"y", 0, 0, 0, 0, 0)])

def invalid_11_empty_name(f):
    """Asset with a zero-length name - not allowed by the spec."""
    asset_table_offset = _align4(HEADER_SIZE)
    string_table_offset = _align4(asset_table_offset + RECORD_SIZE)
    data_section_offset = _align4(string_table_offset + 4)
    gen.write_header(
        f, asset_count=1,
        asset_table_offset=asset_table_offset,
        string_table_offset=string_table_offset,
        string_table_size=4,
        data_section_offset=data_section_offset,
        data_section_size=4,
    )
    gen.write_padding(f, asset_table_offset - HEADER_SIZE, "pad")
    gen.write_asset_record(
        f, name_offset=0, name_length=0,   # bad
        data_offset=0, data_size=1,
        uncompressed_size=0, compression=0, asset_type=0, checksum=0, flags=0,
    )
    f.write(b"\x00\x00\x00\x00")
    f.write(b"WXYZ")

def invalid_12_rle_odd_size(f):
    """RLE-compressed data with an odd number of bytes on disk."""
    _simple_valid(f, assets=[
        (b"rle-odd", b"\x03\x41\xFF", 1, 3, 0, 0, 0),   # 3 bytes - odd
    ])

def invalid_13_rle_zero_count(f):
    """RLE pair with count=0."""
    _simple_valid(f, assets=[
        (b"rle-zero", b"\x00\x41", 1, 0, 0, 0, 0),
    ])

def invalid_14_uncompressed_size_mismatch(f):
    """Compressed data whose actual decompressed size differs from the
    declared uncompressed_size."""
    # Encoded as (3, 'A') => expands to 3 bytes, but we claim 99.
    _simple_valid(f, assets=[
        (b"rle-wrong", b"\x03\x41", 1, 99, 0, 0, 0),
    ])

def invalid_15_uncompressed_size_set_when_uncompressed(f):
    """compression=0 but uncompressed_size != 0 - spec says it MUST be 0."""
    _simple_valid(f, assets=[
        (b"bogus", b"ABCD", 0, 999, 0, 0, 0),
    ])

# Unsupported (BUN_UNSUPPORTED = 2)

def invalid_20_bad_version_major(f):
    """Major version != 1."""
    _simple_valid(f, assets=[(b"v", b"x", 0, 0, 0, 0, 0)], version_major=2)

def invalid_21_bad_version_minor(f):
    """Minor version != 0."""
    _simple_valid(f, assets=[(b"v", b"x", 0, 0, 0, 0, 0)], version_minor=5)

def invalid_22_compression_zlib(f):
    """compression = 2 (zlib) - we do not support this."""
    _simple_valid(f, assets=[
        (b"z", b"\x78\x9c\x01\x00\x00\xff\xff", 2, 0, 0, 0, 0),
    ])

def invalid_23_compression_unknown(f):
    """compression = 99 - unknown scheme."""
    _simple_valid(f, assets=[
        (b"u", b"\x00\x00", 99, 2, 0, 0, 0),
    ])

def invalid_24_checksum_nonzero(f):
    """CRC-32 field is non-zero and we don't implement checksum validation."""
    _simple_valid(f, assets=[
        (b"c", b"ABCD", 0, 0, 0, 0xCAFEBABE, 0),
    ])

def invalid_25_unknown_flag(f):
    """flag bit outside {ENCRYPTED, EXECUTABLE}."""
    _simple_valid(f, assets=[
        (b"f", b"ABCD", 0, 0, 0, 0, 0x80),
    ])

# -----------------------------------------------------------------------------
# Catalogue
# -----------------------------------------------------------------------------

VALID_FIXTURES = [
    ("01-empty.bun",                       valid_01_empty),
    ("02-single-uncompressed.bun",         valid_02_single_uncompressed),
    ("03-multiple-assets.bun",             valid_03_multiple_assets),
    ("04-rle-compressed.bun",              valid_04_rle_compressed),
    ("05-flag-executable.bun",             valid_05_flag_executable),
    ("06-flag-encrypted.bun",              valid_06_flag_encrypted),
    ("07-max-printable-name.bun",          valid_07_max_printable_name),
    ("08-reserved-nonzero.bun",            valid_08_reserved_nonzero),
    ("09-empty-payload.bun",               valid_09_empty_payload),
    ("10-non-canonical-order.bun",         valid_10_non_canonical_section_order),
]

INVALID_FIXTURES = [
    # BUN_MALFORMED
    ("01-bad-magic.bun",                   invalid_01_bad_magic,                   "malformed"),
    ("02-truncated-header.bun",            invalid_02_truncated_header,            "malformed"),
    ("03-truncated-file.bun",              invalid_03_truncated_file,              "malformed"),
    ("04-unaligned-offset.bun",            invalid_04_unaligned_offset,            "malformed"),
    ("05-unaligned-size.bun",              invalid_05_unaligned_size,              "malformed"),
    ("06-overlapping-sections.bun",        invalid_06_overlapping_sections,        "malformed"),
    ("07-asset-count-oversized.bun",       invalid_07_asset_count_overflow,        "malformed"),
    ("08-name-out-of-string-table.bun",    invalid_08_name_out_of_string_table,    "malformed"),
    ("09-data-out-of-data-section.bun",    invalid_09_data_out_of_data_section,    "malformed"),
    ("10-nonprintable-name.bun",           invalid_10_nonprintable_name,           "malformed"),
    ("11-empty-name.bun",                  invalid_11_empty_name,                  "malformed"),
    ("12-rle-odd-size.bun",                invalid_12_rle_odd_size,                "malformed"),
    ("13-rle-zero-count.bun",              invalid_13_rle_zero_count,              "malformed"),
    ("14-uncompressed-size-mismatch.bun",  invalid_14_uncompressed_size_mismatch,  "malformed"),
    ("15-uncompressed-size-set.bun",       invalid_15_uncompressed_size_set_when_uncompressed, "malformed"),
    # BUN_UNSUPPORTED
    ("20-bad-version-major.bun",           invalid_20_bad_version_major,           "unsupported"),
    ("21-bad-version-minor.bun",           invalid_21_bad_version_minor,           "unsupported"),
    ("22-compression-zlib.bun",            invalid_22_compression_zlib,            "unsupported"),
    ("23-compression-unknown.bun",         invalid_23_compression_unknown,         "unsupported"),
    ("24-checksum-nonzero.bun",            invalid_24_checksum_nonzero,            "unsupported"),
    ("25-unknown-flag.bun",                invalid_25_unknown_flag,                "unsupported"),
]


def write_expectations_file():
    """Write a tests/fixtures/expectations.tsv file mapping each fixture to
    its expected exit code. The E2E shell test reads this."""
    lines = ["# fixture\texpected_exit_code"]
    for (name, _) in VALID_FIXTURES:
        lines.append(f"valid/{name}\t0")
    for (name, _, kind) in INVALID_FIXTURES:
        code = {"malformed": 1, "unsupported": 2}[kind]
        lines.append(f"invalid/{name}\t{code}")
    (FIX_ROOT / "expectations.tsv").write_text("\n".join(lines) + "\n")
    print(f"  wrote {FIX_ROOT.joinpath('expectations.tsv').relative_to(ROOT)}")


def main():
    VALID_DIR.mkdir(parents=True, exist_ok=True)
    INVALID_DIR.mkdir(parents=True, exist_ok=True)

    print("Generating valid fixtures:")
    for (name, build) in VALID_FIXTURES:
        _write(VALID_DIR / name, build)
    print("Generating invalid fixtures:")
    for (name, build, _kind) in INVALID_FIXTURES:
        _write(INVALID_DIR / name, build)

    write_expectations_file()
    print("Done.")


if __name__ == "__main__":
    main()
