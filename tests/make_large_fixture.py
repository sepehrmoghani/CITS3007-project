# Group 22:
# Name:                     Student Num:    Github Username:
# Rayan Ramaprasad          24227537        24227537
# Abinandh Radhakrishnan    23689813        abxsnxper
# Campbell Henderson        24278297        phyric1
# Sepehr Moghani Pilehroud  23642415        sepehrmoghani
#!/usr/bin/env python3
"""
make_large_fixture.py - generate a large, well-formed .bun file on demand.

Usage:
    python3 tests/make_large_fixture.py OUT_PATH SIZE_MIB

Emits a valid .bun file of approximately SIZE_MIB MiB with a single asset
whose payload is `SIZE_MIB * 1024 * 1024` bytes of zeroes. Streamed to disk
so the generator itself doesn't need to hold the file in memory.

Used by memcheck_large.sh when no external fixture is supplied.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

# We intentionally don't import bunfile_generator (which is chatty); just do
# the packing inline so this is self-contained.
_HEADER_FMT = "<IHHIQQQQQQ"
_RECORD_FMT = "<IIQQQIIII"
BUN_MAGIC   = 0x304E5542

def _align4(n: int) -> int:
    return (n + 3) & ~3

def main():
    if len(sys.argv) != 3:
        print("Usage: make_large_fixture.py OUT_PATH SIZE_MIB", file=sys.stderr)
        sys.exit(2)

    out_path  = Path(sys.argv[1])
    size_mib  = int(sys.argv[2])
    payload_n = size_mib * 1024 * 1024

    name          = b"large-blob"
    asset_count   = 1
    HEADER_SIZE   = struct.calcsize(_HEADER_FMT)   # 60
    RECORD_SIZE   = struct.calcsize(_RECORD_FMT)   # 48

    asset_table_offset  = _align4(HEADER_SIZE)
    string_table_offset = _align4(asset_table_offset + asset_count * RECORD_SIZE)
    string_table_size   = _align4(len(name))
    data_section_offset = _align4(string_table_offset + string_table_size)
    data_section_size   = _align4(payload_n)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("wb") as f:
        # Header.
        f.write(struct.pack(
            _HEADER_FMT, BUN_MAGIC, 1, 0, asset_count,
            asset_table_offset, string_table_offset, string_table_size,
            data_section_offset, data_section_size, 0,
        ))
        # Pad.
        f.write(b"\x00" * (asset_table_offset - HEADER_SIZE))
        # Single asset record.
        f.write(struct.pack(
            _RECORD_FMT, 0, len(name), 0, payload_n, 0, 0, 0, 0, 0,
        ))
        # Pad to string table.
        here = asset_table_offset + RECORD_SIZE
        f.write(b"\x00" * (string_table_offset - here))
        # String table.
        f.write(name)
        f.write(b"\x00" * (string_table_size - len(name)))
        # Pad to data section.
        here = string_table_offset + string_table_size
        f.write(b"\x00" * (data_section_offset - here))
        # Payload: stream zeros in 1 MiB chunks so we don't allocate payload_n
        # bytes in one shot.
        chunk = b"\x00" * (1024 * 1024)
        remaining = payload_n
        while remaining > 0:
            n = min(len(chunk), remaining)
            f.write(chunk[:n])
            remaining -= n
        # Trailing pad.
        f.write(b"\x00" * (data_section_size - payload_n))

    print(f"Wrote {out_path} ({out_path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
