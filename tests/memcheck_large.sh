#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# memcheck_large.sh - verify that bun_parser uses sub-linear memory on a
# large, well-formed .bun file.
#
# Picks up one of:
#   - tests/fixtures/large.bun   (if it exists)
#   - $BUN_LARGE_FIXTURE env var (path)
#   - generated on the fly (~100 MiB) if neither is present
#
# Uses /usr/bin/time -v to measure RSS. Asserts the maximum resident set
# size (MaxRSS) stays below $MAX_RSS_KIB (default 50 MiB), which is much
# smaller than the input file and therefore evidence of streaming I/O.
#
# For the project's 638 MB Moodle sample, set BUN_LARGE_FIXTURE to its path:
#   BUN_LARGE_FIXTURE=~/Downloads/large.bun make memcheck
#
# Author: Group 22, Member 4.
# -----------------------------------------------------------------------------

set -euo pipefail

PROG=./bun_parser
MAX_RSS_KIB=${MAX_RSS_KIB:-51200}   # 50 MiB default budget

if [[ ! -x "$PROG" ]]; then
  echo "ERROR: $PROG not found; run 'make all' first." >&2
  exit 99
fi

# Locate a large fixture.
if [[ -n "${BUN_LARGE_FIXTURE:-}" && -f "$BUN_LARGE_FIXTURE" ]]; then
  FIXTURE="$BUN_LARGE_FIXTURE"
elif [[ -f tests/fixtures/large.bun ]]; then
  FIXTURE=tests/fixtures/large.bun
else
  echo "No large fixture found; generating a synthetic 100 MiB file..."
  python3 tests/make_large_fixture.py tests/fixtures/large.bun 100
  FIXTURE=tests/fixtures/large.bun
fi

size=$(stat -c%s "$FIXTURE")
size_mib=$(( size / 1024 / 1024 ))
echo "Running $PROG on $FIXTURE ($size_mib MiB)..."
echo "Memory budget: $MAX_RSS_KIB KiB ($(( MAX_RSS_KIB / 1024 )) MiB)"

# /usr/bin/time -v writes its report to stderr. Capture both streams.
TIME_OUT=$(mktemp)
trap 'rm -f "$TIME_OUT"' EXIT

if ! command -v /usr/bin/time >/dev/null 2>&1; then
  echo "ERROR: /usr/bin/time not available; install with 'sudo apt-get install time'." >&2
  exit 99
fi

set +e
/usr/bin/time -v "$PROG" "$FIXTURE" >/dev/null 2> "$TIME_OUT"
exit_code=$?
set -e

echo "----- time -v output -----"
cat "$TIME_OUT"
echo "--------------------------"

# Extract "Maximum resident set size (kbytes): NNNN"
rss_kib=$(awk '/Maximum resident set size/ { print $NF }' "$TIME_OUT")
if [[ -z "$rss_kib" ]]; then
  echo "ERROR: could not parse Max RSS from time output." >&2
  exit 1
fi

echo "bun_parser exit code: $exit_code"
echo "Max RSS             : $rss_kib KiB"
echo "File size           : $size bytes"
echo "RSS / file ratio    : $(awk "BEGIN { printf \"%.4f\", $rss_kib*1024 / $size }")"

if (( rss_kib > MAX_RSS_KIB )); then
  echo "FAIL: RSS $rss_kib KiB exceeds budget $MAX_RSS_KIB KiB." >&2
  exit 1
fi

echo "PASS: RSS within budget."
