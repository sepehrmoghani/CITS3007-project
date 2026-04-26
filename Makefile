# CITS3007 group 22 - bun_parser Makefile
#
# Required targets (per project brief):
#   all        - build the bun_parser executable
#   test       - run the test suite
#
# Additional targets provided for development:
#   asan       - build bun_parser with AddressSanitizer + UBSan
#   fixtures   - regenerate tests/fixtures/{valid,invalid}/*.bun
#   e2e        - run the end-to-end shell test (requires bun_parser + fixtures)
#   memcheck   - run the large-file memory budget test
#   sanity     - run the provided submission_sanity_checker.py
#   clean      - remove build artifacts
#
# The two "official" targets (all, test) are intentionally listed first.

CC       = gcc
# Base flags: C11, warnings, and implicit-fallthrough/implicit-function-decl
# promoted to hard errors (Member 3 wants these on from the start).
CFLAGS   = -std=c11 -Wall -Wextra -Wpedantic \
           -Wshadow -Wconversion -Wstrict-prototypes \
           -Wwrite-strings -Wpointer-arith -Wcast-align \
           -Wformat=2 -Wno-unused-parameter \
           -D_FILE_OFFSET_BITS=64
LDFLAGS  =

# Sanitizer flags - enabled by the "asan" target below, and recommended
# during all local development (see HACKING.md).
SAN_FLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1

# Source groups.
#   LIB    - parser library (no main()). Grows as members 1-3 land code.
#   MAIN   - the CLI entry point
#   OUTPUT - Member 4 secondary contribution: printable-ASCII/hex-dump helpers
#   TEST   - libcheck unit tests
LIB      = bun_parse.c bun_output.c
MAIN     = main.c
TEST     = tests/test_bun.c

PYTHON   = python3

.PHONY: all test asan fixtures e2e memcheck sanity clean distclean help

all: bun_parser

# -----------------------------------------------------------------------------
# Build rules
# -----------------------------------------------------------------------------

bun_parser: $(MAIN) $(LIB) bun.h bun_output.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(MAIN) $(LIB)

# Sanitizer build: same binary name, different flags. Useful for `make asan &&
# ./bun_parser tests/fixtures/valid/01-empty.bun` during development.
asan: CFLAGS += $(SAN_FLAGS)
asan: clean bun_parser

# -----------------------------------------------------------------------------
# Test rules
# -----------------------------------------------------------------------------

# `make test` runs both the libcheck C tests and the end-to-end shell tests.
# Fixtures are (re)generated first so we never run against stale .bun files.
test: fixtures tests/test_runner bun_parser
	./tests/test_runner
	./tests/run_e2e.sh

# libcheck test runner. Links in the parser library but NOT main.c (libcheck
# supplies its own main()).
tests/test_runner: $(TEST) $(LIB) bun.h bun_output.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(TEST) $(LIB) \
	      $$(pkg-config --cflags --libs check)

# Shell-level end-to-end test: runs bun_parser on every fixture and checks
# the exit code. Doesn't require libcheck.
e2e: bun_parser fixtures
	./tests/run_e2e.sh

# Large-file memory usage test. Needs a large .bun file; see the script for
# details. Not run by default because it requires a 600+ MB file.
memcheck: bun_parser
	./tests/memcheck_large.sh

# -----------------------------------------------------------------------------
# Fixture generation (Python helper)
# -----------------------------------------------------------------------------

# Regenerate the full set of valid + invalid fixtures used by the test suite.
fixtures:
	@mkdir -p tests/fixtures/valid tests/fixtures/invalid
	$(PYTHON) tests/make_fixtures.py

# -----------------------------------------------------------------------------
# Submission sanity check
# -----------------------------------------------------------------------------

sanity:
	@echo "Packaging a test zip and running submission_sanity_checker.py..."
	@tmp=$$(mktemp -d); \
	 zip -rq $$tmp/group22-submission.zip . \
	   -x '.git/*' -x 'tests/fixtures/*' -x 'bun_parser' \
	   -x 'tests/test_runner' -x '*.o' -x 'report/*.pdf' ; \
	 $(PYTHON) submission_sanity_checker.py $$tmp/group22-submission.zip; \
	 rm -rf $$tmp

# -----------------------------------------------------------------------------
# Housekeeping
# -----------------------------------------------------------------------------

clean:
	-rm -f bun_parser tests/test_runner *.o tests/*.o

distclean: clean
	-rm -rf tests/fixtures

help:
	@echo "Targets:"
	@echo "  all       - build bun_parser"
	@echo "  test      - run the full test suite (libcheck + E2E)"
	@echo "  asan      - build bun_parser with ASan + UBSan"
	@echo "  fixtures  - (re)generate test .bun files"
	@echo "  e2e       - run end-to-end shell tests only"
	@echo "  memcheck  - run large-file memory budget test"
	@echo "  sanity    - run the TA's submission sanity checker"
	@echo "  clean     - remove build artifacts"
	@echo "  distclean - also remove generated fixtures"
