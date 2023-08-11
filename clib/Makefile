VPATH=../../sop-rs
CFLAGS=-I../../openpgp-stateless-cli
LDFLAGS=-Ltarget/debug
LDLIBS=-lsequoia_sop_c

all: check

.PHONY: check
check: test
	LD_LIBRARY_PATH=target/debug ./test

.PHONY: check-leaks
check-leaks: test
	LD_LIBRARY_PATH=target/debug valgrind ./test
