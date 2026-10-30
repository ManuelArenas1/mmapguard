CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Werror
LDLIBS_THREAD = -pthread
BINS    = poc_shared_write poc_mprotect_upgrade poc_private_cow poc_race_madvise bench_mmap

all: $(BINS)
poc_race_madvise: poc_race_madvise.c common.h
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS_THREAD)
%: %.c common.h
	$(CC) $(CFLAGS) $< -o $@
clean:
	rm -f $(BINS)
.PHONY: all clean
