CC ?= cc
LTO ?= -flto
ifneq ($(strip $(LTO)),)
ifneq ($(findstring clang,$(shell $(CC) --version)),)
ifeq ($(origin AR),default)
AR := $(shell $(CC) -print-prog-name=llvm-ar)
endif
LTO_LDFLAGS ?= $(if $(wildcard $(shell $(CC) -print-prog-name=ld.lld)),-fuse-ld=lld)
endif
endif
AR ?= ar
FUZZ_CC ?= $(or $(shell command -v clang),$(shell command -v clang-19),clang)
BUILD ?= build
CFLAGS ?= -O2 -g
BENCH_MIB ?= 64
INCLUDES = -Iinclude -Isrc
WARNINGS = -std=c11 -Wall -Wextra -Wpedantic -Werror
SOURCES = src/mist.c src/handshake.c src/packet.c src/stream.c src/schedule.c \
          src/ack.c src/loss.c src/crypto/primitives.c src/crypto/blake2s.c src/crypto/noise.c
HEADERS = include/mist.h src/internal.h src/crypto/crypto.h
OBJECTS = $(SOURCES:%.c=$(BUILD)/%.o)
TESTS = $(BUILD)/test_crypto $(BUILD)/test_transport

.PHONY: all test clean sanitize fuzz bench
all: $(BUILD)/libmist.a

$(BUILD)/libmist.a: $(OBJECTS)
	$(AR) rcs $@ $^

$(BUILD)/%.o: %.c Makefile
	@mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(WARNINGS) $(LTO) -MMD -MP -c $< -o $@

$(BUILD)/test_%: tests/test_%.c $(BUILD)/libmist.a $(HEADERS)
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(WARNINGS) $(LTO) $(filter-out %.h,$^) $(LTO_LDFLAGS) $(LDFLAGS) $(LDLIBS) -o $@

test: $(TESTS)
	@set -e; for test in $(TESTS); do "$$test"; done

$(BUILD)/bench_throughput: bench/throughput.c $(BUILD)/libmist.a include/mist.h
	$(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) $(WARNINGS) $(LTO) $(filter-out %.h,$^) $(LTO_LDFLAGS) $(LDFLAGS) $(LDLIBS) -o $@

bench: $(BUILD)/bench_throughput
	$(BUILD)/bench_throughput $(BENCH_MIB)

sanitize:
	$(MAKE) test BUILD=$(BUILD)/sanitize LTO= \
	    CFLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie" LDFLAGS="-no-pie"

fuzz: $(BUILD)/fuzz_packet

$(BUILD)/fuzz_packet: tests/fuzz_packet.c $(SOURCES) $(HEADERS)
	@mkdir -p $(@D)
	$(FUZZ_CC) $(CPPFLAGS) $(INCLUDES) $(WARNINGS) -O1 -g -fno-omit-frame-pointer \
	    -fsanitize=fuzzer,address,undefined $(filter-out %.h,$^) $(LDFLAGS) $(LDLIBS) -o $@

clean:
	rm -rf $(BUILD)

-include $(OBJECTS:.o=.d)
