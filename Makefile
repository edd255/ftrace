CC := gcc
CFLAGS ?= -O2 -fstack-protector-strong -fPIE -fstack-clash-protection -fcf-protection=full
CPPFLAGS ?= -D_FORTIFY_SOURCE=3
LDFLAGS ?= -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -s
LDLIBS ?= -lcapstone

SRC_DIR := src
TEST_DIR := tests
BUILD_DIR := build
BIN_DIR := bin

FTRACE_SRC := $(SRC_DIR)/ftrace.c
FTRACE_OBJ := $(BUILD_DIR)/ftrace.o
TEST_SRC := $(TEST_DIR)/test.c
TEST_OBJ := $(BUILD_DIR)/test.o
DEPS := $(SRC_DIR)/functools.h $(SRC_DIR)/readelf.h $(SRC_DIR)/ptrace.h $(SRC_DIR)/logging.h

.PHONY: all ftrace test clean

all: ftrace

ftrace: $(BIN_DIR)/ftrace

test: $(BIN_DIR)/test

$(BIN_DIR)/ftrace: $(FTRACE_OBJ) | $(BIN_DIR)
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS)

$(BUILD_DIR)/ftrace.o: $(FTRACE_SRC) $(DEPS) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(BIN_DIR)/test: $(TEST_OBJ) | $(BIN_DIR)
	$(CC) $(LDFLAGS) -o $@ $<

$(BUILD_DIR)/test.o: $(TEST_SRC) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR) $(BIN_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
