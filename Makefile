CC := gcc
CFLAGS := -D_POSIX_C_SOURCE=200809L -std=c11 -Wall -Wextra -O2 -g -Iinclude
LDFLAGS :=

BIN_DIR := bin
COMMON_OBJS := build/protocol.o build/logger.o build/sha1_util.o

.PHONY: all clean

all: $(BIN_DIR)/server $(BIN_DIR)/client $(BIN_DIR)/control_server

build:
	mkdir -p build logs output test/cases

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

build/protocol.o: src/protocol.c include/protocol.h | build
	$(CC) $(CFLAGS) -c $< -o $@

build/logger.o: src/logger.c include/logger.h | build
	$(CC) $(CFLAGS) -c $< -o $@

build/sha1_util.o: src/sha1_util.c include/sha1_util.h | build
	$(CC) $(CFLAGS) -c $< -o $@

build/server.o: src/server.c include/protocol.h include/logger.h include/sha1_util.h | build
	$(CC) $(CFLAGS) -c $< -o $@

build/client.o: src/client.c include/protocol.h include/logger.h include/sha1_util.h | build
	$(CC) $(CFLAGS) -c $< -o $@

build/control_server.o: src/control_server.c include/logger.h include/sha1_util.h | build
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR)/server: build/server.o $(COMMON_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/client: build/client.o $(COMMON_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/control_server: build/control_server.o build/logger.o build/sha1_util.o | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -rf build $(BIN_DIR)
