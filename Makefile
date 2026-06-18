CC := gcc
CFLAGS := -D_POSIX_C_SOURCE=200809L -D_FORTIFY_SOURCE=2 -fstack-protector-strong -std=c11 -Wall -Wextra -O2 -g -Iinclude
LDFLAGS := -Wl,-z,relro -Wl,-z,now

BIN_DIR := bin
COMMON_OBJS := build/protocol.o build/logger.o build/sha1_util.o
DEMO_COMMON_OBJS := build/logger.o build/sha1_util.o build/protocol.o build/demo_util.o

.PHONY: all clean test

all: $(BIN_DIR)/server $(BIN_DIR)/client $(BIN_DIR)/control_server \
	$(BIN_DIR)/tcp_server $(BIN_DIR)/tcp_client $(BIN_DIR)/tls_server $(BIN_DIR)/tls_client \
	$(BIN_DIR)/http_demo_server $(BIN_DIR)/http_demo_client \
	$(BIN_DIR)/websocket_demo_server $(BIN_DIR)/websocket_demo_client \
	$(BIN_DIR)/quic_demo_server $(BIN_DIR)/quic_demo_client

test: all
	./test/run_tests.sh

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

build/demo_util.o: src/demo_util.c include/demo_util.h include/logger.h include/sha1_util.h include/protocol.h | build
	$(CC) $(CFLAGS) -c $< -o $@

build/server.o: src/server.c include/protocol.h include/logger.h include/sha1_util.h | build
	$(CC) $(CFLAGS) -c $< -o $@

build/client.o: src/client.c include/protocol.h include/logger.h include/sha1_util.h | build
	$(CC) $(CFLAGS) -c $< -o $@

build/control_server.o: src/control_server.c include/logger.h include/sha1_util.h | build
	$(CC) $(CFLAGS) -c $< -o $@

build/tcp_demo_server.o: src/tcp_demo_server.c include/demo_util.h include/protocol.h | build
	$(CC) $(CFLAGS) -c $< -o $@

build/tcp_demo_client.o: src/tcp_demo_client.c include/demo_util.h include/protocol.h | build
	$(CC) $(CFLAGS) -c $< -o $@

build/http_demo_server.o: src/http_demo_server.c include/demo_util.h include/protocol.h | build
	$(CC) $(CFLAGS) -c $< -o $@

build/http_demo_client.o: src/http_demo_client.c include/demo_util.h include/protocol.h | build
	$(CC) $(CFLAGS) -c $< -o $@

build/websocket_demo_server.o: src/websocket_demo_server.c include/demo_util.h include/protocol.h include/sha1_util.h | build
	$(CC) $(CFLAGS) -c $< -o $@

build/websocket_demo_client.o: src/websocket_demo_client.c include/demo_util.h include/protocol.h include/sha1_util.h | build
	$(CC) $(CFLAGS) -c $< -o $@

build/quic_demo_server.o: src/quic_demo_server.c include/demo_util.h include/protocol.h include/sha1_util.h | build
	$(CC) $(CFLAGS) -c $< -o $@

build/quic_demo_client.o: src/quic_demo_client.c include/demo_util.h include/protocol.h include/sha1_util.h | build
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR)/server: build/server.o $(COMMON_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/client: build/client.o $(COMMON_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/control_server: build/control_server.o build/logger.o build/sha1_util.o | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/tcp_server: build/tcp_demo_server.o $(DEMO_COMMON_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/tcp_client: build/tcp_demo_client.o $(DEMO_COMMON_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/tls_server: build/tcp_demo_server.o $(DEMO_COMMON_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/tls_client: build/tcp_demo_client.o $(DEMO_COMMON_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/http_demo_server: build/http_demo_server.o $(DEMO_COMMON_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/http_demo_client: build/http_demo_client.o $(DEMO_COMMON_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/websocket_demo_server: build/websocket_demo_server.o $(DEMO_COMMON_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/websocket_demo_client: build/websocket_demo_client.o $(DEMO_COMMON_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/quic_demo_server: build/quic_demo_server.o $(DEMO_COMMON_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/quic_demo_client: build/quic_demo_client.o $(DEMO_COMMON_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -rf build $(BIN_DIR)
