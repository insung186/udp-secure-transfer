#include "demo_util.h"
#include "protocol.h"
#include "sha1_util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define WS_HTTP_BUF 8192
#define WS_MAX_PAYLOAD 1024

static volatile sig_atomic_t stop_requested = 0;

static void handle_signal(int signo) {
    (void)signo;
    stop_requested = 1;
}

/* Finds an HTTP header value. Writes up to (cap-1) bytes plus a NUL terminator
   into `out`. Returns 0 on hit, -1 on miss or overflow. Re-entrant: caller-owned
   buffer (previously a static buffer, which broke concurrent callers). */
static int find_header_value(const char *raw, const char *key, char *out, size_t cap) {
    const char *p = raw;
    size_t key_len = strlen(key);
    if (!out || cap == 0) {
        return -1;
    }
    out[0] = '\0';
    while ((p = strstr(p, key)) != NULL) {
        if (p == raw || *(p - 1) == '\n') {
            const char *start = p + key_len;
            const char *end;
            while (*start == ' ' || *start == '\t') {
                start++;
            }
            end = strstr(start, "\r\n");
            if (!end) {
                return -1;
            }
            if ((size_t)(end - start) >= cap) {
                return -1;
            }
            memcpy(out, start, (size_t)(end - start));
            out[end - start] = '\0';
            return 0;
        }
        p += key_len;
    }
    return -1;
}

static int read_http_request(int fd, uint8_t *buf, size_t cap, size_t *out_len) {
    size_t total = 0;
    while (total < cap) {
        ssize_t n = recv(fd, buf + total, cap - total, 0);
        if (n <= 0) {
            return -1;
        }
        total += (size_t)n;
        buf[total] = '\0';
        if (strstr((char *)buf, "\r\n\r\n")) {
            *out_len = total;
            return 0;
        }
    }
    return -1;
}

static void log_ws_packet(Logger *logger, const char *level, const char *event, const char *state,
                          const char *message, const char *peer, const char *direction,
                          const char *packet_type, int packet_code, const char *frame_type,
                          const uint8_t *wire, size_t wire_len) {
    char wire_hex[321];
    char uid[24];
    LogEvent e;
    demo_init_event(&e, level, event, state, message);
    bytes_to_hex(wire, wire_len > 160 ? 160 : wire_len, wire_hex, sizeof(wire_hex));
    compute_packet_uid(uid, sizeof(uid), (uint16_t)packet_code, 0, 0, wire, wire_len);
    e.peer = peer;
    e.direction = direction;
    e.packet_type = packet_type;
    e.packet_code = packet_code;
    e.frame_type = frame_type;
    e.payload_length = (int)wire_len;
    e.bytes = (int)wire_len;
    e.packet_uid = uid;
    e.wire_hex = wire_hex;
    logger_write(logger, &e);
}

static int send_frame(Logger *logger, int fd, const char *peer, uint8_t opcode,
                      const uint8_t *payload, size_t payload_len,
                      const char *packet_type, int packet_code) {
    uint8_t wire[2 + WS_MAX_PAYLOAD];
    const char *frame_type = packet_type;
    if (payload_len > WS_MAX_PAYLOAD) {
        return -1;
    }
    wire[0] = 0x80U | opcode;
    wire[1] = (uint8_t)payload_len;
    if (payload_len > 0) {
        memcpy(wire + 2, payload, payload_len);
    }
    if (demo_write_all(fd, wire, 2 + payload_len) != 0) {
        return -1;
    }
    if (opcode == 0x1U) frame_type = "text";
    else if (opcode == 0x9U) frame_type = "ping";
    else if (opcode == 0xAU) frame_type = "pong";
    else if (opcode == 0x8U) frame_type = "close";
    log_ws_packet(logger, "INFO", "SEND_WS_FRAME", "DATA_TRANSFER", "websocket frame sent",
                  peer, "Server -> Client", packet_type, packet_code, frame_type, wire, 2 + payload_len);
    return 0;
}

static int recv_frame(Logger *logger, int fd, const char *peer, uint8_t *opcode,
                      uint8_t *payload, size_t *payload_len, const char *state) {
    uint8_t header[2];
    uint8_t ext[2];
    uint8_t mask[4];
    uint8_t wire[2 + 2 + 4 + WS_MAX_PAYLOAD];
    uint64_t pl = 0;
    size_t i;
    if (demo_read_all(fd, header, sizeof(header)) != 0) {
        return -1;
    }
    *opcode = header[0] & 0x0fU;
    /* Decode payload length per RFC 6455 §5.2:
         < 126  -> 7 bits inline
         = 126  -> next 2 bytes (16-bit, network order)
         = 127  -> next 8 bytes (64-bit) — rejected here because we cap payload. */
    if ((header[1] & 0x7fU) < 126) {
        pl = header[1] & 0x7fU;
    } else if ((header[1] & 0x7fU) == 126) {
        if (demo_read_all(fd, ext, sizeof(ext)) != 0) {
            return -1;
        }
        pl = ((uint32_t)ext[0] << 8) | ext[1];
    } else {
        /* 64-bit length: we never send payloads > WS_MAX_PAYLOAD, so refuse. */
        return -1;
    }
    if (pl > WS_MAX_PAYLOAD) {
        return -1;
    }
    *payload_len = (size_t)pl;
    wire[0] = header[0];
    wire[1] = header[1];
    size_t wire_used = 2;
    if ((header[1] & 0x7fU) == 126) {
        wire[wire_used++] = ext[0];
        wire[wire_used++] = ext[1];
    }
    if (header[1] & 0x80U) {
        if (demo_read_all(fd, mask, sizeof(mask)) != 0) {
            return -1;
        }
        memcpy(wire + wire_used, mask, sizeof(mask));
        wire_used += sizeof(mask);
        if (*payload_len > 0 && demo_read_all(fd, payload, *payload_len) != 0) {
            return -1;
        }
        memcpy(wire + wire_used, payload, *payload_len);
        for (i = 0; i < *payload_len; i += 1) {
            payload[i] ^= mask[i % 4];
        }
        wire_used += *payload_len;
    } else {
        if (*payload_len > 0 && demo_read_all(fd, payload, *payload_len) != 0) {
            return -1;
        }
        memcpy(wire + wire_used, payload, *payload_len);
        wire_used += *payload_len;
    }
    log_ws_packet(logger, "INFO", "RECV_WS_FRAME", state, "websocket frame received",
                  peer, "Client -> Server",
                  *opcode == 0x1U ? "TEXT" : *opcode == 0x9U ? "PING" : *opcode == 0xAU ? "PONG" : "CLOSE",
                  *opcode == 0x1U ? 42 : *opcode == 0x9U ? 43 : *opcode == 0xAU ? 44 : 45,
                  *opcode == 0x1U ? "text" : *opcode == 0x9U ? "ping" : *opcode == 0xAU ? "pong" : "close",
                  wire, wire_used);
    return 0;
}

static int send_upgrade_response(Logger *logger, int fd, const char *peer, const char *accept_key) {
    char response[512];
    int len = snprintf(response, sizeof(response),
                       "HTTP/1.1 101 Switching Protocols\r\n"
                       "Upgrade: websocket\r\n"
                       "Connection: Upgrade\r\n"
                       "Sec-WebSocket-Accept: %s\r\n\r\n",
                       accept_key);
    if (len < 0 || (size_t)len >= sizeof(response) ||
        demo_write_all(fd, (const uint8_t *)response, (size_t)len) != 0) {
        return -1;
    }
    log_ws_packet(logger, "INFO", "SEND_UPGRADE_RESPONSE", "HANDSHAKE", "websocket upgrade response sent",
                  peer, "Server -> Client", "UPGRADE_RESPONSE", 41, "http-upgrade",
                  (const uint8_t *)response, (size_t)len);
    return 0;
}

int main(int argc, char **argv) {
    Logger logger;
    uint16_t port;
    const char *password;
    const char *input_path;
    int listener = -1;
    int fd = -1;
    struct sockaddr_in peer_addr;
    char peer[64];
    struct stat st;
    uint8_t raw[WS_HTTP_BUF + 1];
    size_t raw_len = 0;
    char key[256];
    char upgrade[64];
    char connection[64];
    char header_password[128];
    char accept_input[512];
    uint8_t accept_digest[SHA1_DIGEST_LENGTH];
    char accept_key[128];
    FILE *fp = NULL;
    uint8_t text_buf[WS_MAX_PAYLOAD];
    size_t text_len = 0;
    const char *scenario = getenv("UDP_SECURE_SCENARIO");
    int rc = 1;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    ensure_runtime_dirs();
    if (logger_open(&logger, "server", "logs/server.jsonl") != 0) {
        return 1;
    }
    if (argc != 4 || parse_port(argv[1], &port) != 0) {
        demo_finish(&logger, "ABORT", "invalid arguments");
        logger_close(&logger);
        return 1;
    }
    password = argv[2];
    input_path = argv[3];
    if (stat(input_path, &st) != 0) {
        demo_finish(&logger, "ABORT", "input file cannot be read");
        logger_close(&logger);
        return 1;
    }
    listener = demo_create_tcp_listener(port);
    if (listener < 0) {
        demo_finish(&logger, "ABORT", strerror(errno));
        logger_close(&logger);
        return 1;
    }
    {
        LogEvent e;
        demo_init_event(&e, "INFO", "SERVER_START", "INIT", "websocket-basic server started");
        e.port = (int)port;
        e.bytes = (int)st.st_size;
        logger_write(&logger, &e);
    }
    fd = demo_accept_client(listener, &peer_addr);
    if (fd < 0) {
        demo_finish(&logger, "ABORT", "accept failed");
        close(listener);
        logger_close(&logger);
        return 1;
    }
    peer_to_string(&peer_addr, peer, sizeof(peer));
    if (read_http_request(fd, raw, WS_HTTP_BUF, &raw_len) != 0) {
        demo_finish(&logger, "ABORT", "upgrade request read failed");
        close(fd);
        close(listener);
        logger_close(&logger);
        return 1;
    }
    log_ws_packet(&logger, "INFO", "RECV_UPGRADE_REQUEST", "HANDSHAKE", "websocket upgrade request received",
                  peer, "Client -> Server", "UPGRADE_REQUEST", 40, "http-upgrade", raw, raw_len);
    if (find_header_value((const char *)raw, "Sec-WebSocket-Key:", key, sizeof(key)) != 0) {
        key[0] = '\0';
    }
    if (find_header_value((const char *)raw, "Upgrade:", upgrade, sizeof(upgrade)) != 0) {
        upgrade[0] = '\0';
    }
    if (find_header_value((const char *)raw, "Connection:", connection, sizeof(connection)) != 0) {
        connection[0] = '\0';
    }
    if (find_header_value((const char *)raw, "X-Demo-Password:", header_password, sizeof(header_password)) != 0) {
        header_password[0] = '\0';
    }
    if (!key[0] || !upgrade[0] || !connection[0] || strcmp(upgrade, "websocket") != 0 ||
        strstr(connection, "Upgrade") == NULL ||
        !header_password[0] || strcmp(header_password, password) != 0) {
        const char *fail = "HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\nConnection: close\r\n\r\nbad upgrade";
        demo_write_all(fd, (const uint8_t *)fail, strlen(fail));
        log_ws_packet(&logger, "ERROR", "SEND_BAD_UPGRADE", "ABORT", "bad upgrade",
                      peer, "Server -> Client", "UPGRADE_RESPONSE", 41, "http-upgrade",
                      (const uint8_t *)fail, strlen(fail));
        demo_finish(&logger, "ABORT", "bad upgrade");
        close(fd);
        close(listener);
        logger_close(&logger);
        return 1;
    }

    snprintf(accept_input, sizeof(accept_input), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);
    {
        Sha1Context ctx;
        sha1_init(&ctx);
        sha1_update(&ctx, (const uint8_t *)accept_input, strlen(accept_input));
        sha1_final(&ctx, accept_digest);
    }
    if (demo_base64_encode(accept_digest, sizeof(accept_digest), accept_key, sizeof(accept_key)) != 0 ||
        send_upgrade_response(&logger, fd, peer, accept_key) != 0) {
        demo_finish(&logger, "ABORT", "upgrade response failed");
        close(fd);
        close(listener);
        logger_close(&logger);
        return 1;
    }
    {
        struct timespec pause_time;
        pause_time.tv_sec = 0;
        pause_time.tv_nsec = 50000000L;
        nanosleep(&pause_time, NULL);
    }

    fp = fopen(input_path, "rb");
    if (!fp) {
        demo_finish(&logger, "ABORT", "input open failed");
        close(fd);
        close(listener);
        logger_close(&logger);
        return 1;
    }
    text_len = fread(text_buf, 1, sizeof(text_buf), fp);
    fclose(fp);
    if (send_frame(&logger, fd, peer, 0x1U, text_buf, text_len, "TEXT", 42) != 0) {
        demo_finish(&logger, "ABORT", "text frame send failed");
        close(fd);
        close(listener);
        logger_close(&logger);
        return 1;
    }
    if (scenario && strcmp(scenario, "unexpected-close") == 0) {
        demo_finish(&logger, "ABORT", "unexpected close scenario");
        close(fd);
        close(listener);
        logger_close(&logger);
        return 1;
    }
    if (send_frame(&logger, fd, peer, 0x9U, (const uint8_t *)"probe", 5, "PING", 43) != 0) {
        demo_finish(&logger, "ABORT", "ping send failed");
        close(fd);
        close(listener);
        logger_close(&logger);
        return 1;
    }
    {
        struct timeval tv = {2, 0};
        uint8_t opcode;
        uint8_t payload[WS_MAX_PAYLOAD];
        size_t payload_len = 0;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        if (recv_frame(&logger, fd, peer, &opcode, payload, &payload_len, "VERIFY") != 0 || opcode != 0xAU) {
            demo_finish(&logger, "ABORT", "pong timeout");
            close(fd);
            close(listener);
            logger_close(&logger);
            return 1;
        }
    }
    if (send_frame(&logger, fd, peer, 0x8U, (const uint8_t *)"bye", 3, "CLOSE", 45) != 0) {
        demo_finish(&logger, "ABORT", "close send failed");
        close(fd);
        close(listener);
        logger_close(&logger);
        return 1;
    }
    rc = 0;
    demo_finish(&logger, "OK", "websocket-basic flow completed");
    close(fd);
    close(listener);
    logger_close(&logger);
    return rc;
}
