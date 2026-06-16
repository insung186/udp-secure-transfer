#include "demo_util.h"
#include "protocol.h"
#include "sha1_util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define WS_HTTP_BUF 8192
#define WS_MAX_PAYLOAD 1024

static volatile sig_atomic_t stop_requested = 0;

static void handle_signal(int signo) {
    (void)signo;
    stop_requested = 1;
}

static int read_http_response(int fd, uint8_t *buf, size_t cap, size_t *out_len) {
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

static int send_frame(Logger *logger, int fd, const char *peer, uint8_t opcode,
                      const uint8_t *payload, size_t payload_len,
                      const char *packet_type, int packet_code) {
    uint8_t mask[4];
    uint8_t wire[2 + 4 + WS_MAX_PAYLOAD];
    size_t i;
    char wire_hex[321];
    char uid[24];
    LogEvent e;
    if (payload_len > WS_MAX_PAYLOAD) {
        return -1;
    }
    demo_random_nonce(mask, sizeof(mask));
    wire[0] = 0x80U | opcode;
    wire[1] = 0x80U | (uint8_t)payload_len;
    memcpy(wire + 2, mask, sizeof(mask));
    for (i = 0; i < payload_len; i += 1) {
        wire[6 + i] = payload[i] ^ mask[i % 4];
    }
    if (demo_write_all(fd, wire, 6 + payload_len) != 0) {
        return -1;
    }
    demo_init_event(&e, "INFO", "SEND_WS_FRAME", "DATA_TRANSFER", "websocket frame sent");
    bytes_to_hex(wire, 6 + payload_len > 160 ? 160 : 6 + payload_len, wire_hex, sizeof(wire_hex));
    compute_packet_uid(uid, sizeof(uid), (uint16_t)packet_code, 0, 0, wire, 6 + payload_len);
    e.peer = peer;
    e.direction = "Client -> Server";
    e.packet_type = packet_type;
    e.packet_code = packet_code;
    e.frame_type = opcode == 0x1U ? "text" : opcode == 0x9U ? "ping" : opcode == 0xAU ? "pong" : "close";
    e.payload_length = (int)(6 + payload_len);
    e.bytes = (int)(6 + payload_len);
    e.packet_uid = uid;
    e.wire_hex = wire_hex;
    logger_write(logger, &e);
    return 0;
}

static int recv_frame(Logger *logger, int fd, const char *peer, uint8_t *opcode,
                      uint8_t *payload, size_t *payload_len) {
    uint8_t header[2];
    uint8_t wire[2 + WS_MAX_PAYLOAD];
    char wire_hex[321];
    char uid[24];
    LogEvent e;
    if (demo_read_all(fd, header, sizeof(header)) != 0) {
        return -1;
    }
    *opcode = header[0] & 0x0fU;
    *payload_len = header[1] & 0x7fU;
    if (*payload_len > WS_MAX_PAYLOAD) {
        return -1;
    }
    wire[0] = header[0];
    wire[1] = header[1];
    if (*payload_len > 0 && demo_read_all(fd, payload, *payload_len) != 0) {
        return -1;
    }
    memcpy(wire + 2, payload, *payload_len);
    demo_init_event(&e, "INFO", "RECV_WS_FRAME", "DATA_TRANSFER", "websocket frame received");
    bytes_to_hex(wire, 2 + *payload_len > 160 ? 160 : 2 + *payload_len, wire_hex, sizeof(wire_hex));
    compute_packet_uid(uid, sizeof(uid), (uint16_t)(*opcode == 0x1U ? 42 : *opcode == 0x9U ? 43 : *opcode == 0xAU ? 44 : 45), 0, 0, wire, 2 + *payload_len);
    e.peer = peer;
    e.direction = "Server -> Client";
    e.packet_type = *opcode == 0x1U ? "TEXT" : *opcode == 0x9U ? "PING" : *opcode == 0xAU ? "PONG" : "CLOSE";
    e.packet_code = *opcode == 0x1U ? 42 : *opcode == 0x9U ? 43 : *opcode == 0xAU ? 44 : 45;
    e.frame_type = *opcode == 0x1U ? "text" : *opcode == 0x9U ? "ping" : *opcode == 0xAU ? "pong" : "close";
    e.payload_length = (int)(2 + *payload_len);
    e.bytes = (int)(2 + *payload_len);
    e.packet_uid = uid;
    e.wire_hex = wire_hex;
    logger_write(logger, &e);
    return 0;
}

int main(int argc, char **argv) {
    Logger logger;
    int interactive = 0;
    char *passwords[3] = {0};
    const char *host;
    const char *output_path;
    char peer_text[64];
    uint16_t port;
    int fd = -1;
    FILE *out = NULL;
    struct sockaddr_in addr;
    uint8_t response[WS_HTTP_BUF + 1];
    size_t response_len = 0;
    char key_input[16];
    char key_b64[64];
    char request[1024];
    const char *scenario = getenv("UDP_SECURE_SCENARIO");

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    ensure_runtime_dirs();
    if (logger_open(&logger, "client", "logs/client.jsonl") != 0) {
        return 1;
    }
    if (argc == 7) {
        host = argv[1];
        passwords[0] = argv[3];
        output_path = argv[6];
    } else if (argc == 4) {
        interactive = 1;
        host = argv[1];
        output_path = argv[3];
    } else {
        demo_finish(&logger, "ABORT", "invalid arguments");
        logger_close(&logger);
        return 1;
    }
    (void)interactive;
    if (parse_port(argv[2], &port) != 0) {
        demo_finish(&logger, "ABORT", "invalid port");
        logger_close(&logger);
        return 1;
    }
    snprintf(peer_text, sizeof(peer_text), "%s:%u", host, (unsigned)port);
    fd = demo_connect_tcp(host, port, &addr);
    if (fd < 0) {
        demo_finish(&logger, "ABORT", "tcp connect failed");
        logger_close(&logger);
        return 1;
    }
    out = fopen(output_path, "wb");
    if (!out) {
        demo_finish(&logger, "ABORT", "output open failed");
        close(fd);
        logger_close(&logger);
        return 1;
    }
    {
        LogEvent e;
        demo_init_event(&e, "INFO", "CLIENT_START", "INIT", "websocket-basic client started");
        e.peer = peer_text;
        e.port = (int)port;
        logger_write(&logger, &e);
    }
    demo_random_nonce((uint8_t *)key_input, sizeof(key_input));
    if (demo_base64_encode((const uint8_t *)key_input, sizeof(key_input), key_b64, sizeof(key_b64)) != 0) {
        demo_finish(&logger, "ABORT", "base64 key failed");
        fclose(out);
        close(fd);
        logger_close(&logger);
        return 1;
    }
    snprintf(request, sizeof(request),
             "GET /chat HTTP/1.1\r\n"
             "Host: %s:%u\r\n"
             "Upgrade: %s\r\n"
             "Connection: %s\r\n"
             "Sec-WebSocket-Key: %s\r\n"
             "Sec-WebSocket-Version: 13\r\n"
             "X-Demo-Password: %s\r\n\r\n",
             host, (unsigned)port,
             (scenario && strcmp(scenario, "bad-upgrade") == 0) ? "not-websocket" : "websocket",
             (scenario && strcmp(scenario, "bad-upgrade") == 0) ? "close" : "Upgrade",
             key_b64, passwords[0] ? passwords[0] : "secret");
    {
        char wire_hex[321];
        char uid[24];
        LogEvent e;
        demo_init_event(&e, "INFO", "SEND_UPGRADE_REQUEST", "HANDSHAKE", "websocket upgrade request sent");
        bytes_to_hex((const uint8_t *)request, strlen(request) > 160 ? 160 : strlen(request), wire_hex, sizeof(wire_hex));
        compute_packet_uid(uid, sizeof(uid), 40, 0, 0, (const uint8_t *)request, strlen(request));
        e.peer = peer_text;
        e.direction = "Client -> Server";
        e.packet_type = "UPGRADE_REQUEST";
        e.packet_code = 40;
        e.frame_type = "http-upgrade";
        e.payload_length = (int)strlen(request);
        e.bytes = (int)strlen(request);
        e.packet_uid = uid;
        e.wire_hex = wire_hex;
        logger_write(&logger, &e);
    }
    if (demo_write_all(fd, (const uint8_t *)request, strlen(request)) != 0 ||
        read_http_response(fd, response, WS_HTTP_BUF, &response_len) != 0) {
        demo_finish(&logger, "ABORT", "upgrade failed");
        fclose(out);
        close(fd);
        logger_close(&logger);
        return 1;
    }
    {
        char wire_hex[321];
        char uid[24];
        int status = 0;
        LogEvent e;
        sscanf((const char *)response, "HTTP/1.1 %d", &status);
        demo_init_event(&e, status == 101 ? "INFO" : "ERROR", "RECV_UPGRADE_RESPONSE", "HANDSHAKE", "websocket upgrade response received");
        bytes_to_hex(response, response_len > 160 ? 160 : response_len, wire_hex, sizeof(wire_hex));
        compute_packet_uid(uid, sizeof(uid), 41, status, 0, response, response_len);
        e.peer = peer_text;
        e.direction = "Server -> Client";
        e.packet_type = "UPGRADE_RESPONSE";
        e.packet_code = 41;
        e.frame_type = "http-upgrade";
        e.status_code = status;
        e.payload_length = (int)response_len;
        e.bytes = (int)response_len;
        e.packet_uid = uid;
        e.wire_hex = wire_hex;
        logger_write(&logger, &e);
        if (status != 101) {
            demo_finish(&logger, "ABORT", "bad-upgrade scenario");
            fclose(out);
            close(fd);
            logger_close(&logger);
            return 1;
        }
    }
    while (!stop_requested) {
        uint8_t opcode;
        uint8_t payload[WS_MAX_PAYLOAD + 1];
        size_t payload_len = 0;
        if (recv_frame(&logger, fd, peer_text, &opcode, payload, &payload_len) != 0) {
            if (scenario && strcmp(scenario, "unexpected-close") == 0) {
                demo_finish(&logger, "ABORT", "unexpected close scenario");
            } else {
                demo_finish(&logger, "ABORT", "frame receive failed");
            }
            fclose(out);
            close(fd);
            logger_close(&logger);
            return 1;
        }
        payload[payload_len] = '\0';
        if (opcode == 0x1U) {
            fwrite(payload, 1, payload_len, out);
            fwrite("\n", 1, 1, out);
        } else if (opcode == 0x9U) {
            if (scenario && strcmp(scenario, "ping-timeout") == 0) {
                continue;
            }
            if (send_frame(&logger, fd, peer_text, 0xAU, payload, payload_len, "PONG", 44) != 0) {
                demo_finish(&logger, "ABORT", "pong send failed");
                fclose(out);
                close(fd);
                logger_close(&logger);
                return 1;
            }
            if (send_frame(&logger, fd, peer_text, 0x1U, (const uint8_t *)"client-ack", 10, "TEXT", 42) != 0) {
                demo_finish(&logger, "ABORT", "text send failed");
                fclose(out);
                close(fd);
                logger_close(&logger);
                return 1;
            }
        } else if (opcode == 0x8U) {
            send_frame(&logger, fd, peer_text, 0x8U, (const uint8_t *)"bye", 3, "CLOSE", 45);
            demo_finish(&logger, "OK", "websocket-basic flow completed");
            fclose(out);
            close(fd);
            logger_close(&logger);
            return 0;
        }
    }
    demo_finish(&logger, "ABORT", "client stopped");
    fclose(out);
    close(fd);
    logger_close(&logger);
    return 1;
}
