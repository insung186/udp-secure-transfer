#include "demo_util.h"
#include "protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define H2_FRAME_HEADER_SIZE 9
#define H2_MAX_FRAME 8192

enum {
    H2_TYPE_DATA          = 0,
    H2_TYPE_HEADERS       = 1,
    H2_TYPE_RST_STREAM    = 3,
    H2_TYPE_SETTINGS      = 4,
    H2_TYPE_PING          = 6,
    H2_TYPE_WINDOW_UPDATE = 8
};

enum {
    H2_PKT_PREFACE = 160,
    H2_PKT_SETTINGS = 161,
    H2_PKT_HEADERS = 162,
    H2_PKT_DATA = 163,
    H2_PKT_WINDOW_UPDATE = 164,
    H2_PKT_PING = 165,
    H2_PKT_RST_STREAM = 166
};

static volatile sig_atomic_t stop_requested = 0;

static void handle_signal(int signo) {
    (void)signo;
    stop_requested = 1;
}

static void put_u16(uint8_t *buf, uint16_t value) {
    uint16_t n = htons(value);
    memcpy(buf, &n, sizeof(n));
}

static void put_u32(uint8_t *buf, uint32_t value) {
    uint32_t n = htonl(value);
    memcpy(buf, &n, sizeof(n));
}

static uint32_t get_u32(const uint8_t *buf) {
    uint32_t n;
    memcpy(&n, buf, sizeof(n));
    return ntohl(n);
}

static void put_u24(uint8_t *buf, uint32_t value) {
    buf[0] = (value >> 16) & 0xff;
    buf[1] = (value >> 8) & 0xff;
    buf[2] = value & 0xff;
}

static void log_h2(Logger *logger, const char *level, const char *event, const char *state,
                   const char *message, const char *peer, const char *direction,
                   int packet_code, const char *packet_type, uint32_t stream_id,
                   const char *header_summary, const uint8_t *wire, size_t wire_len) {
    char wire_hex[321];
    char uid[24];
    LogEvent e;
    demo_init_event(&e, level, event, state, message);
    bytes_to_hex(wire, wire_len > 160 ? 160 : wire_len, wire_hex, sizeof(wire_hex));
    compute_packet_uid(uid, sizeof(uid), (uint16_t)packet_code, (int)stream_id, 0, wire, wire_len);
    e.peer = peer;
    e.direction = direction;
    e.packet_type = packet_type;
    e.packet_code = packet_code;
    e.stream_id = (int)stream_id;
    e.header_summary = header_summary;
    e.payload_length = (int)wire_len;
    e.bytes = (int)wire_len;
    e.packet_uid = uid;
    e.wire_hex = wire_hex;
    logger_write(logger, &e);
}

static int send_h2_frame(int fd, Logger *logger, const char *peer,
                         uint8_t type, uint8_t flags, uint32_t stream_id,
                         const uint8_t *payload, uint32_t payload_len,
                         int packet_code, const char *packet_type,
                         const char *header_summary, const char *event,
                         const char *state) {
    uint8_t wire[H2_MAX_FRAME];
    if (H2_FRAME_HEADER_SIZE + payload_len > H2_MAX_FRAME) return -1;
    put_u24(wire, payload_len);
    wire[3] = type;
    wire[4] = flags;
    put_u32(wire + 5, stream_id);
    if (payload_len > 0) {
        memcpy(wire + H2_FRAME_HEADER_SIZE, payload, payload_len);
    }
    if (demo_write_all(fd, wire, H2_FRAME_HEADER_SIZE + payload_len) != 0) return -1;
    log_h2(logger, "INFO", event, state, "h2 frame sent", peer, "Client -> Server",
           packet_code, packet_type, stream_id, header_summary, wire,
           H2_FRAME_HEADER_SIZE + payload_len);
    return 0;
}

static int hpack_encode_literal(uint8_t *out, size_t cap, const char *name, const char *value) {
    size_t nlen = strlen(name);
    size_t vlen = strlen(value);
    if (nlen > 127 || vlen > 127) return -1;
    if (1 + 1 + nlen + 1 + vlen > cap) return -1;
    out[0] = 0x00;
    out[1] = (uint8_t)nlen;
    memcpy(out + 2, name, nlen);
    out[2 + nlen] = (uint8_t)vlen;
    memcpy(out + 3 + nlen, value, vlen);
    return (int)(3 + nlen + vlen);
}

static int settings_payload(uint8_t *out, size_t cap) {
    if (cap < 6 * 6) return -1;
    size_t pos = 0;
    put_u16(out + pos, 0x0001); pos += 2; put_u32(out + pos, 4096); pos += 4;
    put_u16(out + pos, 0x0002); pos += 2; put_u32(out + pos, 1); pos += 4;
    put_u16(out + pos, 0x0003); pos += 2; put_u32(out + pos, 100); pos += 4;
    put_u16(out + pos, 0x0004); pos += 2; put_u32(out + pos, 65535); pos += 4;
    put_u16(out + pos, 0x0005); pos += 2; put_u32(out + pos, 16384); pos += 4;
    put_u16(out + pos, 0x0006); pos += 2; put_u32(out + pos, 8192); pos += 4;
    return (int)pos;
}

static int read_exact(int fd, uint8_t *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, buf + got, len - got, 0);
        if (n <= 0) return -1;
        got += (size_t)n;
    }
    return 0;
}

int main(int argc, char **argv) {
    Logger logger;
    uint16_t port;
    int fd = -1;
    struct sockaddr_in addr;
    char peer_text[64];
    FILE *out = NULL;
    int rc = 1;
    const char *scenario = getenv("UDP_SECURE_SCENARIO");

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    ensure_runtime_dirs();
    if (logger_open(&logger, "client", "logs/client.jsonl") != 0) {
        return 1;
    }
    if (argc != 4 && argc != 7) {
        demo_finish(&logger, "ABORT", "invalid arguments");
        logger_close(&logger);
        return 1;
    }
    if (parse_port(argv[2], &port) != 0) {
        demo_finish(&logger, "ABORT", "invalid port");
        logger_close(&logger);
        return 1;
    }
    /* 兼容 run_tests.py 传入的 7-arg 格式 */
    const char *out_path = (argc == 7) ? argv[6] : argv[3];
    snprintf(peer_text, sizeof(peer_text), "%s:%u", argv[1], (unsigned)port);
    out = fopen(out_path, "wb");
    if (!out) {
        demo_finish(&logger, "ABORT", "output open failed");
        logger_close(&logger);
        return 1;
    }
    fd = demo_connect_tcp(argv[1], port, &addr);
    if (fd < 0) {
        demo_finish(&logger, "ABORT", "connect failed");
        fclose(out);
        logger_close(&logger);
        return 1;
    }
    {
        LogEvent e;
        demo_init_event(&e, "INFO", "CLIENT_START", "INIT", "http2 client started");
        e.peer = peer_text;
        e.port = (int)port;
        logger_write(&logger, &e);
    }

    /* 1. 发送 client preface (24 字节) */
    const char *PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    if (demo_write_all(fd, (const uint8_t *)PREFACE, 24) != 0) {
        demo_finish(&logger, "ABORT", "preface send failed");
        close(fd);
        fclose(out);
        logger_close(&logger);
        return 1;
    }
    {
        LogEvent e;
        demo_init_event(&e, "INFO", "SEND_PREFACE", "PREFACE", "h2 client preface sent");
        e.peer = peer_text;
        e.packet_type = "PREFACE";
        e.packet_code = H2_PKT_PREFACE;
        e.payload_length = 24;
        e.bytes = 24;
        logger_write(&logger, &e);
    }

    /* 2. 发送 client SETTINGS */
    uint8_t settings[64];
    int slen = settings_payload(settings, sizeof(settings));
    send_h2_frame(fd, &logger, peer_text, H2_TYPE_SETTINGS, 0x00, 0,
                  settings, (uint32_t)slen, H2_PKT_SETTINGS, "SETTINGS", NULL,
                  "SEND_SETTINGS", "SETTINGS");

    /* 3. 接收 server SETTINGS + SETTINGS ACK（两帧，都需要消费掉） */
    for (int settings_idx = 0; settings_idx < 2; settings_idx += 1) {
        uint8_t frame_hdr[9];
        if (read_exact(fd, frame_hdr, 9) != 0) {
            demo_finish(&logger, "ABORT", "server settings read failed");
            close(fd);
            fclose(out);
            logger_close(&logger);
            return 1;
        }
        uint32_t len = ((uint32_t)frame_hdr[0] << 16) | ((uint32_t)frame_hdr[1] << 8) | frame_hdr[2];
        uint8_t full[9 + 64];
        memcpy(full, frame_hdr, 9);
        if (len > 0 && read_exact(fd, full + 9, len) != 0) {
            demo_finish(&logger, "ABORT", "server settings payload failed");
            close(fd);
            fclose(out);
            logger_close(&logger);
            return 1;
        }
        uint8_t frame_type = frame_hdr[3];
        (void)frame_type;
        const char *event_name = (settings_idx == 0 && (frame_hdr[4] & 0x01) == 0) ? "RECV_SETTINGS" : "RECV_SETTINGS_ACK";
        const char *pkt_type = (settings_idx == 0 && (frame_hdr[4] & 0x01) == 0) ? "SETTINGS" : "SETTINGS_ACK";
        log_h2(&logger, "INFO", event_name, "SETTINGS", "server frame received",
               peer_text, "Server -> Client", H2_PKT_SETTINGS, pkt_type, 0, NULL,
               full, 9 + len);
    }
    /* 发送 SETTINGS ACK */
    send_h2_frame(fd, &logger, peer_text, H2_TYPE_SETTINGS, 0x01, 0,
                  NULL, 0, H2_PKT_SETTINGS, "SETTINGS", "ack",
                  "SEND_SETTINGS_ACK", "SETTINGS");

    /* 4. 发送 HEADERS 请求（multiplex 场景：先全部发送，再统一接收响应；
       否则普通场景：每次发送 HEADERS 后等待响应，避免 TCP 死锁） */
    int stream_count = (scenario && strcmp(scenario, "multiplex") == 0) ? 6 : 1;
    /* multiplex: 先发所有 HEADERS */
    if (stream_count > 1) {
        for (int i = 0; i < stream_count; i += 1) {
            uint32_t stream_id = (uint32_t)(i * 2 + 1);
            uint8_t hpack_buf[512];
            size_t hpack_pos = 0;
            char path_buf[32];
            snprintf(path_buf, sizeof(path_buf), "/stream-%d", i);
            hpack_pos += hpack_encode_literal(hpack_buf + hpack_pos, sizeof(hpack_buf) - hpack_pos,
                                               ":method", "GET");
            hpack_pos += hpack_encode_literal(hpack_buf + hpack_pos, sizeof(hpack_buf) - hpack_pos,
                                               ":path", path_buf);
            hpack_pos += hpack_encode_literal(hpack_buf + hpack_pos, sizeof(hpack_buf) - hpack_pos,
                                               ":scheme", "http");
            hpack_pos += hpack_encode_literal(hpack_buf + hpack_pos, sizeof(hpack_buf) - hpack_pos,
                                               ":authority", "demo.local");
            send_h2_frame(fd, &logger, peer_text, H2_TYPE_HEADERS, 0x04, stream_id,
                          hpack_buf, (uint32_t)hpack_pos, H2_PKT_HEADERS, "HEADERS",
                          ":method=GET", "SEND_HEADERS", "HEADERS");
        }
    }
    /* 串行处理：每个 stream 等待 HEADERS + DATA 响应 */
    for (int i = 0; i < stream_count; i += 1) {
        uint32_t stream_id = (uint32_t)(i * 2 + 1);  /* odd-numbered streams from client */
        uint8_t hpack_buf[512];
        size_t hpack_pos = 0;
        const char *path = (stream_count == 1) ? "/index.html" : "/stream-N";
        char path_buf[32];
        if (stream_count > 1) {
            snprintf(path_buf, sizeof(path_buf), "/stream-%d", i);
            path = path_buf;
        }
        hpack_pos += hpack_encode_literal(hpack_buf + hpack_pos, sizeof(hpack_buf) - hpack_pos,
                                           ":method", "GET");
        hpack_pos += hpack_encode_literal(hpack_buf + hpack_pos, sizeof(hpack_buf) - hpack_pos,
                                           ":path", path);
        hpack_pos += hpack_encode_literal(hpack_buf + hpack_pos, sizeof(hpack_buf) - hpack_pos,
                                           ":scheme", "http");
        hpack_pos += hpack_encode_literal(hpack_buf + hpack_pos, sizeof(hpack_buf) - hpack_pos,
                                           ":authority", "demo.local");
        /* hpack-overflow 场景：发一个超长 name */
        if (scenario && strcmp(scenario, "hpack-overflow") == 0) {
            /* encode literal with name length = 200 (>127) — 我们直接放 >127 的 name_len */
            size_t huge_len = 200;
            if (2 + huge_len < sizeof(hpack_buf) - hpack_pos) {
                hpack_buf[hpack_pos++] = 0x00;  /* literal */
                hpack_buf[hpack_pos++] = (uint8_t)huge_len;  /* 教学版溢出 */
                memset(hpack_buf + hpack_pos, 'a', huge_len);
                hpack_pos += huge_len;
            }
        }
        /* END_HEADERS (0x04) - END_STREAM (0x01) on HEADERS: 单 stream 标记为 closed */
        uint8_t flags = 0x04;  /* END_HEADERS only */
        if (stream_count == 1 && (!scenario || strcmp(scenario, "multiplex") != 0)) {
            /* normal: 同一连接上 1 个 stream；DATA 可选 */
            send_h2_frame(fd, &logger, peer_text, H2_TYPE_HEADERS, flags, stream_id,
                          hpack_buf, (uint32_t)hpack_pos, H2_PKT_HEADERS, "HEADERS",
                          ":method=GET", "SEND_HEADERS", "HEADERS");
        }
        /* multiplex: 所有 HEADERS 已在上方发完，这里不再发 */

        /* 接收响应 HEADERS（也可能先到 SETTINGS_ACK；h2-overflow 时也可能到 RST_STREAM） */
        uint8_t frame_hdr[9];
        ssize_t read_rc = read_exact(fd, frame_hdr, 9);
        if (read_rc == 0) {
            uint32_t len = ((uint32_t)frame_hdr[0] << 16) | ((uint32_t)frame_hdr[1] << 8) | frame_hdr[2];
            uint8_t type = frame_hdr[3];
            uint8_t rflags = frame_hdr[4];
            uint32_t rid = get_u32(frame_hdr + 5) & 0x7fffffff;
            uint8_t full[9 + H2_MAX_FRAME];
            if (len < H2_MAX_FRAME && read_exact(fd, full + 9, len) == 0) {
                memcpy(full, frame_hdr, 9);
                if (type == H2_TYPE_HEADERS) {
                    log_h2(&logger, "INFO", "RECV_HEADERS", "HEADERS",
                           "server HEADERS received", peer_text, "Server -> Client",
                           H2_PKT_HEADERS, "HEADERS", rid, ":status=200",
                           full, 9 + len);
                    /* 如果是 hpack-overflow scenario 且 server 没回 RST 而回 HEADERS，
                       说明 server 容忍 — 我们已观测 */
                    /* stream-cancellation: 在 server 回 HEADERS 后客户端主动 RST */
                    if (scenario && strcmp(scenario, "stream-cancellation") == 0) {
                        uint8_t rst_payload[4] = {0, 0, 0, 0x08};  /* CANCEL */
                        send_h2_frame(fd, &logger, peer_text, H2_TYPE_RST_STREAM, 0, stream_id,
                                      rst_payload, 4, H2_PKT_RST_STREAM, "RST_STREAM", NULL,
                                      "SEND_RST_STREAM", "RST_STREAM");
                        demo_finish(&logger, "ABORT", "stream cancelled");
                        close(fd);
                        fclose(out);
                        logger_close(&logger);
                        return 1;
                    }
                } else if (type == H2_TYPE_RST_STREAM) {
                    log_h2(&logger, "WARN", "RECV_RST_STREAM", "RST_STREAM",
                           "server RST_STREAM received", peer_text, "Server -> Client",
                           H2_PKT_RST_STREAM, "RST_STREAM", rid, NULL,
                           full, 9 + len);
                    LogEvent e;
                    demo_init_event(&e, "WARN", "RST_STREAM_RECEIVED", "HPACK",
                                    "client observed server RST_STREAM (hpack overflow detected)");
                    e.peer = peer_text;
                    e.stream_id = (int)rid;
                    logger_write(&logger, &e);
                    demo_finish(&logger, "ABORT", "server RST_STREAM (hpack-overflow scenario)");
                    close(fd);
                    fclose(out);
                    logger_close(&logger);
                    return 1;
                }
            }
            /* 接收 DATA */
            if (read_exact(fd, frame_hdr, 9) == 0) {
                uint32_t len2 = ((uint32_t)frame_hdr[0] << 16) | ((uint32_t)frame_hdr[1] << 8) | frame_hdr[2];
                uint8_t type2 = frame_hdr[3];
                uint32_t rid2 = get_u32(frame_hdr + 5) & 0x7fffffff;
                if (type2 == H2_TYPE_DATA) {
                    uint8_t data[9 + 256];
                    if (len2 < 256 && read_exact(fd, data + 9, len2) == 0) {
                        memcpy(data, frame_hdr, 9);
                        log_h2(&logger, "INFO", "RECV_DATA", "DATA",
                               "server DATA received", peer_text, "Server -> Client",
                               H2_PKT_DATA, "DATA", rid2, NULL,
                               data, 9 + len2);
                        fprintf(out, "stream=%u data=%.*s\n", rid2, (int)len2, (char *)(data + 9));
                        (void)rflags;
                    }
                }
            }
        }
    }

    rc = 0;
    demo_finish(&logger, "OK", "http2 flow completed");
    close(fd);
    fclose(out);
    logger_close(&logger);
    return rc;
}