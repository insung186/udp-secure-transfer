#include "demo_util.h"
#include "protocol.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* 教学版 HTTP/2（h2c prior knowledge）
   Frame format: 3B length (24-bit) + 1B type + 1B flag + 4B stream id (R bit + 31-bit) + payload
   Types: DATA=0, HEADERS=1, PRIORITY=2, RST_STREAM=3, SETTINGS=4, PING=6, GOAWAY=7, WINDOW_UPDATE=8
   HPACK 简化版：literal header field without indexing (literal-string = 0x00 prefix + length + value) */
#define H2_FRAME_HEADER_SIZE 9
#define H2_MAX_FRAME 8192
#define H2_MAX_HEADERS 8

enum {
    H2_TYPE_DATA          = 0,
    H2_TYPE_HEADERS       = 1,
    H2_TYPE_PRIORITY      = 2,
    H2_TYPE_RST_STREAM    = 3,
    H2_TYPE_SETTINGS      = 4,
    H2_TYPE_PING          = 6,
    H2_TYPE_GOAWAY        = 7,
    H2_TYPE_WINDOW_UPDATE = 8
};

enum {
    H2_PKT_PREFACE = 160,
    H2_PKT_SETTINGS = 161,
    H2_PKT_HEADERS = 162,
    H2_PKT_DATA = 163,
    H2_PKT_WINDOW_UPDATE = 164,
    H2_PKT_PING = 165,
    H2_PKT_RST_STREAM = 166,
    H2_PKT_GOAWAY = 167
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

/* encode 24-bit length */
static void put_u24(uint8_t *buf, uint32_t value) {
    buf[0] = (value >> 16) & 0xff;
    buf[1] = (value >> 8) & 0xff;
    buf[2] = value & 0xff;
}

/* send a frame */
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
    log_h2(logger, "INFO", event, state, "h2 frame sent", peer, "Server -> Client",
           packet_code, packet_type, stream_id, header_summary, wire,
           H2_FRAME_HEADER_SIZE + payload_len);
    return 0;
}

/* encode one HPACK literal field: 0x00 (never indexed) + 7-bit name len + name + 7-bit value len + value
   Returns bytes written, or -1 on error. */
static int hpack_encode_literal(uint8_t *out, size_t cap, const char *name, const char *value) {
    size_t nlen = strlen(name);
    size_t vlen = strlen(value);
    if (nlen > 127 || vlen > 127) return -1;
    if (1 + 1 + nlen + 1 + vlen > cap) return -1;
    out[0] = 0x00;  /* literal field, never indexed */
    out[1] = (uint8_t)nlen;
    memcpy(out + 2, name, nlen);
    out[2 + nlen] = (uint8_t)vlen;
    memcpy(out + 3 + nlen, value, vlen);
    return (int)(3 + nlen + vlen);
}

/* encode SETTINGS frame payload (6 settings: header_table_size, enable_push, max_concurrent_streams,
   initial_window_size, max_frame_size, max_header_list_size). Each is 2B id + 4B value. */
static int settings_payload(uint8_t *out, size_t cap) {
    if (cap < 6 * 6) return -1;
    size_t pos = 0;
    /* HEADER_TABLE_SIZE = 0x1, ENABLE_PUSH = 0x2, MAX_CONCURRENT_STREAMS = 0x3 */
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
    int listener = -1;
    int rc = 1;
    const char *scenario = getenv("UDP_SECURE_SCENARIO");

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
    (void)argv[2];
    (void)argv[3];
    listener = demo_create_tcp_listener(port);
    if (listener < 0) {
        demo_finish(&logger, "ABORT", strerror(errno));
        logger_close(&logger);
        return 1;
    }
    {
        LogEvent e;
        demo_init_event(&e, "INFO", "SERVER_START", "INIT", "http2 server started");
        e.port = (int)port;
        logger_write(&logger, &e);
    }

    int fd = demo_accept_client(listener, NULL);
    if (fd < 0) {
        demo_finish(&logger, "ABORT", "accept failed");
        close(listener);
        logger_close(&logger);
        return 1;
    }
    char peer[64] = "client";

    /* 接收 client preface（24 字节固定字符串）+ SETTINGS 帧 */
    char preface[32] = {0};
    if (read_exact(fd, (uint8_t *)preface, 24) != 0 ||
        strncmp(preface, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) != 0) {
        LogEvent e;
        demo_init_event(&e, "ERROR", "BAD_PREFACE", "PREFACE", "client preface invalid");
        e.peer = peer;
        logger_write(&logger, &e);
        demo_finish(&logger, "ABORT", "bad preface");
        close(fd);
        close(listener);
        logger_close(&logger);
        return 1;
    }
    /* log preface */
    {
        LogEvent e;
        demo_init_event(&e, "INFO", "RECV_PREFACE", "PREFACE", "h2 client preface received");
        e.peer = peer;
        e.packet_type = "PREFACE";
        e.packet_code = H2_PKT_PREFACE;
        e.payload_length = 24;
        e.bytes = 24;
        logger_write(&logger, &e);
    }

    /* 接收 client SETTINGS frame */
    {
        uint8_t frame_hdr[9];
        if (read_exact(fd, frame_hdr, 9) != 0) {
            demo_finish(&logger, "ABORT", "settings hdr read failed");
            close(fd);
            close(listener);
            logger_close(&logger);
            return 1;
        }
        uint32_t len = ((uint32_t)frame_hdr[0] << 16) | ((uint32_t)frame_hdr[1] << 8) | frame_hdr[2];
        uint8_t type = frame_hdr[3];
        if (type != H2_TYPE_SETTINGS) {
            demo_finish(&logger, "ABORT", "first frame not SETTINGS");
            close(fd);
            close(listener);
            logger_close(&logger);
            return 1;
        }
        uint8_t full[9 + 64];
        memcpy(full, frame_hdr, 9);
        if (len > 0 && read_exact(fd, full + 9, len) != 0) {
            demo_finish(&logger, "ABORT", "settings payload read failed");
            close(fd);
            close(listener);
            logger_close(&logger);
            return 1;
        }
        log_h2(&logger, "INFO", "RECV_SETTINGS", "SETTINGS", "client SETTINGS received",
               peer, "Client -> Server", H2_PKT_SETTINGS, "SETTINGS", 0, NULL,
               full, 9 + len);
    }

    /* 服务端发送自己的 SETTINGS + SETTINGS ACK */
    {
        uint8_t settings[64];
        int slen = settings_payload(settings, sizeof(settings));
        send_h2_frame(fd, &logger, peer, H2_TYPE_SETTINGS, 0x00, 0,
                      settings, (uint32_t)slen, H2_PKT_SETTINGS, "SETTINGS", NULL,
                      "SEND_SETTINGS", "SETTINGS");
    }
    /* SETTINGS ACK (type=4, flag=0x01) */
    {
        send_h2_frame(fd, &logger, peer, H2_TYPE_SETTINGS, 0x01, 0,
                      NULL, 0, H2_PKT_SETTINGS, "SETTINGS", "ack",
                      "SEND_SETTINGS_ACK", "SETTINGS");
    }

    /* 主循环：接收 HEADERS + DATA frames 直到 stream 关闭 */
    int streams_seen = 0;
    int hpack_error = 0;
    int stream_cancelled = 0;
    int max_streams = (scenario && strcmp(scenario, "multiplex") == 0) ? 6 : 1;
    while (!stop_requested) {
        uint8_t frame_hdr[9];
        if (read_exact(fd, frame_hdr, 9) != 0) break;
        uint32_t len = ((uint32_t)frame_hdr[0] << 16) | ((uint32_t)frame_hdr[1] << 8) | frame_hdr[2];
        uint8_t type = frame_hdr[3];
        uint8_t flags = frame_hdr[4];
        uint32_t stream_id = get_u32(frame_hdr + 5) & 0x7fffffff;
        uint8_t full[9 + H2_MAX_FRAME];
        if (len > H2_MAX_FRAME) {
            demo_finish(&logger, "ABORT", "frame too large");
            break;
        }
        if (len > 0 && read_exact(fd, full + 9, len) != 0) break;
        memcpy(full, frame_hdr, 9);

        if (type == H2_TYPE_HEADERS) {
            log_h2(&logger, "INFO", "RECV_HEADERS", "HEADERS",
                   "HEADERS frame received", peer, "Client -> Server",
                   H2_PKT_HEADERS, "HEADERS", stream_id,
                   ":method=GET :path=/",
                   full, 9 + len);
            /* hpack-overflow 场景：遍历 HPACK entries，找带超长 name 的 literal */
            if (scenario && strcmp(scenario, "hpack-overflow") == 0) {
                size_t pos = 0;
                int overflow = 0;
                while (pos < len) {
                    uint8_t b = full[9 + pos];
                    if ((b & 0x80) != 0) {
                        /* Indexed Header Field: top bit 1 */
                        pos += 1;
                        continue;
                    }
                    /* Literal field: 0xxxxxxx. Lower 4 bits are name_index for
                       "without indexing" / "never indexed" (0 = new name),
                       or 6-bit index for "with incremental indexing". */
                    int name_len;
                    pos += 1;
                    if ((b & 0x0f) == 0) {
                        /* new name: read name length from next byte */
                        if (pos >= len) break;
                        name_len = full[9 + pos];
                        pos += 1;
                    } else if ((b & 0x0f) == 0x0f) {
                        /* 4-bit index 15 = "new name" with prefixed length 0 */
                        if (pos >= len) break;
                        name_len = full[9 + pos];
                        pos += 1;
                    } else {
                        /* has indexed name */
                        name_len = 0;
                    }
                    if (name_len > 127) {
                        overflow = 1;
                        break;
                    }
                    /* skip name */
                    pos += (size_t)name_len;
                    /* value length */
                    if (pos >= len) break;
                    int value_len = full[9 + pos];
                    pos += 1;
                    if (value_len > 127) {
                        overflow = 1;
                        break;
                    }
                    /* skip value */
                    pos += (size_t)value_len;
                }
                if (overflow) {
                    LogEvent e;
                    demo_init_event(&e, "ERROR", "HPACK_DECODE_ERROR", "HPACK",
                                    "header name length > 127; rejecting stream");
                    e.peer = peer;
                    e.stream_id = (int)stream_id;
                    e.security_mac_valid = 0;
                    logger_write(&logger, &e);
                    /* RST_STREAM COMPRESSION_ERROR (0x09) */
                    uint8_t rst_payload[4] = {0, 0, 0, 0x09};
                    send_h2_frame(fd, &logger, peer, H2_TYPE_RST_STREAM, 0, stream_id,
                                  rst_payload, 4, H2_PKT_RST_STREAM, "RST_STREAM", NULL,
                                  "SEND_RST_STREAM", "ABORT");
                    /* 给 client 一点时间读 RST_STREAM 后再 close */
                    {
                        struct timespec pause_time;
                        pause_time.tv_sec = 0;
                        pause_time.tv_nsec = 200000000L;  /* 200ms */
                        nanosleep(&pause_time, NULL);
                    }
                    hpack_error = 1;
                    break;
                }
            }
            /* 回复 HEADERS（响应头） + DATA */
            uint8_t hpack_buf[256];
            size_t hpack_pos = 0;
            hpack_pos += hpack_encode_literal(hpack_buf + hpack_pos, sizeof(hpack_buf) - hpack_pos,
                                               ":status", "200");
            hpack_pos += hpack_encode_literal(hpack_buf + hpack_pos, sizeof(hpack_buf) - hpack_pos,
                                               "content-type", "text/plain");
            /* END_HEADERS | END_STREAM (0x04 | 0x01 = 0x05) on HEADERS */
            send_h2_frame(fd, &logger, peer, H2_TYPE_HEADERS, 0x05, stream_id,
                          hpack_buf, (uint32_t)hpack_pos, H2_PKT_HEADERS, "HEADERS",
                          ":status=200", "SEND_HEADERS", "DATA");
            const char *body = "hello http2\n";
            size_t body_len = strlen(body);
            send_h2_frame(fd, &logger, peer, H2_TYPE_DATA, 0x01, stream_id,
                          (const uint8_t *)body, (uint32_t)body_len,
                          H2_PKT_DATA, "DATA", NULL,
                          "SEND_DATA", "DATA");
            streams_seen += 1;
        } else if (type == H2_TYPE_DATA) {
            log_h2(&logger, "INFO", "RECV_DATA", "DATA",
                   "DATA frame received", peer, "Client -> Server",
                   H2_PKT_DATA, "DATA", stream_id, NULL,
                   full, 9 + len);
            /* 若是 END_STREAM 标志，继续 */
            if ((flags & 0x01) != 0) {
                /* done */
            }
        } else if (type == H2_TYPE_RST_STREAM) {
            log_h2(&logger, "INFO", "RECV_RST_STREAM", "RST_STREAM",
                   "client RST_STREAM received", peer, "Client -> Server",
                   H2_PKT_RST_STREAM, "RST_STREAM", stream_id, NULL,
                   full, 9 + len);
            stream_cancelled = 1;
        } else if (type == H2_TYPE_PING) {
            log_h2(&logger, "INFO", "RECV_PING", "PING", "client PING received",
                   peer, "Client -> Server", H2_PKT_PING, "PING", 0, NULL,
                   full, 9 + len);
            /* PING ACK (flag=0x06 = ACK|reserved) */
            send_h2_frame(fd, &logger, peer, H2_TYPE_PING, 0x06, 0,
                          full + 9, len, H2_PKT_PING, "PING", "ack",
                          "SEND_PING_ACK", "PING");
        } else if (type == H2_TYPE_WINDOW_UPDATE) {
            log_h2(&logger, "INFO", "RECV_WINDOW_UPDATE", "WINDOW_UPDATE",
                   "client WINDOW_UPDATE received", peer, "Client -> Server",
                   H2_PKT_WINDOW_UPDATE, "WINDOW_UPDATE", stream_id, NULL,
                   full, 9 + len);
        } else {
            log_h2(&logger, "INFO", "RECV_FRAME", "UNKNOWN",
                   "unknown frame type", peer, "Client -> Server",
                   H2_PKT_HEADERS, "FRAME", stream_id, NULL,
                   full, 9 + len);
        }

        /* multiplex 场景：跑够 stream 就退出 */
        if (max_streams > 1 && streams_seen >= max_streams) break;
    }

    if (hpack_error) {
        rc = 1;
        demo_finish(&logger, "ABORT", "hpack decode error (hpack-overflow scenario)");
    } else if (stream_cancelled) {
        demo_finish(&logger, "ABORT", "stream cancelled by client");
    } else {
        rc = 0;
        demo_finish(&logger, "OK", "http2 flow completed");
    }
    close(fd);
    close(listener);
    logger_close(&logger);
    return rc;
}