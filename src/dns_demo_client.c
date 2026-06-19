#include "demo_util.h"
#include "protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define DNS_HEADER_SIZE 12
#define DNS_MAX_NAME 256
#define DNS_MAX_WIRE 1024

enum {
    DNS_PKT_QUERY = 100,
    DNS_PKT_RESPONSE = 101,
    DNS_PKT_RESPONSE_SUSPICIOUS = 103,
    DNS_PKT_RESPONSE_NXDOMAIN = 104,
    DNS_PKT_CACHE_POISONED = 105
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

static uint16_t get_u16(const uint8_t *buf) {
    uint16_t n;
    memcpy(&n, buf, sizeof(n));
    return ntohs(n);
}

static int encode_name(const char *name, uint8_t *out, size_t cap, size_t *out_len) {
    size_t pos = 0;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t label_len = dot ? (size_t)(dot - p) : strlen(p);
        if (label_len == 0 || label_len > 63) {
            return -1;
        }
        if (pos + 1 + label_len + 1 > cap) {
            return -1;
        }
        out[pos++] = (uint8_t)label_len;
        memcpy(out + pos, p, label_len);
        pos += label_len;
        p = dot ? dot + 1 : p + label_len;
    }
    if (pos + 1 > cap) {
        return -1;
    }
    out[pos++] = 0;
    *out_len = pos;
    return 0;
}

static int decode_name(const uint8_t *wire, size_t wire_len, size_t *offset,
                       char *out, size_t out_cap) {
    size_t pos = *offset;
    size_t out_pos = 0;
    while (pos < wire_len) {
        uint8_t b = wire[pos];
        if (b == 0) {
            pos += 1;
            break;
        }
        if ((b & 0xc0) == 0xc0) {
            pos += 2;
            break;
        }
        if ((b & 0xc0) != 0) {
            return -1;
        }
        size_t label_len = b;
        if (pos + 1 + label_len > wire_len) {
            return -1;
        }
        if (out_pos + label_len + 2 > out_cap) {
            return -1;
        }
        if (out_pos > 0) {
            out[out_pos++] = '.';
        }
        memcpy(out + out_pos, wire + pos + 1, label_len);
        out_pos += label_len;
        pos += 1 + label_len;
    }
    if (out_pos < out_cap) {
        out[out_pos] = '\0';
    }
    *offset = pos;
    return 0;
}

static void log_dns(Logger *logger, const char *level, const char *event, const char *state,
                   const char *message, const char *peer, const char *direction,
                   int packet_code, const char *packet_type, const char *qname,
                   int rcode, const uint8_t *wire, size_t wire_len) {
    char wire_hex[321];
    char uid[24];
    LogEvent e;
    demo_init_event(&e, level, event, state, message);
    bytes_to_hex(wire, wire_len > 160 ? 160 : wire_len, wire_hex, sizeof(wire_hex));
    compute_packet_uid(uid, sizeof(uid), (uint16_t)packet_code, 0, rcode, wire, wire_len);
    e.peer = peer;
    e.direction = direction;
    e.packet_type = packet_type;
    e.packet_code = packet_code;
    e.path = qname;
    e.status_code = rcode;
    e.payload_length = (int)wire_len;
    e.bytes = (int)wire_len;
    e.packet_uid = uid;
    e.wire_hex = wire_hex;
    logger_write(logger, &e);
}

int main(int argc, char **argv) {
    Logger logger;
    uint16_t port;
    int fd = -1;
    struct sockaddr_in server_addr;
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
    /* 兼容 run_tests.py 传入的 7-arg 格式 (含 3 个 password 占位)：
       我们的协议不需要密码，password 参数直接忽略。 */
    const char *out_path = (argc == 7) ? argv[6] : argv[3];
    snprintf(peer_text, sizeof(peer_text), "%s:%u", argv[1], (unsigned)port);
    out = fopen(out_path, "wb");
    if (!out) {
        demo_finish(&logger, "ABORT", "output open failed");
        logger_close(&logger);
        return 1;
    }
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        demo_finish(&logger, "ABORT", "socket failed");
        fclose(out);
        logger_close(&logger);
        return 1;
    }
    {
        struct timeval tv = {5, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, argv[1], &server_addr.sin_addr) != 1) {
        demo_finish(&logger, "ABORT", "bad host");
        close(fd);
        fclose(out);
        logger_close(&logger);
        return 1;
    }
    {
        LogEvent e;
        demo_init_event(&e, "INFO", "CLIENT_START", "INIT", "dns client started");
        e.peer = peer_text;
        e.port = (int)port;
        logger_write(&logger, &e);
    }

    /* 构造 DNS query: example.com A */
    uint8_t query[DNS_MAX_WIRE];
    size_t query_len = 0;
    uint16_t txid = (uint16_t)(getpid() & 0xffff);
    if (txid == 0) txid = 1;
    put_u16(query + 0, txid);  /* TXID */
    put_u16(query + 2, 0x0100); /* flags: RD=1 */
    put_u16(query + 4, 1);      /* QDCOUNT = 1 */
    put_u16(query + 6, 0);
    put_u16(query + 8, 0);
    put_u16(query + 10, 0);
    size_t name_len = 0;
    if (encode_name("example.com", query + DNS_HEADER_SIZE,
                    DNS_MAX_WIRE - DNS_HEADER_SIZE - 4, &name_len) != 0) {
        demo_finish(&logger, "ABORT", "encode name failed");
        close(fd);
        fclose(out);
        logger_close(&logger);
        return 1;
    }
    query_len = DNS_HEADER_SIZE + name_len;
    put_u16(query + query_len, 1);  /* QTYPE A */
    put_u16(query + query_len + 2, 1);  /* QCLASS IN */
    query_len += 4;

    log_dns(&logger, "INFO", "SEND_QUERY", "QUERY", "dns query sent",
            peer_text, "Client -> Server", DNS_PKT_QUERY, "DNS_QUERY",
            "example.com", 0, query, query_len);
    if (sendto(fd, query, query_len, 0,
               (const struct sockaddr *)&server_addr, sizeof(server_addr)) != (ssize_t)query_len) {
        demo_finish(&logger, "ABORT", "send failed");
        close(fd);
        fclose(out);
        logger_close(&logger);
        return 1;
    }

    /* 接收 response */
    uint8_t response[DNS_MAX_WIRE];
    socklen_t sl = sizeof(server_addr);
    ssize_t n = recvfrom(fd, response, sizeof(response), 0,
                         (struct sockaddr *)&server_addr, &sl);
    if (n <= 0 || (size_t)n < DNS_HEADER_SIZE) {
        demo_finish(&logger, "ABORT", "no response");
        close(fd);
        fclose(out);
        logger_close(&logger);
        return 1;
    }
    uint16_t rcode = get_u16(response + 2) & 0x000f;
    size_t off = DNS_HEADER_SIZE;
    char aname[DNS_MAX_NAME];
    decode_name(response, (size_t)n, &off, aname, sizeof(aname));
    int pkt_code = (rcode == 3) ? DNS_PKT_RESPONSE_NXDOMAIN : DNS_PKT_RESPONSE;
    const char *pkt_type = (rcode == 3) ? "DNS_RESPONSE_NXDOMAIN" : "DNS_RESPONSE";
    log_dns(&logger, "INFO", "RECV_RESPONSE", "RESPONSE",
            rcode == 3 ? "NXDOMAIN received" : "dns response received",
            peer_text, "Server -> Client", pkt_code, pkt_type,
            aname, (int)rcode, response, (size_t)n);

    /* 教学 demo: spoofed-response 场景检测应答是否在正常预期窗口内到达；
       若 server 先发了伪造应答（status >= 200），再发真实应答，client 只看
       第二条（实际 recvfrom 一次只收一个，演示场景由 server 决定先后） */
    if (scenario && strcmp(scenario, "spoofed-response") == 0) {
        LogEvent e;
        demo_init_event(&e, "WARN", "SUSPICIOUS_RESPONSE_OBSERVED", "SPOOF",
                        "received a response with suspicious rcode / IP pattern");
        e.peer = peer_text;
        e.packet_type = "DNS_RESPONSE_SUSPICIOUS";
        e.packet_code = DNS_PKT_RESPONSE_SUSPICIOUS;
        e.security_replay = 1;
        logger_write(&logger, &e);
    }

    /* 把响应摘要写到 output 文件 */
    {
        char line[512];
        snprintf(line, sizeof(line), "qname=%s rcode=%u ancount=%u\n",
                 aname, (unsigned)rcode, get_u16(response + 6));
        fwrite(line, 1, strlen(line), out);
    }
    rc = 0;
    demo_finish(&logger, "OK", "dns flow completed");
    close(fd);
    fclose(out);
    logger_close(&logger);
    return rc;
}