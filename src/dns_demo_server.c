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

/* 教学版 DNS wire 格式（简化 DNS-over-UDP）：
   Header (12 bytes):
     TXID (2B) | FLAGS (2B) | QDCOUNT (2B) | ANCOUNT (2B) | NSCOUNT (2B) | ARCOUNT (2B)
   Question:
     QNAME (length-prefixed: 1B length + label, 0B terminator)
     QTYPE (2B) | QCLASS (2B)
   Answer:
     ANAME (same format)
     ATYPE (2B) | ACLASS (2B) | TTL (4B) | RDLENGTH (2B) | RDATA
   RCODE 编码在 FLAGS 低 4 位：0=NOERROR, 3=NXDOMAIN */
#define DNS_HEADER_SIZE 12
#define DNS_MAX_NAME 256
#define DNS_MAX_WIRE 1024

enum {
    DNS_PKT_QUERY = 100,
    DNS_PKT_RESPONSE = 101,
    DNS_PKT_AUTH_RESPONSE = 102,
    DNS_PKT_RESPONSE_SUSPICIOUS = 103,
    DNS_PKT_RESPONSE_NXDOMAIN = 104,
    DNS_PKT_CACHE_POISONED = 105,
    DNS_PKT_DOH_REQUEST = 110,
    DNS_PKT_DOH_RESPONSE = 111
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

static uint16_t get_u16(const uint8_t *buf) {
    uint16_t n;
    memcpy(&n, buf, sizeof(n));
    return ntohs(n);
}

static int decode_name(const uint8_t *wire, size_t wire_len, size_t *offset,
                       char *out, size_t out_cap) {
    size_t pos = *offset;
    size_t out_pos = 0;
    int jumped = 0;
    size_t return_to = 0;
    while (pos < wire_len) {
        uint8_t b = wire[pos];
        if (b == 0) {
            pos += 1;
            break;
        }
        if ((b & 0xc0) == 0xc0) {
            /* 压缩指针（教学版不实现实际压缩跳跃，只校验） */
            if (pos + 2 > wire_len) {
                return -1;
            }
            pos += 2;
            jumped = 1;
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
        (void)jumped;
        (void)return_to;
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
                   int qtype, int rcode, int answer_count, const uint8_t *wire, size_t wire_len) {
    char wire_hex[321];
    char uid[24];
    LogEvent e;
    demo_init_event(&e, level, event, state, message);
    bytes_to_hex(wire, wire_len > 160 ? 160 : wire_len, wire_hex, sizeof(wire_hex));
    compute_packet_uid(uid, sizeof(uid), (uint16_t)packet_code, qtype, rcode, wire, wire_len);
    e.peer = peer;
    e.direction = direction;
    e.packet_type = packet_type;
    e.packet_code = packet_code;
    e.path = qname;     /* 复用 path 字段承载 qname（前端有该字段） */
    e.status_code = rcode;
    e.payload_length = (int)wire_len;
    e.bytes = (int)wire_len;
    e.packet_uid = uid;
    e.wire_hex = wire_hex;
    (void)answer_count;
    logger_write(logger, &e);
}

static int build_response(const uint8_t *query, size_t query_len,
                          const char *qname, int qtype, uint16_t txid,
                          int rcode, const char *answer_ip,
                          uint8_t *resp, size_t *resp_len) {
    /* 直接把 query 复制作为 response header，更新 flags / counts。 */
    (void)qname;
    if (query_len < DNS_HEADER_SIZE) {
        return -1;
    }
    memcpy(resp, query, DNS_HEADER_SIZE);
    /* flags: QR=1 (response), OPCODE=0, AA=1, RD=1, RA=1, RCODE=rcode */
    uint16_t flags = (1u << 15) | (1u << 10) | (1u << 8) | (1u << 7) | ((uint16_t)rcode & 0x0f);
    put_u16(resp + 2, flags);
    put_u16(resp + 4, 1);   /* qdcount = 1 (echo) */
    if (rcode == 0 && answer_ip != NULL) {
        put_u16(resp + 6, 1);   /* ancount = 1 */
        put_u16(resp + 8, 0);   /* nscount */
        put_u16(resp + 10, 0);  /* arcount */
    } else {
        put_u16(resp + 6, 0);
        put_u16(resp + 8, 0);
        put_u16(resp + 10, 0);
    }
    (void)txid;
    /* 复制 question 段 */
    size_t pos = DNS_HEADER_SIZE;
    if (pos >= query_len) {
        *resp_len = pos;
        return 0;
    }
    /* 找到 qname 结尾（0 byte） */
    size_t qname_start = pos;
    while (pos < query_len && query[pos] != 0) {
        pos += 1 + query[pos];
    }
    if (pos >= query_len) {
        return -1;
    }
    size_t qname_bytes = pos - qname_start + 1;
    if (DNS_HEADER_SIZE + qname_bytes + 4 > DNS_MAX_WIRE) {
        return -1;
    }
    memcpy(resp + DNS_HEADER_SIZE, query + qname_start, qname_bytes);
    pos = DNS_HEADER_SIZE + qname_bytes;
    /* qtype + qclass */
    put_u16(resp + pos, (uint16_t)qtype);
    put_u16(resp + pos + 2, 1);  /* class IN */
    pos += 4;
    /* answer section: only if NOERROR + has answer_ip */
    if (rcode == 0 && answer_ip != NULL) {
        if (pos + 2 + 2 + 2 + 4 + 2 + 4 > DNS_MAX_WIRE) {
            return -1;
        }
        /* 用压缩指针指向 question name: 0xC0 0x0C (offset 12 = DNS_HEADER_SIZE) */
        resp[pos++] = 0xC0;
        resp[pos++] = 0x0C;
        put_u16(resp + pos, 1);  /* TYPE A */
        pos += 2;
        put_u16(resp + pos, 1);  /* CLASS IN */
        pos += 2;
        put_u32(resp + pos, 60); /* TTL */
        pos += 4;
        put_u16(resp + pos, 4);  /* RDLENGTH */
        pos += 2;
        /* RDATA: 4 bytes IPv4 */
        struct in_addr ip_addr;
        if (inet_pton(AF_INET, answer_ip, &ip_addr) != 1) {
            return -1;
        }
        memcpy(resp + pos, &ip_addr.s_addr, 4);
        pos += 4;
    }
    *resp_len = pos;
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
    (void)argv[2];  /* password */
    (void)argv[3];  /* input path */
    listener = socket(AF_INET, SOCK_DGRAM, 0);
    if (listener < 0) {
        demo_finish(&logger, "ABORT", strerror(errno));
        logger_close(&logger);
        return 1;
    }
    {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons(port);
        if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            demo_finish(&logger, "ABORT", strerror(errno));
            close(listener);
            logger_close(&logger);
            return 1;
        }
    }
    {
        struct timeval tv = {5, 0};
        setsockopt(listener, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    {
        LogEvent e;
        demo_init_event(&e, "INFO", "SERVER_START", "INIT", "dns server started");
        e.port = (int)port;
        logger_write(&logger, &e);
    }

    /* 仅接受一个 query（教学 demo 一次性交互） */
    {
        struct sockaddr_in peer_addr;
        socklen_t peer_len = sizeof(peer_addr);
        uint8_t query[DNS_MAX_WIRE];
        ssize_t n = recvfrom(listener, query, sizeof(query), 0,
                             (struct sockaddr *)&peer_addr, &peer_len);
        if (n <= 0) {
            demo_finish(&logger, "ABORT", "no query received");
            close(listener);
            logger_close(&logger);
            return 1;
        }
        char peer[64];
        peer_to_string(&peer_addr, peer, sizeof(peer));
        if ((size_t)n < DNS_HEADER_SIZE) {
            demo_finish(&logger, "ABORT", "query too short");
            close(listener);
            logger_close(&logger);
            return 1;
        }
        uint16_t txid = get_u16(query);
        uint16_t qdcount = get_u16(query + 4);
        if (qdcount != 1) {
            demo_finish(&logger, "ABORT", "only 1 question supported");
            close(listener);
            logger_close(&logger);
            return 1;
        }
        /* 解析 qname + qtype */
        size_t off = DNS_HEADER_SIZE;
        char qname[DNS_MAX_NAME];
        if (decode_name(query, (size_t)n, &off, qname, sizeof(qname)) != 0) {
            demo_finish(&logger, "ABORT", "bad qname encoding");
            close(listener);
            logger_close(&logger);
            return 1;
        }
        if (off + 4 > (size_t)n) {
            demo_finish(&logger, "ABORT", "truncated question");
            close(listener);
            logger_close(&logger);
            return 1;
        }
        uint16_t qtype = get_u16(query + off);
        uint16_t qclass = get_u16(query + off + 2);
        log_dns(&logger, "INFO", "RECV_QUERY", "QUERY", "dns query received",
                peer, "Client -> Server", DNS_PKT_QUERY, "DNS_QUERY", qname,
                (int)qtype, 0, 0, query, (size_t)n);

        /* 决定响应 */
        uint8_t response[DNS_MAX_WIRE];
        size_t response_len = 0;
        int rcode = 0;
        const char *answer_ip = "1.2.3.4";

        if (scenario && strcmp(scenario, "spoofed-response") == 0) {
            /* 立即发送伪造应答（txid 匹配，但 rdata 是恶意 IP） */
            int sr = build_response(query, (size_t)n, qname, (int)qtype, txid, 0,
                                    "6.6.6.6", response, &response_len);
            if (sr == 0) {
                sendto(listener, response, response_len, 0,
                       (const struct sockaddr *)&peer_addr, peer_len);
                log_dns(&logger, "WARN", "SPOOFED_RESPONSE_SENT", "SPOOF",
                        "spoofed DNS response sent (txid match, fake IP)",
                        peer, "Server -> Client", DNS_PKT_RESPONSE_SUSPICIOUS,
                        "DNS_RESPONSE_SUSPICIOUS", qname, (int)qtype, 0, 1,
                        response, response_len);
            }
        } else if (scenario && strcmp(scenario, "nxdomain-redir") == 0) {
            rcode = 3;  /* NXDOMAIN */
            answer_ip = NULL;
            log_dns(&logger, "WARN", "NXDOMAIN_RESPONDED", "REDIR",
                    "non-existent domain redirected",
                    peer, "Server -> Client", DNS_PKT_RESPONSE_NXDOMAIN,
                    "DNS_RESPONSE_NXDOMAIN", qname, (int)qtype, rcode, 0,
                    NULL, 0);
            (void)qclass;
        } else if (scenario && strcmp(scenario, "doh-tls") == 0) {
            /* DoH 场景：标记 cache poisoned（实际不实现真实 DoH，演示降级告警） */
            log_dns(&logger, "INFO", "DOH_TLS_NOT_IMPLEMENTED", "WARN",
                    "DoH-TLS not implemented in this teaching demo; falling back to plain UDP",
                    peer, "Observed", DNS_PKT_CACHE_POISONED, "DNS_CACHE_POISONED",
                    qname, (int)qtype, 0, 0, NULL, 0);
        }

        /* normal + 其他场景：发送 NOERROR + 1.2.3.4 */
        if (build_response(query, (size_t)n, qname, (int)qtype, txid, rcode,
                           rcode == 0 ? answer_ip : NULL, response, &response_len) == 0) {
            if (sendto(listener, response, response_len, 0,
                       (const struct sockaddr *)&peer_addr, peer_len) != (ssize_t)response_len) {
                demo_finish(&logger, "ABORT", "response send failed");
                close(listener);
                logger_close(&logger);
                return 1;
            }
            const char *evt = (rcode == 3) ? "SEND_NXDOMAIN" : "SEND_RESPONSE";
            log_dns(&logger, "INFO", evt, "RESPONSE", "dns response sent",
                    peer, "Server -> Client", DNS_PKT_RESPONSE, "DNS_RESPONSE",
                    qname, (int)qtype, rcode, rcode == 0 ? 1 : 0, response, response_len);
        }
        rc = 0;
    }

    if (rc == 0) {
        demo_finish(&logger, "OK", "dns flow completed");
    } else {
        demo_finish(&logger, "ABORT", "dns flow failed");
    }
    close(listener);
    logger_close(&logger);
    return rc;
}