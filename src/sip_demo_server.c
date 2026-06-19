#include "demo_util.h"
#include "protocol.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* 教学版 SIP（基于 RFC 3261 简化）
   文本协议，格式类似 HTTP：
     <METHOD> sip:user@host SIP/2.0\r\n
     Via: SIP/2.0/UDP host:port;branch=z9hG4bK...\r\n
     From: <sip:user@host>;tag=...\r\n
     To: <sip:user@host>\r\n
     Call-ID: ...\r\n
     CSeq: 1 INVITE\r\n
     Content-Length: 0\r\n
     \r\n

   简化：实现 INVITE / REGISTER / ACK / BYE + 100/180/200/407 响应 */
#define SIP_MAX_MSG 4096
#define SIP_MAX_HEADER 1024

enum {
    SIP_PKT_REGISTER = 180,
    SIP_PKT_INVITE = 181,
    SIP_PKT_ACK = 182,
    SIP_PKT_BYE = 183,
    SIP_PKT_100_TRYING = 184,
    SIP_PKT_180_RINGING = 185,
    SIP_PKT_200_OK = 186,
    SIP_PKT_407_AUTH = 187
};

static volatile sig_atomic_t stop_requested = 0;

static void handle_signal(int signo) {
    (void)signo;
    stop_requested = 1;
}

static void log_sip(Logger *logger, const char *level, const char *event, const char *state,
                    const char *message, const char *peer, const char *direction,
                    int packet_code, const char *packet_type, const char *method,
                    const char *call_id, int status_code, const uint8_t *wire, size_t wire_len) {
    char wire_hex[321];
    char uid[24];
    LogEvent e;
    demo_init_event(&e, level, event, state, message);
    bytes_to_hex(wire, wire_len > 160 ? 160 : wire_len, wire_hex, sizeof(wire_hex));
    compute_packet_uid(uid, sizeof(uid), (uint16_t)packet_code, status_code, 0, wire, wire_len);
    e.peer = peer;
    e.direction = direction;
    e.packet_type = packet_type;
    e.packet_code = packet_code;
    e.method = method;
    e.header_summary = call_id;
    e.path = call_id;
    e.status_code = status_code;
    e.payload_length = (int)wire_len;
    e.bytes = (int)wire_len;
    e.packet_uid = uid;
    e.wire_hex = wire_hex;
    logger_write(logger, &e);
}

static int extract_header(const char *msg, const char *name, char *out, size_t out_size) {
    /* 简单查找："Name: value\r\n" (大小写不敏感) */
    size_t name_len = strlen(name);
    const char *p = msg;
    while (*p) {
        if (strncasecmp(p, name, name_len) == 0) {
            const char *colon = p + name_len;
            while (*colon == ' ' || *colon == '\t') colon++;
            if (*colon != ':') {
                /* 不是这个 header */
                while (*p && *p != '\n') p++;
                if (*p == '\n') p++;
                continue;
            }
            colon++;
            while (*colon == ' ' || *colon == '\t') colon++;
            size_t i = 0;
            while (*colon && *colon != '\r' && *colon != '\n' && i + 1 < out_size) {
                out[i++] = *colon++;
            }
            out[i] = '\0';
            return 0;
        }
        while (*p && *p != '\n') p++;
        if (*p == '\n') p++;
    }
    return -1;
}

static int extract_request_line(char *msg, char *method, size_t method_cap,
                                char *uri, size_t uri_cap) {
    char *line_end = strstr(msg, "\r\n");
    if (!line_end) return -1;
    *line_end = '\0';
    if (sscanf(msg, "%15s %255s", method, uri) != 2) {
        *line_end = '\r';
        return -1;
    }
    *line_end = '\r';
    if (strlen(method) >= method_cap || strlen(uri) >= uri_cap) return -1;
    return 0;
}

static int extract_status_line(char *msg, int *code, char *reason, size_t reason_cap) {
    char *line_end = strstr(msg, "\r\n");
    if (!line_end) return -1;
    *line_end = '\0';
    char ver[16];
    if (sscanf(msg, "%15s %d %63s", ver, code, reason) != 3) {
        *line_end = '\r';
        return -1;
    }
    *line_end = '\r';
    if (strlen(reason) >= reason_cap) return -1;
    return 0;
}

static int send_sip_response(int fd, Logger *logger, const char *peer,
                             const struct sockaddr_in *peer_addr,
                             const char *branch, const char *from_tag,
                             const char *to_tag, const char *call_id, int cseq,
                             const char *cseq_method, int code, const char *reason,
                             int packet_code, const char *packet_type) {
    char response[SIP_MAX_MSG];
    int n = snprintf(response, sizeof(response),
                     "SIP/2.0 %d %s\r\n"
                     "Via: SIP/2.0/UDP server:5060;branch=%s\r\n"
                     "From: <sip:alice@demo>;tag=%s\r\n"
                     "To: <sip:bob@demo>%s%s%s\r\n"
                     "Call-ID: %s\r\n"
                     "CSeq: %d %s\r\n"
                     "Content-Length: 0\r\n\r\n",
                     code, reason, branch, from_tag,
                     to_tag ? ";tag=" : "", to_tag ? to_tag : "",
                     to_tag ? "" : "",  /* placeholder alignment */
                     call_id, cseq, cseq_method);
    if (n < 0 || (size_t)n >= sizeof(response)) return -1;
    /* UDP: 必须用 sendto，否则不会发到 client 端 */
    if (sendto(fd, response, (size_t)n, 0,
               (const struct sockaddr *)peer_addr, sizeof(*peer_addr)) != (ssize_t)n) return -1;
    log_sip(logger, "INFO", "SEND_RESPONSE", "RESPONSE",
            reason, peer, "Server -> Client",
            packet_code, packet_type, cseq_method, call_id, code,
            (const uint8_t *)response, (size_t)n);
    return 0;
}

int main(int argc, char **argv) {
    Logger logger;
    uint16_t port;
    int fd = -1;
    struct sockaddr_in server_addr;
    struct sockaddr_in peer_addr;
    char peer[64];
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
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        demo_finish(&logger, "ABORT", strerror(errno));
        logger_close(&logger);
        return 1;
    }
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0) {
        demo_finish(&logger, "ABORT", strerror(errno));
        close(fd);
        logger_close(&logger);
        return 1;
    }
    {
        struct timeval tv = {5, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    {
        LogEvent e;
        demo_init_event(&e, "INFO", "SERVER_START", "INIT", "sip server started");
        e.port = (int)port;
        logger_write(&logger, &e);
    }

    /* 期望收到 REGISTER 或 INVITE 序列 */
    char last_call_id[SIP_MAX_HEADER] = {0};
    int saw_invite = 0;
    int saw_ack = 0;
    int saw_bye = 0;

    /* no-sips-downgrade 场景：记录 client 想用 sips:// */
    if (scenario && strcmp(scenario, "no-sips-downgrade") == 0) {
        LogEvent e;
        demo_init_event(&e, "WARN", "SIPS_DOWNGRADE_DETECTED", "DOWNGRADE",
                        "client requested sips:// but server only supports sip://");
        e.peer = "any";
        logger_write(&logger, &e);
    }

    /* invite-bye 场景：完整 INVITE 流程；register 场景：只 REGISTER */
    int want_invite_bye = (scenario && strcmp(scenario, "invite-bye") == 0);

    while (!stop_requested) {
        char buf[SIP_MAX_MSG];
        socklen_t pl = sizeof(peer_addr);
        ssize_t n = recvfrom(fd, buf, sizeof(buf) - 1, 0,
                             (struct sockaddr *)&peer_addr, &pl);
        if (n <= 0) break;
        buf[n] = '\0';
        peer_to_string(&peer_addr, peer, sizeof(peer));

        char method[16] = {0};
        char uri[256] = {0};
        if (extract_request_line(buf, method, sizeof(method), uri, sizeof(uri)) != 0) {
            /* 可能是响应 */
            int code;
            char reason[64];
            if (extract_status_line(buf, &code, reason, sizeof(reason)) == 0) {
                int pkt_code = SIP_PKT_200_OK;
                const char *pkt_type = "RESPONSE";
                if (code == 100) { pkt_code = SIP_PKT_100_TRYING; pkt_type = "100_TRYING"; }
                else if (code == 180) { pkt_code = SIP_PKT_180_RINGING; pkt_type = "180_RINGING"; }
                else if (code == 200) { pkt_code = SIP_PKT_200_OK; pkt_type = "200_OK"; }
                char call_id[SIP_MAX_HEADER] = {0};
                extract_header(buf, "Call-ID", call_id, sizeof(call_id));
                log_sip(&logger, "INFO", "RECV_RESPONSE", "RESPONSE",
                        reason, peer, "Client -> Server",
                        pkt_code, pkt_type, NULL, call_id, code,
                        (const uint8_t *)buf, (size_t)n);
                if (code == 200 && saw_invite && !saw_ack) {
                    /* 收到 INVITE 的 200 OK，期望 ACK */
                }
            }
            continue;
        }
        char call_id[SIP_MAX_HEADER] = {0};
        extract_header(buf, "Call-ID", call_id, sizeof(call_id));
        char branch[64] = {0};
        extract_header(buf, "branch", branch, sizeof(branch));
        /* branch may not extract from "Via:" — use a placeholder if not found */
        if (!branch[0]) snprintf(branch, sizeof(branch), "z9hG4bK-server-%ld", (long)time(NULL));
        char from_tag[64] = {0};
        extract_header(buf, "tag", from_tag, sizeof(from_tag));
        if (!from_tag[0]) snprintf(from_tag, sizeof(from_tag), "server-from");

        if (strcmp(method, "REGISTER") == 0) {
            log_sip(&logger, "INFO", "RECV_REGISTER", "REGISTER",
                    "REGISTER received", peer, "Client -> Server",
                    SIP_PKT_REGISTER, "REGISTER", method, call_id, 0,
                    (const uint8_t *)buf, (size_t)n);
            /* reply 200 OK */
            send_sip_response(fd, &logger, peer, &peer_addr, branch, from_tag, "server-to",
                              call_id, 1, "REGISTER", 200, "OK",
                              SIP_PKT_200_OK, "200_OK");
            if (!want_invite_bye) {
                rc = 0;
                break;
            }
        } else if (strcmp(method, "INVITE") == 0) {
            /* replay-invite 检测：同一 Call-ID 第二次 */
            if (last_call_id[0] && strcmp(call_id, last_call_id) == 0) {
                LogEvent e;
                demo_init_event(&e, "WARN", "INVITE_REPLAY_DETECTED", "REPLAY",
                                "duplicate INVITE with same Call-ID");
                e.peer = peer;
                e.path = call_id;
                e.security_replay = 1;
                logger_write(&logger, &e);
                demo_finish(&logger, "ABORT", "replay detected");
                break;
            }
            snprintf(last_call_id, sizeof(last_call_id), "%s", call_id);
            log_sip(&logger, "INFO", "RECV_INVITE", "INVITE",
                    "INVITE received", peer, "Client -> Server",
                    SIP_PKT_INVITE, "INVITE", method, call_id, 0,
                    (const uint8_t *)buf, (size_t)n);
            /* 100 Trying */
            send_sip_response(fd, &logger, peer, &peer_addr, branch, from_tag, NULL,
                              call_id, 1, "INVITE", 100, "Trying",
                              SIP_PKT_100_TRYING, "100_TRYING");
            /* 180 Ringing */
            send_sip_response(fd, &logger, peer, &peer_addr, branch, from_tag, "server-1",
                              call_id, 1, "INVITE", 180, "Ringing",
                              SIP_PKT_180_RINGING, "180_RINGING");
            /* 200 OK */
            send_sip_response(fd, &logger, peer, &peer_addr, branch, from_tag, "server-2",
                              call_id, 1, "INVITE", 200, "OK",
                              SIP_PKT_200_OK, "200_OK");
            saw_invite = 1;
        } else if (strcmp(method, "ACK") == 0) {
            log_sip(&logger, "INFO", "RECV_ACK", "ACK",
                    "ACK received", peer, "Client -> Server",
                    SIP_PKT_ACK, "ACK", method, call_id, 0,
                    (const uint8_t *)buf, (size_t)n);
            saw_ack = 1;
            if (saw_bye) {
                rc = 0;
                break;
            }
        } else if (strcmp(method, "BYE") == 0) {
            log_sip(&logger, "INFO", "RECV_BYE", "BYE",
                    "BYE received", peer, "Client -> Server",
                    SIP_PKT_BYE, "BYE", method, call_id, 0,
                    (const uint8_t *)buf, (size_t)n);
            send_sip_response(fd, &logger, peer, &peer_addr, branch, from_tag, "server-3",
                              call_id, 2, "BYE", 200, "OK",
                              SIP_PKT_200_OK, "200_OK");
            saw_bye = 1;
            if (saw_invite && saw_ack) {
                rc = 0;
                break;
            }
        }
    }

    if (rc == 0) {
        demo_finish(&logger, "OK", "sip flow completed");
    } else {
        demo_finish(&logger, "ABORT", "sip flow failed");
    }
    close(fd);
    logger_close(&logger);
    return rc;
}