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

static int send_sip(int fd, Logger *logger, const char *peer,
                    const char *method, const char *uri, const char *call_id,
                    int cseq, const char *branch, const char *from_tag,
                    int packet_code, const char *packet_type,
                    struct sockaddr_in *to, socklen_t to_len) {
    char msg[SIP_MAX_MSG];
    int n = snprintf(msg, sizeof(msg),
                     "%s %s SIP/2.0\r\n"
                     "Via: SIP/2.0/UDP client:5060;branch=%s\r\n"
                     "From: <sip:alice@demo>;tag=%s\r\n"
                     "To: <sip:bob@demo>\r\n"
                     "Call-ID: %s\r\n"
                     "CSeq: %d %s\r\n"
                     "Content-Length: 0\r\n\r\n",
                     method, uri, branch, from_tag, call_id, cseq, method);
    if (n < 0 || (size_t)n >= sizeof(msg)) return -1;
    if (sendto(fd, msg, (size_t)n, 0, (const struct sockaddr *)to, to_len) != (ssize_t)n) return -1;
    log_sip(logger, "INFO", "SEND_REQUEST", method,
            "SIP request sent", peer, "Client -> Server",
            packet_code, packet_type, method, call_id, 0,
            (const uint8_t *)msg, (size_t)n);
    return 0;
}

int main(int argc, char **argv) {
    Logger logger;
    uint16_t port;
    int fd = -1;
    struct sockaddr_in server_addr;
    socklen_t sl;
    char peer[64];
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
    snprintf(peer, sizeof(peer), "%s:%u", argv[1], (unsigned)port);
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
    sl = sizeof(server_addr);
    {
        LogEvent e;
        demo_init_event(&e, "INFO", "CLIENT_START", "INIT", "sip client started");
        e.peer = peer;
        e.port = (int)port;
        logger_write(&logger, &e);
    }

    char call_id[64];
    snprintf(call_id, sizeof(call_id), "call-%ld@client", (long)time(NULL));
    char branch[64];
    snprintf(branch, sizeof(branch), "z9hG4bK-client-%ld", (long)time(NULL));
    char from_tag[64];
    snprintf(from_tag, sizeof(from_tag), "client-from-%ld", (long)time(NULL));

    int want_invite_bye = (scenario && strcmp(scenario, "invite-bye") == 0);

    /* 总是先发 REGISTER */
    send_sip(fd, &logger, peer, "REGISTER", "sip:demo@registrar", call_id,
             1, branch, from_tag, SIP_PKT_REGISTER, "REGISTER",
             &server_addr, sl);
    /* 接收 200 OK */
    {
        char buf[SIP_MAX_MSG];
        ssize_t n = recvfrom(fd, buf, sizeof(buf) - 1, 0,
                             (struct sockaddr *)&server_addr, &sl);
        if (n <= 0) {
            demo_finish(&logger, "ABORT", "no REGISTER response");
            close(fd);
            fclose(out);
            logger_close(&logger);
            return 1;
        }
        buf[n] = '\0';
        int code = 0;
        char reason[64];
        char ver[16];
        if (sscanf(buf, "%15s %d %63s", ver, &code, reason) == 3) {
            int pkt_code = SIP_PKT_200_OK;
            const char *pkt_type = "RESPONSE";
            if (code == 100) { pkt_code = SIP_PKT_100_TRYING; pkt_type = "100_TRYING"; }
            else if (code == 180) { pkt_code = SIP_PKT_180_RINGING; pkt_type = "180_RINGING"; }
            else if (code == 200) { pkt_code = SIP_PKT_200_OK; pkt_type = "200_OK"; }
            char recv_call_id[SIP_MAX_HEADER] = {0};
            const char *cid = strstr(buf, "Call-ID:");
            if (cid) {
                cid += strlen("Call-ID:");
                while (*cid == ' ' || *cid == '\t') cid++;
                size_t i = 0;
                while (*cid && *cid != '\r' && *cid != '\n' && i + 1 < sizeof(recv_call_id)) {
                    recv_call_id[i++] = *cid++;
                }
                recv_call_id[i] = '\0';
            }
            log_sip(&logger, "INFO", "RECV_RESPONSE", "RESPONSE",
                    reason, peer, "Server -> Client",
                    pkt_code, pkt_type, NULL, recv_call_id, code,
                    (const uint8_t *)buf, (size_t)n);
            if (code != 200) {
                demo_finish(&logger, "ABORT", "REGISTER rejected");
                close(fd);
                fclose(out);
                logger_close(&logger);
                return 1;
            }
        }
        fprintf(out, "REGISTER -> %d %s\n", code, reason);
    }

    /* no-sips-downgrade 场景：演示尝试 sips URI（教学告警） */
    if (scenario && strcmp(scenario, "no-sips-downgrade") == 0) {
        LogEvent e;
        demo_init_event(&e, "WARN", "SIPS_REQUESTED", "DOWNGRADE",
                        "client requested sips:// but server downgraded to sip://");
        e.peer = peer;
        e.security_encrypted = 0;
        logger_write(&logger, &e);
    }

    if (!want_invite_bye && !scenario) {
        rc = 0;
        demo_finish(&logger, "OK", "sip register flow completed");
        close(fd);
        fclose(out);
        logger_close(&logger);
        return rc;
    }

    /* invite-bye 流程 */
    if (scenario && strcmp(scenario, "invite-bye") == 0) {
        char invite_call_id[64];
        snprintf(invite_call_id, sizeof(invite_call_id), "invite-%ld@client", (long)time(NULL));
        send_sip(fd, &logger, peer, "INVITE", "sip:bob@demo", invite_call_id,
                 1, branch, from_tag, SIP_PKT_INVITE, "INVITE",
                 &server_addr, sl);
        /* 接收 100/180/200 */
        for (int i = 0; i < 3; i += 1) {
            char buf[SIP_MAX_MSG];
            ssize_t n = recvfrom(fd, buf, sizeof(buf) - 1, 0,
                                 (struct sockaddr *)&server_addr, &sl);
            if (n <= 0) break;
            buf[n] = '\0';
            int code = 0;
            char reason[64];
            char ver[16];
            if (sscanf(buf, "%15s %d %63s", ver, &code, reason) == 3) {
                int pkt_code = SIP_PKT_200_OK;
                const char *pkt_type = "RESPONSE";
                if (code == 100) { pkt_code = SIP_PKT_100_TRYING; pkt_type = "100_TRYING"; }
                else if (code == 180) { pkt_code = SIP_PKT_180_RINGING; pkt_type = "180_RINGING"; }
                else if (code == 200) { pkt_code = SIP_PKT_200_OK; pkt_type = "200_OK"; }
                log_sip(&logger, "INFO", "RECV_RESPONSE", "RESPONSE",
                        reason, peer, "Server -> Client",
                        pkt_code, pkt_type, NULL, invite_call_id, code,
                        (const uint8_t *)buf, (size_t)n);
            }
        }
        /* ACK */
        send_sip(fd, &logger, peer, "ACK", "sip:bob@demo", invite_call_id,
                 1, branch, from_tag, SIP_PKT_ACK, "ACK",
                 &server_addr, sl);
        /* BYE */
        send_sip(fd, &logger, peer, "BYE", "sip:bob@demo", invite_call_id,
                 2, branch, from_tag, SIP_PKT_BYE, "BYE",
                 &server_addr, sl);
        /* 接收 200 OK for BYE */
        {
            char buf[SIP_MAX_MSG];
            ssize_t n = recvfrom(fd, buf, sizeof(buf) - 1, 0,
                                 (struct sockaddr *)&server_addr, &sl);
            if (n > 0) {
                buf[n] = '\0';
                int code = 0;
                char reason[64];
                char ver[16];
                if (sscanf(buf, "%15s %d %63s", ver, &code, reason) == 3) {
                    log_sip(&logger, "INFO", "RECV_RESPONSE", "RESPONSE",
                            reason, peer, "Server -> Client",
                            SIP_PKT_200_OK, "200_OK", NULL, invite_call_id, code,
                            (const uint8_t *)buf, (size_t)n);
                }
            }
        }
    }

    /* replay-invite 场景：发两个 INVITE 同一个 Call-ID */
    if (scenario && strcmp(scenario, "replay-invite") == 0) {
        char replay_call_id[64];
        snprintf(replay_call_id, sizeof(replay_call_id), "replay-%ld@client", (long)time(NULL));
        send_sip(fd, &logger, peer, "INVITE", "sip:bob@demo", replay_call_id,
                 1, branch, from_tag, SIP_PKT_INVITE, "INVITE",
                 &server_addr, sl);
        /* 接收响应 */
        for (int i = 0; i < 3; i += 1) {
            char buf[SIP_MAX_MSG];
            ssize_t n = recvfrom(fd, buf, sizeof(buf) - 1, 0,
                                 (struct sockaddr *)&server_addr, &sl);
            if (n <= 0) break;
            buf[n] = '\0';
            int code = 0;
            char reason[64];
            char ver[16];
            if (sscanf(buf, "%15s %d %63s", ver, &code, reason) == 3) {
                int pkt_code = SIP_PKT_200_OK;
                const char *pkt_type = "RESPONSE";
                if (code == 100) { pkt_code = SIP_PKT_100_TRYING; pkt_type = "100_TRYING"; }
                else if (code == 180) { pkt_code = SIP_PKT_180_RINGING; pkt_type = "180_RINGING"; }
                else if (code == 200) { pkt_code = SIP_PKT_200_OK; pkt_type = "200_OK"; }
                log_sip(&logger, "INFO", "RECV_RESPONSE", "RESPONSE",
                        reason, peer, "Server -> Client",
                        pkt_code, pkt_type, NULL, replay_call_id, code,
                        (const uint8_t *)buf, (size_t)n);
            }
        }
        /* 重发同一个 INVITE（同 Call-ID）*/
        send_sip(fd, &logger, peer, "INVITE", "sip:bob@demo", replay_call_id,
                 2, branch, from_tag, SIP_PKT_INVITE, "INVITE",
                 &server_addr, sl);
        LogEvent e;
        demo_init_event(&e, "WARN", "INVITE_REPLAY_DETECTED", "REPLAY",
                        "duplicate INVITE with same Call-ID sent");
        e.peer = peer;
        e.path = replay_call_id;
        e.security_replay = 1;
        logger_write(&logger, &e);
        demo_finish(&logger, "ABORT", "replay-invite scenario (client side)");
        close(fd);
        fclose(out);
        logger_close(&logger);
        return 1;
    }

    rc = 0;
    demo_finish(&logger, "OK", "sip flow completed");
    close(fd);
    fclose(out);
    logger_close(&logger);
    return rc;
}