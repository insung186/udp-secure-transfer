#include "demo_util.h"
#include "protocol.h"
#include "sha1_util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define RADIUS_HEADER_SIZE 20
#define RADIUS_AUTH_SIZE 16
#define RADIUS_MAX_PACKET 4096
#define RADIUS_SECRET "teaching-radius-secret"

enum {
    RADIUS_PKT_ACCESS_REQUEST = 200,
    RADIUS_PKT_ACCESS_ACCEPT = 201,
    RADIUS_PKT_ACCESS_REJECT = 202,
    RADIUS_PKT_ACCOUNTING_REQUEST = 203,
    RADIUS_PKT_ACCOUNTING_RESPONSE = 204
};

enum {
    RADIUS_ATTR_USER_NAME = 1,
    RADIUS_ATTR_USER_PASSWORD = 2,
    RADIUS_ATTR_CHAP_PASSWORD = 3,
    RADIUS_ATTR_CHAP_CHALLENGE = 32
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

/* obfuscate PAP password: XOR with SHA1(request_auth || password) 前 16 字节 (简化版) */
static void pap_obfuscate(const char *password, const uint8_t *request_auth,
                          uint8_t *out, size_t *out_len) {
    Sha1Context ctx;
    uint8_t digest[SHA1_DIGEST_LENGTH];
    sha1_init(&ctx);
    sha1_update(&ctx, request_auth, 16);
    sha1_update(&ctx, (const uint8_t *)password, strlen(password));
    sha1_final(&ctx, digest);
    memcpy(out, digest, 16);
    *out_len = 16;
    /* XOR 前 strlen(password) 字节 */
    size_t pp_len = strlen(password);
    if (pp_len > 16) pp_len = 16;
    for (size_t i = 0; i < pp_len; i += 1) {
        out[i] ^= (uint8_t)password[i];
    }
}

static void log_radius(Logger *logger, const char *level, const char *event, const char *state,
                       const char *message, const char *peer, const char *direction,
                       int packet_code, const char *packet_type, int radius_id,
                       const char *username, const char *auth_protocol,
                       int mac_valid, int replay_detected,
                       const uint8_t *wire, size_t wire_len) {
    char wire_hex[321];
    char uid[24];
    LogEvent e;
    demo_init_event(&e, level, event, state, message);
    bytes_to_hex(wire, wire_len > 160 ? 160 : 160, wire_hex, sizeof(wire_hex));
    compute_packet_uid(uid, sizeof(uid), (uint16_t)packet_code, radius_id, 0, wire, wire_len);
    e.peer = peer;
    e.direction = direction;
    e.packet_type = packet_type;
    e.packet_code = packet_code;
    e.path = username;
    e.header_summary = auth_protocol;
    e.security_mac_valid = mac_valid;
    e.security_replay = replay_detected;
    e.payload_length = (int)wire_len;
    e.bytes = (int)wire_len;
    e.packet_uid = uid;
    e.wire_hex = wire_hex;
    logger_write(logger, &e);
}

/* generate 16B random authenticator */
static void generate_authenticator(uint8_t out[16]) {
    demo_random_nonce(out, 16);
}

static int send_radius(int fd, Logger *logger, const char *peer,
                       uint8_t code, uint8_t id,
                       const uint8_t *auth, const uint8_t *attrs, size_t attrs_len,
                       int packet_code, const char *packet_type, const char *username,
                       const char *auth_protocol, struct sockaddr_in *to, socklen_t to_len) {
    uint8_t buf[RADIUS_MAX_PACKET];
    if (RADIUS_HEADER_SIZE + attrs_len > RADIUS_MAX_PACKET) return -1;
    buf[0] = code;
    buf[1] = id;
    put_u16(buf + 2, (uint16_t)(RADIUS_HEADER_SIZE + attrs_len));
    memcpy(buf + 4, auth, 16);
    if (attrs_len > 0) memcpy(buf + RADIUS_HEADER_SIZE, attrs, attrs_len);
    size_t total = RADIUS_HEADER_SIZE + attrs_len;
    if (sendto(fd, buf, total, 0, (const struct sockaddr *)to, to_len) != (ssize_t)total) return -1;
    log_radius(logger, "INFO", "SEND_RADIUS", "REQUEST", "radius packet sent",
               peer, "Client -> Server", packet_code, packet_type, (int)id,
               username, auth_protocol, 1, 0, buf, total);
    return 0;
}

/* encode one attribute TLV; returns bytes written or -1 */
__attribute__((unused)) static int encode_attr(uint8_t *out, size_t cap, uint8_t type, const uint8_t *value, uint8_t value_len) {
    if ((size_t)2 + value_len > cap) return -1;
    out[0] = type;
    out[1] = (uint8_t)(2 + value_len);
    memcpy(out + 2, value, value_len);
    return (int)(2 + value_len);
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
        demo_init_event(&e, "INFO", "CLIENT_START", "INIT", "radius client started");
        e.peer = peer;
        e.port = (int)port;
        logger_write(&logger, &e);
    }

    /* chap-vs-pap 场景：用 CHAP 而不是 PAP */
    int chap_mode = (scenario && strcmp(scenario, "chap-vs-pap") == 0);

    /* 构造 Access-Request */
    uint8_t auth[16];
    generate_authenticator(auth);
    uint8_t attrs[512];
    size_t attrs_len = 0;
    /* User-Name = "alice" */
    attrs_len += encode_attr(attrs + attrs_len, sizeof(attrs) - attrs_len,
                              RADIUS_ATTR_USER_NAME, (const uint8_t *)"alice", 5);
    if (chap_mode) {
        /* CHAP-Password: chap_id (1B) + chap_response (16B) */
        uint8_t chap_id = 1;
        uint8_t chap_challenge[16];
        demo_random_nonce(chap_challenge, 16);
        uint8_t expected[16];
        uint8_t digest[SHA1_DIGEST_LENGTH];
        Sha1Context ctx;
        sha1_init(&ctx);
        sha1_update(&ctx, &chap_id, 1);
        sha1_update(&ctx, (const uint8_t *)"secret", 6);
        sha1_update(&ctx, chap_challenge, 16);
        sha1_final(&ctx, digest);
        memcpy(expected, digest, 16);
        uint8_t chap_password[17];
        chap_password[0] = chap_id;
        memcpy(chap_password + 1, expected, 16);
        attrs_len += encode_attr(attrs + attrs_len, sizeof(attrs) - attrs_len,
                                  RADIUS_ATTR_CHAP_PASSWORD, chap_password, 17);
        attrs_len += encode_attr(attrs + attrs_len, sizeof(attrs) - attrs_len,
                                  RADIUS_ATTR_CHAP_CHALLENGE, chap_challenge, 16);
    } else {
        /* PAP: obfuscated password */
        uint8_t obf[16];
        size_t obf_len = 0;
        pap_obfuscate("secret", auth, obf, &obf_len);
        attrs_len += encode_attr(attrs + attrs_len, sizeof(attrs) - attrs_len,
                                  RADIUS_ATTR_USER_PASSWORD, obf, (uint8_t)obf_len);
    }
    send_radius(fd, &logger, peer, 1, 1, auth, attrs, attrs_len,
                RADIUS_PKT_ACCESS_REQUEST, "ACCESS_REQUEST", "alice",
                chap_mode ? "CHAP" : "PAP", &server_addr, sl);

    /* 接收 Access-Accept/Reject */
    uint8_t response[RADIUS_MAX_PACKET];
    ssize_t n = recvfrom(fd, response, sizeof(response), 0,
                         (struct sockaddr *)&server_addr, &sl);
    if (n <= 0) {
        demo_finish(&logger, "ABORT", "no response");
        close(fd);
        fclose(out);
        logger_close(&logger);
        return 1;
    }
    uint8_t code = response[0];
    uint8_t id = response[1];
    const char *resp_type = (code == 2) ? "ACCESS_ACCEPT" : "ACCESS_REJECT";
    int pkt_code = (code == 2) ? RADIUS_PKT_ACCESS_ACCEPT : RADIUS_PKT_ACCESS_REJECT;
    log_radius(&logger, code == 2 ? "INFO" : "ERROR", "RECV_RESPONSE", "RESPONSE",
               code == 2 ? "Access-Accept" : "Access-Reject",
               peer, "Server -> Client", pkt_code, resp_type, (int)id,
               "alice", chap_mode ? "CHAP" : "PAP", 1, 0, response, (size_t)n);
    fprintf(out, "%s\n", resp_type);

    /* 验证 response authenticator */
    {
        /* Response Authenticator = HMAC-SHA1(code||id||length||request_auth||attributes, secret) 前 16B */
        uint16_t length = get_u16(response + 2);
        if (length >= RADIUS_HEADER_SIZE && (size_t)n >= length) {
            size_t resp_attrs_len = length - RADIUS_HEADER_SIZE;
            const uint8_t *resp_attrs = response + RADIUS_HEADER_SIZE;
            uint8_t input[20 + 64];
            if (4 + 16 + resp_attrs_len <= sizeof(input)) {
                input[0] = response[0];
                input[1] = response[1];
                input[2] = (uint8_t)(length >> 8);
                input[3] = (uint8_t)(length & 0xff);
                memcpy(input + 4, auth, 16);
                if (resp_attrs_len > 0) memcpy(input + 20, resp_attrs, resp_attrs_len);
                uint8_t expected[16];
                uint8_t full_digest[SHA1_DIGEST_LENGTH];
                demo_hmac_sha1((const uint8_t *)RADIUS_SECRET, strlen(RADIUS_SECRET),
                                input, 4 + 16 + resp_attrs_len, full_digest);
                memcpy(expected, full_digest, 16);
                if (memcmp(expected, response + 4, 16) != 0) {
                    LogEvent e;
                    demo_init_event(&e, "ERROR", "AUTHENTICATOR_INVALID", "VERIFY",
                                    "response authenticator mismatch");
                    e.peer = peer;
                    e.security_mac_valid = 0;
                    logger_write(&logger, &e);
                    demo_finish(&logger, "ABORT", "authenticator invalid");
                    close(fd);
                    fclose(out);
                    logger_close(&logger);
                    return 1;
                }
            }
        }
    }

    if (code == 3) {
        /* Access-Reject — finished */
        demo_finish(&logger, "ABORT", "radius access rejected");
        close(fd);
        fclose(out);
        logger_close(&logger);
        return 1;
    }

    /* replay-attack 场景：再次发送同一个 Access-Request */
    if (scenario && strcmp(scenario, "replay-attack") == 0) {
        /* 重新发送同样的 authenticator + attrs */
        send_radius(fd, &logger, peer, 1, 2, auth, attrs, attrs_len,
                    RADIUS_PKT_ACCESS_REQUEST, "ACCESS_REQUEST", "alice",
                    chap_mode ? "CHAP" : "PAP", &server_addr, sl);
        ssize_t n2 = recvfrom(fd, response, sizeof(response), 0,
                              (struct sockaddr *)&server_addr, &sl);
        if (n2 > 0) {
            log_radius(&logger, "ERROR", "RECV_RESPONSE_REPLAY", "REPLAY",
                       "Access-Reject (replay)", peer, "Server -> Client",
                       RADIUS_PKT_ACCESS_REJECT, "ACCESS_REJECT", (int)response[1],
                       "alice", chap_mode ? "CHAP" : "PAP", 0, 1,
                       response, (size_t)n2);
            LogEvent e;
            demo_init_event(&e, "WARN", "REPLAY_DETECTED", "VERIFY",
                            "client observed replay rejection");
            e.peer = peer;
            e.security_replay = 1;
            logger_write(&logger, &e);
        }
        demo_finish(&logger, "ABORT", "replay-attack scenario");
        close(fd);
        fclose(out);
        logger_close(&logger);
        return 1;
    }

    /* 正常：发送 Accounting-Request */
    {
        uint8_t acct_auth[16];
        demo_random_nonce(acct_auth, 16);
        /* Acct-Status-Type = 1 (Start) */
        uint8_t acct_attrs[64];
        size_t acct_attrs_len = 0;
        acct_attrs_len += encode_attr(acct_attrs + acct_attrs_len,
                                       sizeof(acct_attrs) - acct_attrs_len,
                                       RADIUS_ATTR_USER_NAME, (const uint8_t *)"alice", 5);
        send_radius(fd, &logger, peer, 4, 1, acct_auth, acct_attrs, acct_attrs_len,
                    RADIUS_PKT_ACCOUNTING_REQUEST, "ACCOUNTING_REQUEST", "alice",
                    chap_mode ? "CHAP" : "PAP", &server_addr, sl);
        ssize_t an = recvfrom(fd, response, sizeof(response), 0,
                              (struct sockaddr *)&server_addr, &sl);
        if (an > 0 && response[0] == 5) {
            log_radius(&logger, "INFO", "RECV_ACCOUNTING_RESPONSE", "ACCOUNTING",
                       "Accounting-Response received", peer, "Server -> Client",
                       RADIUS_PKT_ACCOUNTING_RESPONSE, "ACCOUNTING_RESPONSE",
                       (int)response[1], "alice", chap_mode ? "CHAP" : "PAP",
                       1, 0, response, (size_t)an);
            fprintf(out, "ACCOUNTING_RESPONSE\n");
        }
    }

    rc = 0;
    demo_finish(&logger, "OK", "radius flow completed");
    close(fd);
    fclose(out);
    logger_close(&logger);
    return rc;
}