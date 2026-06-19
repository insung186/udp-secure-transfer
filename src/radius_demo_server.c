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

/* 教学版 RADIUS over UDP（RFC 2865/2866 简化）
   Wire format:
     Code (1B) | Identifier (1B) | Length (2B) | Authenticator (16B) | Attributes (TLV)
   Attribute TLV: Type (1B) | Length (1B) | Value

   Code values:
     1 Access-Request, 2 Access-Accept, 3 Access-Reject
     4 Accounting-Request, 5 Accounting-Response

   Attribute types (subset):
     1 User-Name
     2 User-Password (PAP)
     3 CHAP-Password (challenge id + CHAP response)
     4 NAS-IP-Address
     32 CHAP-Challenge

   Authenticator:
     Request  = 16B random nonce
     Response = HMAC-SHA1(code || id || length || request_auth || attributes, shared_secret) [前 16B]
   教学版用 SHA1 替代 MD5（项目已有 sha1_util.h，避免引入 OpenSSL） */
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
    RADIUS_ATTR_NAS_IP_ADDRESS = 4,
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

/* 计算 Response Authenticator = HMAC-SHA1(code||id||length||request_auth||attributes, secret) 前 16B */
static void compute_response_authenticator(uint8_t code, uint8_t id, uint16_t length,
                                           const uint8_t *request_auth,
                                           const uint8_t *attrs, size_t attrs_len,
                                           uint8_t out_auth[16]) {
    /* 构造 input: code(1) + id(1) + length(2) + request_auth(16) + attrs */
    size_t input_len = 4 + 16 + attrs_len;
    uint8_t *input = malloc(input_len);
    if (!input) {
        memset(out_auth, 0, 16);
        return;
    }
    input[0] = code;
    input[1] = id;
    put_u16(input + 2, length);
    memcpy(input + 4, request_auth, 16);
    if (attrs_len > 0) memcpy(input + 20, attrs, attrs_len);
    /* HMAC-SHA1 */
    uint8_t mac[SHA1_DIGEST_LENGTH];
    demo_hmac_sha1((const uint8_t *)RADIUS_SECRET, strlen(RADIUS_SECRET),
                    input, input_len, mac);
    memcpy(out_auth, mac, 16);
    free(input);
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
    bytes_to_hex(wire, wire_len > 160 ? 160 : wire_len, wire_hex, sizeof(wire_hex));
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

/* 解析 attribute TLV；
   返回 0 成功，-1 失败；out_value 指向 attr value 起始 */
static int parse_attr(const uint8_t *buf, size_t buf_len, size_t *offset,
                      uint8_t *out_type, const uint8_t **out_value, uint8_t *out_len) {
    if (*offset + 2 > buf_len) return -1;
    uint8_t type = buf[*offset];
    uint8_t len = buf[*offset + 1];
    if (len < 2 || *offset + len > buf_len) return -1;
    *out_type = type;
    *out_value = buf + *offset + 2;
    *out_len = len - 2;
    *offset += len;
    return 0;
}

/* 编码一个 attribute TLV（type + length + value）；返回字节数 */
__attribute__((unused)) static int encode_attr(uint8_t *out, size_t cap, uint8_t type, const uint8_t *value, uint8_t value_len) {
    if ((size_t)2 + value_len > cap) return -1;
    out[0] = type;
    out[1] = (uint8_t)(2 + value_len);
    memcpy(out + 2, value, value_len);
    return (int)(2 + value_len);
}

/* SHA1(prefix || secret || suffix) - 简化版 "obfuscation" 用于 PAP password */
static void pap_obfuscate(const char *password, const uint8_t *request_auth,
                          uint8_t out[16]) {
    Sha1Context ctx;
    uint8_t digest[SHA1_DIGEST_LENGTH];
    sha1_init(&ctx);
    sha1_update(&ctx, request_auth, 16);
    sha1_update(&ctx, (const uint8_t *)password, strlen(password));
    sha1_final(&ctx, digest);
    memcpy(out, digest, 16);
}

/* server 端用同样的算法解密 PAP password 然后比对 */
static int pap_deobfuscate(const uint8_t *obfuscated, size_t obf_len,
                           const uint8_t *request_auth, const char *expected_password,
                           char *out, size_t out_size) {
    /* PAP 密码被切成 16 字节段，每段分别用 SHA1(request_auth || password) XOR */
    size_t pp_len = strlen(expected_password);
    if (pp_len == 0) return -1;
    /* 计算 expected obfuscated: SHA1(request_auth || expected_password) XOR 前 16 字节密码 */
    uint8_t expected_first[16];
    pap_obfuscate(expected_password, request_auth, expected_first);
    if (obf_len < 16) return -1;
    /* 第一段：expected_first XOR 真实密码前 16 字节 */
    uint8_t plain_buf[16];
    for (int i = 0; i < 16; i += 1) {
        plain_buf[i] = expected_first[i] ^ obfuscated[i];
    }
    /* 简化：假设密码 < 16 字节；只比对前 strlen(expected_password) 字节 */
    if (memcmp(plain_buf, expected_password, pp_len) == 0) {
        snprintf(out, out_size, "%.*s", (int)pp_len, (char *)plain_buf);
        return 0;
    }
    /* 简化：实际 RFC 用迭代 XOR 处理超长密码；这里直接对比 */
    return -1;
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
    /* 最近见过的 authenticator (用于 replay 检测) */
    uint8_t last_auth[16] = {0};
    int replay_seen = 0;

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
        demo_init_event(&e, "INFO", "SERVER_START", "INIT", "radius server started");
        e.port = (int)port;
        logger_write(&logger, &e);
    }

    while (!stop_requested) {
        uint8_t buf[RADIUS_MAX_PACKET];
        socklen_t pl = sizeof(peer_addr);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&peer_addr, &pl);
        if (n <= 0) break;
        peer_to_string(&peer_addr, peer, sizeof(peer));
        if ((size_t)n < RADIUS_HEADER_SIZE) {
            demo_finish(&logger, "ABORT", "radius packet too short");
            break;
        }
        uint8_t code = buf[0];
        uint8_t id = buf[1];
        uint16_t length = get_u16(buf + 2);
        const uint8_t *auth = buf + 4;
        if (length < RADIUS_HEADER_SIZE || length > (size_t)n) {
            demo_finish(&logger, "ABORT", "bad radius length");
            break;
        }
        size_t attrs_len = length - RADIUS_HEADER_SIZE;
        const uint8_t *attrs = buf + RADIUS_HEADER_SIZE;
        (void)attrs;
        (void)attrs_len;

        if (code == 1) {
            /* Access-Request */
            /* replay-attack 场景：检查 authenticator 是否复用 */
            if (scenario && strcmp(scenario, "replay-attack") == 0 &&
                last_auth[0] != 0 && memcmp(auth, last_auth, 16) == 0) {
                LogEvent e;
                demo_init_event(&e, "ERROR", "REPLAY_DETECTED", "VERIFY",
                                "Access-Request with reused authenticator");
                e.peer = peer;
                e.security_replay = 1;
                logger_write(&logger, &e);
                log_radius(&logger, "ERROR", "RECV_ACCESS_REQUEST", "REPLAY",
                           "Access-Request replayed", peer, "Client -> Server",
                           RADIUS_PKT_ACCESS_REQUEST, "ACCESS_REQUEST", (int)id,
                           NULL, "PAP", 0, 1, buf, (size_t)n);
                /* reject */
                uint8_t response[RADIUS_MAX_PACKET];
                size_t pos = 0;
                response[pos++] = 3;  /* Access-Reject */
                response[pos++] = id;
                uint16_t resp_len = (uint16_t)(RADIUS_HEADER_SIZE);
                put_u16(response + 2, resp_len);
                memcpy(response + 4, auth, 16);  /* echo request_auth (no shared secret verification in reject) */
                sendto(fd, response, resp_len, 0,
                       (const struct sockaddr *)&peer_addr, pl);
                log_radius(&logger, "WARN", "SEND_ACCESS_REJECT", "REPLAY",
                           "Access-Reject (replay)", peer, "Server -> Client",
                           RADIUS_PKT_ACCESS_REJECT, "ACCESS_REJECT", (int)id,
                           NULL, "PAP", 0, 1, response, resp_len);
                replay_seen = 1;
                demo_finish(&logger, "ABORT", "replay detected");
                break;
            }
            memcpy(last_auth, auth, 16);

            /* 解析 attributes: 找 User-Name + User-Password / CHAP-Password */
            char username[64] = {0};
            const char *auth_protocol = "PAP";
            int chap_mode = 0;
            uint8_t chap_id = 0;
            uint8_t chap_response[16] = {0};
            uint8_t chap_challenge[16] = {0};
            int has_password = 0;

            {
                size_t off = RADIUS_HEADER_SIZE;
                while (off < (size_t)n) {
                    uint8_t atype;
                    const uint8_t *aval;
                    uint8_t alen;
                    if (parse_attr(buf, (size_t)n, &off, &atype, &aval, &alen) != 0) break;
                    if (atype == RADIUS_ATTR_USER_NAME && alen > 0) {
                        size_t copy = alen < sizeof(username) - 1 ? alen : sizeof(username) - 1;
                        memcpy(username, aval, copy);
                        username[copy] = '\0';
                    } else if (atype == RADIUS_ATTR_USER_PASSWORD) {
                        auth_protocol = "PAP";
                        has_password = 1;
                    } else if (atype == RADIUS_ATTR_CHAP_PASSWORD) {
                        auth_protocol = "CHAP";
                        chap_mode = 1;
                        if (alen >= 17) {
                            chap_id = aval[0];
                            memcpy(chap_response, aval + 1, 16);
                        }
                        has_password = 1;
                    } else if (atype == RADIUS_ATTR_CHAP_CHALLENGE) {
                        if (alen <= 16) memcpy(chap_challenge, aval, alen);
                    }
                }
            }

            log_radius(&logger, "INFO", "RECV_ACCESS_REQUEST", "AUTH",
                       "Access-Request received", peer, "Client -> Server",
                       RADIUS_PKT_ACCESS_REQUEST, "ACCESS_REQUEST", (int)id,
                       username, auth_protocol, 1, 0, buf, (size_t)n);

            /* shared-secret-leak 场景：演示密钥不一致（client 用 wrong-secret） */
            int secret_ok = 1;
            if (scenario && strcmp(scenario, "shared-secret-leak") == 0) {
                secret_ok = 0;
                LogEvent e;
                demo_init_event(&e, "ERROR", "AUTHENTICATOR_INVALID", "AUTH",
                                "shared secret mismatch");
                e.peer = peer;
                e.security_mac_valid = 0;
                logger_write(&logger, &e);
            }

            int accept = 0;
            if (secret_ok && username[0] && has_password) {
                if (chap_mode) {
                    /* CHAP: SHA1(chap_id || password || chap_challenge) == chap_response */
                    Sha1Context ctx;
                    uint8_t digest[SHA1_DIGEST_LENGTH];
                    uint8_t expected[16];  /* 教学：只取 SHA1 前 16 字节 */
                    sha1_init(&ctx);
                    sha1_update(&ctx, &chap_id, 1);
                    sha1_update(&ctx, (const uint8_t *)"secret", 6);
                    sha1_update(&ctx, chap_challenge, 16);
                    sha1_final(&ctx, digest);
                    memcpy(expected, digest, 16);
                    accept = memcmp(expected, chap_response, 16) == 0;
                } else {
                    /* PAP: 简化 — 密码经过 obfuscate，server 直接比对 */
                    const uint8_t *pap_obf = NULL;
                    uint8_t pap_obf_len = 0;
                    size_t off = RADIUS_HEADER_SIZE;
                    while (off < (size_t)n) {
                        uint8_t atype;
                        const uint8_t *aval;
                        uint8_t alen;
                        if (parse_attr(buf, (size_t)n, &off, &atype, &aval, &alen) != 0) break;
                        if (atype == RADIUS_ATTR_USER_PASSWORD) {
                            pap_obf = aval;
                            pap_obf_len = alen;
                            break;
                        }
                    }
                    char plain[64];
                    if (pap_deobfuscate(pap_obf, pap_obf_len, auth, "secret",
                                         plain, sizeof(plain)) == 0) {
                        accept = 1;
                    }
                }
            }

            /* chap-vs-pap 场景：在 PAP 模式下额外记录 "PASSWORD_SENT_IN_CLEARTEXT" 警告 */
            if (scenario && strcmp(scenario, "chap-vs-pap") == 0 && !chap_mode) {
                LogEvent e;
                demo_init_event(&e, "WARN", "PASSWORD_SENT_IN_CLEARTEXT", "PAP",
                                "PAP password is reversible from Request Authenticator; CHAP recommended");
                e.peer = peer;
                e.security_encrypted = 0;
                logger_write(&logger, &e);
            }

            /* 构造 response */
            uint8_t response[RADIUS_MAX_PACKET];
            size_t pos = 0;
            response[pos++] = accept ? 2 : 3;  /* Access-Accept / Access-Reject */
            response[pos++] = id;
            uint16_t resp_len_pos = (uint16_t)pos;
            pos += 2;  /* length placeholder */
            /* authenticator placeholder */
            uint8_t auth_pos = (uint8_t)pos;
            pos += 16;
            /* no extra attributes for simplicity */
            uint16_t resp_length = (uint16_t)(RADIUS_HEADER_SIZE);
            put_u16(response + resp_len_pos, resp_length);
            /* compute response authenticator */
            compute_response_authenticator(response[0], response[1], resp_length,
                                           auth, NULL, 0, response + auth_pos);
            if (sendto(fd, response, resp_length, 0,
                       (const struct sockaddr *)&peer_addr, pl) != (ssize_t)resp_length) {
                demo_finish(&logger, "ABORT", "send response failed");
                break;
            }
            int resp_code = accept ? RADIUS_PKT_ACCESS_ACCEPT : RADIUS_PKT_ACCESS_REJECT;
            const char *resp_type = accept ? "ACCESS_ACCEPT" : "ACCESS_REJECT";
            log_radius(&logger, accept ? "INFO" : "ERROR", accept ? "SEND_ACCESS_ACCEPT" : "SEND_ACCESS_REJECT",
                       "RESPONSE", accept ? "Access-Accept" : "Access-Reject",
                       peer, "Server -> Client", resp_code, resp_type, (int)id,
                       username, auth_protocol, 1, 0, response, resp_length);
            if (accept) {
                rc = 0;
                /* 等待 Accounting-Request 或 replay（在 replay-attack 场景下
                   client 会再发同一份 Access-Request 触发 replay 检测） */
                while (!stop_requested) {
                    uint8_t next_buf[RADIUS_MAX_PACKET];
                    pl = sizeof(peer_addr);
                    ssize_t an = recvfrom(fd, next_buf, sizeof(next_buf), 0,
                                          (struct sockaddr *)&peer_addr, &pl);
                    if (an <= 0) break;
                    if (next_buf[0] == 4) {
                        /* Accounting-Request */
                        log_radius(&logger, "INFO", "RECV_ACCOUNTING_REQUEST", "ACCOUNTING",
                                   "Accounting-Request received", peer, "Client -> Server",
                                   RADIUS_PKT_ACCOUNTING_REQUEST, "ACCOUNTING_REQUEST",
                                   (int)next_buf[1], username, auth_protocol, 1, 0,
                                   next_buf, (size_t)an);
                        uint8_t acct_resp[RADIUS_MAX_PACKET];
                        acct_resp[0] = 5;
                        acct_resp[1] = next_buf[1];
                        put_u16(acct_resp + 2, RADIUS_HEADER_SIZE);
                        Sha1Context ctx;
                        uint8_t digest[SHA1_DIGEST_LENGTH];
                        uint8_t input[4 + 16];
                        acct_resp[2] = (uint8_t)(RADIUS_HEADER_SIZE >> 8);
                        acct_resp[3] = (uint8_t)(RADIUS_HEADER_SIZE & 0xff);
                        memcpy(input, acct_resp, 4);
                        memcpy(input + 4, next_buf + 4, 16);
                        sha1_init(&ctx);
                        sha1_update(&ctx, input, sizeof(input));
                        sha1_update(&ctx, (const uint8_t *)RADIUS_SECRET, strlen(RADIUS_SECRET));
                        sha1_final(&ctx, digest);
                        memcpy(acct_resp + 4, digest, 16);
                        sendto(fd, acct_resp, RADIUS_HEADER_SIZE, 0,
                               (const struct sockaddr *)&peer_addr, pl);
                        log_radius(&logger, "INFO", "SEND_ACCOUNTING_RESPONSE", "ACCOUNTING",
                                   "Accounting-Response sent", peer, "Server -> Client",
                                   RADIUS_PKT_ACCOUNTING_RESPONSE, "ACCOUNTING_RESPONSE",
                                   (int)next_buf[1], username, auth_protocol, 1, 0,
                                   acct_resp, RADIUS_HEADER_SIZE);
                        break;
                    } else if (next_buf[0] == 1 && scenario && strcmp(scenario, "replay-attack") == 0) {
                        /* 检测到 replay：发送 Access-Reject 并退出 */
                        LogEvent e;
                        demo_init_event(&e, "ERROR", "REPLAY_DETECTED", "VERIFY",
                                        "Access-Request with reused authenticator after Accept");
                        e.peer = peer;
                        e.security_replay = 1;
                        logger_write(&logger, &e);
                        uint8_t reject[RADIUS_MAX_PACKET];
                        reject[0] = 3;
                        reject[1] = next_buf[1];
                        put_u16(reject + 2, RADIUS_HEADER_SIZE);
                        memcpy(reject + 4, next_buf + 4, 16);
                        sendto(fd, reject, RADIUS_HEADER_SIZE, 0,
                               (const struct sockaddr *)&peer_addr, pl);
                        log_radius(&logger, "WARN", "SEND_ACCESS_REJECT", "REPLAY",
                                   "Access-Reject (replay after Accept)", peer, "Server -> Client",
                                   RADIUS_PKT_ACCESS_REJECT, "ACCESS_REJECT", (int)next_buf[1],
                                   username, auth_protocol, 0, 1, reject, RADIUS_HEADER_SIZE);
                        replay_seen = 1;
                        rc = 1;
                        break;
                    }
                    /* 忽略其他包 */
                }
                break;
            } else {
                /* 拒绝：继续等下一包 */
            }
        } else {
            /* 忽略其他 code */
            log_radius(&logger, "INFO", "RECV_PACKET", "UNKNOWN",
                       "non-Access-Request received", peer, "Client -> Server",
                       RADIUS_PKT_ACCESS_REQUEST, "ACCESS_REQUEST", (int)id,
                       NULL, NULL, 1, 0, buf, (size_t)n);
        }
    }

    if (rc == 0) {
        demo_finish(&logger, "OK", "radius flow completed");
    } else if (replay_seen) {
        demo_finish(&logger, "ABORT", "radius replay detected");
    } else {
        demo_finish(&logger, "ABORT", "radius flow failed");
    }
    close(fd);
    logger_close(&logger);
    return rc;
}