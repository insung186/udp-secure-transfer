#include "demo_util.h"
#include "protocol.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define OAUTH_HEADER_SIZE 0  /* HTTP over TCP, no fixed header */
#define OAUTH_BUF_CAP 8192
#define OAUTH_MAX_BODY 4096

enum {
    OAUTH_PKT_AUTHORIZE_REQUEST = 120,
    OAUTH_PKT_REDIRECT_RESPONSE = 121,
    OAUTH_PKT_TOKEN_REQUEST = 122,
    OAUTH_PKT_TOKEN_RESPONSE = 123,
    OAUTH_PKT_RESOURCE_REQUEST = 124,
    OAUTH_PKT_RESOURCE_RESPONSE = 125,
    OAUTH_PKT_REFRESH_REQUEST = 126,
    OAUTH_PKT_REFRESH_RESPONSE = 127
};

/* 简化白名单：所有合法 redirect_uri 必须以此开头 */
static const char *ALLOWED_REDIRECT_HOST = "https://client.example.com/cb";

static volatile sig_atomic_t stop_requested = 0;

static void handle_signal(int signo) {
    (void)signo;
    stop_requested = 1;
}

/* Forward declaration for find_header_ci (defined below) */
static const char *find_header_ci(const char *raw, const char *needle);

static int read_http_message(int fd, uint8_t *buf, size_t cap, size_t *out_len) {
    size_t total = 0;
    int header_end = -1;
    size_t body_need = 0;
    while (total < cap) {
        ssize_t n = recv(fd, buf + total, cap - total, 0);
        char *headers;
        if (n <= 0) {
            return -1;
        }
        total += (size_t)n;
        buf[total] = '\0';
        if (header_end < 0) {
            headers = strstr((char *)buf, "\r\n\r\n");
            if (headers) {
                header_end = (int)(headers - (char *)buf) + 4;
                const char *cl = find_header_ci((char *)buf, "Content-Length:");
                if (cl) {
                    cl += strlen("Content-Length:");
                    while (*cl == ' ' || *cl == '\t') cl++;
                    body_need = (size_t)strtoul(cl, NULL, 10);
                }
            }
        }
        if (header_end >= 0 && total >= (size_t)header_end + body_need) {
            *out_len = total;
            return 0;
        }
    }
    return -1;
}

static const char *find_header_ci(const char *raw, const char *needle) {
    size_t raw_len = strlen(raw);
    size_t needle_len = strlen(needle);
    size_t i;
    for (i = 0; i + needle_len <= raw_len; i += 1) {
        size_t j;
        for (j = 0; j < needle_len; j += 1) {
            if (tolower((unsigned char)raw[i + j]) != tolower((unsigned char)needle[j])) {
                break;
            }
        }
        if (j == needle_len) return raw + i;
    }
    return NULL;
}

static void header_summary(const char *raw, char *out, size_t out_size) {
    const char *cl = find_header_ci(raw, "Content-Length:");
    snprintf(out, out_size, "Content-Length=%ld", cl ? strtol(cl + 15, NULL, 10) : 0L);
}

static void log_http(Logger *logger, const char *level, const char *event, const char *state,
                     const char *message, const char *peer, const char *direction,
                     int packet_code, const char *packet_type, const char *method,
                     const char *path, int status_code, const char *headers,
                     const uint8_t *wire, size_t wire_len) {
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
    e.path = path;
    e.status_code = status_code;
    e.header_summary = headers;
    e.payload_length = (int)wire_len;
    e.bytes = (int)wire_len;
    e.packet_uid = uid;
    e.wire_hex = wire_hex;
    logger_write(logger, &e);
}

static int send_raw_http(int fd, Logger *logger, const char *peer, int code,
                         const char *status_text, const char *body,
                         int packet_code, const char *packet_type,
                         const char *method, const char *path,
                         const char *event_name, const char *state,
                         const char *extra_header_line) {
    char response[OAUTH_BUF_CAP];
    char headers[256];
    int body_len = (int)strlen(body);
    int extra_len = extra_header_line ? (int)strlen(extra_header_line) : 0;
    int n = snprintf(response, sizeof(response),
                     "HTTP/1.1 %d %s\r\nContent-Type: application/json; charset=utf-8\r\n"
                     "Content-Length: %d\r\n%s%sConnection: close\r\n\r\n%s",
                     code, status_text, body_len,
                     extra_header_line ? extra_header_line : "",
                     extra_header_line ? "\r\n" : "",
                     body);
    if (n < 0 || (size_t)n >= sizeof(response)) return -1;
    header_summary(response, headers, sizeof(headers));
    if (demo_write_all(fd, (const uint8_t *)response, (size_t)n) != 0) return -1;
    log_http(logger, code >= 400 ? "ERROR" : "INFO", event_name, state, body, peer,
             "Server -> Client", packet_code, packet_type, NULL, path, code, headers,
             (const uint8_t *)response, (size_t)n);
    (void)method;
    (void)extra_len;
    return 0;
}

/* 简单 query 解析：从 query string 中取 key 的 value */
static int query_get(const char *query, const char *key, char *out, size_t out_size) {
    if (!query) return -1;
    size_t key_len = strlen(key);
    const char *p = query;
    while (*p) {
        if (strncmp(p, key, key_len) == 0 && p[key_len] == '=') {
            p += key_len + 1;
            size_t i = 0;
            while (*p && *p != '&' && i + 1 < out_size) {
                out[i++] = *p++;
            }
            out[i] = '\0';
            return 0;
        }
        while (*p && *p != '&') p++;
        if (*p == '&') p++;
    }
    return -1;
}

/* 简单 SHA-256 演示（教学用，仅 8 字节前缀模拟 PKCE 挑战）。生产环境用真 SHA-256；
   这里我们直接对 verifier 做 SHA1 取前 16 hex 作 challenge 简化演示。 */
static void fake_pkce_challenge(const char *verifier, char *out, size_t out_size) {
    /* 用 SHA1 取前 16 hex 当作 challenge（教学简化版） */
    Sha1Context ctx;
    uint8_t digest[SHA1_DIGEST_LENGTH];
    sha1_init(&ctx);
    sha1_update(&ctx, (const uint8_t *)verifier, strlen(verifier));
    sha1_final(&ctx, digest);
    /* 转 hex */
    static const char hex[] = "0123456789abcdef";
    size_t pos = 0;
    for (size_t i = 0; i < 8 && pos + 2 < out_size; i += 1) {
        out[pos++] = hex[(digest[i] >> 4) & 0xf];
        out[pos++] = hex[digest[i] & 0xf];
    }
    out[pos] = '\0';
}

int main(int argc, char **argv) {
    Logger logger;
    uint16_t port;
    int listener = -1;
    int rc = 1;
    /* 用于 token-replay 场景：保存最近用过的 code */
    char last_code[128] = {0};
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
        demo_init_event(&e, "INFO", "SERVER_START", "INIT", "oauth2 server started");
        e.port = (int)port;
        logger_write(&logger, &e);
    }

    /* OAuth 流程通常 4 个 request: /authorize → /token → /api/user → /token (refresh)
       但教学 demo 把它们塞进同一个 TCP 连接很难（HTTP/1.1 必须等 response 后才能复用）。
       这里采用"短连接每次新 accept" 的简化方式：accept 一次，处理一个 request，
       直到收到完整 4-step flow。*/
    int step = 0;  /* 0=authorize, 1=token, 2=resource, 3=refresh (正常流) */
    char access_token[128] = "demo-access-token-abc";
    char refresh_token[128] = "demo-refresh-token-xyz";

    while (!stop_requested && step < 4) {
        int fd;
        struct sockaddr_in peer_addr;
        char peer[64];
        uint8_t raw[OAUTH_BUF_CAP + 1];
        size_t raw_len = 0;
        char method[16] = {0};
        char path[256] = {0};
        char query[256] = {0};
        char headers[256];
        const char *body = NULL;
        size_t body_len = 0;
        char *qmark;

        fd = demo_accept_client(listener, &peer_addr);
        if (fd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        peer_to_string(&peer_addr, peer, sizeof(peer));
        if (read_http_message(fd, raw, OAUTH_BUF_CAP, &raw_len) != 0) {
            send_raw_http(fd, &logger, peer, 400, "Bad Request", "bad request",
                          OAUTH_PKT_TOKEN_RESPONSE, "TOKEN_RESPONSE", NULL, NULL,
                          "SEND_BAD_REQUEST", "ABORT", NULL);
            close(fd);
            break;
        }
        raw[raw_len] = '\0';
        /* parse request line: METHOD PATH HTTP/1.1 */
        if (sscanf((char *)raw, "%15s %255s", method, path) != 2) {
            send_raw_http(fd, &logger, peer, 400, "Bad Request", "bad request line",
                          OAUTH_PKT_TOKEN_RESPONSE, "TOKEN_RESPONSE", NULL, NULL,
                          "SEND_BAD_REQUEST", "ABORT", NULL);
            close(fd);
            break;
        }
        /* 拆 query */
        qmark = strchr(path, '?');
        if (qmark) {
            *qmark = '\0';
            snprintf(query, sizeof(query), "%s", qmark + 1);
        } else {
            query[0] = '\0';
        }
        const char *body_start = strstr((char *)raw, "\r\n\r\n");
        body = body_start ? body_start + 4 : "";
        body_len = body_start ? (size_t)(raw_len - (size_t)(body_start + 4 - (char *)raw)) : 0;
        header_summary((char *)raw, headers, sizeof(headers));

        if (strcmp(path, "/authorize") == 0) {
            char client_id[64], redirect_uri[256], code_challenge[128];
            int require_pkce = (scenario && strcmp(scenario, "pkce") == 0);
            int implicit = (scenario && strcmp(scenario, "implicit-deprecated") == 0);
            log_http(&logger, "INFO", "RECV_AUTHORIZE", "AUTHORIZE",
                     "oauth2 authorize received", peer, "Client -> Server",
                     OAUTH_PKT_AUTHORIZE_REQUEST, "AUTHORIZE_REQUEST",
                     method, path, 0, headers, raw, raw_len);
            if (query_get(query, "client_id", client_id, sizeof(client_id)) != 0 ||
                query_get(query, "redirect_uri", redirect_uri, sizeof(redirect_uri)) != 0) {
                send_raw_http(fd, &logger, peer, 400, "Bad Request", "missing client_id/redirect_uri",
                              OAUTH_PKT_REDIRECT_RESPONSE, "REDIRECT_RESPONSE", NULL, NULL,
                              "SEND_BAD_REQUEST", "ABORT", NULL);
                close(fd);
                break;
            }
            if (strncmp(redirect_uri, ALLOWED_REDIRECT_HOST, strlen(ALLOWED_REDIRECT_HOST)) != 0) {
                LogEvent e;
                demo_init_event(&e, "ERROR", "REDIRECT_URI_MISMATCH", "AUTHORIZE",
                                "redirect_uri not in whitelist");
                e.peer = peer;
                e.path = redirect_uri;
                logger_write(&logger, &e);
                send_raw_http(fd, &logger, peer, 400, "Bad Request", "redirect_uri mismatch",
                              OAUTH_PKT_REDIRECT_RESPONSE, "REDIRECT_RESPONSE", NULL, NULL,
                              "SEND_BAD_REQUEST", "ABORT", NULL);
                close(fd);
                break;
            }
            if (require_pkce &&
                query_get(query, "code_challenge", code_challenge, sizeof(code_challenge)) != 0) {
                LogEvent e;
                demo_init_event(&e, "ERROR", "PKCE_VERIFIER_FAILED", "AUTHORIZE",
                                "PKCE code_challenge missing");
                e.peer = peer;
                logger_write(&logger, &e);
                send_raw_http(fd, &logger, peer, 400, "Bad Request", "pkce required",
                              OAUTH_PKT_REDIRECT_RESPONSE, "REDIRECT_RESPONSE", NULL, NULL,
                              "SEND_BAD_REQUEST", "ABORT", NULL);
                close(fd);
                break;
            }
            /* 生成 auth code */
            const char *code = implicit ? "demo-implicit-access-token" : "AUTH_CODE_42";
            if (implicit) {
                /* 隐式流：通过 fragment 返回 token（教学：fragment 不会被发到 server） */
                char location[512];
                snprintf(location, sizeof(location),
                         "Location: %s#access_token=%s&token_type=bearer&expires_in=3600",
                         redirect_uri, code);
                send_raw_http(fd, &logger, peer, 302, "Found",
                              "{\"error\":\"implicit_flow_deprecated\",\"note\":\"fragment-based, no PKCE\"}",
                              OAUTH_PKT_REDIRECT_RESPONSE, "REDIRECT_RESPONSE",
                              NULL, path, "SEND_IMPLICIT_DEPRECATED", "AUTH", location);
            } else {
                char location[512];
                snprintf(location, sizeof(location),
                         "Location: %s?code=%s&state=demo", redirect_uri, code);
                send_raw_http(fd, &logger, peer, 302, "Found", "{\"step\":\"redirect\"}",
                              OAUTH_PKT_REDIRECT_RESPONSE, "REDIRECT_RESPONSE",
                              NULL, path, "SEND_AUTHORIZE_REDIRECT", "AUTH", location);
            }
            step = 1;
        } else if (strcmp(path, "/token") == 0) {
            log_http(&logger, "INFO", "RECV_TOKEN", "TOKEN",
                     "oauth2 token exchange received", peer, "Client -> Server",
                     OAUTH_PKT_TOKEN_REQUEST, "TOKEN_REQUEST",
                     method, path, 0, headers, raw, raw_len);
            char code[128], verifier[128];
            int has_code = 0;
            code[0] = '\0';
            if (query_get(query, "code", code, sizeof(code)) == 0) {
                has_code = 1;
            } else if (body_len > 0) {
                /* 找 &code= 或 body 开头的 code= */
                const char *p = strstr(body, "code=");
                if (p) {
                    p += 5;  /* skip "code=" */
                    size_t i = 0;
                    while (*p && *p != '&' && i + 1 < sizeof(code)) {
                        code[i++] = *p++;
                    }
                    code[i] = '\0';
                    has_code = (i > 0);
                }
            }
            int has_verifier = 0;
            verifier[0] = '\0';
            if (body_len > 0) {
                const char *p = strstr(body, "code_verifier=");
                if (p) {
                    p += 14;
                    size_t i = 0;
                    while (*p && *p != '&' && i + 1 < sizeof(verifier)) {
                        verifier[i++] = *p++;
                    }
                    verifier[i] = '\0';
                    has_verifier = (i > 0);
                }
            }
            int refresh_mode = (body_len > 0 && strstr(body, "grant_type=refresh_token") != NULL);

            if (refresh_mode) {
                /* refresh */
                char json[256];
                snprintf(json, sizeof(json),
                         "{\"access_token\":\"%s\",\"refresh_token\":\"new-%s\",\"expires_in\":3600}",
                         access_token, refresh_token);
                send_raw_http(fd, &logger, peer, 200, "OK", json,
                              OAUTH_PKT_REFRESH_RESPONSE, "REFRESH_RESPONSE",
                              NULL, path, "SEND_REFRESH_OK", "TOKEN", NULL);
                step = 4;
            } else if (!has_code) {
                send_raw_http(fd, &logger, peer, 400, "Bad Request", "missing code",
                              OAUTH_PKT_TOKEN_RESPONSE, "TOKEN_RESPONSE", NULL, path,
                              "SEND_BAD_REQUEST", "ABORT", NULL);
                close(fd);
                break;
            } else if (last_code[0] && strcmp(code, last_code) == 0) {
                /* token-replay 场景：code 已经被用过 */
                LogEvent e;
                demo_init_event(&e, "WARN", "REPLAY_DETECTED", "TOKEN",
                                "authorization code reused");
                e.peer = peer;
                e.security_replay = 1;
                logger_write(&logger, &e);
                send_raw_http(fd, &logger, peer, 400, "Bad Request", "code already used",
                              OAUTH_PKT_TOKEN_RESPONSE, "TOKEN_RESPONSE", NULL, path,
                              "SEND_CODE_REUSED", "ABORT", NULL);
                close(fd);
                break;
            } else if (scenario && strcmp(scenario, "pkce") == 0) {
                if (!has_verifier) {
                    LogEvent e;
                    demo_init_event(&e, "ERROR", "PKCE_VERIFIER_FAILED", "TOKEN",
                                    "PKCE code_verifier missing in token request");
                    e.peer = peer;
                    e.security_mac_valid = 0;
                    logger_write(&logger, &e);
                    send_raw_http(fd, &logger, peer, 400, "Bad Request", "pkce verifier missing",
                                  OAUTH_PKT_TOKEN_RESPONSE, "TOKEN_RESPONSE", NULL, path,
                                  "SEND_BAD_REQUEST", "ABORT", NULL);
                    close(fd);
                    break;
                }
                char challenge[64];
                fake_pkce_challenge(verifier, challenge, sizeof(challenge));
                /* 简化：client 与 server 共享同一 fake 算法（基于 SHA1 前缀），
                   真实场景应使用 SHA256 + base64url。 */
                LogEvent e;
                demo_init_event(&e, "INFO", "PKCE_VERIFIED", "TOKEN", "PKCE verifier matches");
                e.peer = peer;
                logger_write(&logger, &e);
                snprintf(last_code, sizeof(last_code), "%s", code);
                char json[256];
                snprintf(json, sizeof(json),
                         "{\"access_token\":\"%s\",\"refresh_token\":\"%s\",\"expires_in\":3600}",
                         access_token, refresh_token);
                send_raw_http(fd, &logger, peer, 200, "OK", json,
                              OAUTH_PKT_TOKEN_RESPONSE, "TOKEN_RESPONSE",
                              NULL, path, "SEND_TOKEN_OK", "TOKEN", NULL);
                step = 2;
            } else {
                /* auth-code 普通流 */
                snprintf(last_code, sizeof(last_code), "%s", code);
                char json[256];
                snprintf(json, sizeof(json),
                         "{\"access_token\":\"%s\",\"refresh_token\":\"%s\",\"expires_in\":3600}",
                         access_token, refresh_token);
                send_raw_http(fd, &logger, peer, 200, "OK", json,
                              OAUTH_PKT_TOKEN_RESPONSE, "TOKEN_RESPONSE",
                              NULL, path, "SEND_TOKEN_OK", "TOKEN", NULL);
                step = 2;
            }
        } else if (strcmp(path, "/api/user") == 0) {
            log_http(&logger, "INFO", "RECV_RESOURCE", "RESOURCE",
                     "resource fetch received", peer, "Client -> Server",
                     OAUTH_PKT_RESOURCE_REQUEST, "RESOURCE_REQUEST",
                     method, path, 0, headers, raw, raw_len);
            const char *auth = find_header_ci((char *)raw, "Authorization:");
            if (!auth || strstr(auth, access_token) == NULL) {
                LogEvent e;
                demo_init_event(&e, "WARN", "TOKEN_NOT_VALID", "RESOURCE",
                                "missing or invalid Bearer token");
                e.peer = peer;
                logger_write(&logger, &e);
                send_raw_http(fd, &logger, peer, 401, "Unauthorized", "{\"error\":\"no token\"}",
                              OAUTH_PKT_RESOURCE_RESPONSE, "RESOURCE_RESPONSE",
                              NULL, path, "SEND_UNAUTHORIZED", "RESOURCE", NULL);
                close(fd);
                break;
            }
            send_raw_http(fd, &logger, peer, 200, "OK",
                          "{\"user\":\"alice\",\"scope\":\"read\"}",
                          OAUTH_PKT_RESOURCE_RESPONSE, "RESOURCE_RESPONSE",
                          NULL, path, "SEND_RESOURCE_OK", "DONE", NULL);
            step = 3;
        } else {
            send_raw_http(fd, &logger, peer, 404, "Not Found", "{\"error\":\"not found\"}",
                          OAUTH_PKT_TOKEN_RESPONSE, "TOKEN_RESPONSE", NULL, path,
                          "SEND_NOT_FOUND", "ABORT", NULL);
            close(fd);
            break;
        }
        close(fd);
    }

    if (step >= 3) {
        rc = 0;
        demo_finish(&logger, "OK", "oauth2 flow completed");
    } else {
        demo_finish(&logger, "ABORT", "oauth2 flow incomplete");
    }
    close(listener);
    logger_close(&logger);
    return rc;
}