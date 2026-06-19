#include "demo_util.h"
#include "protocol.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define OAUTH_BUF_CAP 8192

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
        if (n <= 0) return -1;
        total += (size_t)n;
        buf[total] = '\0';
        if (header_end < 0) {
            char *headers = strstr((char *)buf, "\r\n\r\n");
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
            if (tolower((unsigned char)raw[i + j]) != tolower((unsigned char)needle[j])) break;
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

static int do_http(Logger *logger, const char *host, uint16_t port, const char *peer_text,
                   const char *method, const char *path_with_query, const char *body,
                   const char *extra_headers, int req_code, const char *req_type,
                   int resp_code, const char *resp_type, FILE *out) {
    char request[OAUTH_BUF_CAP];
    char headers[256];
    uint8_t response[OAUTH_BUF_CAP + 1];
    size_t response_len = 0;
    int status_code = 0;
    int fd = -1;
    struct sockaddr_in addr;
    int body_len = (int)strlen(body);
    int n = snprintf(request, sizeof(request),
                     "%s %s HTTP/1.1\r\nHost: %s:%u\r\nContent-Length: %d%s\r\n%sConnection: close\r\n\r\n%s",
                     method, path_with_query, host, (unsigned)port, body_len,
                     extra_headers ? extra_headers : "",
                     extra_headers ? "\r\n" : "",
                     body);
    if (n < 0 || (size_t)n >= sizeof(request)) return -1;
    header_summary(request, headers, sizeof(headers));
    fd = demo_connect_tcp(host, port, &addr);
    if (fd < 0) return -1;
    log_http(logger, "INFO", "SEND_HTTP_REQUEST", "REQUEST", body,
             peer_text, "Client -> Server", req_code, req_type, method,
             path_with_query, 0, headers, (const uint8_t *)request, (size_t)n);
    if (demo_write_all(fd, (const uint8_t *)request, (size_t)n) != 0 ||
        read_http_message(fd, response, OAUTH_BUF_CAP, &response_len) != 0) {
        close(fd);
        return -1;
    }
    response[response_len] = '\0';
    if (sscanf((char *)response, "HTTP/1.1 %d", &status_code) != 1) {
        close(fd);
        return -1;
    }
    char resp_headers[256];
    header_summary((char *)response, resp_headers, sizeof(resp_headers));
    log_http(logger, status_code >= 400 ? "ERROR" : "INFO", "RECV_HTTP_RESPONSE",
             "RESPONSE", "http response received", peer_text, "Server -> Client",
             resp_code, resp_type, NULL, path_with_query, status_code,
             resp_headers, response, response_len);
    /* 写响应摘要到 output */
    if (out) {
        const char *body_start = strstr((char *)response, "\r\n\r\n");
        if (body_start) {
            fprintf(out, "%s %s -> %d %s\n", method, path_with_query, status_code,
                    body_start + 4);
        }
    }
    close(fd);
    return status_code == resp_code ? 0 : -1;
}

static void fake_pkce_challenge(const char *verifier, char *out, size_t out_size) {
    Sha1Context ctx;
    uint8_t digest[SHA1_DIGEST_LENGTH];
    sha1_init(&ctx);
    sha1_update(&ctx, (const uint8_t *)verifier, strlen(verifier));
    sha1_final(&ctx, digest);
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
    char peer_text[64];
    FILE *out = NULL;
    const char *scenario = getenv("UDP_SECURE_SCENARIO");
    int rc = 1;

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
    {
        LogEvent e;
        demo_init_event(&e, "INFO", "CLIENT_START", "INIT", "oauth2 client started");
        e.peer = peer_text;
        e.port = (int)port;
        logger_write(&logger, &e);
    }

    int require_pkce = (scenario && strcmp(scenario, "pkce") == 0);
    int implicit = (scenario && strcmp(scenario, "implicit-deprecated") == 0);
    int replay = (scenario && strcmp(scenario, "token-replay") == 0);

    /* Step 1: /authorize */
    char auth_path[512];
    char verifier[128] = "demo-verifier-12345";
    char challenge[64];
    fake_pkce_challenge(verifier, challenge, sizeof(challenge));
    if (implicit) {
        snprintf(auth_path, sizeof(auth_path),
                 "/authorize?response_type=token&client_id=demo-client"
                 "&redirect_uri=https://client.example.com/cb&state=demo");
    } else if (require_pkce) {
        snprintf(auth_path, sizeof(auth_path),
                 "/authorize?response_type=code&client_id=demo-client"
                 "&redirect_uri=https://client.example.com/cb&state=demo"
                 "&code_challenge=%s&code_challenge_method=SHA1", challenge);
    } else {
        snprintf(auth_path, sizeof(auth_path),
                 "/authorize?response_type=code&client_id=demo-client"
                 "&redirect_uri=https://client.example.com/cb&state=demo");
    }
    if (do_http(&logger, argv[1], port, peer_text, "GET", auth_path, "",
                NULL, OAUTH_PKT_AUTHORIZE_REQUEST, "AUTHORIZE_REQUEST",
                302, "REDIRECT_RESPONSE", out) != 0) {
        demo_finish(&logger, "ABORT", "authorize failed");
        fclose(out);
        logger_close(&logger);
        return 1;
    }

    /* token-replay 场景：用同一个 code 两次 */
    if (replay) {
        /* first token request (with new code) */
        char token_path[256];
        snprintf(token_path, sizeof(token_path),
                 "/token?grant_type=authorization_code&code=AUTH_CODE_REPLAY_42");
        if (do_http(&logger, argv[1], port, peer_text, "POST", token_path,
                    "code=AUTH_CODE_REPLAY_42",
                    "Content-Type: application/x-www-form-urlencoded",
                    OAUTH_PKT_TOKEN_REQUEST, "TOKEN_REQUEST",
                    200, "TOKEN_RESPONSE", out) != 0) {
            demo_finish(&logger, "ABORT", "token (first) failed");
            fclose(out);
            logger_close(&logger);
            return 1;
        }
        /* second token request with same code (replay) - expect reject */
        if (do_http(&logger, argv[1], port, peer_text, "POST", token_path,
                    "code=AUTH_CODE_REPLAY_42",
                    "Content-Type: application/x-www-form-urlencoded",
                    OAUTH_PKT_TOKEN_REQUEST, "TOKEN_REQUEST",
                    400, "TOKEN_RESPONSE", out) != 0) {
            /* expect 400 - demo expects this to "succeed" since it returned 400 */
            LogEvent e;
            demo_init_event(&e, "WARN", "REPLAY_DETECTED", "TOKEN",
                            "replay attack detected by server (code reuse)");
            e.peer = peer_text;
            e.security_replay = 1;
            logger_write(&logger, &e);
        }
        demo_finish(&logger, "ABORT", "oauth2 token-replay scenario");
        fclose(out);
        logger_close(&logger);
        return 1;  /* ABORT - this scenario is about detecting replay */
    }

    /* Step 2: /token (POST form) */
    char token_body[256];
    if (require_pkce) {
        snprintf(token_body, sizeof(token_body),
                 "grant_type=authorization_code&code=AUTH_CODE_42&code_verifier=%s",
                 verifier);
    } else {
        snprintf(token_body, sizeof(token_body),
                 "grant_type=authorization_code&code=AUTH_CODE_42");
    }
    if (do_http(&logger, argv[1], port, peer_text, "POST", "/token",
                token_body, "Content-Type: application/x-www-form-urlencoded",
                OAUTH_PKT_TOKEN_REQUEST, "TOKEN_REQUEST",
                200, "TOKEN_RESPONSE", out) != 0) {
        demo_finish(&logger, "ABORT", "token exchange failed");
        fclose(out);
        logger_close(&logger);
        return 1;
    }

    /* Step 3: /api/user (with Bearer token) */
    if (do_http(&logger, argv[1], port, peer_text, "GET", "/api/user", "",
                "Authorization: Bearer demo-access-token-abc",
                OAUTH_PKT_RESOURCE_REQUEST, "RESOURCE_REQUEST",
                200, "RESOURCE_RESPONSE", out) != 0) {
        demo_finish(&logger, "ABORT", "resource fetch failed");
        fclose(out);
        logger_close(&logger);
        return 1;
    }

    /* Step 4: /token (refresh) */
    if (do_http(&logger, argv[1], port, peer_text, "POST", "/token",
                "grant_type=refresh_token&refresh_token=demo-refresh-token-xyz",
                "Content-Type: application/x-www-form-urlencoded",
                OAUTH_PKT_REFRESH_REQUEST, "REFRESH_REQUEST",
                200, "REFRESH_RESPONSE", out) != 0) {
        demo_finish(&logger, "ABORT", "refresh failed");
        fclose(out);
        logger_close(&logger);
        return 1;
    }

    rc = 0;
    demo_finish(&logger, "OK", "oauth2 flow completed");
    fclose(out);
    logger_close(&logger);
    return rc;
}