#include "demo_util.h"
#include "protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#define HTTP_BUF_CAP 8192

static volatile sig_atomic_t stop_requested = 0;

static void handle_signal(int signo) {
    (void)signo;
    stop_requested = 1;
}

static int read_http_message(int fd, uint8_t *buf, size_t cap, size_t *out_len) {
    size_t total = 0;
    int header_end = -1;
    size_t body_need = 0;
    while (total < cap) {
        ssize_t n = recv(fd, buf + total, cap - total, 0);
        char *headers;
        char *cl;
        if (n <= 0) {
            return -1;
        }
        total += (size_t)n;
        buf[total] = '\0';
        if (header_end < 0) {
            headers = strstr((char *)buf, "\r\n\r\n");
            if (headers) {
                header_end = (int)(headers - (char *)buf) + 4;
                cl = (char *)NULL;
                {
                    size_t i;
                    const char *needle = "Content-Length:";
                    size_t needle_len = strlen(needle);
                    for (i = 0; i + needle_len <= total; i += 1) {
                        size_t j;
                        for (j = 0; j < needle_len; j += 1) {
                            if (tolower((unsigned char)buf[i + j]) != tolower((unsigned char)needle[j])) {
                                break;
                            }
                        }
                        if (j == needle_len) {
                            cl = (char *)(buf + i);
                            break;
                        }
                    }
                }
                if (cl) {
                    body_need = (size_t)strtoul(cl + 15, NULL, 10);
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
        if (j == needle_len) {
            return raw + i;
        }
    }
    return NULL;
}

static int parse_status(const uint8_t *buf, int *status_code, const char **body, size_t *body_len) {
    const char *headers_end = strstr((const char *)buf, "\r\n\r\n");
    if (sscanf((const char *)buf, "HTTP/1.1 %d", status_code) != 1 || !headers_end) {
        return -1;
    }
    *body = headers_end + 4;
    *body_len = strlen(headers_end + 4);
    return 0;
}

static void header_summary(const char *raw, char *out, size_t out_size) {
    const char *cl = find_header_ci(raw, "Content-Length:");
    snprintf(out, out_size, "Content-Length=%ld; Connection=close",
             cl ? strtol(cl + 15, NULL, 10) : 0L);
}

static void log_http_packet(Logger *logger, const char *level, const char *event, const char *state,
                            const char *message, const char *peer, const char *direction,
                            const char *packet_type, int packet_code, const char *method,
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

static int do_request(Logger *logger, const char *host, uint16_t port, const char *peer_text,
                      const char *method, const char *path, const char *body,
                      const char *req_type, int req_code,
                      const char *resp_type, int resp_code,
                      int expect_status, FILE *out) {
    char request[HTTP_BUF_CAP];
    char headers[128];
    uint8_t response[HTTP_BUF_CAP + 1];
    size_t response_len = 0;
    const char *resp_body = NULL;
    size_t resp_body_len = 0;
    int status_code = 0;
    int fd = -1;
    struct sockaddr_in addr;
    int len = snprintf(request, sizeof(request),
                       "%s %s HTTP/1.1\r\nHost: %s:%u\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                       method, path, host, (unsigned)port, strlen(body), body);
    if (len < 0 || (size_t)len >= sizeof(request)) {
        return -1;
    }
    snprintf(headers, sizeof(headers), "Content-Length=%zu; Connection=close", strlen(body));
    fd = demo_connect_tcp(host, port, &addr);
    if (fd < 0) {
        return -1;
    }
    log_http_packet(logger, "INFO", "SEND_HTTP_REQUEST", "HTTP_REQUEST", "http request sent",
                    peer_text, "Client -> Server", req_type, req_code, method, path, 0, headers,
                    (const uint8_t *)request, (size_t)len);
    if (demo_write_all(fd, (const uint8_t *)request, (size_t)len) != 0 ||
        read_http_message(fd, response, HTTP_BUF_CAP, &response_len) != 0 ||
        parse_status(response, &status_code, &resp_body, &resp_body_len) != 0) {
        close(fd);
        return -1;
    }
    header_summary((const char *)response, headers, sizeof(headers));
    log_http_packet(logger, status_code >= 400 ? "ERROR" : "INFO", "RECV_HTTP_RESPONSE", "HTTP_RESPONSE",
                    "http response received", peer_text, "Server -> Client", resp_type, resp_code,
                    NULL, path, status_code, headers, response, response_len);
    if (out && resp_body_len > 0) {
        fwrite(resp_body, 1, resp_body_len, out);
        fwrite("\n", 1, 1, out);
    }
    close(fd);
    return status_code == expect_status ? 0 : -1;
}

int main(int argc, char **argv) {
    Logger logger;
    int interactive = 0;
    char *passwords[3] = {0};
    const char *host;
    const char *output_path;
    char peer_text[64];
    uint16_t port;
    FILE *out = NULL;
    const char *scenario = getenv("UDP_SECURE_SCENARIO");
    char request_body[4096];
    int rc = 1;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    ensure_runtime_dirs();
    if (logger_open(&logger, "client", "logs/client.jsonl") != 0) {
        return 1;
    }
    if (argc == 7) {
        host = argv[1];
        passwords[0] = argv[3];
        passwords[1] = argv[4];
        passwords[2] = argv[5];
        output_path = argv[6];
    } else if (argc == 4) {
        interactive = 1;
        host = argv[1];
        output_path = argv[3];
    } else {
        demo_finish(&logger, "ABORT", "invalid arguments");
        logger_close(&logger);
        return 1;
    }
    (void)interactive;
    if (parse_port(argv[2], &port) != 0) {
        demo_finish(&logger, "ABORT", "invalid port");
        logger_close(&logger);
        return 1;
    }
    snprintf(peer_text, sizeof(peer_text), "%s:%u", host, (unsigned)port);
    out = fopen(output_path, "wb");
    if (!out) {
        demo_finish(&logger, "ABORT", "output open failed");
        logger_close(&logger);
        return 1;
    }
    {
        LogEvent e;
        demo_init_event(&e, "INFO", "CLIENT_START", "INIT", "http-basic client started");
        e.peer = peer_text;
        e.port = (int)port;
        logger_write(&logger, &e);
    }

    if (scenario && strcmp(scenario, "bad-method") == 0) {
        rc = do_request(&logger, host, port, peer_text, "PUT", "/status", "",
                        "STATUS_REQUEST", 30, "STATUS_RESPONSE", 31, 405, out);
        demo_finish(&logger, rc == 0 ? "ABORT" : "ABORT", "http-basic bad-method scenario");
        fclose(out);
        logger_close(&logger);
        return 1;
    }

    if (do_request(&logger, host, port, peer_text, "GET", "/status", "",
                   "STATUS_REQUEST", 30, "STATUS_RESPONSE", 31, 200, out) != 0) {
        demo_finish(&logger, "ABORT", "status request failed");
        fclose(out);
        logger_close(&logger);
        return 1;
    }

    snprintf(request_body, sizeof(request_body), "password=%s",
             (scenario && strcmp(scenario, "bad-auth") == 0) ? "wrong" : (passwords[0] ? passwords[0] : "secret"));
    if (do_request(&logger, host, port, peer_text, "POST", "/auth", request_body,
                   "AUTH_REQUEST", 32, "AUTH_RESPONSE", 33,
                   (scenario && strcmp(scenario, "bad-auth") == 0) ? 403 : 200, out) != 0) {
        demo_finish(&logger, "ABORT", "auth request failed");
        fclose(out);
        logger_close(&logger);
        return 1;
    }
    if (scenario && strcmp(scenario, "bad-auth") == 0) {
        demo_finish(&logger, "ABORT", "http-basic bad-auth scenario");
        fclose(out);
        logger_close(&logger);
        return 1;
    }

    if (scenario && strcmp(scenario, "payload-too-large") == 0) {
        memset(request_body, 'A', sizeof(request_body) - 1);
        request_body[sizeof(request_body) - 1] = '\0';
        rc = do_request(&logger, host, port, peer_text, "POST", "/upload", request_body,
                        "UPLOAD_REQUEST", 34, "UPLOAD_RESPONSE", 35, 413, out);
        demo_finish(&logger, "ABORT", "http-basic payload-too-large scenario");
        fclose(out);
        logger_close(&logger);
        return rc == 0 ? 1 : 1;
    }

    snprintf(request_body, sizeof(request_body), "demo upload from %s", host);
    if (do_request(&logger, host, port, peer_text, "POST", "/upload", request_body,
                   "UPLOAD_REQUEST", 34, "UPLOAD_RESPONSE", 35, 201, out) != 0) {
        demo_finish(&logger, "ABORT", "upload request failed");
        fclose(out);
        logger_close(&logger);
        return 1;
    }

    demo_finish(&logger, "OK", "http-basic flow completed");
    fclose(out);
    logger_close(&logger);
    return 0;
}
