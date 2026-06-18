#include "demo_util.h"
#include "protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>

#define HTTP_BUF_CAP 8192
#define HTTP_UPLOAD_LIMIT 1024

static volatile sig_atomic_t stop_requested = 0;

static void handle_signal(int signo) {
    (void)signo;
    stop_requested = 1;
}

/* Forward declaration for the parser helper defined further below. */
static long header_value_int(const char *match, const char *name);

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
                    long v = header_value_int(cl, "Content-Length:");
                    body_need = (v > 0) ? (size_t)v : 0;
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

/* Parse the integer value of a header line whose substring match begins at `match`.
   Skips whitespace and ':' to reach the numeric value. Robust to `Name: N`,
   `Name:N`, and case differences. Returns -1 on parse failure. */
static long header_value_int(const char *match, const char *name) {
    const char *p = match + strlen(name);
    while (*p == ':' || *p == ' ' || *p == '\t') {
        p += 1;
    }
    if (!*p) {
        return -1;
    }
    char *end = NULL;
    long v = strtol(p, &end, 10);
    if (end == p) {
        return -1;
    }
    return v;
}

static void header_summary(const char *raw, char *out, size_t out_size) {
    const char *cl = find_header_ci(raw, "Content-Length:");
    const char *conn = find_header_ci(raw, "Connection:");
    long cl_val = cl ? header_value_int(cl, "Content-Length:") : 0;
    snprintf(out, out_size, "Content-Length=%ld; Connection=%s",
             cl_val,
             conn ? "close" : "default");
}

static void wire_hex_from_text(const uint8_t *buf, size_t len, char *out, size_t out_size) {
    bytes_to_hex(buf, len > 160 ? 160 : len, out, out_size);
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
    wire_hex_from_text(wire, wire_len, wire_hex, sizeof(wire_hex));
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

static int send_http_response(Logger *logger, int fd, const char *peer, int status_code,
                              const char *status_text, const char *body, const char *packet_type,
                              int packet_code, const char *state, const char *event) {
    char response[HTTP_BUF_CAP];
    char headers[128];
    int body_len = (int)strlen(body);
    int len = snprintf(response, sizeof(response),
                       "HTTP/1.1 %d %s\r\n"
                       "Content-Type: text/plain; charset=utf-8\r\n"
                       "Content-Length: %d\r\n"
                       "Connection: close\r\n\r\n%s",
                       status_code, status_text, body_len, body);
    if (len < 0 || (size_t)len >= sizeof(response)) {
        return -1;
    }
    snprintf(headers, sizeof(headers), "Content-Length=%d; Connection=close", body_len);
    if (demo_write_all(fd, (const uint8_t *)response, (size_t)len) != 0) {
        return -1;
    }
    log_http_packet(logger, status_code >= 400 ? "ERROR" : "INFO", event, state,
                    body, peer, "Server -> Client", packet_type, packet_code,
                    NULL, NULL, status_code, headers, (const uint8_t *)response, (size_t)len);
    return 0;
}

static int parse_request(uint8_t *buf, size_t len, char *method, size_t method_cap,
                         char *path, size_t path_cap, const char **body, size_t *body_len) {
    char *line_end;
    char *headers_end;
    (void)len;
    buf[len] = '\0';
    line_end = strstr((char *)buf, "\r\n");
    headers_end = strstr((char *)buf, "\r\n\r\n");
    if (!line_end || !headers_end) {
        return -1;
    }
    if (sscanf((char *)buf, "%15s %127s", method, path) != 2) {
        return -1;
    }
    *body = headers_end + 4;
    *body_len = len - (size_t)(headers_end + 4 - (char *)buf);
    if (strlen(method) >= method_cap || strlen(path) >= path_cap) {
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    Logger logger;
    uint16_t port;
    const char *password;
    const char *input_path;
    int listener = -1;
    int rc = 1;
    int authed = 0;
    int completed = 0;
    struct stat st;

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
    password = argv[2];
    input_path = argv[3];
    if (stat(input_path, &st) != 0) {
        demo_finish(&logger, "ABORT", "input file cannot be read");
        logger_close(&logger);
        return 1;
    }
    listener = demo_create_tcp_listener(port);
    if (listener < 0) {
        demo_finish(&logger, "ABORT", strerror(errno));
        logger_close(&logger);
        return 1;
    }
    {
        LogEvent e;
        demo_init_event(&e, "INFO", "SERVER_START", "INIT", "http-basic server started");
        e.port = (int)port;
        e.bytes = (int)st.st_size;
        logger_write(&logger, &e);
    }

    while (!stop_requested && !completed) {
        int fd;
        struct sockaddr_in peer_addr;
        char peer[64];
        uint8_t raw[HTTP_BUF_CAP + 1];
        size_t raw_len = 0;
        char method[16];
        char path[128];
        char headers[128];
        const char *body = NULL;
        size_t body_len = 0;
        const char *req_type = "STATUS_REQUEST";
        const char *resp_type = "STATUS_RESPONSE";
        int req_code = 30;
        int resp_code = 31;

        fd = demo_accept_client(listener, &peer_addr);
        if (fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        peer_to_string(&peer_addr, peer, sizeof(peer));
        if (read_http_message(fd, raw, HTTP_BUF_CAP, &raw_len) != 0 ||
            parse_request(raw, raw_len, method, sizeof(method), path, sizeof(path), &body, &body_len) != 0) {
            send_http_response(&logger, fd, peer, 400, "Bad Request", "invalid request",
                               resp_type, resp_code, "ABORT", "SEND_BAD_REQUEST");
            close(fd);
            break;
        }
        if (strcmp(path, "/auth") == 0) {
            req_type = "AUTH_REQUEST";
            resp_type = "AUTH_RESPONSE";
            req_code = 32;
            resp_code = 33;
        } else if (strcmp(path, "/upload") == 0) {
            req_type = "UPLOAD_REQUEST";
            resp_type = "UPLOAD_RESPONSE";
            req_code = 34;
            resp_code = 35;
        }
        header_summary((char *)raw, headers, sizeof(headers));
        log_http_packet(&logger, "INFO", "RECV_HTTP_REQUEST", "HTTP_REQUEST", "http request received",
                        peer, "Client -> Server", req_type, req_code, method, path, 0, headers, raw, raw_len);

        if (strcmp(method, "GET") == 0 && strcmp(path, "/status") == 0) {
            if (send_http_response(&logger, fd, peer, 200, "OK", "status=ready",
                                   resp_type, resp_code, "HTTP_RESPONSE", "SEND_STATUS_OK") != 0) {
                close(fd);
                break;
            }
        } else if (strcmp(method, "POST") == 0 && strcmp(path, "/auth") == 0) {
            if (body_len == strlen(password) + 9 && strncmp(body, "password=", 9) == 0 &&
                strncmp(body + 9, password, strlen(password)) == 0) {
                authed = 1;
                if (send_http_response(&logger, fd, peer, 200, "OK", "auth=accepted",
                                       resp_type, resp_code, "AUTH", "SEND_AUTH_OK") != 0) {
                    close(fd);
                    break;
                }
            } else {
                send_http_response(&logger, fd, peer, 403, "Forbidden", "auth=failed",
                                   resp_type, resp_code, "ABORT", "SEND_AUTH_FAIL");
                close(fd);
                break;
            }
        } else if (strcmp(method, "POST") == 0 && strcmp(path, "/upload") == 0) {
            char body_text[160];
            if (!authed) {
                send_http_response(&logger, fd, peer, 401, "Unauthorized", "auth required",
                                   resp_type, resp_code, "ABORT", "SEND_UPLOAD_UNAUTHORIZED");
                close(fd);
                break;
            }
            if (body_len > HTTP_UPLOAD_LIMIT) {
                send_http_response(&logger, fd, peer, 413, "Payload Too Large", "payload too large",
                                   resp_type, resp_code, "ABORT", "SEND_UPLOAD_TOO_LARGE");
                close(fd);
                break;
            }
            snprintf(body_text, sizeof(body_text), "uploaded=%zu", body_len);
            if (send_http_response(&logger, fd, peer, 201, "Created", body_text,
                                   resp_type, resp_code, "DONE", "SEND_UPLOAD_OK") != 0) {
                close(fd);
                break;
            }
            completed = 1;
            rc = 0;
        } else {
            send_http_response(&logger, fd, peer, 405, "Method Not Allowed", "method not allowed",
                               resp_type, resp_code, "ABORT", "SEND_METHOD_NOT_ALLOWED");
            close(fd);
            break;
        }
        close(fd);
    }

    if (rc == 0) {
        demo_finish(&logger, "OK", "http-basic flow completed");
    } else {
        demo_finish(&logger, "ABORT", "http-basic flow failed");
    }
    close(listener);
    logger_close(&logger);
    return rc;
}
