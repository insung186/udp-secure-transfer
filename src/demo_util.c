#include "demo_util.h"
#include "sha1_util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <time.h>
#include <unistd.h>

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

static uint32_t get_u32(const uint8_t *buf) {
    uint32_t n;
    memcpy(&n, buf, sizeof(n));
    return ntohl(n);
}

void demo_init_event(LogEvent *e, const char *level, const char *event,
                     const char *state, const char *message) {
    memset(e, 0, sizeof(*e));
    e->level = level;
    e->event = event;
    e->state = state;
    e->message = message;
    e->packet_id = LOG_INT_UNSET;
    e->seq = LOG_INT_UNSET;
    e->ack = LOG_INT_UNSET;
    e->window_size = LOG_INT_UNSET;
    e->retransmit_count = LOG_INT_UNSET;
    e->stream_id = LOG_INT_UNSET;
    e->stream_offset = LOG_INT_UNSET;
    e->status_code = LOG_INT_UNSET;
    e->payload_length = LOG_INT_UNSET;
    e->bytes = LOG_INT_UNSET;
    e->attempt = LOG_INT_UNSET;
    e->port = LOG_INT_UNSET;
    e->security_encrypted = LOG_INT_UNSET;
    e->security_mac_valid = LOG_INT_UNSET;
    e->security_replay = LOG_INT_UNSET;
}

void demo_finish(Logger *logger, const char *result, const char *reason) {
    LogEvent e;
    demo_init_event(&e,
                    strcmp(result, "OK") == 0 ? "SUCCESS" : "ABORT",
                    strcmp(result, "OK") == 0 ? "FINAL_OK" : "FINAL_ABORT",
                    strcmp(result, "OK") == 0 ? "DONE" : "ABORT",
                    reason);
    e.result = result;
    logger_write(logger, &e);
    printf("%s\n", result);
    fflush(stdout);
}

int demo_create_tcp_listener(uint16_t port) {
    int fd;
    int yes = 1;
    struct sockaddr_in addr;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(fd, 8) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int demo_accept_client(int listener_fd, struct sockaddr_in *peer) {
    socklen_t len = sizeof(*peer);
    return accept(listener_fd, (struct sockaddr *)peer, &len);
}

int demo_connect_tcp(const char *host, uint16_t port, struct sockaddr_in *addr) {
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *rp = NULL;
    char port_text[16];
    int fd = -1;
    int rc;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port_text, sizeof(port_text), "%u", (unsigned)port);
    rc = getaddrinfo(host, port_text, &hints, &result);
    if (rc != 0) {
        return -1;
    }
    for (rp = result; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            if (addr && rp->ai_addrlen == sizeof(*addr)) {
                memcpy(addr, rp->ai_addr, sizeof(*addr));
            }
            freeaddrinfo(result);
            return fd;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(result);
    return -1;
}

int demo_write_all(int fd, const uint8_t *buf, size_t len) {
    while (len > 0) {
        ssize_t n = send(fd, buf, len, 0);
        if (n <= 0) {
            return -1;
        }
        buf += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

int demo_read_all(int fd, uint8_t *buf, size_t len) {
    while (len > 0) {
        ssize_t n = recv(fd, buf, len, 0);
        if (n <= 0) {
            return -1;
        }
        buf += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

int demo_send_frame(int fd, uint16_t type, const uint8_t *payload, uint32_t length,
                    int fragment_mode) {
    uint8_t buf[DEMO_MAX_FRAME];
    if (length > DEMO_MAX_PAYLOAD) {
        return -1;
    }
    put_u16(buf, type);
    put_u32(buf + 2, length);
    if (length > 0 && payload) {
        memcpy(buf + DEMO_HEADER_SIZE, payload, length);
    }
    if (fragment_mode && length > 0) {
        size_t first = DEMO_HEADER_SIZE + length / 2U;
        if (demo_write_all(fd, buf, first) != 0) return -1;
        return demo_write_all(fd, buf + first, DEMO_HEADER_SIZE + length - first);
    }
    return demo_write_all(fd, buf, DEMO_HEADER_SIZE + length);
}

int demo_recv_frame(int fd, DemoFrame *frame) {
    uint8_t header[DEMO_HEADER_SIZE];
    if (demo_read_all(fd, header, sizeof(header)) != 0) {
        return -1;
    }
    frame->type = get_u16(header);
    frame->length = get_u32(header + 2);
    if (frame->length > DEMO_MAX_PAYLOAD) {
        return -1;
    }
    if (frame->length > 0 && demo_read_all(fd, frame->payload, frame->length) != 0) {
        return -1;
    }
    return 0;
}

const char *demo_packet_type_name(uint16_t type) {
    switch (type) {
    case DEMO_PKT_JOIN_REQ: return "JOIN_REQ";
    case DEMO_PKT_PASS_REQ: return "PASS_REQ";
    case DEMO_PKT_PASS_RESP: return "PASS_RESP";
    case DEMO_PKT_PASS_ACCEPT: return "PASS_ACCEPT";
    case DEMO_PKT_DATA: return "DATA";
    case DEMO_PKT_TERMINATE: return "TERMINATE";
    case DEMO_PKT_REJECT: return "REJECT";
    case DEMO_PKT_ACK: return "ACK";
    case DEMO_PKT_NACK: return "NACK";
    case DEMO_PKT_CLIENT_HELLO: return "CLIENT_HELLO";
    case DEMO_PKT_SERVER_HELLO: return "SERVER_HELLO";
    case DEMO_PKT_FINISHED: return "FINISHED";
    case DEMO_PKT_APP_DATA: return "APP_DATA";
    default: return "UNKNOWN";
    }
}

static void trim_line(char *text) {
    size_t len = strlen(text);
    while (len > 0 && (text[len - 1] == '\n' || text[len - 1] == '\r')) {
        text[--len] = '\0';
    }
}

int demo_read_password(int interactive, char **passwords, int index, char *buf, size_t size) {
    if (!interactive) {
        if (index < 0 || index >= 3 || strlen(passwords[index]) >= size) {
            return -1;
        }
        snprintf(buf, size, "%s", passwords[index]);
        return 0;
    }
    fprintf(stderr, "Password attempt %d: ", index + 1);
    fflush(stderr);
    if (!fgets(buf, (int)size, stdin)) {
        return -1;
    }
    trim_line(buf);
    return 0;
}

int demo_prompt_interactive_password(int stdin_fd, int index, char *buf, size_t size) {
    if (size == 0) {
        return -1;
    }
    buf[0] = '\0';
    fprintf(stderr, "Password attempt %d: ", index + 1);
    fflush(stderr);
    if (stdin_fd >= 0) {
        /* Read one line from the control_server's pipe. Non-blocking pipe writes
           from the UI may arrive in chunks; loop until newline or EOF. */
        size_t pos = 0;
        while (pos + 1 < size) {
            char c;
            ssize_t n = read(stdin_fd, &c, 1);
            if (n == 0) {
                break;
            }
            if (n < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    struct timespec pause = {0, 50000000L};
                    nanosleep(&pause, NULL);
                    continue;
                }
                break;
            }
            if (c == '\n' || c == '\r') {
                break;
            }
            buf[pos++] = c;
        }
        buf[pos] = '\0';
        return (int)pos;
    }
    /* Legacy CLI path. */
    if (!fgets(buf, (int)size, stdin)) {
        return -1;
    }
    trim_line(buf);
    return (int)strlen(buf);
}

void demo_hmac_sha1(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
                    uint8_t out[SHA1_DIGEST_LENGTH]) {
    uint8_t ipad[64];
    uint8_t opad[64];
    uint8_t key_block[64];
    uint8_t inner[SHA1_DIGEST_LENGTH];
    Sha1Context ctx;
    size_t i;
    memset(key_block, 0, sizeof(key_block));
    if (key_len > sizeof(key_block)) {
        sha1_init(&ctx);
        sha1_update(&ctx, key, key_len);
        sha1_final(&ctx, key_block);
    } else if (key_len > 0) {
        memcpy(key_block, key, key_len);
    }
    for (i = 0; i < sizeof(key_block); i += 1) {
        ipad[i] = (uint8_t)(key_block[i] ^ 0x36U);
        opad[i] = (uint8_t)(key_block[i] ^ 0x5cU);
    }
    sha1_init(&ctx);
    sha1_update(&ctx, ipad, sizeof(ipad));
    sha1_update(&ctx, data, data_len);
    sha1_final(&ctx, inner);
    sha1_init(&ctx);
    sha1_update(&ctx, opad, sizeof(opad));
    sha1_update(&ctx, inner, sizeof(inner));
    sha1_final(&ctx, out);
}

void demo_xor_crypt(uint8_t *data, size_t len, const uint8_t *key, size_t key_len) {
    size_t i;
    if (!key_len) {
        return;
    }
    for (i = 0; i < len; i += 1) {
        data[i] ^= key[i % key_len];
    }
}

void demo_derive_session_key(const char *password,
                             const uint8_t *left, size_t left_len,
                             const uint8_t *right, size_t right_len,
                             uint8_t out[SHA1_DIGEST_LENGTH]) {
    Sha1Context ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, (const uint8_t *)password, strlen(password));
    sha1_update(&ctx, left, left_len);
    sha1_update(&ctx, right, right_len);
    sha1_final(&ctx, out);
}

void demo_random_nonce(uint8_t *out, size_t len) {
    size_t i;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    srand((unsigned)(ts.tv_nsec ^ ts.tv_sec));
    for (i = 0; i < len; i += 1) {
        out[i] = (uint8_t)(rand() & 0xff);
    }
}

int demo_base64_encode(const uint8_t *data, size_t len, char *out, size_t out_size) {
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t in_pos = 0;
    size_t out_pos = 0;
    while (in_pos < len) {
        uint32_t block = 0;
        size_t remain = len - in_pos;
        size_t take = remain >= 3 ? 3 : remain;
        size_t i;
        for (i = 0; i < take; i += 1) {
            block |= (uint32_t)data[in_pos + i] << (16U - (unsigned)(i * 8U));
        }
        if (out_pos + 4 >= out_size) {
            return -1;
        }
        out[out_pos++] = alphabet[(block >> 18) & 0x3fU];
        out[out_pos++] = alphabet[(block >> 12) & 0x3fU];
        out[out_pos++] = take >= 2 ? alphabet[(block >> 6) & 0x3fU] : '=';
        out[out_pos++] = take == 3 ? alphabet[block & 0x3fU] : '=';
        in_pos += take;
    }
    if (out_pos >= out_size) {
        return -1;
    }
    out[out_pos] = '\0';
    return 0;
}
