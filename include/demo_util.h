#ifndef UDP_SECURE_DEMO_UTIL_H
#define UDP_SECURE_DEMO_UTIL_H

#include "logger.h"
#include "sha1_util.h"

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

#define DEMO_HEADER_SIZE 6
#define DEMO_MAX_PAYLOAD 4096
#define DEMO_MAX_FRAME (DEMO_HEADER_SIZE + DEMO_MAX_PAYLOAD)

enum {
    DEMO_PKT_JOIN_REQ = 1,
    DEMO_PKT_PASS_REQ = 2,
    DEMO_PKT_PASS_RESP = 3,
    DEMO_PKT_PASS_ACCEPT = 4,
    DEMO_PKT_DATA = 5,
    DEMO_PKT_TERMINATE = 6,
    DEMO_PKT_REJECT = 7,
    DEMO_PKT_ACK = 8,
    DEMO_PKT_NACK = 9,
    DEMO_PKT_CLIENT_HELLO = 20,
    DEMO_PKT_SERVER_HELLO = 21,
    DEMO_PKT_FINISHED = 22,
    DEMO_PKT_APP_DATA = 23
};

typedef struct {
    uint16_t type;
    uint32_t length;
    uint8_t payload[DEMO_MAX_PAYLOAD];
} DemoFrame;

void demo_init_event(LogEvent *e, const char *level, const char *event,
                     const char *state, const char *message);
void demo_finish(Logger *logger, const char *result, const char *reason);

int demo_create_tcp_listener(uint16_t port);
int demo_accept_client(int listener_fd, struct sockaddr_in *peer);
int demo_connect_tcp(const char *host, uint16_t port, struct sockaddr_in *addr);
int demo_write_all(int fd, const uint8_t *buf, size_t len);
int demo_read_all(int fd, uint8_t *buf, size_t len);
int demo_send_frame(int fd, uint16_t type, const uint8_t *payload, uint32_t length,
                    int fragment_mode);
int demo_recv_frame(int fd, DemoFrame *frame);
const char *demo_packet_type_name(uint16_t type);
int demo_read_password(int interactive, char **passwords, int index, char *buf, size_t size);
void demo_hmac_sha1(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
                    uint8_t out[SHA1_DIGEST_LENGTH]);
void demo_xor_crypt(uint8_t *data, size_t len, const uint8_t *key, size_t key_len);
void demo_derive_session_key(const char *password,
                             const uint8_t *left, size_t left_len,
                             const uint8_t *right, size_t right_len,
                             uint8_t out[SHA1_DIGEST_LENGTH]);
void demo_random_nonce(uint8_t *out, size_t len);
int demo_base64_encode(const uint8_t *data, size_t len, char *out, size_t out_size);

#endif
