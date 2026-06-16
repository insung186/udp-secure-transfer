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

static volatile sig_atomic_t stop_requested = 0;

static void handle_signal(int signo) {
    (void)signo;
    stop_requested = 1;
}

static void tls_app_mac(uint32_t seq, const uint8_t *cipher, uint32_t cipher_len,
                        const uint8_t *key, uint8_t out[SHA1_DIGEST_LENGTH]) {
    uint8_t *buf;
    size_t total = 4U + cipher_len;
    buf = malloc(total);
    if (!buf) {
        memset(out, 0, SHA1_DIGEST_LENGTH);
        return;
    }
    buf[0] = (uint8_t)((seq >> 24) & 0xffU);
    buf[1] = (uint8_t)((seq >> 16) & 0xffU);
    buf[2] = (uint8_t)((seq >> 8) & 0xffU);
    buf[3] = (uint8_t)(seq & 0xffU);
    if (cipher_len > 0) {
        memcpy(buf + 4, cipher, cipher_len);
    }
    demo_hmac_sha1(key, SHA1_DIGEST_LENGTH, buf, total, out);
    free(buf);
}

static int tls_payload_app_data(uint32_t seq, const uint8_t *plain, uint32_t plain_len,
                                const uint8_t *key, int tamper_mac,
                                uint8_t *out, uint32_t *out_len) {
    uint8_t mac[SHA1_DIGEST_LENGTH];
    uint8_t *cipher;
    if (plain_len + 4U + SHA1_DIGEST_LENGTH > DEMO_MAX_PAYLOAD) {
        return -1;
    }
    out[0] = (uint8_t)((seq >> 24) & 0xffU);
    out[1] = (uint8_t)((seq >> 16) & 0xffU);
    out[2] = (uint8_t)((seq >> 8) & 0xffU);
    out[3] = (uint8_t)(seq & 0xffU);
    cipher = out + 4 + SHA1_DIGEST_LENGTH;
    memcpy(cipher, plain, plain_len);
    demo_xor_crypt(cipher, plain_len, key, SHA1_DIGEST_LENGTH);
    tls_app_mac(seq, cipher, plain_len, key, mac);
    if (tamper_mac) {
        mac[0] ^= 0x5aU;
    }
    memcpy(out + 4, mac, SHA1_DIGEST_LENGTH);
    *out_len = 4U + SHA1_DIGEST_LENGTH + plain_len;
    return 0;
}

static void build_frame_wire(uint16_t type, const uint8_t *payload, uint32_t payload_len,
                             uint8_t *wire, size_t *wire_len) {
    uint16_t n_type = htons(type);
    uint32_t n_len = htonl(payload_len);
    memcpy(wire, &n_type, 2);
    memcpy(wire + 2, &n_len, 4);
    if (payload_len > 0 && payload) {
        memcpy(wire + DEMO_HEADER_SIZE, payload, payload_len);
    }
    *wire_len = DEMO_HEADER_SIZE + payload_len;
}

static void log_frame(Logger *logger, const char *level, const char *event,
                      const char *state, const char *peer, uint16_t type,
                      const uint8_t *payload, uint32_t payload_len,
                      const char *direction, int stream_offset) {
    uint8_t wire[DEMO_MAX_FRAME];
    size_t wire_len = 0;
    char hex[DEMO_MAX_FRAME * 2 + 1];
    char uid[24];
    LogEvent e;
    demo_init_event(&e, level, event, state, "packet event");
    build_frame_wire(type, payload, payload_len, wire, &wire_len);
    bytes_to_hex(wire, wire_len > 160 ? 160 : wire_len, hex, sizeof(hex));
    e.peer = peer;
    e.packet_type = demo_packet_type_name(type);
    e.packet_code = (int)type;
    e.payload_length = (int)payload_len;
    e.bytes = (int)payload_len;
    e.direction = direction;
    e.stream_offset = stream_offset;
    if (type == DEMO_PKT_DATA || type == DEMO_PKT_APP_DATA) {
        e.packet_id = stream_offset;
        e.seq = stream_offset;
    }
    e.wire_hex = hex;
    compute_packet_uid(uid, sizeof(uid), type, stream_offset, 0, wire, wire_len);
    e.packet_uid = uid;
    logger_write(logger, &e);
}

static int send_frame_logged(Logger *logger, int fd, const char *peer, uint16_t type,
                             const uint8_t *payload, uint32_t payload_len,
                             const char *state, const char *event, int *stream_offset,
                             int fragment_mode) {
    if (demo_send_frame(fd, type, payload, payload_len, fragment_mode) != 0) {
        return -1;
    }
    log_frame(logger, (type == DEMO_PKT_DATA || type == DEMO_PKT_APP_DATA) ? "DATA" : "INFO",
              event, state, peer, type, payload, payload_len, "Server -> Client", *stream_offset);
    *stream_offset += DEMO_HEADER_SIZE + (int)payload_len;
    return 0;
}

static int recv_frame_logged(Logger *logger, int fd, const char *peer, DemoFrame *frame,
                             const char *state, const char *event, int *stream_offset) {
    if (demo_recv_frame(fd, frame) != 0) {
        return -1;
    }
    log_frame(logger, (frame->type == DEMO_PKT_DATA || frame->type == DEMO_PKT_APP_DATA) ? "DATA" : "INFO",
              event, state, peer, frame->type, frame->payload, frame->length,
              "Client -> Server", *stream_offset);
    *stream_offset += DEMO_HEADER_SIZE + (int)frame->length;
    return 0;
}

static int run_tcp_basic(Logger *logger, int client_fd, const char *peer_text,
                         const char *input_path, const uint8_t digest[SHA1_DIGEST_LENGTH],
                         int connection_close_mid_transfer, int fragment_mode) {
    FILE *fp = fopen(input_path, "rb");
    uint8_t buf[PROTOCOL_DATA_CHUNK_SIZE];
    uint32_t n;
    int send_offset = 0;
    int chunks = 0;
    if (!fp) {
        return -1;
    }
    while ((n = (uint32_t)fread(buf, 1, sizeof(buf), fp)) > 0) {
        if (send_frame_logged(logger, client_fd, peer_text, DEMO_PKT_DATA, buf, n,
                              "DATA_TRANSFER", "SEND_DATA", &send_offset,
                              fragment_mode && chunks == 0) != 0) {
            fclose(fp);
            return -1;
        }
        chunks += 1;
        if (connection_close_mid_transfer && chunks == 1) {
            fclose(fp);
            close(client_fd);
            demo_finish(logger, "ABORT", "connection closed mid transfer");
            return 1;
        }
    }
    fclose(fp);
    if (send_frame_logged(logger, client_fd, peer_text, DEMO_PKT_TERMINATE, digest, SHA1_DIGEST_LENGTH,
                          "VERIFY", "SEND_TERMINATE", &send_offset, 0) != 0) {
        return -1;
    }
    demo_finish(logger, "OK", "tcp-basic transfer completed");
    return 0;
}

static int run_tls_like(Logger *logger, int client_fd, const char *peer_text,
                        const char *password, const char *input_path,
                        int tamper_finished, int tamper_app_data, int replay_mode) {
    DemoFrame frame;
    uint8_t client_nonce[16];
    uint8_t server_nonce[16];
    uint8_t session_key[SHA1_DIGEST_LENGTH];
    uint8_t expected[SHA1_DIGEST_LENGTH];
    uint8_t reply[SHA1_DIGEST_LENGTH];
    uint8_t file_buf[PROTOCOL_DATA_CHUNK_SIZE];
    FILE *fp = fopen(input_path, "rb");
    int recv_offset = 0;
    int send_offset = 0;
    size_t file_len = 0;
    uint32_t seq = 1;
    uint8_t digest[SHA1_DIGEST_LENGTH];
    char sha_hex[SHA1_HEX_LENGTH + 1];
    if (!fp) {
        return -1;
    }

    if (recv_frame_logged(logger, client_fd, peer_text, &frame, "HANDSHAKE", "RECV_CLIENT_HELLO", &recv_offset) != 0 ||
        frame.type != DEMO_PKT_CLIENT_HELLO || frame.length != sizeof(client_nonce)) {
        fclose(fp);
        return -1;
    }
    memcpy(client_nonce, frame.payload, sizeof(client_nonce));
    demo_random_nonce(server_nonce, sizeof(server_nonce));
    if (send_frame_logged(logger, client_fd, peer_text, DEMO_PKT_SERVER_HELLO, server_nonce, sizeof(server_nonce),
                          "HANDSHAKE", "SEND_SERVER_HELLO", &send_offset, 0) != 0) {
        return -1;
    }

    demo_derive_session_key(password, client_nonce, sizeof(client_nonce),
                            server_nonce, sizeof(server_nonce), session_key);
    demo_hmac_sha1(session_key, sizeof(session_key),
                   (const uint8_t *)"client-finished", strlen("client-finished"), expected);
    if (recv_frame_logged(logger, client_fd, peer_text, &frame, "HANDSHAKE", "RECV_FINISHED", &recv_offset) != 0 ||
        frame.type != DEMO_PKT_FINISHED || frame.length != sizeof(expected)) {
        fclose(fp);
        return -1;
    }
    if (memcmp(frame.payload, expected, sizeof(expected)) != 0) {
        LogEvent e;
        demo_init_event(&e, "ERROR", "FINISHED_VERIFY_FAIL", "HANDSHAKE", "client FINISHED MAC invalid");
        e.peer = peer_text;
        e.security_encrypted = 0;
        e.security_mac_valid = 0;
        e.security_replay = 0;
        e.handshake_phase = "finished";
        logger_write(logger, &e);
        fclose(fp);
        return -1;
    }

    demo_hmac_sha1(session_key, sizeof(session_key),
                   (const uint8_t *)"server-finished", strlen("server-finished"), reply);
    if (tamper_finished) {
        reply[0] ^= 0x33U;
    }
    if (send_frame_logged(logger, client_fd, peer_text, DEMO_PKT_FINISHED, reply, sizeof(reply),
                          "HANDSHAKE", "SEND_FINISHED", &send_offset, 0) != 0) {
        fclose(fp);
        return -1;
    }
    if (tamper_finished) {
        fclose(fp);
        demo_finish(logger, "ABORT", "tampered FINISHED sent");
        return 1;
    }

    while ((file_len = fread(file_buf, 1, sizeof(file_buf), fp)) > 0) {
        uint8_t app_payload[DEMO_MAX_PAYLOAD];
        uint32_t app_len = 0;
        int tamper = tamper_app_data && seq == 1;
        if (tls_payload_app_data(seq, file_buf, (uint32_t)file_len, session_key, tamper,
                                 app_payload, &app_len) != 0) {
            fclose(fp);
            return -1;
        }
        if (send_frame_logged(logger, client_fd, peer_text, DEMO_PKT_APP_DATA, app_payload, app_len,
                              "DATA_TRANSFER", "SEND_APP_DATA", &send_offset, 0) != 0) {
            fclose(fp);
            return -1;
        }
        if (replay_mode && seq == 1) {
            if (send_frame_logged(logger, client_fd, peer_text, DEMO_PKT_APP_DATA, app_payload, app_len,
                                  "DATA_TRANSFER", "SEND_APP_DATA_REPLAY", &send_offset, 0) != 0) {
                fclose(fp);
                return -1;
            }
            fclose(fp);
            demo_finish(logger, "ABORT", "replayed APP_DATA sent");
            return 1;
        }
        seq += 1;
    }
    fclose(fp);
    if (tamper_app_data) {
        demo_finish(logger, "ABORT", "tampered APP_DATA sent");
        return 1;
    }
    if (sha1_file(input_path, digest) != 0) {
        return -1;
    }
    sha1_to_hex(digest, sha_hex);
    {
        LogEvent e;
        demo_init_event(&e, "INFO", "SERVER_DIGEST", "VERIFY", "server digest ready");
        e.peer = peer_text;
        e.sha1 = sha_hex;
        logger_write(logger, &e);
    }
    if (send_frame_logged(logger, client_fd, peer_text, DEMO_PKT_TERMINATE, digest, SHA1_DIGEST_LENGTH,
                          "VERIFY", "SEND_TERMINATE", &send_offset, 0) != 0) {
        return -1;
    }
    demo_finish(logger, "OK", "tls-like transfer completed");
    return 0;
}

int main(int argc, char **argv) {
    Logger logger;
    uint16_t port;
    const char *password;
    const char *input_path;
    int listener_fd = -1;
    int client_fd = -1;
    struct sockaddr_in peer;
    char peer_text[64];
    struct stat st;
    uint8_t digest[SHA1_DIGEST_LENGTH];
    char sha_hex[SHA1_HEX_LENGTH + 1];
    DemoFrame frame;
    int attempt = 0;
    int authed = 0;
    int recv_offset = 0;
    int send_offset = 0;
    int fragment_mode = getenv("UDP_SECURE_STREAM_FRAGMENTATION") && strcmp(getenv("UDP_SECURE_STREAM_FRAGMENTATION"), "1") == 0;
    int tamper_finished = getenv("UDP_SECURE_TAMPER_FINISHED") && strcmp(getenv("UDP_SECURE_TAMPER_FINISHED"), "1") == 0;
    int tamper_app_data = getenv("UDP_SECURE_TAMPER_APP_DATA") && strcmp(getenv("UDP_SECURE_TAMPER_APP_DATA"), "1") == 0;
    const char *protocol = getenv("UDP_SECURE_PROTOCOL");

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
    if (stat(input_path, &st) != 0 || sha1_file(input_path, digest) != 0) {
        demo_finish(&logger, "ABORT", "input file cannot be read");
        logger_close(&logger);
        return 1;
    }
    sha1_to_hex(digest, sha_hex);
    listener_fd = demo_create_tcp_listener(port);
    if (listener_fd < 0) {
        demo_finish(&logger, "ABORT", strerror(errno));
        logger_close(&logger);
        return 1;
    }
    {
        LogEvent e;
        demo_init_event(&e, "INFO", "SERVER_START", "WAIT_JOIN_REQ", "tcp-family server started");
        e.port = (int)port;
        e.bytes = (int)st.st_size;
        e.sha1 = sha_hex;
        logger_write(&logger, &e);
    }
    client_fd = demo_accept_client(listener_fd, &peer);
    if (client_fd < 0) {
        demo_finish(&logger, "ABORT", strerror(errno));
        close(listener_fd);
        logger_close(&logger);
        return 1;
    }
    peer_to_string(&peer, peer_text, sizeof(peer_text));
    if (recv_frame_logged(&logger, client_fd, peer_text, &frame, "WAIT_JOIN_REQ", "RECV_JOIN_REQ", &recv_offset) != 0 ||
        frame.type != DEMO_PKT_JOIN_REQ) {
        demo_finish(&logger, "ABORT", "expected JOIN_REQ");
        close(client_fd);
        close(listener_fd);
        logger_close(&logger);
        return 1;
    }
    if (send_frame_logged(&logger, client_fd, peer_text, DEMO_PKT_PASS_REQ, NULL, 0,
                          "AUTH", "SEND_PASS_REQ", &send_offset, 0) != 0) {
        demo_finish(&logger, "ABORT", "failed to send PASS_REQ");
        close(client_fd);
        close(listener_fd);
        logger_close(&logger);
        return 1;
    }
    while (!stop_requested && attempt < 3 && !authed) {
        if (recv_frame_logged(&logger, client_fd, peer_text, &frame, "AUTH", "RECV_PASS_RESP", &recv_offset) != 0 ||
            frame.type != DEMO_PKT_PASS_RESP) {
            demo_finish(&logger, "ABORT", "expected PASS_RESP");
            close(client_fd);
            close(listener_fd);
            logger_close(&logger);
            return 1;
        }
        attempt += 1;
        if (frame.length == strlen(password) && memcmp(frame.payload, password, frame.length) == 0) {
            authed = 1;
            if (send_frame_logged(&logger, client_fd, peer_text, DEMO_PKT_PASS_ACCEPT, NULL, 0,
                                  "AUTH", "SEND_PASS_ACCEPT", &send_offset, 0) != 0) {
                demo_finish(&logger, "ABORT", "failed to send PASS_ACCEPT");
                close(client_fd);
                close(listener_fd);
                logger_close(&logger);
                return 1;
            }
        } else if (attempt >= 3) {
            send_frame_logged(&logger, client_fd, peer_text, DEMO_PKT_REJECT, NULL, 0,
                              "AUTH", "SEND_REJECT", &send_offset, 0);
            demo_finish(&logger, "ABORT", "authentication failed");
            close(client_fd);
            close(listener_fd);
            logger_close(&logger);
            return 1;
        } else {
            send_frame_logged(&logger, client_fd, peer_text, DEMO_PKT_PASS_REQ, NULL, 0,
                              "AUTH", "SEND_PASS_REQ", &send_offset, 0);
        }
    }

    if (strcmp(protocol ? protocol : "tcp-basic", "tls-like") == 0) {
        int rc = run_tls_like(&logger, client_fd, peer_text, password, input_path,
                              tamper_finished, tamper_app_data,
                              strcmp(getenv("UDP_SECURE_SCENARIO") ? getenv("UDP_SECURE_SCENARIO") : "", "replay") == 0);
        if (rc < 0) {
            demo_finish(&logger, "ABORT", "tls-like flow failed");
            rc = 1;
        }
        close(client_fd);
        close(listener_fd);
        logger_close(&logger);
        return rc;
    }

    {
        int rc = run_tcp_basic(&logger, client_fd, peer_text, input_path, digest,
                               strcmp(getenv("UDP_SECURE_SCENARIO") ? getenv("UDP_SECURE_SCENARIO") : "", "connection-close-mid-transfer") == 0,
                               fragment_mode);
        if (rc < 0) {
            demo_finish(&logger, "ABORT", "tcp-basic flow failed");
            rc = 1;
        }
        close(client_fd);
        close(listener_fd);
        logger_close(&logger);
        return rc;
    }
}
