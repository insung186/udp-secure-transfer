#include "demo_util.h"
#include "protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
                             const char *state, const char *event, int *stream_offset) {
    if (demo_send_frame(fd, type, payload, payload_len, 0) != 0) {
        return -1;
    }
    log_frame(logger, (type == DEMO_PKT_DATA || type == DEMO_PKT_APP_DATA) ? "DATA" : "INFO",
              event, state, peer, type, payload, payload_len, "Client -> Server", *stream_offset);
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
              "Server -> Client", *stream_offset);
    *stream_offset += DEMO_HEADER_SIZE + (int)frame->length;
    return 0;
}

static int verify_tls_app_data(Logger *logger, const char *peer_text, const DemoFrame *frame,
                               const uint8_t *key, FILE *out, uint32_t *seen_seq) {
    uint32_t seq;
    uint8_t mac[SHA1_DIGEST_LENGTH];
    uint8_t expected[SHA1_DIGEST_LENGTH];
    uint8_t *cipher = (uint8_t *)(frame->payload + 4 + SHA1_DIGEST_LENGTH);
    uint32_t cipher_len;
    if (frame->length < 4U + SHA1_DIGEST_LENGTH) {
        return -1;
    }
    seq = ((uint32_t)frame->payload[0] << 24) |
          ((uint32_t)frame->payload[1] << 16) |
          ((uint32_t)frame->payload[2] << 8) |
          (uint32_t)frame->payload[3];
    cipher_len = frame->length - 4U - SHA1_DIGEST_LENGTH;
    memcpy(mac, frame->payload + 4, SHA1_DIGEST_LENGTH);
    tls_app_mac(seq, cipher, cipher_len, key, expected);
    if (seq <= *seen_seq) {
        LogEvent e;
        demo_init_event(&e, "ERROR", "REPLAY_DETECTED", "VERIFY", "replayed APP_DATA detected");
        e.peer = peer_text;
        e.security_encrypted = 1;
        e.security_mac_valid = 1;
        e.security_replay = 1;
        e.handshake_phase = "app-data";
        e.seq = (int)seq;
        logger_write(logger, &e);
        return -1;
    }
    if (memcmp(mac, expected, SHA1_DIGEST_LENGTH) != 0) {
        LogEvent e;
        demo_init_event(&e, "ERROR", "APP_DATA_MAC_FAIL", "VERIFY", "APP_DATA MAC invalid");
        e.peer = peer_text;
        e.security_encrypted = 1;
        e.security_mac_valid = 0;
        e.security_replay = 0;
        e.handshake_phase = "app-data";
        e.seq = (int)seq;
        logger_write(logger, &e);
        return -1;
    }
    demo_xor_crypt(cipher, cipher_len, key, SHA1_DIGEST_LENGTH);
    if (cipher_len > 0 && fwrite(cipher, 1, cipher_len, out) != cipher_len) {
        return -1;
    }
    *seen_seq = seq;
    return 0;
}

int main(int argc, char **argv) {
    Logger logger;
    int interactive = 0;
    char *passwords[3] = {0};
    const char *host;
    const char *output_path;
    char temp_path[512];
    uint16_t port;
    struct sockaddr_in addr;
    char peer_text[64];
    int fd = -1;
    FILE *out = NULL;
    DemoFrame frame;
    int recv_offset = 0;
    int send_offset = 0;
    int attempt = 0;
    const char *protocol = getenv("UDP_SECURE_PROTOCOL");
    char session_password[PROTOCOL_MAX_PASSWORD + 1] = "secret";

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
    if (parse_port(argv[2], &port) != 0) {
        demo_finish(&logger, "ABORT", "invalid port");
        logger_close(&logger);
        return 1;
    }
    fd = demo_connect_tcp(host, port, &addr);
    if (fd < 0) {
        demo_finish(&logger, "ABORT", "tcp connect failed");
        logger_close(&logger);
        return 1;
    }
    peer_to_string(&addr, peer_text, sizeof(peer_text));
    snprintf(temp_path, sizeof(temp_path), "%s.part", output_path);
    out = fopen(temp_path, "wb");
    if (!out) {
        demo_finish(&logger, "ABORT", "output open failed");
        close(fd);
        logger_close(&logger);
        return 1;
    }
    {
        LogEvent e;
        demo_init_event(&e, "INFO", "CLIENT_START", "INIT", "tcp-family client started");
        e.peer = peer_text;
        e.port = (int)port;
        logger_write(&logger, &e);
    }
    if (send_frame_logged(&logger, fd, peer_text, DEMO_PKT_JOIN_REQ, NULL, 0, "WAIT_PASS_REQ", "SEND_JOIN_REQ", &send_offset) != 0) {
        demo_finish(&logger, "ABORT", "failed to send JOIN_REQ");
        fclose(out);
        close(fd);
        logger_close(&logger);
        return 1;
    }
    while (!stop_requested) {
        char password[PROTOCOL_MAX_PASSWORD + 1];
        if (recv_frame_logged(&logger, fd, peer_text, &frame, "AUTH", "RECV_AUTH_PACKET", &recv_offset) != 0) {
            demo_finish(&logger, "ABORT", "authentication receive failed");
            fclose(out);
            remove(temp_path);
            close(fd);
            logger_close(&logger);
            return 1;
        }
        if (frame.type == DEMO_PKT_PASS_REQ) {
            if (demo_read_password(interactive, passwords, attempt, password, sizeof(password)) != 0) {
                demo_finish(&logger, "ABORT", "password unavailable");
                fclose(out);
                remove(temp_path);
                close(fd);
                logger_close(&logger);
                return 1;
            }
            attempt += 1;
            snprintf(session_password, sizeof(session_password), "%s", password);
            if (send_frame_logged(&logger, fd, peer_text, DEMO_PKT_PASS_RESP,
                                  (const uint8_t *)password, (uint32_t)strlen(password),
                                  "AUTH", "SEND_PASS_RESP", &send_offset) != 0) {
                demo_finish(&logger, "ABORT", "failed to send PASS_RESP");
                fclose(out);
                remove(temp_path);
                close(fd);
                logger_close(&logger);
                return 1;
            }
        } else if (frame.type == DEMO_PKT_PASS_ACCEPT) {
            break;
        } else if (frame.type == DEMO_PKT_REJECT) {
            demo_finish(&logger, "ABORT", "server rejected authentication");
            fclose(out);
            remove(temp_path);
            close(fd);
            logger_close(&logger);
            return 1;
        }
    }

    if (strcmp(protocol ? protocol : "tcp-basic", "tls-like") == 0) {
        uint8_t client_nonce[16];
        uint8_t server_nonce[16];
        uint8_t session_key[SHA1_DIGEST_LENGTH];
        uint8_t finished[SHA1_DIGEST_LENGTH];
        uint32_t seen_seq = 0;
        demo_random_nonce(client_nonce, sizeof(client_nonce));
        if (send_frame_logged(&logger, fd, peer_text, DEMO_PKT_CLIENT_HELLO, client_nonce, sizeof(client_nonce),
                              "HANDSHAKE", "SEND_CLIENT_HELLO", &send_offset) != 0 ||
            recv_frame_logged(&logger, fd, peer_text, &frame, "HANDSHAKE", "RECV_SERVER_HELLO", &recv_offset) != 0 ||
            frame.type != DEMO_PKT_SERVER_HELLO || frame.length != sizeof(server_nonce)) {
            demo_finish(&logger, "ABORT", "tls-like hello failed");
            fclose(out);
            remove(temp_path);
            close(fd);
            logger_close(&logger);
            return 1;
        }
        memcpy(server_nonce, frame.payload, sizeof(server_nonce));
        demo_derive_session_key(session_password,
                                client_nonce, sizeof(client_nonce), server_nonce, sizeof(server_nonce), session_key);
        demo_hmac_sha1(session_key, sizeof(session_key),
                       (const uint8_t *)"client-finished", strlen("client-finished"), finished);
        if (send_frame_logged(&logger, fd, peer_text, DEMO_PKT_FINISHED, finished, sizeof(finished),
                              "HANDSHAKE", "SEND_FINISHED", &send_offset) != 0 ||
            recv_frame_logged(&logger, fd, peer_text, &frame, "HANDSHAKE", "RECV_FINISHED", &recv_offset) != 0 ||
            frame.type != DEMO_PKT_FINISHED) {
            demo_finish(&logger, "ABORT", "tls-like finished failed");
            fclose(out);
            remove(temp_path);
            close(fd);
            logger_close(&logger);
            return 1;
        }
        demo_hmac_sha1(session_key, sizeof(session_key),
                       (const uint8_t *)"server-finished", strlen("server-finished"), finished);
        if (memcmp(frame.payload, finished, sizeof(finished)) != 0) {
            LogEvent e;
            demo_init_event(&e, "ERROR", "FINISHED_VERIFY_FAIL", "HANDSHAKE", "server FINISHED invalid");
            e.peer = peer_text;
            e.security_encrypted = 0;
            e.security_mac_valid = 0;
            e.security_replay = 0;
            e.handshake_phase = "finished";
            logger_write(&logger, &e);
            demo_finish(&logger, "ABORT", "tls-like finished verify failed");
            fclose(out);
            remove(temp_path);
            close(fd);
            logger_close(&logger);
            return 1;
        }
        while (!stop_requested) {
            if (recv_frame_logged(&logger, fd, peer_text, &frame, "DATA_TRANSFER", "RECV_TRANSFER_PACKET", &recv_offset) != 0) {
                demo_finish(&logger, "ABORT", "tls-like app data receive failed");
                fclose(out);
                remove(temp_path);
                close(fd);
                logger_close(&logger);
                return 1;
            }
            if (frame.type != DEMO_PKT_APP_DATA) {
                break;
            }
            if (verify_tls_app_data(&logger, peer_text, &frame, session_key, out, &seen_seq) != 0) {
                demo_finish(&logger, "ABORT", "tls-like app data verify failed");
                fclose(out);
                remove(temp_path);
                close(fd);
                logger_close(&logger);
                return 1;
            }
            if (strcmp(getenv("UDP_SECURE_SCENARIO") ? getenv("UDP_SECURE_SCENARIO") : "", "replay") != 0) {
                continue;
            }
        }
        if (frame.type == DEMO_PKT_TERMINATE) {
            uint8_t local_digest[SHA1_DIGEST_LENGTH];
            char sha_hex[SHA1_HEX_LENGTH + 1];
            fclose(out);
            out = NULL;
            if (sha1_file(temp_path, local_digest) != 0 || memcmp(local_digest, frame.payload, SHA1_DIGEST_LENGTH) != 0) {
                demo_finish(&logger, "ABORT", "tls-like digest mismatch");
                remove(temp_path);
                close(fd);
                logger_close(&logger);
                return 1;
            }
            sha1_to_hex(local_digest, sha_hex);
            {
                LogEvent e;
                demo_init_event(&e, "SUCCESS", "DIGEST_MATCH", "DONE", "tls-like digest matched");
                e.peer = peer_text;
                e.sha1 = sha_hex;
                logger_write(&logger, &e);
            }
            rename(temp_path, output_path);
            demo_finish(&logger, "OK", "tls-like transfer completed");
            close(fd);
            logger_close(&logger);
            return 0;
        }
        demo_finish(&logger, "ABORT", "missing terminate for tls-like flow");
        fclose(out);
        remove(temp_path);
        close(fd);
        logger_close(&logger);
        return 1;
    }

    while (!stop_requested) {
        if (recv_frame_logged(&logger, fd, peer_text, &frame, "DATA_TRANSFER", "RECV_TRANSFER_PACKET", &recv_offset) != 0) {
            demo_finish(&logger, "ABORT", "tcp-basic receive failed");
            fclose(out);
            remove(temp_path);
            close(fd);
            logger_close(&logger);
            return 1;
        }
        if (frame.type == DEMO_PKT_DATA) {
            if (frame.length > 0 && fwrite(frame.payload, 1, frame.length, out) != frame.length) {
                demo_finish(&logger, "ABORT", "output write failed");
                fclose(out);
                remove(temp_path);
                close(fd);
                logger_close(&logger);
                return 1;
            }
        } else if (frame.type == DEMO_PKT_TERMINATE) {
            uint8_t local_digest[SHA1_DIGEST_LENGTH];
            fclose(out);
            out = NULL;
            if (sha1_file(temp_path, local_digest) != 0 || memcmp(local_digest, frame.payload, SHA1_DIGEST_LENGTH) != 0) {
                demo_finish(&logger, "ABORT", "digest mismatch");
                remove(temp_path);
                close(fd);
                logger_close(&logger);
                return 1;
            }
            rename(temp_path, output_path);
            demo_finish(&logger, "OK", "tcp-basic transfer completed");
            close(fd);
            logger_close(&logger);
            return 0;
        }
    }
    demo_finish(&logger, "ABORT", "client stopped");
    if (out) fclose(out);
    remove(temp_path);
    close(fd);
    logger_close(&logger);
    return 1;
}
