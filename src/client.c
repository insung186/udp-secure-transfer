#include "logger.h"
#include "protocol.h"
#include "sha1_util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static volatile sig_atomic_t stop_requested = 0;

typedef struct {
    uint8_t *data;
    uint32_t length;
    int present;
} BufferedChunk;

static void handle_signal(int signo) {
    (void)signo;
    stop_requested = 1;
}

static LogEvent log_defaults(const char *level, const char *event, const char *state,
                             const char *message) {
    LogEvent e;
    memset(&e, 0, sizeof(e));
    e.level = level;
    e.event = event;
    e.state = state;
    e.message = message;
    e.stream_id = LOG_INT_UNSET;
    e.stream_offset = LOG_INT_UNSET;
    e.status_code = LOG_INT_UNSET;
    e.seq = LOG_INT_UNSET;
    e.ack = LOG_INT_UNSET;
    e.window_size = LOG_INT_UNSET;
    e.retransmit_count = LOG_INT_UNSET;
    e.security_encrypted = LOG_INT_UNSET;
    e.security_mac_valid = LOG_INT_UNSET;
    e.security_replay = LOG_INT_UNSET;
    e.packet_id = LOG_INT_UNSET;
    e.payload_length = LOG_INT_UNSET;
    e.bytes = LOG_INT_UNSET;
    e.attempt = LOG_INT_UNSET;
    e.port = LOG_INT_UNSET;
    return e;
}

static void finish(Logger *logger, const char *result, const char *reason) {
    LogEvent e = log_defaults(strcmp(result, "OK") == 0 ? "SUCCESS" : "ABORT",
                              strcmp(result, "OK") == 0 ? "FINAL_OK" : "FINAL_ABORT",
                              strcmp(result, "OK") == 0 ? "DONE" : "ABORT", reason);
    e.result = result;
    logger_write(logger, &e);
    printf("%s\n", result);
    fflush(stdout);
}

static void free_buffered_chunks(BufferedChunk *chunks, size_t count) {
    size_t i;
    if (!chunks) {
        return;
    }
    for (i = 0; i < count; i += 1) {
        free(chunks[i].data);
    }
    free(chunks);
}

static void log_packet(Logger *logger, const char *level, const char *event,
                       const char *state, const char *peer, const uint8_t *wire,
                       size_t wire_len, const Packet *packet, const char *direction,
                       int attempt, int retransmit_count) {
    char hex[PROTOCOL_RECV_BUFFER * 2 + 1];
    char uid[24];
    LogEvent e = log_defaults(level, event, state, "packet event");
    size_t hex_len = wire_len > 160 ? 160 : wire_len;
    bytes_to_hex(wire, hex_len, hex, sizeof(hex));
    e.peer = peer;
    e.packet_type = packet_type_name(packet->type);
    e.packet_code = (int)packet->type;
    e.payload_length = (int)packet->payload_length;
    e.direction = direction;
    e.retransmit_count = retransmit_count;
    compute_packet_uid(uid, sizeof(uid), packet->type,
                       packet->type == PKT_DATA ? (int)packet->packet_id : 0,
                       attempt, wire, wire_len);
    e.packet_uid = uid[0] ? uid : NULL;
    if (packet->type != PKT_PASS_RESP) {
        e.wire_hex = hex;
        if (hex_len < wire_len) {
            e.message = "packet event; wire_hex preview truncated";
        }
    } else {
        e.message = "packet event; password payload redacted";
    }
    if (packet->type == PKT_DATA) {
        e.packet_id = (int)packet->packet_id;
        e.seq = (int)packet->packet_id;
        e.bytes = (int)packet->payload_length;
    } else if (packet->type == PKT_ACK || packet->type == PKT_NACK) {
        e.ack = (int)packet->ack_id;
        e.window_size = (int)packet->window_size;
        e.packet_id = (int)packet->ack_id;
    }
    logger_write(logger, &e);
}

static int send_logged(Logger *logger, int sockfd, const struct sockaddr_in *peer,
                       const char *peer_text, uint16_t type, const uint8_t *wire,
                       size_t wire_len, uint32_t payload_len, uint32_t ack_id,
                       uint32_t window_size, const char *state,
                       const char *event, int attempt, int retransmit_count) {
    Packet packet;
    memset(&packet, 0, sizeof(packet));
    packet.type = type;
    packet.payload_length = payload_len;
    packet.ack_id = ack_id;
    packet.window_size = window_size;
    if (send_all_packet(sockfd, wire, wire_len, peer) != 0) {
        LogEvent e = log_defaults("ERROR", "SEND_ERROR", state, strerror(errno));
        e.peer = peer_text;
        e.packet_type = packet_type_name(type);
        e.packet_code = (int)type;
        e.direction = "Client -> Server";
        e.retransmit_count = retransmit_count;
        logger_write(logger, &e);
        return -1;
    }
    log_packet(logger, "INFO", event, state, peer_text, wire, wire_len, &packet,
               "Client -> Server", attempt, retransmit_count);
    if (attempt != LOG_INT_UNSET) {
        LogEvent e = log_defaults("AUTH", "AUTH_ATTEMPT_SENT", state, "password attempt sent");
        e.peer = peer_text;
        e.attempt = attempt;
        e.direction = "Client -> Server";
        logger_write(logger, &e);
    }
    return 0;
}

static int recv_logged_timeout(Logger *logger, int sockfd, Packet *packet,
                               struct sockaddr_in *peer, const char *state,
                               const char *event, char *peer_text, size_t peer_text_size,
                               int timeout_ms, int log_timeout) {
    char error[160];
    if (recv_packet_timeout(sockfd, packet, peer, timeout_ms, error, sizeof(error)) != 0) {
        if (!log_timeout && strcmp(error, "timeout") == 0) {
            return 1;
        }
        LogEvent e = log_defaults(strcmp(error, "timeout") == 0 ? "WARN" : "ERROR",
                                  strcmp(error, "timeout") == 0 ? "TIMEOUT" : "PARSE_ERROR",
                                  state, error);
        e.error_code = error;
        e.direction = "Server -> Client";
        logger_write(logger, &e);
        return -1;
    }
    peer_to_string(peer, peer_text, peer_text_size);
    log_packet(logger, packet->type == PKT_DATA ? "DATA" : "INFO", event, state,
               peer_text, packet->wire, packet->wire_length, packet, "Server -> Client", 0, 0);
    return 0;
}

static int recv_logged(Logger *logger, int sockfd, Packet *packet,
                       struct sockaddr_in *peer, const char *state,
                       const char *event, char *peer_text, size_t peer_text_size) {
    return recv_logged_timeout(logger, sockfd, packet, peer, state, event,
                               peer_text, peer_text_size, env_timeout_ms(), 1);
}

static int resolve_server(const char *host, uint16_t port, struct sockaddr_in *addr) {
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *rp;
    char port_text[16];
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    snprintf(port_text, sizeof(port_text), "%u", (unsigned)port);
    rc = getaddrinfo(host, port_text, &hints, &result);
    if (rc != 0) {
        return -1;
    }
    for (rp = result; rp; rp = rp->ai_next) {
        if (rp->ai_addrlen == sizeof(struct sockaddr_in)) {
            memcpy(addr, rp->ai_addr, sizeof(struct sockaddr_in));
            freeaddrinfo(result);
            return 0;
        }
    }
    freeaddrinfo(result);
    return -1;
}

static void trim_line(char *text) {
    size_t len = strlen(text);
    while (len > 0 && (text[len - 1] == '\n' || text[len - 1] == '\r')) {
        text[len - 1] = '\0';
        len--;
    }
}

static int get_password(int interactive, char **passwords, int index, char *buf, size_t size) {
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
    return strlen(buf) <= PROTOCOL_MAX_PASSWORD ? 0 : -1;
}

static int send_feedback(Logger *logger, int sockfd, const struct sockaddr_in *peer,
                         const char *peer_text, uint16_t type, uint32_t ack_id,
                         uint32_t window_size, const char *state, const char *event) {
    uint8_t wire[PROTOCOL_MAX_DATAGRAM];
    size_t wire_len = 0;
    if (build_feedback_packet(type, ack_id, window_size, wire, sizeof(wire), &wire_len) != 0) {
        return -1;
    }
    return send_logged(logger, sockfd, peer, peer_text, type, wire, wire_len,
                       PROTOCOL_FEEDBACK_PAYLOAD_SIZE, ack_id, window_size,
                       state, event, LOG_INT_UNSET, 0);
}

static int ensure_buffer_capacity(BufferedChunk **chunks, size_t *capacity, size_t need) {
    BufferedChunk *next;
    size_t new_cap = *capacity;
    if (need <= *capacity) {
        return 0;
    }
    while (new_cap < need) {
        new_cap = new_cap ? new_cap * 2 : 32;
    }
    next = realloc(*chunks, new_cap * sizeof(*next));
    if (!next) {
        return -1;
    }
    memset(next + *capacity, 0, (new_cap - *capacity) * sizeof(*next));
    *chunks = next;
    *capacity = new_cap;
    return 0;
}

static int transfer_file_reliable(Logger *logger, int sockfd, const struct sockaddr_in *server_addr,
                                  const char *server_peer_text, const char *output_path,
                                  const char *temp_path, FILE *out,
                                  uint64_t *received_bytes_out) {
    BufferedChunk *buffered = NULL;
    size_t buffered_cap = 0;
    uint32_t expected_packet_id = 0;
    uint64_t received_bytes = 0;
    Packet packet;
    struct sockaddr_in recv_peer;
    char recv_peer_text[64];
    int receiver_window = env_reliable_window_size();

    while (!stop_requested) {
        if (recv_logged(logger, sockfd, &packet, &recv_peer, "DATA_TRANSFER", "RECV_TRANSFER_PACKET",
                        recv_peer_text, sizeof(recv_peer_text)) != 0 ||
            !is_same_peer(server_addr, &recv_peer)) {
            free_buffered_chunks(buffered, buffered_cap);
            return -1;
        }

        if (packet.type == PKT_DATA) {
            if (packet.packet_id < expected_packet_id) {
                LogEvent dup = log_defaults("WARN", "DUPLICATE_DATA", "DATA_TRANSFER",
                                            "duplicate DATA packet ignored");
                dup.peer = server_peer_text;
                dup.packet_id = (int)packet.packet_id;
                dup.seq = (int)packet.packet_id;
                logger_write(logger, &dup);
                if (send_feedback(logger, sockfd, server_addr, server_peer_text, PKT_ACK,
                                  expected_packet_id, (uint32_t)receiver_window,
                                  "DATA_TRANSFER", "SEND_ACK") != 0) {
                    free_buffered_chunks(buffered, buffered_cap);
                    return -1;
                }
                continue;
            }

            if (ensure_buffer_capacity(&buffered, &buffered_cap, (size_t)packet.packet_id + 1) != 0) {
                free_buffered_chunks(buffered, buffered_cap);
                return -1;
            }

            if (!buffered[packet.packet_id].present) {
                buffered[packet.packet_id].data = malloc(packet.payload_length ? packet.payload_length : 1);
                if (!buffered[packet.packet_id].data) {
                    free_buffered_chunks(buffered, buffered_cap);
                    return -1;
                }
                if (packet.payload_length > 0) {
                    memcpy(buffered[packet.packet_id].data, packet.payload, packet.payload_length);
                }
                buffered[packet.packet_id].length = packet.payload_length;
                buffered[packet.packet_id].present = 1;
            }

            if (packet.packet_id > expected_packet_id) {
                LogEvent gap = log_defaults("WARN", "OUT_OF_ORDER_DATA", "DATA_TRANSFER",
                                            "received out-of-order DATA packet");
                gap.peer = server_peer_text;
                gap.packet_id = (int)packet.packet_id;
                gap.seq = (int)packet.packet_id;
                gap.ack = (int)expected_packet_id;
                logger_write(logger, &gap);
                if (send_feedback(logger, sockfd, server_addr, server_peer_text, PKT_NACK,
                                  expected_packet_id, (uint32_t)receiver_window,
                                  "DATA_TRANSFER", "SEND_NACK") != 0) {
                    free_buffered_chunks(buffered, buffered_cap);
                    return -1;
                }
            }

            while (expected_packet_id < buffered_cap && buffered[expected_packet_id].present) {
                if (buffered[expected_packet_id].length > 0 &&
                    fwrite(buffered[expected_packet_id].data, 1, buffered[expected_packet_id].length, out) !=
                        buffered[expected_packet_id].length) {
                    free_buffered_chunks(buffered, buffered_cap);
                    return -1;
                }
                received_bytes += buffered[expected_packet_id].length;
                free(buffered[expected_packet_id].data);
                buffered[expected_packet_id].data = NULL;
                buffered[expected_packet_id].length = 0;
                buffered[expected_packet_id].present = 0;
                expected_packet_id += 1;
            }

            if (send_feedback(logger, sockfd, server_addr, server_peer_text, PKT_ACK,
                              expected_packet_id, (uint32_t)receiver_window,
                              "DATA_TRANSFER", "SEND_ACK") != 0) {
                free_buffered_chunks(buffered, buffered_cap);
                return -1;
            }
        } else if (packet.type == PKT_TERMINATE) {
            uint8_t local_digest[PROTOCOL_DIGEST_SIZE];
            char server_sha[SHA1_HEX_LENGTH + 1];
            char local_sha[SHA1_HEX_LENGTH + 1];
            int match;
            fclose(out);
            if (sha1_file(temp_path, local_digest) != 0) {
                free_buffered_chunks(buffered, buffered_cap);
                return -1;
            }
            sha1_to_hex(packet.payload, server_sha);
            sha1_to_hex(local_digest, local_sha);
            match = memcmp(packet.payload, local_digest, PROTOCOL_DIGEST_SIZE) == 0;
            {
                LogEvent digest = log_defaults(match ? "SUCCESS" : "ERROR",
                                               match ? "DIGEST_MATCH" : "DIGEST_MISMATCH",
                                               "VERIFY",
                                               match ? "SHA1 digest matched" : "SHA1 digest mismatched");
                digest.peer = server_peer_text;
                digest.sha1 = local_sha;
                digest.bytes = (int)received_bytes;
                digest.packet_id = (int)expected_packet_id;
                digest.result = match ? "OK" : "ABORT";
                logger_write(logger, &digest);
            }
            {
                LogEvent server_digest = log_defaults("INFO", "SERVER_DIGEST", "VERIFY",
                                                      "server SHA1 digest");
                server_digest.peer = server_peer_text;
                server_digest.sha1 = server_sha;
                logger_write(logger, &server_digest);
            }
            if (send_feedback(logger, sockfd, server_addr, server_peer_text, PKT_ACK,
                              expected_packet_id, (uint32_t)receiver_window,
                              "VERIFY", "SEND_ACK") != 0) {
                free_buffered_chunks(buffered, buffered_cap);
                return -1;
            }
            if (!match) {
                free_buffered_chunks(buffered, buffered_cap);
                return -1;
            }
            if (rename(temp_path, output_path) != 0) {
                free_buffered_chunks(buffered, buffered_cap);
                return -1;
            }
            *received_bytes_out = received_bytes;
            free_buffered_chunks(buffered, buffered_cap);
            return 0;
        } else {
            free_buffered_chunks(buffered, buffered_cap);
            return -1;
        }
    }

    free_buffered_chunks(buffered, buffered_cap);
    return -1;
}

static void usage(const char *program) {
    fprintf(stderr,
            "Usage: %s <servername> <serverport> <clientpwd1> <clientpwd2> <clientpwd3> <outputfile>\n"
            "Interactive extension: %s <servername> <serverport> <outputfile>\n",
            program, program);
}

int main(int argc, char **argv) {
    Logger logger;
    int interactive = 0;
    char *passwords[3] = {0};
    const char *server_name;
    const char *output_path;
    char temp_path[512];
    uint16_t port;
    int sockfd = -1;
    struct sockaddr_in server_addr;
    struct sockaddr_in recv_peer;
    char server_peer_text[64];
    char recv_peer_text[64];
    uint8_t wire[PROTOCOL_MAX_DATAGRAM];
    size_t wire_len = 0;
    Packet packet;
    int attempt = 0;
    int authed = 0;
    FILE *out = NULL;
    uint32_t expected_packet_id = 0;
    uint64_t received_bytes = 0;
    int reliable_mode = protocol_is_reliable();

    ensure_runtime_dirs();
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    if (logger_open(&logger, "client", "logs/client.jsonl") != 0) {
        fprintf(stderr, "Cannot open logs/client.jsonl: %s\n", strerror(errno));
        printf("ABORT\n");
        return 1;
    }

    if (argc == 7) {
        interactive = 0;
        server_name = argv[1];
        passwords[0] = argv[3];
        passwords[1] = argv[4];
        passwords[2] = argv[5];
        output_path = argv[6];
    } else if (argc == 4) {
        interactive = 1;
        server_name = argv[1];
        output_path = argv[3];
    } else {
        usage(argv[0]);
        finish(&logger, "ABORT", "invalid arguments");
        logger_close(&logger);
        return 1;
    }

    if (parse_port(argv[2], &port) != 0 || strlen(output_path) + 6 >= sizeof(temp_path)) {
        usage(argv[0]);
        finish(&logger, "ABORT", "invalid port or output path");
        logger_close(&logger);
        return 1;
    }

    if (resolve_server(server_name, port, &server_addr) != 0) {
        finish(&logger, "ABORT", "server name resolution failed");
        logger_close(&logger);
        return 1;
    }
    peer_to_string(&server_addr, server_peer_text, sizeof(server_peer_text));

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        finish(&logger, "ABORT", strerror(errno));
        logger_close(&logger);
        return 1;
    }

    snprintf(temp_path, sizeof(temp_path), "%s.part", output_path);
    out = fopen(temp_path, "wb");
    if (!out) {
        finish(&logger, "ABORT", "output file cannot be created");
        close(sockfd);
        logger_close(&logger);
        return 1;
    }

    LogEvent start = log_defaults("INFO", "CLIENT_START", "INIT", "client started");
    start.peer = server_peer_text;
    start.port = (int)port;
    logger_write(&logger, &start);

    if (build_control_packet(PKT_JOIN_REQ, wire, sizeof(wire), &wire_len) != 0 ||
        send_logged(&logger, sockfd, &server_addr, server_peer_text, PKT_JOIN_REQ, wire,
                    wire_len, 0, 0, 0, "WAIT_PASS_REQ", "SEND_JOIN_REQ",
                    LOG_INT_UNSET, 0) != 0) {
        finish(&logger, "ABORT", "failed to send JOIN_REQ");
        fclose(out);
        remove(temp_path);
        close(sockfd);
        logger_close(&logger);
        return 1;
    }

    while (!authed && !stop_requested) {
        char password[PROTOCOL_MAX_PASSWORD + 1];
        if (recv_logged(&logger, sockfd, &packet, &recv_peer, "AUTH", "RECV_AUTH_PACKET",
                        recv_peer_text, sizeof(recv_peer_text)) != 0 ||
            !is_same_peer(&server_addr, &recv_peer)) {
            finish(&logger, "ABORT", "authentication receive failed");
            fclose(out);
            remove(temp_path);
            close(sockfd);
            logger_close(&logger);
            return 1;
        }

        if (packet.type == PKT_PASS_REQ) {
            if (attempt >= 3 || get_password(interactive, passwords, attempt, password, sizeof(password)) != 0) {
                finish(&logger, "ABORT", "password attempt unavailable");
                fclose(out);
                remove(temp_path);
                close(sockfd);
                logger_close(&logger);
                return 1;
            }
            attempt++;
            if (build_pass_resp_packet(password, wire, sizeof(wire), &wire_len) != 0 ||
                send_logged(&logger, sockfd, &server_addr, server_peer_text, PKT_PASS_RESP, wire,
                            wire_len, (uint32_t)strlen(password), 0, 0,
                            "AUTH", "SEND_PASS_RESP", attempt, 0) != 0) {
                finish(&logger, "ABORT", "failed to send PASS_RESP");
                fclose(out);
                remove(temp_path);
                close(sockfd);
                logger_close(&logger);
                return 1;
            }
        } else if (packet.type == PKT_PASS_ACCEPT) {
            LogEvent e = log_defaults("AUTH", "AUTH_SUCCESS", "DATA_TRANSFER", "authentication accepted");
            e.peer = server_peer_text;
            e.attempt = attempt;
            logger_write(&logger, &e);
            authed = 1;
        } else if (packet.type == PKT_REJECT) {
            finish(&logger, "ABORT", "server rejected authentication");
            fclose(out);
            remove(temp_path);
            close(sockfd);
            logger_close(&logger);
            return 1;
        } else {
            finish(&logger, "ABORT", "unexpected packet during authentication");
            fclose(out);
            remove(temp_path);
            close(sockfd);
            logger_close(&logger);
            return 1;
        }
    }

    if (reliable_mode) {
        if (transfer_file_reliable(&logger, sockfd, &server_addr, server_peer_text,
                                   output_path, temp_path, out, &received_bytes) != 0) {
            finish(&logger, "ABORT", "reliable transfer failed");
            remove(temp_path);
            close(sockfd);
            logger_close(&logger);
            return 1;
        }
        finish(&logger, "OK", "file received and SHA1 verified");
        close(sockfd);
        logger_close(&logger);
        return 0;
    }

    while (!stop_requested) {
        if (recv_logged(&logger, sockfd, &packet, &recv_peer, "DATA_TRANSFER", "RECV_TRANSFER_PACKET",
                        recv_peer_text, sizeof(recv_peer_text)) != 0 ||
            !is_same_peer(&server_addr, &recv_peer)) {
            finish(&logger, "ABORT", "transfer receive failed");
            fclose(out);
            remove(temp_path);
            close(sockfd);
            logger_close(&logger);
            return 1;
        }

        if (packet.type == PKT_DATA) {
            if (packet.packet_id != expected_packet_id) {
                LogEvent e = log_defaults("ERROR", "SEQUENCE_ERROR", "DATA_TRANSFER",
                                          "DATA packet id is not continuous");
                e.peer = server_peer_text;
                e.packet_id = (int)packet.packet_id;
                e.error_code = "SEQUENCE_ERROR";
                logger_write(&logger, &e);
                finish(&logger, "ABORT", "DATA packet id is not continuous");
                fclose(out);
                remove(temp_path);
                close(sockfd);
                logger_close(&logger);
                return 1;
            }
            if (packet.payload_length > 0 &&
                fwrite(packet.payload, 1, packet.payload_length, out) != packet.payload_length) {
                finish(&logger, "ABORT", "output file write failed");
                fclose(out);
                remove(temp_path);
                close(sockfd);
                logger_close(&logger);
                return 1;
            }
            expected_packet_id++;
            received_bytes += packet.payload_length;
        } else if (packet.type == PKT_TERMINATE) {
            uint8_t local_digest[PROTOCOL_DIGEST_SIZE];
            char server_sha[SHA1_HEX_LENGTH + 1];
            char local_sha[SHA1_HEX_LENGTH + 1];
            int match;
            fclose(out);
            out = NULL;
            if (sha1_file(temp_path, local_digest) != 0) {
                finish(&logger, "ABORT", "failed to calculate local SHA1");
                remove(temp_path);
                close(sockfd);
                logger_close(&logger);
                return 1;
            }
            sha1_to_hex(packet.payload, server_sha);
            sha1_to_hex(local_digest, local_sha);
            match = memcmp(packet.payload, local_digest, PROTOCOL_DIGEST_SIZE) == 0;
            LogEvent digest = log_defaults(match ? "SUCCESS" : "ERROR",
                                           match ? "DIGEST_MATCH" : "DIGEST_MISMATCH",
                                           "VERIFY",
                                           match ? "SHA1 digest matched" : "SHA1 digest mismatched");
            digest.peer = server_peer_text;
            digest.sha1 = local_sha;
            digest.bytes = (int)received_bytes;
            digest.packet_id = (int)expected_packet_id;
            digest.result = match ? "OK" : "ABORT";
            logger_write(&logger, &digest);
            LogEvent server_digest = log_defaults("INFO", "SERVER_DIGEST", "VERIFY", "server SHA1 digest");
            server_digest.peer = server_peer_text;
            server_digest.sha1 = server_sha;
            logger_write(&logger, &server_digest);
            if (!match) {
                finish(&logger, "ABORT", "SHA1 digest mismatch");
                remove(temp_path);
                close(sockfd);
                logger_close(&logger);
                return 1;
            }
            if (rename(temp_path, output_path) != 0) {
                finish(&logger, "ABORT", "failed to commit output file");
                remove(temp_path);
                close(sockfd);
                logger_close(&logger);
                return 1;
            }
            finish(&logger, "OK", "file received and SHA1 verified");
            close(sockfd);
            logger_close(&logger);
            return 0;
        } else {
            finish(&logger, "ABORT", "unexpected packet during file transfer");
            fclose(out);
            remove(temp_path);
            close(sockfd);
            logger_close(&logger);
            return 1;
        }
    }

    finish(&logger, "ABORT", "client stopped");
    if (out) {
        fclose(out);
    }
    remove(temp_path);
    close(sockfd);
    logger_close(&logger);
    return 1;
}
