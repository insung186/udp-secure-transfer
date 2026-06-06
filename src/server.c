#include "logger.h"
#include "protocol.h"
#include "sha1_util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stop_requested = 0;

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

static void log_packet(Logger *logger, const char *level, const char *event,
                       const char *state, const char *peer, const uint8_t *wire,
                       size_t wire_len, const Packet *packet) {
    char hex[PROTOCOL_RECV_BUFFER * 2 + 1];
    LogEvent e = log_defaults(level, event, state, "packet event");
    size_t hex_len = wire_len > 160 ? 160 : wire_len;
    bytes_to_hex(wire, hex_len, hex, sizeof(hex));
    e.peer = peer;
    e.packet_type = packet_type_name(packet->type);
    e.payload_length = (int)packet->payload_length;
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
        e.bytes = (int)packet->payload_length;
    }
    logger_write(logger, &e);
}

static int send_logged(Logger *logger, int sockfd, const struct sockaddr_in *peer,
                       const char *peer_text, uint16_t type, const uint8_t *wire,
                       size_t wire_len, uint32_t packet_id, uint32_t payload_len,
                       const char *state, const char *event) {
    Packet packet;
    memset(&packet, 0, sizeof(packet));
    packet.type = type;
    packet.payload_length = payload_len;
    packet.packet_id = packet_id;
    if (send_all_packet(sockfd, wire, wire_len, peer) != 0) {
        LogEvent e = log_defaults("ERROR", "SEND_ERROR", state, strerror(errno));
        e.peer = peer_text;
        e.packet_type = packet_type_name(type);
        logger_write(logger, &e);
        return -1;
    }
    log_packet(logger, type == PKT_DATA ? "DATA" : "INFO", event, state,
               peer_text, wire, wire_len, &packet);
    return 0;
}

static int recv_expected(Logger *logger, int sockfd, Packet *packet,
                         struct sockaddr_in *peer, const char *state,
                         const char *event, char *peer_text, size_t peer_text_size) {
    char error[160];
    if (recv_packet_timeout(sockfd, packet, peer, env_timeout_ms(), error, sizeof(error)) != 0) {
        LogEvent e = log_defaults(strcmp(error, "timeout") == 0 ? "WARN" : "ERROR",
                                  strcmp(error, "timeout") == 0 ? "TIMEOUT" : "PARSE_ERROR",
                                  state, error);
        e.error_code = error;
        logger_write(logger, &e);
        return -1;
    }
    peer_to_string(peer, peer_text, peer_text_size);
    log_packet(logger, packet->type == PKT_DATA ? "DATA" : "INFO", event, state,
               peer_text, packet->wire, packet->wire_length, packet);
    return 0;
}

static int send_control(Logger *logger, int sockfd, const struct sockaddr_in *peer,
                        const char *peer_text, uint16_t type, const char *state,
                        const char *event) {
    uint8_t wire[PROTOCOL_MAX_DATAGRAM];
    size_t wire_len = 0;
    if (build_control_packet(type, wire, sizeof(wire), &wire_len) != 0) {
        return -1;
    }
    return send_logged(logger, sockfd, peer, peer_text, type, wire, wire_len, 0, 0,
                       state, event);
}

static int transfer_file(Logger *logger, int sockfd, const struct sockaddr_in *peer,
                         const char *peer_text, const char *input_path,
                         const uint8_t digest[PROTOCOL_DIGEST_SIZE]) {
    FILE *fp;
    uint8_t data[PROTOCOL_DATA_CHUNK_SIZE];
    uint8_t wire[PROTOCOL_MAX_DATAGRAM];
    size_t n;
    size_t wire_len;
    uint32_t packet_id = 0;
    char sha_hex[SHA1_HEX_LENGTH + 1];

    fp = fopen(input_path, "rb");
    if (!fp) {
        LogEvent e = log_defaults("ERROR", "FILE_OPEN_ERROR", "DATA_TRANSFER", strerror(errno));
        e.error_code = "FILE_OPEN_ERROR";
        logger_write(logger, &e);
        return -1;
    }

    while ((n = fread(data, 1, sizeof(data), fp)) > 0) {
        struct timespec pause_time;
        if (stop_requested) {
            fclose(fp);
            return -1;
        }
        if (build_data_packet(packet_id, data, (uint32_t)n, wire, sizeof(wire), &wire_len) != 0) {
            fclose(fp);
            return -1;
        }
        if (send_logged(logger, sockfd, peer, peer_text, PKT_DATA, wire, wire_len,
                        packet_id, (uint32_t)n, "DATA_TRANSFER", "SEND_DATA") != 0) {
            fclose(fp);
            return -1;
        }
        packet_id++;
        pause_time.tv_sec = 0;
        pause_time.tv_nsec = 1000000L;
        nanosleep(&pause_time, NULL);
    }
    if (ferror(fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    if (build_terminate_packet(digest, wire, sizeof(wire), &wire_len) != 0) {
        return -1;
    }
    if (send_logged(logger, sockfd, peer, peer_text, PKT_TERMINATE, wire, wire_len,
                    0, PROTOCOL_DIGEST_SIZE, "VERIFY", "SEND_TERMINATE") != 0) {
        return -1;
    }
    sha1_to_hex(digest, sha_hex);
    LogEvent e = log_defaults("SUCCESS", "SERVER_DIGEST", "VERIFY", "server SHA1 digest sent");
    e.peer = peer_text;
    e.sha1 = sha_hex;
    e.bytes = (int)packet_id;
    logger_write(logger, &e);
    return 0;
}

static void usage(const char *program) {
    fprintf(stderr, "Usage: %s <serverport> <password> <inputfile>\n", program);
}

int main(int argc, char **argv) {
    Logger logger;
    uint16_t port;
    const char *password;
    const char *input_path;
    int sockfd = -1;
    struct sockaddr_in server_addr;
    struct sockaddr_in peer;
    char peer_text[64] = "";
    Packet packet;
    uint8_t digest[PROTOCOL_DIGEST_SIZE];
    char sha_hex[SHA1_HEX_LENGTH + 1];
    struct stat st;
    int authed = 0;
    int attempt;

    ensure_runtime_dirs();
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    if (logger_open(&logger, "server", "logs/server.jsonl") != 0) {
        fprintf(stderr, "Cannot open logs/server.jsonl: %s\n", strerror(errno));
        printf("ABORT\n");
        return 1;
    }

    if (argc != 4) {
        usage(argv[0]);
        finish(&logger, "ABORT", "invalid arguments");
        logger_close(&logger);
        return 1;
    }

    if (parse_port(argv[1], &port) != 0 || strlen(argv[2]) > PROTOCOL_MAX_PASSWORD ||
        strlen(argv[2]) == 0) {
        usage(argv[0]);
        finish(&logger, "ABORT", "invalid port or password");
        logger_close(&logger);
        return 1;
    }
    password = argv[2];
    input_path = argv[3];

    if (stat(input_path, &st) != 0 || !S_ISREG(st.st_mode) ||
        sha1_file(input_path, digest) != 0) {
        finish(&logger, "ABORT", "input file cannot be read");
        logger_close(&logger);
        return 1;
    }
    sha1_to_hex(digest, sha_hex);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        finish(&logger, "ABORT", strerror(errno));
        logger_close(&logger);
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0) {
        finish(&logger, "ABORT", strerror(errno));
        close(sockfd);
        logger_close(&logger);
        return 1;
    }

    LogEvent start = log_defaults("INFO", "SERVER_START", "WAIT_JOIN_REQ", "server started");
    start.port = (int)port;
    start.bytes = (int)st.st_size;
    start.sha1 = sha_hex;
    logger_write(&logger, &start);

    if (recv_expected(&logger, sockfd, &packet, &peer, "WAIT_JOIN_REQ", "RECV_JOIN_REQ",
                      peer_text, sizeof(peer_text)) != 0 ||
        packet.type != PKT_JOIN_REQ) {
        finish(&logger, "ABORT", "expected JOIN_REQ");
        close(sockfd);
        logger_close(&logger);
        return 1;
    }

    if (send_control(&logger, sockfd, &peer, peer_text, PKT_PASS_REQ, "AUTH",
                     "SEND_PASS_REQ") != 0) {
        finish(&logger, "ABORT", "failed to send PASS_REQ");
        close(sockfd);
        logger_close(&logger);
        return 1;
    }

    for (attempt = 1; attempt <= 3 && !authed && !stop_requested; attempt++) {
        struct sockaddr_in auth_peer;
        char auth_peer_text[64];
        int password_ok = 0;

        if (recv_expected(&logger, sockfd, &packet, &auth_peer, "AUTH", "RECV_PASS_RESP",
                          auth_peer_text, sizeof(auth_peer_text)) != 0) {
            finish(&logger, "ABORT", "authentication receive failed");
            close(sockfd);
            logger_close(&logger);
            return 1;
        }
        if (!is_same_peer(&peer, &auth_peer)) {
            LogEvent e = log_defaults("WARN", "UNEXPECTED_PEER", "AUTH", "ignored packet from another peer");
            e.peer = auth_peer_text;
            logger_write(&logger, &e);
            attempt--;
            continue;
        }
        if (packet.type != PKT_PASS_RESP) {
            finish(&logger, "ABORT", "expected PASS_RESP");
            close(sockfd);
            logger_close(&logger);
            return 1;
        }
        password_ok = packet.payload_length == strlen(password) &&
                      memcmp(packet.payload, password, packet.payload_length) == 0;
        if (password_ok) {
            LogEvent e = log_defaults("AUTH", "AUTH_SUCCESS", "AUTH", "password accepted");
            e.peer = peer_text;
            e.attempt = attempt;
            logger_write(&logger, &e);
            if (send_control(&logger, sockfd, &peer, peer_text, PKT_PASS_ACCEPT, "AUTH",
                             "SEND_PASS_ACCEPT") != 0) {
                finish(&logger, "ABORT", "failed to send PASS_ACCEPT");
                close(sockfd);
                logger_close(&logger);
                return 1;
            }
            authed = 1;
        } else {
            LogEvent e = log_defaults("AUTH", "AUTH_FAIL", "AUTH", "password rejected");
            e.peer = peer_text;
            e.attempt = attempt;
            logger_write(&logger, &e);
            if (attempt == 3) {
                send_control(&logger, sockfd, &peer, peer_text, PKT_REJECT, "AUTH", "SEND_REJECT");
                finish(&logger, "ABORT", "three password attempts failed");
                close(sockfd);
                logger_close(&logger);
                return 1;
            }
            if (send_control(&logger, sockfd, &peer, peer_text, PKT_PASS_REQ, "AUTH",
                             "SEND_PASS_REQ") != 0) {
                finish(&logger, "ABORT", "failed to send PASS_REQ");
                close(sockfd);
                logger_close(&logger);
                return 1;
            }
        }
    }

    if (!authed || stop_requested) {
        finish(&logger, "ABORT", "server stopped before authentication completed");
        close(sockfd);
        logger_close(&logger);
        return 1;
    }

    if (transfer_file(&logger, sockfd, &peer, peer_text, input_path, digest) != 0) {
        finish(&logger, "ABORT", "file transfer failed");
        close(sockfd);
        logger_close(&logger);
        return 1;
    }

    finish(&logger, "OK", "file sent and digest transmitted");
    close(sockfd);
    logger_close(&logger);
    return 0;
}
