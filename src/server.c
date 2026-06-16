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

typedef struct {
    uint32_t packet_id;
    uint32_t payload_length;
    size_t wire_len;
    uint8_t wire[PROTOCOL_MAX_DATAGRAM];
    int acked;
    int send_count;
    int drop_first_send;
    int dup_first_send;
    int reorder_first_send;
    int reorder_pending;
    struct timespec last_send;
} ReliableChunk;

typedef struct {
    uint32_t ids[128];
    size_t count;
} PacketIdList;

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

static long elapsed_ms_since(const struct timespec *ts) {
    struct timespec now;
    long sec_diff;
    long nsec_diff;
    clock_gettime(CLOCK_MONOTONIC, &now);
    sec_diff = (long)(now.tv_sec - ts->tv_sec);
    nsec_diff = now.tv_nsec - ts->tv_nsec;
    return sec_diff * 1000L + nsec_diff / 1000000L;
}

static void parse_packet_id_list(const char *text, PacketIdList *list) {
    const char *p = text;
    char *end = NULL;
    long value;
    if (!list) {
        return;
    }
    memset(list, 0, sizeof(*list));
    if (!text || !*text) {
        return;
    }
    while (*p && list->count < (sizeof(list->ids) / sizeof(list->ids[0]))) {
        while (*p == ' ' || *p == '\t' || *p == ',') {
            p++;
        }
        if (!*p) {
            break;
        }
        errno = 0;
        value = strtol(p, &end, 10);
        if (errno == 0 && end != p && value >= 0 && value <= 0x7fffffffL) {
            list->ids[list->count++] = (uint32_t)value;
        }
        p = end && end > p ? end : p + 1;
    }
}

static int packet_id_list_contains(const PacketIdList *list, uint32_t packet_id) {
    size_t i;
    if (!list) {
        return 0;
    }
    for (i = 0; i < list->count; i += 1) {
        if (list->ids[i] == packet_id) {
            return 1;
        }
    }
    return 0;
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
                       size_t wire_len, uint32_t packet_id, uint32_t payload_len,
                       uint32_t ack_id, uint32_t window_size, int retransmit_count,
                       const char *state, const char *event) {
    Packet packet;
    memset(&packet, 0, sizeof(packet));
    packet.type = type;
    packet.payload_length = payload_len;
    packet.packet_id = packet_id;
    packet.ack_id = ack_id;
    packet.window_size = window_size;
    if (send_all_packet(sockfd, wire, wire_len, peer) != 0) {
        LogEvent e = log_defaults("ERROR", "SEND_ERROR", state, strerror(errno));
        e.peer = peer_text;
        e.packet_type = packet_type_name(type);
        e.packet_code = (int)type;
        e.direction = "Server -> Client";
        e.retransmit_count = retransmit_count;
        logger_write(logger, &e);
        return -1;
    }
    log_packet(logger, type == PKT_DATA ? "DATA" : "INFO", event, state,
               peer_text, wire, wire_len, &packet, "Server -> Client", 0, retransmit_count);
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
        e.direction = "Client -> Server";
        logger_write(logger, &e);
        return -1;
    }
    peer_to_string(peer, peer_text, peer_text_size);
    log_packet(logger, packet->type == PKT_DATA ? "DATA" : "INFO", event, state,
               peer_text, packet->wire, packet->wire_length, packet, "Client -> Server", 0, 0);
    return 0;
}

static int recv_expected(Logger *logger, int sockfd, Packet *packet,
                         struct sockaddr_in *peer, const char *state,
                         const char *event, char *peer_text, size_t peer_text_size) {
    return recv_logged_timeout(logger, sockfd, packet, peer, state, event,
                               peer_text, peer_text_size, env_timeout_ms(), 1);
}

static int send_control(Logger *logger, int sockfd, const struct sockaddr_in *peer,
                        const char *peer_text, uint16_t type, const char *state,
                        const char *event) {
    uint8_t wire[PROTOCOL_MAX_DATAGRAM];
    size_t wire_len = 0;
    if (build_control_packet(type, wire, sizeof(wire), &wire_len) != 0) {
        return -1;
    }
    return send_logged(logger, sockfd, peer, peer_text, type, wire, wire_len, 0, 0, 0, 0, 0,
                       state, event);
}

static int load_reliable_chunks(const char *input_path, ReliableChunk **out_chunks,
                                size_t *out_count) {
    FILE *fp;
    ReliableChunk *chunks = NULL;
    size_t count = 0;
    size_t cap = 0;
    PacketIdList loss_ids;
    PacketIdList dup_ids;
    PacketIdList reorder_ids;
    uint8_t data[PROTOCOL_DATA_CHUNK_SIZE];
    size_t n;

    parse_packet_id_list(getenv("UDP_SECURE_RELIABLE_LOSS_IDS"), &loss_ids);
    parse_packet_id_list(getenv("UDP_SECURE_RELIABLE_DUP_IDS"), &dup_ids);
    parse_packet_id_list(getenv("UDP_SECURE_RELIABLE_REORDER_IDS"), &reorder_ids);

    fp = fopen(input_path, "rb");
    if (!fp) {
        return -1;
    }
    while ((n = fread(data, 1, sizeof(data), fp)) > 0) {
        size_t wire_len = 0;
        ReliableChunk *next;
        if (count == cap) {
            size_t new_cap = cap ? cap * 2 : 32;
            next = realloc(chunks, new_cap * sizeof(*chunks));
            if (!next) {
                free(chunks);
                fclose(fp);
                return -1;
            }
            chunks = next;
            cap = new_cap;
        }
        memset(&chunks[count], 0, sizeof(chunks[count]));
        chunks[count].packet_id = (uint32_t)count;
        chunks[count].payload_length = (uint32_t)n;
        if (build_data_packet((uint32_t)count, data, (uint32_t)n,
                              chunks[count].wire, sizeof(chunks[count].wire), &wire_len) != 0) {
            free(chunks);
            fclose(fp);
            return -1;
        }
        chunks[count].wire_len = wire_len;
        chunks[count].drop_first_send = packet_id_list_contains(&loss_ids, (uint32_t)count);
        chunks[count].dup_first_send = packet_id_list_contains(&dup_ids, (uint32_t)count);
        chunks[count].reorder_first_send = packet_id_list_contains(&reorder_ids, (uint32_t)count);
        count += 1;
    }
    fclose(fp);
    *out_chunks = chunks;
    *out_count = count;
    return 0;
}

static int send_reliable_chunk(Logger *logger, int sockfd, const struct sockaddr_in *peer,
                               const char *peer_text, ReliableChunk *chunk,
                               const char *state, const char *event) {
    LogEvent sim_event;
    int retransmits;
    if (!chunk) {
        return -1;
    }
    retransmits = chunk->send_count > 0 ? chunk->send_count - 1 : 0;
    if (chunk->send_count == 0 && chunk->reorder_first_send) {
        chunk->reorder_first_send = 0;
        chunk->reorder_pending = 1;
        sim_event = log_defaults("WARN", "SIMULATED_REORDER_HOLD", state,
                                 "held packet for first-send reordering");
        sim_event.packet_id = (int)chunk->packet_id;
        sim_event.seq = (int)chunk->packet_id;
        logger_write(logger, &sim_event);
        return 0;
    }
    if (chunk->send_count == 0 && chunk->drop_first_send) {
        chunk->drop_first_send = 0;
        chunk->send_count += 1;
        clock_gettime(CLOCK_MONOTONIC, &chunk->last_send);
        sim_event = log_defaults("WARN", "SIMULATED_DROP", state,
                                 "dropped first transmission to trigger retransmission");
        sim_event.packet_id = (int)chunk->packet_id;
        sim_event.seq = (int)chunk->packet_id;
        logger_write(logger, &sim_event);
        return 0;
    }
    if (send_logged(logger, sockfd, peer, peer_text, PKT_DATA, chunk->wire, chunk->wire_len,
                    chunk->packet_id, chunk->payload_length, 0, 0, retransmits,
                    state, event) != 0) {
        return -1;
    }
    clock_gettime(CLOCK_MONOTONIC, &chunk->last_send);
    chunk->send_count += 1;
    if (chunk->send_count == 1 && chunk->dup_first_send) {
        chunk->dup_first_send = 0;
        if (send_logged(logger, sockfd, peer, peer_text, PKT_DATA, chunk->wire, chunk->wire_len,
                        chunk->packet_id, chunk->payload_length, 0, 0, retransmits,
                        state, "SEND_DATA_DUPLICATE") != 0) {
            return -1;
        }
        sim_event = log_defaults("WARN", "SIMULATED_DUPLICATE", state,
                                 "duplicated first transmission for receiver dedup testing");
        sim_event.packet_id = (int)chunk->packet_id;
        sim_event.seq = (int)chunk->packet_id;
        logger_write(logger, &sim_event);
    }
    return 0;
}

static int release_delayed_chunks(Logger *logger, int sockfd, const struct sockaddr_in *peer,
                                  const char *peer_text, ReliableChunk *chunks,
                                  size_t chunk_count, const char *state) {
    size_t i;
    for (i = 0; i < chunk_count; i += 1) {
        if (!chunks[i].reorder_pending || chunks[i].acked) {
            continue;
        }
        chunks[i].reorder_pending = 0;
        if (send_reliable_chunk(logger, sockfd, peer, peer_text, &chunks[i],
                                state, "SEND_DATA_REORDERED") != 0) {
            return -1;
        }
    }
    return 0;
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
    /* total_data_bytes: 已成功发送的 DATA 包 payload 累计字节数；
       与 SERVER_START.bytes（输入文件总字节数）保持同语义，
       便于前端 / 终端用户一眼对照"发了多少 / 共有多少"。*/
    size_t total_data_bytes = 0;
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
                        packet_id, (uint32_t)n, 0, 0, 0,
                        "DATA_TRANSFER", "SEND_DATA") != 0) {
            fclose(fp);
            return -1;
        }
        total_data_bytes += n;
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
                    0, PROTOCOL_DIGEST_SIZE, 0, 0, 0,
                    "VERIFY", "SEND_TERMINATE") != 0) {
        return -1;
    }
    sha1_to_hex(digest, sha_hex);
    LogEvent e = log_defaults("SUCCESS", "SERVER_DIGEST", "VERIFY", "server SHA1 digest sent");
    e.peer = peer_text;
    e.sha1 = sha_hex;
    /* 发送完成后：bytes = 累计发送的 payload 字节数（与 SERVER_START.bytes 同语义）。
       若传输中途因 stop_requested 或 send 失败提前返回，bytes 不会更新——这是有意的，
       表示"未完成"。*/
    e.bytes = (int)total_data_bytes;
    logger_write(logger, &e);
    return 0;
}

static int transfer_file_reliable(Logger *logger, int sockfd, const struct sockaddr_in *peer,
                                  const char *peer_text, const char *input_path,
                                  const uint8_t digest[PROTOCOL_DIGEST_SIZE]) {
    ReliableChunk *chunks = NULL;
    size_t chunk_count = 0;
    size_t base = 0;
    size_t next_to_send = 0;
    size_t total_data_bytes = 0;
    int window_size = env_reliable_window_size();
    int retransmit_timeout = env_reliable_timeout_ms();
    int terminate_sent = 0;
    uint8_t terminate_wire[PROTOCOL_MAX_DATAGRAM];
    size_t terminate_len = 0;
    Packet packet;
    struct sockaddr_in fb_peer;
    char fb_peer_text[64];
    char sha_hex[SHA1_HEX_LENGTH + 1];
    size_t i;

    if (load_reliable_chunks(input_path, &chunks, &chunk_count) != 0) {
        LogEvent e = log_defaults("ERROR", "FILE_OPEN_ERROR", "DATA_TRANSFER",
                                  "failed to prepare reliable transfer chunks");
        e.error_code = "FILE_OPEN_ERROR";
        logger_write(logger, &e);
        return -1;
    }
    for (i = 0; i < chunk_count; i += 1) {
        total_data_bytes += chunks[i].payload_length;
    }

    while (!stop_requested && base < chunk_count) {
        while (next_to_send < chunk_count && next_to_send < base + (size_t)window_size) {
            if (send_reliable_chunk(logger, sockfd, peer, peer_text, &chunks[next_to_send],
                                    "DATA_TRANSFER", "SEND_DATA") != 0) {
                free(chunks);
                return -1;
            }
            if (release_delayed_chunks(logger, sockfd, peer, peer_text, chunks,
                                       next_to_send + 1, "DATA_TRANSFER") != 0) {
                free(chunks);
                return -1;
            }
            next_to_send += 1;
        }

        {
            int recv_rc = recv_logged_timeout(logger, sockfd, &packet, &fb_peer, "DATA_TRANSFER",
                                              "RECV_FEEDBACK", fb_peer_text,
                                              sizeof(fb_peer_text), 80, 0);
            if (recv_rc < 0) {
                free(chunks);
                return -1;
            }
            if (recv_rc == 0) {
                if (!is_same_peer(peer, &fb_peer)) {
                    LogEvent e = log_defaults("WARN", "UNEXPECTED_PEER", "DATA_TRANSFER",
                                              "ignored feedback from another peer");
                    e.peer = fb_peer_text;
                    logger_write(logger, &e);
                } else if (packet.type == PKT_ACK) {
                    uint32_t ack_upto = packet.ack_id;
                    if (ack_upto > chunk_count) {
                        ack_upto = (uint32_t)chunk_count;
                    }
                    for (i = base; i < (size_t)ack_upto; i += 1) {
                        chunks[i].acked = 1;
                    }
                    while (base < chunk_count && chunks[base].acked) {
                        base += 1;
                    }
                } else if (packet.type == PKT_NACK) {
                    uint32_t missing = packet.ack_id;
                    if (missing < chunk_count && !chunks[missing].acked) {
                        if (send_reliable_chunk(logger, sockfd, peer, peer_text, &chunks[missing],
                                                "DATA_TRANSFER", "RETRANSMIT_DATA") != 0) {
                            free(chunks);
                            return -1;
                        }
                    }
                } else {
                    LogEvent e = log_defaults("WARN", "UNEXPECTED_FEEDBACK_TYPE", "DATA_TRANSFER",
                                              "ignored non-feedback packet during reliable transfer");
                    e.packet_type = packet_type_name(packet.type);
                    e.packet_code = (int)packet.type;
                    logger_write(logger, &e);
                }
            }
        }

        for (i = base; i < next_to_send; i += 1) {
            if (chunks[i].acked || chunks[i].reorder_pending || chunks[i].send_count <= 0) {
                continue;
            }
            if (elapsed_ms_since(&chunks[i].last_send) >= retransmit_timeout) {
                if (send_reliable_chunk(logger, sockfd, peer, peer_text, &chunks[i],
                                        "DATA_TRANSFER", "RETRANSMIT_DATA") != 0) {
                    free(chunks);
                    return -1;
                }
            }
        }
    }

    if (stop_requested) {
        free(chunks);
        return -1;
    }

    if (build_terminate_packet(digest, terminate_wire, sizeof(terminate_wire), &terminate_len) != 0) {
        free(chunks);
        return -1;
    }
    for (terminate_sent = 0; terminate_sent < 3; terminate_sent += 1) {
        struct timespec pause_time;
        if (send_logged(logger, sockfd, peer, peer_text, PKT_TERMINATE, terminate_wire, terminate_len,
                        0, PROTOCOL_DIGEST_SIZE, 0, 0, terminate_sent,
                        "VERIFY", terminate_sent == 0 ? "SEND_TERMINATE" : "RETRANSMIT_TERMINATE") != 0) {
            free(chunks);
            return -1;
        }
        pause_time.tv_sec = 0;
        pause_time.tv_nsec = 40000000L;
        nanosleep(&pause_time, NULL);
    }
    sha1_to_hex(digest, sha_hex);
    {
        LogEvent e = log_defaults("SUCCESS", "SERVER_DIGEST", "VERIFY",
                                  "server SHA1 digest sent after reliable transfer");
        e.peer = peer_text;
        e.sha1 = sha_hex;
        e.bytes = (int)total_data_bytes;
        e.retransmit_count = 0;
        logger_write(logger, &e);
    }
    free(chunks);
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
    int reliable_mode = protocol_is_reliable();

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

    if ((reliable_mode
             ? transfer_file_reliable(&logger, sockfd, &peer, peer_text, input_path, digest)
             : transfer_file(&logger, sockfd, &peer, peer_text, input_path, digest)) != 0) {
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
