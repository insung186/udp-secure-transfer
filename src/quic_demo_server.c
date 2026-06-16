#include "demo_util.h"
#include "protocol.h"
#include "sha1_util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define QUIC_HEADER_SIZE 19
#define QUIC_MAX_PAYLOAD 1200

enum {
    QUIC_PKT_INITIAL = 60,
    QUIC_PKT_HANDSHAKE = 61,
    QUIC_PKT_HANDSHAKE_ACK = 62,
    QUIC_PKT_STREAM = 63,
    QUIC_PKT_ACK = 64,
    QUIC_PKT_CLOSE = 65,
    QUIC_PKT_ZERO_RTT = 66
};

typedef struct {
    uint8_t type;
    uint8_t flags;
    uint16_t stream_id;
    uint32_t connection_id;
    uint32_t seq;
    uint32_t ack;
    uint8_t retransmit_count;
    uint16_t payload_len;
    uint8_t payload[QUIC_MAX_PAYLOAD];
} QuicPacket;

static volatile sig_atomic_t stop_requested = 0;

static void handle_signal(int signo) {
    (void)signo;
    stop_requested = 1;
}

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

static int encode_packet(const QuicPacket *packet, uint8_t *wire, size_t *wire_len) {
    if (packet->payload_len > QUIC_MAX_PAYLOAD) {
        return -1;
    }
    wire[0] = packet->type;
    wire[1] = packet->flags;
    put_u16(wire + 2, packet->stream_id);
    put_u32(wire + 4, packet->connection_id);
    put_u32(wire + 8, packet->seq);
    put_u32(wire + 12, packet->ack);
    wire[16] = packet->retransmit_count;
    put_u16(wire + 17, packet->payload_len);
    if (packet->payload_len > 0) {
        memcpy(wire + QUIC_HEADER_SIZE, packet->payload, packet->payload_len);
    }
    *wire_len = QUIC_HEADER_SIZE + packet->payload_len;
    return 0;
}

static int decode_packet(const uint8_t *wire, size_t wire_len, QuicPacket *packet) {
    if (wire_len < QUIC_HEADER_SIZE) {
        return -1;
    }
    packet->type = wire[0];
    packet->flags = wire[1];
    packet->stream_id = get_u16(wire + 2);
    packet->connection_id = get_u32(wire + 4);
    packet->seq = get_u32(wire + 8);
    packet->ack = get_u32(wire + 12);
    packet->retransmit_count = wire[16];
    packet->payload_len = get_u16(wire + 17);
    if (wire_len < (size_t)QUIC_HEADER_SIZE + packet->payload_len || packet->payload_len > QUIC_MAX_PAYLOAD) {
        return -1;
    }
    if (packet->payload_len > 0) {
        memcpy(packet->payload, wire + QUIC_HEADER_SIZE, packet->payload_len);
    }
    return 0;
}

static const char *quic_type_name(uint8_t type) {
    switch (type) {
    case QUIC_PKT_INITIAL: return "INITIAL";
    case QUIC_PKT_HANDSHAKE: return "HANDSHAKE";
    case QUIC_PKT_HANDSHAKE_ACK: return "HANDSHAKE_ACK";
    case QUIC_PKT_STREAM: return "STREAM";
    case QUIC_PKT_ACK: return "ACK";
    case QUIC_PKT_CLOSE: return "CLOSE";
    case QUIC_PKT_ZERO_RTT: return "ZERO_RTT";
    default: return "UNKNOWN";
    }
}

static void log_quic(Logger *logger, const char *level, const char *event, const char *state,
                     const char *message, const char *peer, const char *direction,
                     const QuicPacket *packet, const uint8_t *wire, size_t wire_len) {
    char wire_hex[321];
    char uid[24];
    char conn_text[32];
    LogEvent e;
    demo_init_event(&e, level, event, state, message);
    bytes_to_hex(wire, wire_len > 160 ? 160 : wire_len, wire_hex, sizeof(wire_hex));
    snprintf(conn_text, sizeof(conn_text), "cid-%08x", packet->connection_id);
    compute_packet_uid(uid, sizeof(uid), packet->type, (int)packet->seq, (int)packet->ack, wire, wire_len);
    e.peer = peer;
    e.direction = direction;
    e.packet_type = quic_type_name(packet->type);
    e.packet_code = packet->type;
    e.connection_id = conn_text;
    e.stream_id = packet->stream_id;
    e.seq = (int)packet->seq;
    e.ack = (int)packet->ack;
    e.retransmit_count = packet->retransmit_count;
    e.payload_length = packet->payload_len;
    e.bytes = packet->payload_len;
    e.packet_uid = uid;
    e.wire_hex = wire_hex;
    logger_write(logger, &e);
}

static int send_packet_logged(Logger *logger, int fd, const struct sockaddr_in *peer, const char *peer_text,
                              QuicPacket *packet, const char *state, const char *event) {
    uint8_t wire[QUIC_HEADER_SIZE + QUIC_MAX_PAYLOAD];
    size_t wire_len = 0;
    if (encode_packet(packet, wire, &wire_len) != 0 ||
        sendto(fd, wire, wire_len, 0, (const struct sockaddr *)peer, sizeof(*peer)) != (ssize_t)wire_len) {
        return -1;
    }
    log_quic(logger, packet->type == QUIC_PKT_STREAM ? "DATA" : "INFO", event, state,
             "quic-like packet sent", peer_text, "Server -> Client", packet, wire, wire_len);
    return 0;
}

static int recv_packet_logged(Logger *logger, int fd, struct sockaddr_in *peer, char *peer_text,
                              QuicPacket *packet, const char *state, const char *event) {
    uint8_t wire[QUIC_HEADER_SIZE + QUIC_MAX_PAYLOAD];
    socklen_t len = sizeof(*peer);
    ssize_t n = recvfrom(fd, wire, sizeof(wire), 0, (struct sockaddr *)peer, &len);
    if (n <= 0 || decode_packet(wire, (size_t)n, packet) != 0) {
        return -1;
    }
    peer_to_string(peer, peer_text, 64);
    log_quic(logger, packet->type == QUIC_PKT_STREAM ? "DATA" : "INFO", event, state,
             "quic-like packet received", peer_text, "Client -> Server", packet, wire, (size_t)n);
    return 0;
}

static int await_ack(Logger *logger, int fd, struct sockaddr_in *peer, char *peer_text, uint32_t expect_ack) {
    QuicPacket packet;
    if (recv_packet_logged(logger, fd, peer, peer_text, &packet, "VERIFY", "RECV_ACK") != 0) {
        return -1;
    }
    return packet.type == QUIC_PKT_ACK && packet.ack == expect_ack ? 0 : -1;
}

int main(int argc, char **argv) {
    Logger logger;
    uint16_t port;
    const char *input_path;
    int fd = -1;
    struct sockaddr_in server_addr;
    struct sockaddr_in peer_addr;
    char peer_text[64] = "-";
    struct stat st;
    FILE *fp = NULL;
    uint8_t file_buf[QUIC_MAX_PAYLOAD];
    size_t file_len = 0;
    uint8_t digest[SHA1_DIGEST_LENGTH];
    const char *scenario = getenv("UDP_SECURE_SCENARIO");
    int rc = 1;

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
    input_path = argv[3];
    if (stat(input_path, &st) != 0 || sha1_file(input_path, digest) != 0) {
        demo_finish(&logger, "ABORT", "input file cannot be read");
        logger_close(&logger);
        return 1;
    }
    fp = fopen(input_path, "rb");
    if (!fp) {
        demo_finish(&logger, "ABORT", "input open failed");
        logger_close(&logger);
        return 1;
    }
    file_len = fread(file_buf, 1, sizeof(file_buf), fp);
    fclose(fp);
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        demo_finish(&logger, "ABORT", "socket failed");
        logger_close(&logger);
        return 1;
    }
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0) {
        demo_finish(&logger, "ABORT", strerror(errno));
        close(fd);
        logger_close(&logger);
        return 1;
    }
    {
        struct timeval tv = {2, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    {
        LogEvent e;
        demo_init_event(&e, "INFO", "SERVER_START", "INIT", "quic-like server started");
        e.port = (int)port;
        e.bytes = (int)st.st_size;
        logger_write(&logger, &e);
    }

    {
        QuicPacket packet;
        if (recv_packet_logged(&logger, fd, &peer_addr, peer_text, &packet, "HANDSHAKE", "RECV_INITIAL") != 0 ||
            packet.type != QUIC_PKT_INITIAL) {
            demo_finish(&logger, "ABORT", "initial packet missing");
            close(fd);
            logger_close(&logger);
            return 1;
        }
        if (scenario && strcmp(scenario, "zero-rtt-replay-risk") == 0) {
            QuicPacket zero;
            if (recv_packet_logged(&logger, fd, &peer_addr, peer_text, &zero, "HANDSHAKE", "RECV_ZERO_RTT") == 0 &&
                zero.type == QUIC_PKT_ZERO_RTT) {
                LogEvent e;
                demo_init_event(&e, "WARN", "ZERO_RTT_REPLAY_RISK", "HANDSHAKE", "0-RTT replay risk observed");
                e.peer = peer_text;
                e.connection_id = "0-rtt";
                e.security_replay = 1;
                e.handshake_phase = "0-rtt";
                logger_write(&logger, &e);
            }
        }
        {
            QuicPacket reply;
            memset(&reply, 0, sizeof(reply));
            reply.type = QUIC_PKT_HANDSHAKE;
            reply.connection_id = packet.connection_id;
            reply.payload_len = (uint16_t)snprintf((char *)reply.payload, sizeof(reply.payload), "server-hello");
            if (send_packet_logged(&logger, fd, &peer_addr, peer_text, &reply, "HANDSHAKE", "SEND_HANDSHAKE") != 0) {
                demo_finish(&logger, "ABORT", "handshake send failed");
                close(fd);
                logger_close(&logger);
                return 1;
            }
            if (recv_packet_logged(&logger, fd, &peer_addr, peer_text, &packet, "HANDSHAKE", "RECV_HANDSHAKE_ACK") != 0 ||
                packet.type != QUIC_PKT_HANDSHAKE_ACK) {
                demo_finish(&logger, "ABORT", "handshake ack missing");
                close(fd);
                logger_close(&logger);
                return 1;
            }
            if (scenario && strcmp(scenario, "stream-reorder") == 0 && file_len > 2) {
                QuicPacket stream_two;
                QuicPacket stream_one;
                memset(&stream_two, 0, sizeof(stream_two));
                memset(&stream_one, 0, sizeof(stream_one));
                stream_two.type = QUIC_PKT_STREAM;
                stream_two.connection_id = reply.connection_id;
                stream_two.stream_id = 3;
                stream_two.seq = 2;
                stream_two.payload_len = (uint16_t)(file_len / 2);
                memcpy(stream_two.payload, file_buf + (file_len - stream_two.payload_len), stream_two.payload_len);
                stream_one.type = QUIC_PKT_STREAM;
                stream_one.connection_id = reply.connection_id;
                stream_one.stream_id = 1;
                stream_one.seq = 1;
                stream_one.payload_len = (uint16_t)(file_len - stream_two.payload_len);
                memcpy(stream_one.payload, file_buf, stream_one.payload_len);
                if (send_packet_logged(&logger, fd, &peer_addr, peer_text, &stream_two, "DATA_TRANSFER", "SEND_STREAM") != 0 ||
                    await_ack(&logger, fd, &peer_addr, peer_text, 2) != 0 ||
                    send_packet_logged(&logger, fd, &peer_addr, peer_text, &stream_one, "DATA_TRANSFER", "SEND_STREAM") != 0 ||
                    await_ack(&logger, fd, &peer_addr, peer_text, 1) != 0) {
                    demo_finish(&logger, "ABORT", "stream reorder flow failed");
                    close(fd);
                    logger_close(&logger);
                    return 1;
                }
            } else {
                QuicPacket stream;
                memset(&stream, 0, sizeof(stream));
                stream.type = QUIC_PKT_STREAM;
                stream.connection_id = reply.connection_id;
                stream.stream_id = 1;
                stream.seq = 1;
                stream.payload_len = (uint16_t)file_len;
                memcpy(stream.payload, file_buf, file_len);
                if (scenario && strcmp(scenario, "loss-recovery") == 0) {
                    stream.retransmit_count = 1;
                    {
                        struct timespec pause_time;
                        pause_time.tv_sec = 0;
                        pause_time.tv_nsec = 150000000L;
                        nanosleep(&pause_time, NULL);
                    }
                }
                if (send_packet_logged(&logger, fd, &peer_addr, peer_text, &stream, "DATA_TRANSFER", "SEND_STREAM") != 0 ||
                    await_ack(&logger, fd, &peer_addr, peer_text, 1) != 0) {
                    demo_finish(&logger, "ABORT", "stream send failed");
                    close(fd);
                    logger_close(&logger);
                    return 1;
                }
            }
            {
                QuicPacket close_packet;
                memset(&close_packet, 0, sizeof(close_packet));
                close_packet.type = QUIC_PKT_CLOSE;
                close_packet.connection_id = reply.connection_id;
                close_packet.payload_len = SHA1_DIGEST_LENGTH;
                memcpy(close_packet.payload, digest, SHA1_DIGEST_LENGTH);
                if (send_packet_logged(&logger, fd, &peer_addr, peer_text, &close_packet, "DONE", "SEND_CLOSE") != 0) {
                    demo_finish(&logger, "ABORT", "close send failed");
                    close(fd);
                    logger_close(&logger);
                    return 1;
                }
            }
        }
    }
    rc = 0;
    demo_finish(&logger, "OK", "quic-like flow completed");
    close(fd);
    logger_close(&logger);
    return rc;
}
