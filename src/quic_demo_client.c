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
#include <sys/time.h>
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

typedef struct {
    uint16_t stream_id;
    uint32_t seq;
    uint8_t payload[QUIC_MAX_PAYLOAD];
    uint16_t payload_len;
} StreamChunk;

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
             "quic-like packet sent", peer_text, "Client -> Server", packet, wire, wire_len);
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
             "quic-like packet received", peer_text, "Server -> Client", packet, wire, (size_t)n);
    return 0;
}

static int chunk_cmp(const void *left, const void *right) {
    const StreamChunk *a = left;
    const StreamChunk *b = right;
    if (a->stream_id != b->stream_id) {
        return (int)a->stream_id - (int)b->stream_id;
    }
    if (a->seq < b->seq) return -1;
    if (a->seq > b->seq) return 1;
    return 0;
}

int main(int argc, char **argv) {
    Logger logger;
    int interactive = 0;
    const char *host;
    const char *output_path;
    uint16_t port;
    int fd = -1;
    struct sockaddr_in peer_addr;
    char peer_text[64];
    QuicPacket packet;
    uint32_t connection_id;
    StreamChunk chunks[8];
    size_t chunk_count = 0;
    FILE *out = NULL;
    char temp_path[512];
    const char *scenario = getenv("UDP_SECURE_SCENARIO");

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    ensure_runtime_dirs();
    if (logger_open(&logger, "client", "logs/client.jsonl") != 0) {
        return 1;
    }
    if (argc == 7) {
        host = argv[1];
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
    /* QUIC-like does one auth round; interactive flag is informational. */
    (void)interactive;
    if (parse_port(argv[2], &port) != 0) {
        demo_finish(&logger, "ABORT", "invalid port");
        logger_close(&logger);
        return 1;
    }
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        demo_finish(&logger, "ABORT", "socket failed");
        logger_close(&logger);
        return 1;
    }
    memset(&peer_addr, 0, sizeof(peer_addr));
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &peer_addr.sin_addr) != 1) {
        demo_finish(&logger, "ABORT", "invalid host");
        close(fd);
        logger_close(&logger);
        return 1;
    }
    {
        struct timeval tv = {2, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    snprintf(peer_text, sizeof(peer_text), "%s:%u", host, (unsigned)port);
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
        demo_init_event(&e, "INFO", "CLIENT_START", "INIT", "quic-like client started");
        e.peer = peer_text;
        e.port = (int)port;
        logger_write(&logger, &e);
    }
    demo_random_nonce((uint8_t *)&connection_id, sizeof(connection_id));
    memset(&packet, 0, sizeof(packet));
    packet.type = QUIC_PKT_INITIAL;
    packet.connection_id = connection_id;
    packet.payload_len = (uint16_t)snprintf((char *)packet.payload, sizeof(packet.payload), "client-hello");
    if (send_packet_logged(&logger, fd, &peer_addr, peer_text, &packet, "HANDSHAKE", "SEND_INITIAL") != 0) {
        demo_finish(&logger, "ABORT", "initial send failed");
        fclose(out);
        close(fd);
        logger_close(&logger);
        return 1;
    }
    if (scenario && strcmp(scenario, "zero-rtt-replay-risk") == 0) {
        QuicPacket zero_rtt;
        memset(&zero_rtt, 0, sizeof(zero_rtt));
        zero_rtt.type = QUIC_PKT_ZERO_RTT;
        zero_rtt.connection_id = connection_id;
        zero_rtt.payload_len = (uint16_t)snprintf((char *)zero_rtt.payload, sizeof(zero_rtt.payload), "warmup");
        if (send_packet_logged(&logger, fd, &peer_addr, peer_text, &zero_rtt, "HANDSHAKE", "SEND_ZERO_RTT") != 0) {
            demo_finish(&logger, "ABORT", "0-rtt send failed");
            fclose(out);
            close(fd);
            logger_close(&logger);
            return 1;
        }
    }
    if (recv_packet_logged(&logger, fd, &peer_addr, peer_text, &packet, "HANDSHAKE", "RECV_HANDSHAKE") != 0 ||
        packet.type != QUIC_PKT_HANDSHAKE) {
        demo_finish(&logger, "ABORT", "handshake receive failed");
        fclose(out);
        close(fd);
        logger_close(&logger);
        return 1;
    }
    memset(&packet, 0, sizeof(packet));
    packet.type = QUIC_PKT_HANDSHAKE_ACK;
    packet.connection_id = connection_id;
    if (send_packet_logged(&logger, fd, &peer_addr, peer_text, &packet, "HANDSHAKE", "SEND_HANDSHAKE_ACK") != 0) {
        demo_finish(&logger, "ABORT", "handshake ack send failed");
        fclose(out);
        close(fd);
        logger_close(&logger);
        return 1;
    }
    while (!stop_requested) {
        if (recv_packet_logged(&logger, fd, &peer_addr, peer_text, &packet, "DATA_TRANSFER", "RECV_QUIC_PACKET") != 0) {
            demo_finish(&logger, "ABORT", "receive failed");
            fclose(out);
            remove(temp_path);
            close(fd);
            logger_close(&logger);
            return 1;
        }
        if (packet.type == QUIC_PKT_STREAM) {
            QuicPacket ack;
            if (chunk_count < sizeof(chunks) / sizeof(chunks[0])) {
                chunks[chunk_count].stream_id = packet.stream_id;
                chunks[chunk_count].seq = packet.seq;
                chunks[chunk_count].payload_len = packet.payload_len;
                memcpy(chunks[chunk_count].payload, packet.payload, packet.payload_len);
                chunk_count += 1;
            }
            memset(&ack, 0, sizeof(ack));
            ack.type = QUIC_PKT_ACK;
            ack.connection_id = packet.connection_id;
            ack.ack = packet.seq;
            if (send_packet_logged(&logger, fd, &peer_addr, peer_text, &ack, "VERIFY", "SEND_ACK") != 0) {
                demo_finish(&logger, "ABORT", "ack send failed");
                fclose(out);
                remove(temp_path);
                close(fd);
                logger_close(&logger);
                return 1;
            }
        } else if (packet.type == QUIC_PKT_CLOSE) {
            uint8_t local_digest[SHA1_DIGEST_LENGTH];
            char sha_hex[SHA1_HEX_LENGTH + 1];
            size_t i;
            qsort(chunks, chunk_count, sizeof(chunks[0]), chunk_cmp);
            for (i = 0; i < chunk_count; i += 1) {
                fwrite(chunks[i].payload, 1, chunks[i].payload_len, out);
            }
            fclose(out);
            out = NULL;
            if (sha1_file(temp_path, local_digest) != 0 ||
                packet.payload_len != SHA1_DIGEST_LENGTH ||
                memcmp(local_digest, packet.payload, SHA1_DIGEST_LENGTH) != 0) {
                demo_finish(&logger, "ABORT", "quic-like digest mismatch");
                remove(temp_path);
                close(fd);
                logger_close(&logger);
                return 1;
            }
            sha1_to_hex(local_digest, sha_hex);
            {
                LogEvent e;
                demo_init_event(&e, "SUCCESS", "DIGEST_MATCH", "DONE", "quic-like digest matched");
                e.peer = peer_text;
                e.sha1 = sha_hex;
                logger_write(&logger, &e);
            }
            rename(temp_path, output_path);
            demo_finish(&logger, "OK", "quic-like flow completed");
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
