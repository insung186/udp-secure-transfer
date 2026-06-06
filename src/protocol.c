#include "protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
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

const char *packet_type_name(uint16_t type) {
    switch (type) {
    case PKT_JOIN_REQ:
        return "JOIN_REQ";
    case PKT_PASS_REQ:
        return "PASS_REQ";
    case PKT_PASS_RESP:
        return "PASS_RESP";
    case PKT_PASS_ACCEPT:
        return "PASS_ACCEPT";
    case PKT_DATA:
        return "DATA";
    case PKT_TERMINATE:
        return "TERMINATE";
    case PKT_REJECT:
        return "REJECT";
    default:
        return "UNKNOWN";
    }
}

int packet_type_valid(uint16_t type) {
    return type >= PKT_JOIN_REQ && type <= PKT_REJECT;
}

int is_same_peer(const struct sockaddr_in *a, const struct sockaddr_in *b) {
    return a->sin_family == b->sin_family && a->sin_port == b->sin_port &&
           a->sin_addr.s_addr == b->sin_addr.s_addr;
}

void peer_to_string(const struct sockaddr_in *addr, char *buf, size_t size) {
    char ip[INET_ADDRSTRLEN] = "0.0.0.0";
    if (!addr || !buf || size == 0) {
        return;
    }
    inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
    snprintf(buf, size, "%s:%u", ip, (unsigned)ntohs(addr->sin_port));
}

void bytes_to_hex(const uint8_t *bytes, size_t len, char *out, size_t out_size) {
    static const char hex[] = "0123456789abcdef";
    size_t i;
    if (!out || out_size == 0) {
        return;
    }
    if (!bytes) {
        out[0] = '\0';
        return;
    }
    for (i = 0; i < len && (i * 2 + 2) <= out_size; i++) {
        out[i * 2] = hex[(bytes[i] >> 4) & 0x0f];
        out[i * 2 + 1] = hex[bytes[i] & 0x0f];
    }
    out[i * 2 < out_size ? i * 2 : out_size - 1] = '\0';
}

int build_control_packet(uint16_t type, uint8_t *out, size_t cap, size_t *out_len) {
    if (!out || !out_len || cap < PROTOCOL_HEADER_SIZE || !packet_type_valid(type) ||
        type == PKT_PASS_RESP || type == PKT_DATA || type == PKT_TERMINATE) {
        return -1;
    }
    put_u16(out, type);
    put_u32(out + 2, 0);
    *out_len = PROTOCOL_HEADER_SIZE;
    return 0;
}

int build_pass_resp_packet(const char *password, uint8_t *out, size_t cap, size_t *out_len) {
    size_t len;
    if (!password || !out || !out_len) {
        return -1;
    }
    len = strlen(password);
    if (len > PROTOCOL_MAX_PASSWORD || cap < PROTOCOL_HEADER_SIZE + len) {
        return -1;
    }
    put_u16(out, PKT_PASS_RESP);
    put_u32(out + 2, (uint32_t)len);
    memcpy(out + PROTOCOL_HEADER_SIZE, password, len);
    *out_len = PROTOCOL_HEADER_SIZE + len;
    return 0;
}

int build_data_packet(uint32_t packet_id, const uint8_t *data, uint32_t data_len,
                      uint8_t *out, size_t cap, size_t *out_len) {
    if ((!data && data_len > 0) || !out || !out_len ||
        data_len > PROTOCOL_DATA_CHUNK_SIZE ||
        cap < PROTOCOL_DATA_HEADER_SIZE + (size_t)data_len) {
        return -1;
    }
    put_u16(out, PKT_DATA);
    put_u32(out + 2, data_len);
    put_u32(out + PROTOCOL_HEADER_SIZE, packet_id);
    if (data_len > 0) {
        memcpy(out + PROTOCOL_DATA_HEADER_SIZE, data, data_len);
    }
    *out_len = PROTOCOL_DATA_HEADER_SIZE + data_len;
    return 0;
}

int build_terminate_packet(const uint8_t digest[PROTOCOL_DIGEST_SIZE],
                           uint8_t *out, size_t cap, size_t *out_len) {
    if (!digest || !out || !out_len ||
        cap < PROTOCOL_HEADER_SIZE + PROTOCOL_DIGEST_SIZE) {
        return -1;
    }
    put_u16(out, PKT_TERMINATE);
    put_u32(out + 2, PROTOCOL_DIGEST_SIZE);
    memcpy(out + PROTOCOL_HEADER_SIZE, digest, PROTOCOL_DIGEST_SIZE);
    *out_len = PROTOCOL_HEADER_SIZE + PROTOCOL_DIGEST_SIZE;
    return 0;
}

static int parse_fail(char *error, size_t error_size, const char *message) {
    if (error && error_size > 0) {
        snprintf(error, error_size, "%s", message);
    }
    return -1;
}

int parse_packet(const uint8_t *buf, size_t len, Packet *packet,
                 char *error, size_t error_size) {
    uint16_t type;
    uint32_t payload_len;

    if (!buf || !packet) {
        return parse_fail(error, error_size, "null packet buffer");
    }
    if (len < PROTOCOL_HEADER_SIZE) {
        return parse_fail(error, error_size, "packet shorter than 6-byte header");
    }
    if (len > PROTOCOL_RECV_BUFFER) {
        return parse_fail(error, error_size, "packet exceeds receive buffer");
    }

    memset(packet, 0, sizeof(*packet));
    memcpy(packet->wire, buf, len);
    packet->wire_length = len;
    type = get_u16(buf);
    payload_len = get_u32(buf + 2);
    packet->type = type;
    packet->payload_length = payload_len;
    packet->packet_id = 0;

    if (!packet_type_valid(type)) {
        return parse_fail(error, error_size, "unknown packet type");
    }

    switch (type) {
    case PKT_JOIN_REQ:
    case PKT_PASS_REQ:
    case PKT_PASS_ACCEPT:
    case PKT_REJECT:
        if (payload_len != 0 || len != PROTOCOL_HEADER_SIZE) {
            return parse_fail(error, error_size, "control packet must have zero payload");
        }
        packet->payload = NULL;
        return 0;
    case PKT_PASS_RESP:
        if (payload_len > PROTOCOL_MAX_PASSWORD) {
            return parse_fail(error, error_size, "password payload is too long");
        }
        if (len != PROTOCOL_HEADER_SIZE + (size_t)payload_len) {
            return parse_fail(error, error_size, "PASS_RESP length mismatch");
        }
        packet->payload = packet->wire + PROTOCOL_HEADER_SIZE;
        return 0;
    case PKT_DATA:
        if (payload_len > PROTOCOL_DATA_CHUNK_SIZE) {
            return parse_fail(error, error_size, "DATA payload is too long");
        }
        if (len != PROTOCOL_DATA_HEADER_SIZE + (size_t)payload_len) {
            return parse_fail(error, error_size, "DATA length mismatch");
        }
        packet->packet_id = get_u32(buf + PROTOCOL_HEADER_SIZE);
        packet->payload = packet->wire + PROTOCOL_DATA_HEADER_SIZE;
        return 0;
    case PKT_TERMINATE:
        if (payload_len != PROTOCOL_DIGEST_SIZE ||
            len != PROTOCOL_HEADER_SIZE + PROTOCOL_DIGEST_SIZE) {
            return parse_fail(error, error_size, "TERMINATE digest length mismatch");
        }
        packet->payload = packet->wire + PROTOCOL_HEADER_SIZE;
        return 0;
    default:
        return parse_fail(error, error_size, "invalid packet");
    }
}

int send_all_packet(int sockfd, const uint8_t *buf, size_t len,
                    const struct sockaddr_in *peer) {
    ssize_t sent;
    sent = sendto(sockfd, buf, len, 0, (const struct sockaddr *)peer, sizeof(*peer));
    if (sent < 0 || (size_t)sent != len) {
        return -1;
    }
    return 0;
}

int recv_packet_timeout(int sockfd, Packet *packet, struct sockaddr_in *peer,
                        int timeout_ms, char *error, size_t error_size) {
    fd_set readfds;
    struct timeval tv;
    socklen_t peer_len = sizeof(*peer);
    uint8_t buf[PROTOCOL_RECV_BUFFER];
    ssize_t n;
    int ready;

    FD_ZERO(&readfds);
    FD_SET(sockfd, &readfds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    ready = select(sockfd + 1, &readfds, NULL, NULL, &tv);
    if (ready == 0) {
        return parse_fail(error, error_size, "timeout");
    }
    if (ready < 0) {
        return parse_fail(error, error_size, strerror(errno));
    }
    memset(peer, 0, sizeof(*peer));
    n = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)peer, &peer_len);
    if (n < 0) {
        return parse_fail(error, error_size, strerror(errno));
    }
    return parse_packet(buf, (size_t)n, packet, error, error_size);
}

int parse_port(const char *text, uint16_t *port) {
    char *end = NULL;
    long value;
    if (!text || !*text || !port) {
        return -1;
    }
    errno = 0;
    value = strtol(text, &end, 10);
    if (errno != 0 || !end || *end != '\0' || value <= 0 || value > 65535) {
        return -1;
    }
    *port = (uint16_t)value;
    return 0;
}

int env_timeout_ms(void) {
    const char *text = getenv("UDP_SECURE_TIMEOUT_MS");
    char *end = NULL;
    long value;
    if (!text || !*text) {
        return 10000;
    }
    errno = 0;
    value = strtol(text, &end, 10);
    if (errno != 0 || !end || *end != '\0' || value < 200 || value > 120000) {
        return 10000;
    }
    return (int)value;
}
