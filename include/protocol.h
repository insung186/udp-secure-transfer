#ifndef UDP_SECURE_PROTOCOL_H
#define UDP_SECURE_PROTOCOL_H

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

#define PROTOCOL_HEADER_SIZE 6
#define PROTOCOL_DATA_HEADER_SIZE 10
#define PROTOCOL_FEEDBACK_PAYLOAD_SIZE 8
#define PROTOCOL_FEEDBACK_HEADER_SIZE 14
#define PROTOCOL_DATA_CHUNK_SIZE 1000
#define PROTOCOL_DIGEST_SIZE 20
#define PROTOCOL_MAX_PASSWORD 255
#define PROTOCOL_MAX_DATAGRAM (PROTOCOL_DATA_HEADER_SIZE + PROTOCOL_DATA_CHUNK_SIZE)
#define PROTOCOL_RECV_BUFFER 2048

typedef enum {
    PKT_JOIN_REQ = 1,
    PKT_PASS_REQ = 2,
    PKT_PASS_RESP = 3,
    PKT_PASS_ACCEPT = 4,
    PKT_DATA = 5,
    PKT_TERMINATE = 6,
    PKT_REJECT = 7,
    PKT_ACK = 8,
    PKT_NACK = 9
} PacketType;

typedef struct {
    uint16_t type;
    uint32_t payload_length;
    uint32_t packet_id;
    uint32_t ack_id;
    uint32_t window_size;
    const uint8_t *payload;
    size_t wire_length;
    uint8_t wire[PROTOCOL_RECV_BUFFER];
} Packet;

const char *packet_type_name(uint16_t type);
int packet_type_valid(uint16_t type);
int is_same_peer(const struct sockaddr_in *a, const struct sockaddr_in *b);
void peer_to_string(const struct sockaddr_in *addr, char *buf, size_t size);
void bytes_to_hex(const uint8_t *bytes, size_t len, char *out, size_t out_size);

int build_control_packet(uint16_t type, uint8_t *out, size_t cap, size_t *out_len);
int build_pass_resp_packet(const char *password, uint8_t *out, size_t cap, size_t *out_len);
int build_data_packet(uint32_t packet_id, const uint8_t *data, uint32_t data_len,
                      uint8_t *out, size_t cap, size_t *out_len);
int build_feedback_packet(uint16_t type, uint32_t ack_id, uint32_t window_size,
                          uint8_t *out, size_t cap, size_t *out_len);
int build_terminate_packet(const uint8_t digest[PROTOCOL_DIGEST_SIZE],
                           uint8_t *out, size_t cap, size_t *out_len);
int parse_packet(const uint8_t *buf, size_t len, Packet *packet,
                 char *error, size_t error_size);

int send_all_packet(int sockfd, const uint8_t *buf, size_t len,
                    const struct sockaddr_in *peer);
int recv_packet_timeout(int sockfd, Packet *packet, struct sockaddr_in *peer,
                        int timeout_ms, char *error, size_t error_size);

int parse_port(const char *text, uint16_t *port);
int env_timeout_ms(void);
int protocol_is_reliable(void);
int env_reliable_window_size(void);
int env_reliable_timeout_ms(void);

#endif
