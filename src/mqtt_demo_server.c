#include "demo_util.h"
#include "protocol.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* 教学版 MQTT 3.1.1（参考 OASIS 标准，简化）
   Fixed header (1 byte): control packet type (4b high) + flags (4b low)
   Remaining length (variable encoding, 1-4 bytes)
   Variable header + Payload (protocol-specific)

   Type values:
     1  CONNECT
     2  CONNACK
     3  PUBLISH
     4  PUBACK
     5  PUBREC
     6  PUBREL
     7  PUBCOMP
     8  SUBSCRIBE
     9  SUBACK
     10 UNSUBSCRIBE (skipped in demo)
     12 PINGREQ
     14 DISCONNECT
*/
#define MQTT_HEADER_SIZE 2
#define MQTT_MAX_PACKET 2048
#define MQTT_MAX_TOPIC 256
#define MQTT_MAX_PAYLOAD 1024

enum {
    MQTT_PKT_CONNECT = 140,
    MQTT_PKT_CONNACK = 141,
    MQTT_PKT_SUBSCRIBE = 142,
    MQTT_PKT_SUBACK = 143,
    MQTT_PKT_PUBLISH = 144,
    MQTT_PKT_PUBACK = 145,
    MQTT_PKT_PUBREC = 146,
    MQTT_PKT_PUBREL = 147,
    MQTT_PKT_PUBCOMP = 148,
    MQTT_PKT_DISCONNECT = 149
};

enum {
    MQTT_TYPE_CONNECT     = (1 << 4),
    MQTT_TYPE_CONNACK     = (2 << 4),
    MQTT_TYPE_PUBLISH     = (3 << 4),
    MQTT_TYPE_PUBACK      = (4 << 4),
    MQTT_TYPE_PUBREC      = (5 << 4),
    MQTT_TYPE_PUBREL      = (6 << 4),
    MQTT_TYPE_PUBCOMP     = (7 << 4),
    MQTT_TYPE_SUBSCRIBE   = (8 << 4),
    MQTT_TYPE_SUBACK      = (9 << 4),
    MQTT_TYPE_PINGREQ     = (12 << 4),
    MQTT_TYPE_DISCONNECT  = (14 << 4)
};

static volatile sig_atomic_t stop_requested = 0;

static void handle_signal(int signo) {
    (void)signo;
    stop_requested = 1;
}

static void put_u16(uint8_t *buf, uint16_t value) {
    uint16_t n = htons(value);
    memcpy(buf, &n, sizeof(n));
}

static uint16_t get_u16(const uint8_t *buf) {
    uint16_t n;
    memcpy(&n, buf, sizeof(n));
    return ntohs(n);
}

/* encode remaining length (variable length encoding) */
__attribute__((unused)) static int encode_remaining_length(uint32_t len, uint8_t *out, size_t cap, size_t *out_len) {
    size_t pos = 0;
    do {
        if (pos >= cap) return -1;
        uint8_t byte = len & 0x7f;
        len >>= 7;
        if (len > 0) byte |= 0x80;
        out[pos++] = byte;
    } while (len > 0);
    *out_len = pos;
    return 0;
}

/* decode remaining length (capped at 4 bytes / 268 MB) */
__attribute__((unused)) static int decode_remaining_length(const uint8_t *buf, size_t cap, uint32_t *out, size_t *consumed) {
    uint32_t multiplier = 1;
    uint32_t value = 0;
    size_t i = 0;
    for (i = 0; i < 4 && i < cap; i += 1) {
        value += (uint32_t)(buf[i] & 0x7f) * multiplier;
        if ((buf[i] & 0x80) == 0) {
            *out = value;
            *consumed = i + 1;
            return 0;
        }
        multiplier *= 128;
    }
    return -1;
}

__attribute__((unused)) static int encode_string(uint8_t *out, size_t cap, const char *str) {
    size_t len = strlen(str);
    if (len > 65535 || 2 + len > cap) return -1;
    put_u16(out, (uint16_t)len);
    memcpy(out + 2, str, len);
    return (int)(2 + len);
}

static int decode_string(const uint8_t *buf, size_t cap, size_t *offset, char *out, size_t out_size) {
    if (*offset + 2 > cap) return -1;
    uint16_t len = get_u16(buf + *offset);
    *offset += 2;
    if (*offset + len > cap) return -1;
    if ((size_t)len + 1 > out_size) return -1;
    memcpy(out, buf + *offset, len);
    out[len] = '\0';
    *offset += len;
    return 0;
}

static void log_mqtt(Logger *logger, const char *level, const char *event, const char *state,
                     const char *message, const char *peer, const char *direction,
                     int packet_code, const char *packet_type, const char *topic,
                     int message_id, int qos, int retain, const uint8_t *wire, size_t wire_len) {
    char wire_hex[321];
    char uid[24];
    LogEvent e;
    demo_init_event(&e, level, event, state, message);
    bytes_to_hex(wire, wire_len > 160 ? 160 : wire_len, wire_hex, sizeof(wire_hex));
    compute_packet_uid(uid, sizeof(uid), (uint16_t)packet_code, message_id, 0, wire, wire_len);
    e.peer = peer;
    e.direction = direction;
    e.packet_type = packet_type;
    e.packet_code = packet_code;
    e.path = topic;
    e.packet_id = message_id;
    e.header_summary = topic;
    e.payload_length = (int)wire_len;
    e.bytes = (int)wire_len;
    e.packet_uid = uid;
    e.wire_hex = wire_hex;
    (void)qos;
    (void)retain;
    logger_write(logger, &e);
}

static int send_mqtt_packet(int fd, Logger *logger, const char *peer,
                            uint8_t type, const uint8_t *payload, uint32_t payload_len,
                            int packet_code, const char *packet_type,
                            const char *topic, int message_id, int qos, int retain,
                            const char *event, const char *state) {
    uint8_t wire[MQTT_MAX_PACKET];
    size_t pos = 0;
    wire[pos++] = type;
    uint8_t rem_buf[4];
    size_t rem_len = 0;
    if (encode_remaining_length(payload_len, rem_buf, sizeof(rem_buf), &rem_len) != 0) return -1;
    memcpy(wire + pos, rem_buf, rem_len);
    pos += rem_len;
    if (payload_len > 0) {
        memcpy(wire + pos, payload, payload_len);
        pos += payload_len;
    }
    if (demo_write_all(fd, wire, pos) != 0) return -1;
    log_mqtt(logger, "INFO", event, state, "mqtt packet sent", peer, "Server -> Client",
             packet_code, packet_type, topic, message_id, qos, retain, wire, pos);
    return 0;
}

int main(int argc, char **argv) {
    Logger logger;
    uint16_t port;
    int listener = -1;
    int rc = 1;
    int unauth_subscribe = 0;  /* scenario: unauth-subscribe */
    const char *scenario = getenv("UDP_SECURE_SCENARIO");
    /* 受限主题（unauth-subscribe 场景） */
    const char *RESTRICTED_TOPIC = "admin/secret";

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
    (void)argv[2];
    (void)argv[3];
    listener = demo_create_tcp_listener(port);
    if (listener < 0) {
        demo_finish(&logger, "ABORT", strerror(errno));
        logger_close(&logger);
        return 1;
    }
    {
        LogEvent e;
        demo_init_event(&e, "INFO", "SERVER_START", "INIT", "mqtt broker started");
        e.port = (int)port;
        logger_write(&logger, &e);
    }

    if (scenario && strcmp(scenario, "unauth-subscribe") == 0) {
        unauth_subscribe = 1;
    }

    int fd = demo_accept_client(listener, NULL);
    if (fd < 0) {
        demo_finish(&logger, "ABORT", "accept failed");
        close(listener);
        logger_close(&logger);
        return 1;
    }
    char peer[64] = "client";

    /* 简化流程：读 CONNECT → 回 CONNACK → 读 SUBSCRIBE → 视情况 SUBACK / 拒 →
       读 PUBLISH → 回 PUBACK → 读 DISCONNECT */
    {
        /* CONNECT */
        uint8_t buf[MQTT_MAX_PACKET];
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0 || buf[0] != MQTT_TYPE_CONNECT) {
            demo_finish(&logger, "ABORT", "CONNECT missing");
            close(fd);
            close(listener);
            logger_close(&logger);
            return 1;
        }
        log_mqtt(&logger, "INFO", "RECV_CONNECT", "CONNECT", "client CONNECT received",
                 peer, "Client -> Server", MQTT_PKT_CONNECT, "CONNECT", NULL, 0, 0, 0,
                 buf, (size_t)n);
        /* CONNACK: 2 bytes payload: 0x00 0x00 (session not present, accepted) */
        uint8_t connack_payload[2] = {0x00, 0x00};
        send_mqtt_packet(fd, &logger, peer, MQTT_TYPE_CONNACK, connack_payload, 2,
                         MQTT_PKT_CONNACK, "CONNACK", NULL, 0, 0, 0,
                         "SEND_CONNACK", "CONNECT");
    }

    {
        /* SUBSCRIBE */
        uint8_t buf[MQTT_MAX_PACKET];
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0 || buf[0] != MQTT_TYPE_SUBSCRIBE) {
            demo_finish(&logger, "ABORT", "SUBSCRIBE missing");
            close(fd);
            close(listener);
            logger_close(&logger);
            return 1;
        }
        /* parse message_id + topic + qos */
        uint32_t rem = 0;
        size_t rem_consumed = 0;
        if (decode_remaining_length(buf + 1, (size_t)n - 1, &rem, &rem_consumed) != 0) {
            demo_finish(&logger, "ABORT", "bad remaining length");
            close(fd);
            close(listener);
            logger_close(&logger);
            return 1;
        }
        size_t off = 1 + rem_consumed;
        int message_id = get_u16(buf + off);
        off += 2;
        char topic[MQTT_MAX_TOPIC];
        if (decode_string(buf, (size_t)n, &off, topic, sizeof(topic)) != 0) {
            demo_finish(&logger, "ABORT", "topic decode failed");
            close(fd);
            close(listener);
            logger_close(&logger);
            return 1;
        }
        uint8_t qos = buf[off];
        log_mqtt(&logger, "INFO", "RECV_SUBSCRIBE", "SUBSCRIBE", "client SUBSCRIBE received",
                 peer, "Client -> Server", MQTT_PKT_SUBSCRIBE, "SUBSCRIBE", topic,
                 message_id, qos, 0, buf, (size_t)n);

        /* ACL 检查 */
        int allowed = 1;
        if (unauth_subscribe && strcmp(topic, RESTRICTED_TOPIC) == 0) {
            allowed = 0;
            LogEvent e;
            demo_init_event(&e, "WARN", "SUBSCRIBE_DENIED", "ACL",
                            "subscribe to restricted topic denied");
            e.peer = peer;
            e.path = topic;
            logger_write(&logger, &e);
        }
        uint8_t suback_payload[3] = {(uint8_t)(message_id >> 8), (uint8_t)(message_id & 0xff),
                                     allowed ? (uint8_t)qos : 0x80};
        const char *evt = allowed ? "SEND_SUBACK" : "SEND_SUBACK_DENIED";
        send_mqtt_packet(fd, &logger, peer, MQTT_TYPE_SUBACK, suback_payload, 3,
                         MQTT_PKT_SUBACK, "SUBACK", topic, message_id, qos, 0,
                         evt, allowed ? "SUBSCRIBE" : "ACL_DENY");
        if (!allowed) {
            demo_finish(&logger, "ABORT", "subscribe denied (unauth-subscribe scenario)");
            close(fd);
            close(listener);
            logger_close(&logger);
            return 1;
        }
    }

    {
        /* PUBLISH from client */
        uint8_t buf[MQTT_MAX_PACKET];
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0 || (buf[0] & 0xf0) != MQTT_TYPE_PUBLISH) {
            demo_finish(&logger, "ABORT", "PUBLISH missing");
            close(fd);
            close(listener);
            logger_close(&logger);
            return 1;
        }
        uint8_t qos = (buf[0] >> 1) & 0x03;
        uint8_t retain = buf[0] & 0x01;
        uint32_t rem = 0;
        size_t rem_consumed = 0;
        if (decode_remaining_length(buf + 1, (size_t)n - 1, &rem, &rem_consumed) != 0) {
            demo_finish(&logger, "ABORT", "bad remaining length");
            close(fd);
            close(listener);
            logger_close(&logger);
            return 1;
        }
        size_t off = 1 + rem_consumed;
        char topic[MQTT_MAX_TOPIC];
        if (decode_string(buf, (size_t)n, &off, topic, sizeof(topic)) != 0) {
            demo_finish(&logger, "ABORT", "topic decode failed");
            close(fd);
            close(listener);
            logger_close(&logger);
            return 1;
        }
        int message_id = 0;
        if (qos > 0 && off + 2 <= (size_t)n) {
            message_id = get_u16(buf + off);
            off += 2;
        }
        log_mqtt(&logger, qos >= 2 ? "DATA" : "INFO", "RECV_PUBLISH", "PUBLISH",
                 "client PUBLISH received", peer, "Client -> Server",
                 MQTT_PKT_PUBLISH, "PUBLISH", topic, message_id, qos, retain,
                 buf, (size_t)n);

        /* qos2-replay 场景：发两次 PUBREC，演示 QoS 2 防重放 */
        if (scenario && strcmp(scenario, "qos2-replay") == 0 && qos == 2) {
            uint8_t pubrec_payload[2] = {(uint8_t)(message_id >> 8), (uint8_t)(message_id & 0xff)};
            /* 故意发两次以演示 QoS 2 的 4 次握手防御 */
            send_mqtt_packet(fd, &logger, peer, MQTT_TYPE_PUBREC, pubrec_payload, 2,
                             MQTT_PKT_PUBREC, "PUBREC", topic, message_id, 2, 0,
                             "SEND_PUBREC", "PUBLISH");
            /* 微小间隔让 client 来得及 read 第一次 PUBREC 再 read 第二次 */
            {
                struct timespec pause_time;
                pause_time.tv_sec = 0;
                pause_time.tv_nsec = 100000000L;  /* 100ms */
                nanosleep(&pause_time, NULL);
            }
            send_mqtt_packet(fd, &logger, peer, MQTT_TYPE_PUBREC, pubrec_payload, 2,
                             MQTT_PKT_PUBREC, "PUBREC", topic, message_id, 2, 0,
                             "SEND_PUBREC_DUPLICATE", "PUBLISH");
            LogEvent e;
            demo_init_event(&e, "WARN", "QOS2_DUP_DETECTED", "PUBLISH",
                            "duplicate PUBREC observed; QoS 2 4-way handshake detects replay");
            e.peer = peer;
            e.security_replay = 1;
            logger_write(&logger, &e);
            /* qos2-replay 场景：预期 client 检测到重放并 ABORT；server 也标记 ABORT */
            demo_finish(&logger, "ABORT", "qos2-replay scenario (server)");
            close(fd);
            close(listener);
            logger_close(&logger);
            return 1;
        } else if (qos >= 1) {
            uint8_t puback_payload[2] = {(uint8_t)(message_id >> 8), (uint8_t)(message_id & 0xff)};
            send_mqtt_packet(fd, &logger, peer, MQTT_TYPE_PUBACK, puback_payload, 2,
                             MQTT_PKT_PUBACK, "PUBACK", topic, message_id, qos, 0,
                             "SEND_PUBACK", "PUBLISH");
        }

        /* cleartext-eavesdrop 场景：告警明文可读 */
        if (scenario && strcmp(scenario, "cleartext-eavesdrop") == 0) {
            LogEvent e;
            demo_init_event(&e, "WARN", "EAVESDROP_DETECTED", "PUBLISH",
                            "PUBLISH payload transmitted in cleartext; consider MQTTS");
            e.peer = peer;
            e.security_encrypted = 0;
            e.path = topic;
            logger_write(&logger, &e);
        }
    }

    {
        /* DISCONNECT */
        uint8_t buf[8];
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n >= 2 && buf[0] == MQTT_TYPE_DISCONNECT) {
            log_mqtt(&logger, "INFO", "RECV_DISCONNECT", "DISCONNECT", "client DISCONNECT",
                     peer, "Client -> Server", MQTT_PKT_DISCONNECT, "DISCONNECT", NULL,
                     0, 0, 0, buf, (size_t)n);
        }
    }

    rc = 0;
    demo_finish(&logger, "OK", "mqtt flow completed");
    close(fd);
    close(listener);
    logger_close(&logger);
    return rc;
}