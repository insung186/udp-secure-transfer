#include "demo_util.h"
#include "protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MQTT_MAX_PACKET 2048
#define MQTT_MAX_TOPIC 256

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

static int encode_remaining_length(uint32_t len, uint8_t *out, size_t cap, size_t *out_len) {
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

__attribute__((unused)) static int decode_string(const uint8_t *buf, size_t cap, size_t *offset, char *out, size_t out_size) {
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
    e.payload_length = (int)wire_len;
    e.bytes = (int)wire_len;
    e.packet_uid = uid;
    e.wire_hex = wire_hex;
    (void)qos;
    (void)retain;
    logger_write(logger, &e);
}

static int send_mqtt(int fd, Logger *logger, const char *peer,
                     uint8_t type, const uint8_t *payload, uint32_t payload_len,
                     int packet_code, const char *packet_type, const char *topic,
                     int message_id, int qos, int retain,
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
    log_mqtt(logger, "INFO", event, state, "mqtt packet sent", peer, "Client -> Server",
             packet_code, packet_type, topic, message_id, qos, retain, wire, pos);
    return 0;
}

int main(int argc, char **argv) {
    Logger logger;
    uint16_t port;
    int fd = -1;
    struct sockaddr_in addr;
    char peer_text[64];
    FILE *out = NULL;
    int rc = 1;
    const char *scenario = getenv("UDP_SECURE_SCENARIO");

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    ensure_runtime_dirs();
    if (logger_open(&logger, "client", "logs/client.jsonl") != 0) {
        return 1;
    }
    if (argc != 4 && argc != 7) {
        demo_finish(&logger, "ABORT", "invalid arguments");
        logger_close(&logger);
        return 1;
    }
    if (parse_port(argv[2], &port) != 0) {
        demo_finish(&logger, "ABORT", "invalid port");
        logger_close(&logger);
        return 1;
    }
    /* 兼容 run_tests.py 传入的 7-arg 格式 (含 3 个 password 占位) */
    const char *out_path = (argc == 7) ? argv[6] : argv[3];
    snprintf(peer_text, sizeof(peer_text), "%s:%u", argv[1], (unsigned)port);
    out = fopen(out_path, "wb");
    if (!out) {
        demo_finish(&logger, "ABORT", "output open failed");
        logger_close(&logger);
        return 1;
    }
    fd = demo_connect_tcp(argv[1], port, &addr);
    if (fd < 0) {
        demo_finish(&logger, "ABORT", "connect failed");
        fclose(out);
        logger_close(&logger);
        return 1;
    }
    {
        LogEvent e;
        demo_init_event(&e, "INFO", "CLIENT_START", "INIT", "mqtt client started");
        e.peer = peer_text;
        e.port = (int)port;
        logger_write(&logger, &e);
    }

    /* CONNECT: variable header = "MQTT" (4B) + protocol level (1B) + connect flags (1B) + keepalive (2B)
       payload = client_id (string) */
    {
        uint8_t payload[256];
        size_t pos = 0;
        memcpy(payload + pos, "MQTT", 4);
        pos += 4;
        payload[pos++] = 4;       /* protocol level 4 (MQTT 3.1.1) */
        payload[pos++] = 0x02;    /* connect flags: clean session */
        put_u16(payload + pos, 60); pos += 2;  /* keepalive */
        pos += encode_string(payload + pos, sizeof(payload) - pos, "demo-client");
        send_mqtt(fd, &logger, peer_text, MQTT_TYPE_CONNECT, payload, (uint32_t)pos,
                  MQTT_PKT_CONNECT, "CONNECT", NULL, 0, 0, 0,
                  "SEND_CONNECT", "CONNECT");
    }

    /* 接收 CONNACK */
    {
        uint8_t buf[MQTT_MAX_PACKET];
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0 || buf[0] != MQTT_TYPE_CONNACK) {
            demo_finish(&logger, "ABORT", "CONNACK missing");
            close(fd);
            fclose(out);
            logger_close(&logger);
            return 1;
        }
        log_mqtt(&logger, "INFO", "RECV_CONNACK", "CONNECT", "CONNACK received",
                 peer_text, "Server -> Client", MQTT_PKT_CONNACK, "CONNACK", NULL,
                 0, 0, 0, buf, (size_t)n);
    }

    /* SUBSCRIBE: 消息 id (2B) + topic (string) + qos (1B)
       topic 根据 scenario 选择: normal/qos2-replay -> "sensors/temp", unauth-subscribe -> "admin/secret" */
    {
        uint8_t payload[256];
        size_t pos = 0;
        put_u16(payload + pos, 1); pos += 2;  /* message_id = 1 */
        const char *topic = (scenario && strcmp(scenario, "unauth-subscribe") == 0)
                                ? "admin/secret" : "sensors/temp";
        pos += encode_string(payload + pos, sizeof(payload) - pos, topic);
        payload[pos++] = 0;  /* QoS 0 */
        send_mqtt(fd, &logger, peer_text, MQTT_TYPE_SUBSCRIBE, payload, (uint32_t)pos,
                  MQTT_PKT_SUBSCRIBE, "SUBSCRIBE", topic, 1, 0, 0,
                  "SEND_SUBSCRIBE", "SUBSCRIBE");
        /* 接收 SUBACK */
        uint8_t buf[MQTT_MAX_PACKET];
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0 || buf[0] != MQTT_TYPE_SUBACK) {
            demo_finish(&logger, "ABORT", "SUBACK missing");
            close(fd);
            fclose(out);
            logger_close(&logger);
            return 1;
        }
        int granted = buf[4];  /* buf[0]=type, buf[1]=remaining length, buf[2-3]=msg_id, buf[4]=granted_qos */
        if (granted == 0x80) {
            LogEvent e;
            demo_init_event(&e, "WARN", "SUBSCRIBE_FAILED", "SUBSCRIBE",
                            "server returned 0x80 (failure)");
            e.peer = peer_text;
            logger_write(&logger, &e);
            if (scenario && strcmp(scenario, "unauth-subscribe") == 0) {
                /* unauth-subscribe 场景：客户端观测到 server 拒绝，记录 ACL_DENY 后退出 */
                LogEvent e2;
                demo_init_event(&e2, "WARN", "ACL_DENY_OBSERVED", "ACL",
                                "client observed subscribe denial");
                e2.peer = peer_text;
                logger_write(&logger, &e2);
            }
            demo_finish(&logger, "ABORT", "subscribe failed (unauth-subscribe)");
            close(fd);
            fclose(out);
            logger_close(&logger);
            return 1;
        }
        log_mqtt(&logger, "INFO", "RECV_SUBACK", "SUBSCRIBE", "SUBACK received",
                 peer_text, "Server -> Client", MQTT_PKT_SUBACK, "SUBACK", topic,
                 1, granted, 0, buf, (size_t)n);
    }

    /* PUBLISH */
    {
        uint8_t payload[MQTT_MAX_PACKET];
        size_t pos = 0;
        const char *topic = "sensors/temp";
        int message_id = 1;
        int qos = (scenario && strcmp(scenario, "qos2-replay") == 0) ? 2 : 0;
        pos += encode_string(payload + pos, sizeof(payload) - pos, topic);
        if (qos > 0) {
            put_u16(payload + pos, message_id); pos += 2;
        }
        const char *msg = "{\"temp\":23.4}";
        memcpy(payload + pos, msg, strlen(msg));
        pos += strlen(msg);
        uint8_t type = MQTT_TYPE_PUBLISH | (qos << 1);  /* QoS bits in flags */
        send_mqtt(fd, &logger, peer_text, type, payload, (uint32_t)pos,
                  MQTT_PKT_PUBLISH, "PUBLISH", topic, message_id, qos, 0,
                  "SEND_PUBLISH", "PUBLISH");
        /* qos1/qos2: 接收 PUBACK / PUBREC */
        if (qos == 1) {
            uint8_t buf[8];
            ssize_t n = recv(fd, buf, sizeof(buf), 0);
            if (n <= 0 || buf[0] != MQTT_TYPE_PUBACK) {
                demo_finish(&logger, "ABORT", "PUBACK missing");
                close(fd);
                fclose(out);
                logger_close(&logger);
                return 1;
            }
            log_mqtt(&logger, "INFO", "RECV_PUBACK", "PUBLISH", "PUBACK received",
                     peer_text, "Server -> Client", MQTT_PKT_PUBACK, "PUBACK", topic,
                     message_id, qos, 0, buf, (size_t)n);
        } else if (qos == 2) {
            /* qos2: 期望先收到 PUBREC（可能被发两次演示 replay） */
            uint8_t buf[8];
            ssize_t n1 = recv(fd, buf, sizeof(buf), 0);
            if (n1 <= 0 || buf[0] != MQTT_TYPE_PUBREC) {
                demo_finish(&logger, "ABORT", "PUBREC missing");
                close(fd);
                fclose(out);
                logger_close(&logger);
                return 1;
            }
            log_mqtt(&logger, "INFO", "RECV_PUBREC", "PUBLISH", "PUBREC received",
                     peer_text, "Server -> Client", MQTT_PKT_PUBREC, "PUBREC", topic,
                     message_id, qos, 0, buf, (size_t)n1);
            /* qos2-replay: 再收一个 PUBREC（演示重复） */
            if (scenario && strcmp(scenario, "qos2-replay") == 0) {
                uint8_t buf2[8];
                ssize_t n2 = recv(fd, buf2, sizeof(buf2), 0);
                if (n2 > 0 && buf2[0] == MQTT_TYPE_PUBREC) {
                    LogEvent e;
                    demo_init_event(&e, "WARN", "QOS2_DUP_DETECTED", "PUBLISH",
                                    "QoS 2 detected duplicate PUBREC; reject and abort");
                    e.peer = peer_text;
                    e.security_replay = 1;
                    logger_write(&logger, &e);
                    /* 检测到重放：教学 demo 中 client 直接 ABORT */
                    demo_finish(&logger, "ABORT", "qos2-replay detected");
                    close(fd);
                    fclose(out);
                    logger_close(&logger);
                    return 1;
                }
            }
        }
    }

    /* DISCONNECT */
    {
        send_mqtt(fd, &logger, peer_text, MQTT_TYPE_DISCONNECT, NULL, 0,
                  MQTT_PKT_DISCONNECT, "DISCONNECT", NULL, 0, 0, 0,
                  "SEND_DISCONNECT", "DISCONNECT");
    }

    fprintf(out, "topic=sensors/temp qos=0 payload={\"temp\":23.4}\n");
    rc = 0;
    demo_finish(&logger, "OK", "mqtt flow completed");
    close(fd);
    fclose(out);
    logger_close(&logger);
    return rc;
}