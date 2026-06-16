#ifndef UDP_SECURE_LOGGER_H
#define UDP_SECURE_LOGGER_H

#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

typedef struct {
    FILE *fp;
    char role[32];
    char path[256];
    char schema_version[16];
    char protocol[64];
    char transport[32];
    char flow_id[64];
    char session_id[64];
    char scenario[64];
} Logger;

#define LOG_INT_UNSET (-2147483647)

typedef struct {
    const char *level;
    const char *event;
    const char *peer;
    const char *state;
    const char *message;
    const char *packet_type;
    const char *result;
    const char *sha1;
    const char *error_code;
    const char *wire_hex;
    /* direction: 记录该包在网络中的真实方向（"Client -> Server" / "Server -> Client" / "Observed"），
       供前端直接读取，避免基于 role+event 推断。前端如未读到该字段则回退到原推断逻辑。*/
    const char *direction;
    const char *schema_version;
    const char *protocol;
    const char *transport;
    const char *flow_id;
    const char *session_id;
    const char *scenario;
    const char *connection_id;
    const char *method;
    const char *path;
    const char *header_summary;
    const char *frame_type;
    const char *handshake_phase;
    /* packet_uid: 真实数据包的稳定 ID（同一 wire 包在 client/server 两端日志中完全一致）；
       派生规则：SHA1(packet_type || packet_id || first 8 bytes of wire) 的前 16 hex 字符。
       PASS_RESP 由于日志中 wire_hex 被 redact，UID 派生时回退到 SHA1(packet_type + "_attempt_" + attempt)。*/
    const char *packet_uid;
    /* packet_code: packet_type 对应的整数码值，方便前端显示。0 表示非包事件。*/
    int packet_code;
    int seq;
    int ack;
    int window_size;
    int retransmit_count;
    int stream_id;
    int stream_offset;
    int status_code;
    int security_encrypted;
    int security_mac_valid;
    int security_replay;
    int packet_id;
    int payload_length;
    int bytes;
    int attempt;
    int port;
    pid_t pid;
} LogEvent;

int logger_open(Logger *logger, const char *role, const char *path);
void logger_close(Logger *logger);
void logger_write(Logger *logger, const LogEvent *event);
void ensure_runtime_dirs(void);

/* 计算 packet_uid：同一 wire 包在 client/server 两端必须产生相同值。
   派生规则：SHA1("pkt:<type>:<packet_id>:" + wire 前 8 字节) 的前 16 hex 字符。
   attempt 可选；如 wire 不足 8 字节则混入 attempt 提升稳定性。*/
void compute_packet_uid(char *out, size_t out_size, uint16_t packet_type,
                        int packet_id, int attempt, const uint8_t *wire, size_t wire_len);

#endif
