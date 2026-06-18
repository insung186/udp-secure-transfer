#include "logger.h"
#include "protocol.h"
#include "sha1_util.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static void logger_copy_default(char *dst, size_t dst_size,
                                const char *env_name, const char *fallback) {
    const char *value = getenv(env_name);
    if (!value || !value[0]) {
        value = fallback ? fallback : "";
    }
    snprintf(dst, dst_size, "%s", value);
}

void ensure_runtime_dirs(void) {
    mkdir("logs", 0755);
    mkdir("output", 0755);
    mkdir("test", 0755);
    mkdir("test/cases", 0755);
}

int logger_open(Logger *logger, const char *role, const char *path) {
    if (!logger || !role || !path) {
        return -1;
    }
    ensure_runtime_dirs();
    memset(logger, 0, sizeof(*logger));
    snprintf(logger->role, sizeof(logger->role), "%s", role);
    snprintf(logger->path, sizeof(logger->path), "%s", path);
    logger_copy_default(logger->schema_version, sizeof(logger->schema_version),
                        "UDP_SECURE_SCHEMA_VERSION", "2");
    if (strcmp(role, "control") == 0) {
        logger_copy_default(logger->protocol, sizeof(logger->protocol),
                            "UDP_SECURE_PROTOCOL", "control-plane");
        logger_copy_default(logger->transport, sizeof(logger->transport),
                            "UDP_SECURE_TRANSPORT", "http-ws");
    } else {
        logger_copy_default(logger->protocol, sizeof(logger->protocol),
                            "UDP_SECURE_PROTOCOL", "udp-basic");
        logger_copy_default(logger->transport, sizeof(logger->transport),
                            "UDP_SECURE_TRANSPORT", "udp");
    }
    logger_copy_default(logger->flow_id, sizeof(logger->flow_id), "UDP_SECURE_FLOW_ID", "");
    logger_copy_default(logger->session_id, sizeof(logger->session_id), "UDP_SECURE_SESSION_ID", "");
    logger_copy_default(logger->scenario, sizeof(logger->scenario), "UDP_SECURE_SCENARIO", "");
    logger->fp = fopen(path, "a");
    if (!logger->fp) {
        return -1;
    }
    setvbuf(logger->fp, NULL, _IOLBF, 0);
    return 0;
}

void logger_close(Logger *logger) {
    if (logger && logger->fp) {
        fclose(logger->fp);
        logger->fp = NULL;
    }
}

static void json_escape(FILE *fp, const char *text) {
    const unsigned char *p = (const unsigned char *)text;
    fputc('"', fp);
    if (text) {
        while (*p) {
            switch (*p) {
            case '\\':
                fputs("\\\\", fp);
                break;
            case '"':
                fputs("\\\"", fp);
                break;
            case '\b':
                fputs("\\b", fp);
                break;
            case '\f':
                fputs("\\f", fp);
                break;
            case '\n':
                fputs("\\n", fp);
                break;
            case '\r':
                fputs("\\r", fp);
                break;
            case '\t':
                fputs("\\t", fp);
                break;
            default:
                if (*p < 0x20) {
                    fprintf(fp, "\\u%04x", *p);
                } else {
                    fputc(*p, fp);
                }
                break;
            }
            p++;
        }
    }
    fputc('"', fp);
}

static void timestamp_now(char *buf, size_t size) {
    struct timespec ts;
    struct tm tm_value;
    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm_value);
    strftime(buf, size, "%Y-%m-%dT%H:%M:%S", &tm_value);
    snprintf(buf + strlen(buf), size - strlen(buf), ".%03ld", ts.tv_nsec / 1000000L);
}

static void write_string_field(FILE *fp, int *first, const char *key, const char *value) {
    if (!value) {
        return;
    }
    if (!*first) {
        fputc(',', fp);
    }
    *first = 0;
    json_escape(fp, key);
    fputc(':', fp);
    json_escape(fp, value);
}

static void write_int_field(FILE *fp, int *first, const char *key, int value) {
    if (value == LOG_INT_UNSET) {
        return;
    }
    if (!*first) {
        fputc(',', fp);
    }
    *first = 0;
    json_escape(fp, key);
    fprintf(fp, ":%d", value);
}

static void write_pid_field(FILE *fp, int *first, const char *key, pid_t value) {
    if (value <= 0) {
        return;
    }
    if (!*first) {
        fputc(',', fp);
    }
    *first = 0;
    json_escape(fp, key);
    fprintf(fp, ":%ld", (long)value);
}

static void write_bool_field(FILE *fp, int *first, const char *key, int value) {
    if (value == LOG_INT_UNSET) {
        return;
    }
    if (!*first) {
        fputc(',', fp);
    }
    *first = 0;
    json_escape(fp, key);
    fprintf(fp, ":%s", value ? "true" : "false");
}

/* 计算 packet_uid：同一 wire 包在 client/server 两端必须产生相同值。
   派生规则：
   - PASS_RESP 哈希完整 wire（header + 整个密码载荷）。原因：前 8 字节对 PASS_RESP
     来说只覆盖 type+length+密码前 2 字节，两个不同密码如果前 2 字节相同
     （如 "secret1" / "secret2"）会碰撞。完整 wire 哈希能保证不同密码得到不同 uid。
   - 其他类型哈希 wire 前 8 字节。type/length 头 6 字节对所有非 PASS_RESP 都足够
     区分；DATA 类型额外依赖 packet_id 字段（前 4 字节 payload 中前 4 字节是 packet_id）。
   - 若 wire 不可用（< 8 字节），混入 attempt 作降级 key。*/
void compute_packet_uid(char *out, size_t out_size, uint16_t packet_type,
                        int packet_id, int attempt, const uint8_t *wire, size_t wire_len) {
    if (out_size < 17) {
        if (out_size > 0) out[0] = '\0';
        return;
    }
    Sha1Context ctx;
    uint8_t digest[SHA1_DIGEST_LENGTH];
    sha1_init(&ctx);
    char header[64];
    int header_len = snprintf(header, sizeof(header), "pkt:%u:%d:", (unsigned)packet_type, packet_id);
    sha1_update(&ctx, (const uint8_t *)header, (size_t)header_len);
    if (packet_type == PKT_PASS_RESP && wire && wire_len > 0) {
        /* PASS_RESP：哈希完整 wire（header + 完整密码）。两端都看到相同的 wire 字节，
           所以 uid 一致；不同密码会得到不同 uid。 */
        sha1_update(&ctx, wire, wire_len);
    } else {
        /* Widened from 8 to 32 bytes: with only 8 bytes (the protocol header +
           2 leading payload bytes), two DATA packets that share the first
           2 payload bytes (very common for ASCII transfers) collide. 32 bytes
           covers header + first 22 payload bytes, which is enough to distinguish
           typical chunks. Capped at the actual wire length so short frames still
           produce a stable UID. */
        size_t take = wire_len < 32 ? wire_len : 32;
        if (take > 0 && wire) {
            sha1_update(&ctx, wire, take);
        } else if (attempt > 0) {
            /* 降级：仅靠 packet_type+id 无法稳定时，混入 attempt */
            char buf[16];
            int n = snprintf(buf, sizeof(buf), ":a%d", attempt);
            sha1_update(&ctx, (const uint8_t *)buf, (size_t)n);
        }
    }
    sha1_final(&ctx, digest);
    /* 取前 8 字节，输出 16 hex 字符 */
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 8; i += 1) {
        out[i * 2]     = hex[(digest[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex[digest[i] & 0x0F];
    }
    out[16] = '\0';
}

void logger_write(Logger *logger, const LogEvent *event) {
    char time_buf[64];
    int first = 1;
    LogEvent empty;

    if (!logger || !logger->fp) {
        return;
    }
    if (!event) {
        memset(&empty, 0, sizeof(empty));
        empty.packet_id = LOG_INT_UNSET;
        empty.seq = LOG_INT_UNSET;
        empty.ack = LOG_INT_UNSET;
        empty.window_size = LOG_INT_UNSET;
        empty.retransmit_count = LOG_INT_UNSET;
        empty.stream_id = LOG_INT_UNSET;
        empty.stream_offset = LOG_INT_UNSET;
        empty.status_code = LOG_INT_UNSET;
        empty.security_encrypted = LOG_INT_UNSET;
        empty.security_mac_valid = LOG_INT_UNSET;
        empty.security_replay = LOG_INT_UNSET;
        empty.payload_length = LOG_INT_UNSET;
        empty.bytes = LOG_INT_UNSET;
        empty.attempt = LOG_INT_UNSET;
        empty.port = LOG_INT_UNSET;
        event = &empty;
    }

    timestamp_now(time_buf, sizeof(time_buf));
    fputc('{', logger->fp);
    write_string_field(logger->fp, &first, "time", time_buf);
    write_string_field(logger->fp, &first, "schema_version",
                       event->schema_version ? event->schema_version : logger->schema_version);
    write_string_field(logger->fp, &first, "protocol",
                       event->protocol ? event->protocol : logger->protocol);
    write_string_field(logger->fp, &first, "transport",
                       event->transport ? event->transport : logger->transport);
    write_string_field(logger->fp, &first, "role", logger->role);
    write_string_field(logger->fp, &first, "flow_id",
                       event->flow_id ? event->flow_id : logger->flow_id);
    write_string_field(logger->fp, &first, "session_id",
                       event->session_id ? event->session_id : logger->session_id);
    write_string_field(logger->fp, &first, "scenario",
                       event->scenario ? event->scenario : logger->scenario);
    write_string_field(logger->fp, &first, "connection_id", event->connection_id);
    write_string_field(logger->fp, &first, "level", event->level ? event->level : "INFO");
    write_string_field(logger->fp, &first, "event", event->event ? event->event : "EVENT");
    write_string_field(logger->fp, &first, "peer", event->peer ? event->peer : "");
    write_string_field(logger->fp, &first, "state", event->state);
    write_string_field(logger->fp, &first, "packet_type", event->packet_type);
    write_string_field(logger->fp, &first, "result", event->result);
    write_string_field(logger->fp, &first, "sha1", event->sha1);
    write_string_field(logger->fp, &first, "error_code", event->error_code);
    write_string_field(logger->fp, &first, "wire_hex", event->wire_hex);
    write_string_field(logger->fp, &first, "message", event->message);
    write_string_field(logger->fp, &first, "direction", event->direction);
    write_string_field(logger->fp, &first, "packet_uid", event->packet_uid);
    write_string_field(logger->fp, &first, "method", event->method);
    write_string_field(logger->fp, &first, "path", event->path);
    write_string_field(logger->fp, &first, "header_summary", event->header_summary);
    write_string_field(logger->fp, &first, "frame_type", event->frame_type);
    write_string_field(logger->fp, &first, "handshake_phase", event->handshake_phase);
    write_int_field(logger->fp, &first, "packet_code", event->packet_code);
    write_int_field(logger->fp, &first, "seq", event->seq);
    write_int_field(logger->fp, &first, "ack", event->ack);
    write_int_field(logger->fp, &first, "window_size", event->window_size);
    write_int_field(logger->fp, &first, "retransmit_count", event->retransmit_count);
    write_int_field(logger->fp, &first, "stream_id", event->stream_id);
    write_int_field(logger->fp, &first, "stream_offset", event->stream_offset);
    write_int_field(logger->fp, &first, "status_code", event->status_code);
    write_int_field(logger->fp, &first, "packet_id", event->packet_id);
    write_int_field(logger->fp, &first, "payload_length", event->payload_length);
    write_int_field(logger->fp, &first, "bytes", event->bytes);
    write_int_field(logger->fp, &first, "attempt", event->attempt);
    write_int_field(logger->fp, &first, "port", event->port);
    if (event->security_encrypted != LOG_INT_UNSET ||
        event->security_mac_valid != LOG_INT_UNSET ||
        event->security_replay != LOG_INT_UNSET ||
        event->handshake_phase) {
        if (!first) {
            fputc(',', logger->fp);
        }
        first = 0;
        json_escape(logger->fp, "security");
        fputc(':', logger->fp);
        fputc('{', logger->fp);
        {
            int security_first = 1;
            write_bool_field(logger->fp, &security_first, "encrypted", event->security_encrypted);
            write_bool_field(logger->fp, &security_first, "mac_valid", event->security_mac_valid);
            write_bool_field(logger->fp, &security_first, "replay", event->security_replay);
            write_string_field(logger->fp, &security_first, "handshake_phase", event->handshake_phase);
        }
        fputc('}', logger->fp);
    }
    write_pid_field(logger->fp, &first, "pid", event->pid);
    fputs("}\n", logger->fp);
    fflush(logger->fp);
}
