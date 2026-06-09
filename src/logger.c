#include "logger.h"
#include "sha1_util.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

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

/* 计算 packet_uid：同一 wire 包在 client/server 两端必须产生相同值。
   派生规则：SHA1(packet_type + packet_id + wire 前 8 字节) 的前 16 hex 字符。
   对于 PASS_RESP（密码载荷在日志中被 redact），wire 前 8 字节仍然是协议头
   + attempt 序号足够稳定；若 attempt 已知则使用 attempt 作降级 key。*/
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
    size_t take = wire_len < 8 ? wire_len : 8;
    if (take > 0 && wire) {
        sha1_update(&ctx, wire, take);
    } else if (attempt > 0) {
        /* 降级：仅靠 packet_type+id 无法稳定时，混入 attempt */
        char buf[16];
        int n = snprintf(buf, sizeof(buf), ":a%d", attempt);
        sha1_update(&ctx, (const uint8_t *)buf, (size_t)n);
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
        empty.payload_length = LOG_INT_UNSET;
        empty.bytes = LOG_INT_UNSET;
        empty.attempt = LOG_INT_UNSET;
        empty.port = LOG_INT_UNSET;
        event = &empty;
    }

    timestamp_now(time_buf, sizeof(time_buf));
    fputc('{', logger->fp);
    write_string_field(logger->fp, &first, "time", time_buf);
    write_string_field(logger->fp, &first, "role", logger->role);
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
    write_int_field(logger->fp, &first, "packet_code", event->packet_code);
    write_int_field(logger->fp, &first, "packet_id", event->packet_id);
    write_int_field(logger->fp, &first, "payload_length", event->payload_length);
    write_int_field(logger->fp, &first, "bytes", event->bytes);
    write_int_field(logger->fp, &first, "attempt", event->attempt);
    write_int_field(logger->fp, &first, "port", event->port);
    write_pid_field(logger->fp, &first, "pid", event->pid);
    fputs("}\n", logger->fp);
    fflush(logger->fp);
}
