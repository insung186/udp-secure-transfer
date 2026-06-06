#ifndef UDP_SECURE_LOGGER_H
#define UDP_SECURE_LOGGER_H

#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

typedef struct {
    FILE *fp;
    char role[32];
    char path[256];
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

#endif
