#include "logger.h"
#include "sha1_util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CONTROL_PORT 8080
#define HTTP_BUF 32768
#define JSON_BUF 262144
#define SMALL_BUF 512

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef struct {
    pid_t pid;
    int stdout_fd;
    int stderr_fd;
    int stdin_fd;
    char name[16];
    char result[16];
    char last_output[512];
} ChildProc;

typedef struct {
    char protocol[64];
    char transport[32];
    char scenario[64];
    char flow_id[64];
    char session_id[64];
    unsigned int run_seq;
} ExperimentState;

typedef struct {
    const char *key;
    const char *value;
} ChildEnv;

typedef struct {
    ChildProc server;
    ChildProc client;
    ExperimentState experiment;
    int ws_fd;
    long server_log_offset;
    long client_log_offset;
    long control_log_offset;
    long packets_log_offset;
    char last_test_result[8192];
} ControlState;

static ControlState state;
static Logger control_logger;

static LogEvent log_defaults(const char *level, const char *event, const char *message) {
    LogEvent e;
    memset(&e, 0, sizeof(e));
    e.level = level;
    e.event = event;
    e.message = message;
    e.stream_id = LOG_INT_UNSET;
    e.stream_offset = LOG_INT_UNSET;
    e.status_code = LOG_INT_UNSET;
    e.seq = LOG_INT_UNSET;
    e.ack = LOG_INT_UNSET;
    e.window_size = LOG_INT_UNSET;
    e.retransmit_count = LOG_INT_UNSET;
    e.security_encrypted = LOG_INT_UNSET;
    e.security_mac_valid = LOG_INT_UNSET;
    e.security_replay = LOG_INT_UNSET;
    e.packet_id = LOG_INT_UNSET;
    e.payload_length = LOG_INT_UNSET;
    e.bytes = LOG_INT_UNSET;
    e.attempt = LOG_INT_UNSET;
    e.port = LOG_INT_UNSET;
    return e;
}

static void experiment_set_default_protocol(void) {
    if (!state.experiment.protocol[0]) {
        snprintf(state.experiment.protocol, sizeof(state.experiment.protocol), "%s", "udp-basic");
    }
    if (!state.experiment.transport[0]) {
        snprintf(state.experiment.transport, sizeof(state.experiment.transport), "%s", "udp");
    }
    if (!state.experiment.scenario[0]) {
        snprintf(state.experiment.scenario, sizeof(state.experiment.scenario), "%s", "normal");
    }
}

static void experiment_clear(void) {
    memset(&state.experiment, 0, sizeof(state.experiment));
}

static void experiment_apply_to_event(LogEvent *event) {
    if (!event) {
        return;
    }
    experiment_set_default_protocol();
    event->schema_version = "2";
    event->protocol = state.experiment.protocol;
    event->transport = state.experiment.transport;
    event->scenario = state.experiment.scenario;
    event->flow_id = state.experiment.flow_id[0] ? state.experiment.flow_id : NULL;
    event->session_id = state.experiment.session_id[0] ? state.experiment.session_id : NULL;
}

static void experiment_configure(const char *protocol, const char *scenario) {
    state.experiment.run_seq += 1;
    snprintf(state.experiment.protocol, sizeof(state.experiment.protocol), "%s",
             (protocol && protocol[0]) ? protocol : "udp-basic");
    if (strncmp(state.experiment.protocol, "tcp", 3) == 0 ||
        strcmp(state.experiment.protocol, "tls-like") == 0 ||
        strcmp(state.experiment.protocol, "http-basic") == 0 ||
        strcmp(state.experiment.protocol, "websocket-basic") == 0) {
        snprintf(state.experiment.transport, sizeof(state.experiment.transport), "%s", "tcp");
    } else {
        snprintf(state.experiment.transport, sizeof(state.experiment.transport), "%s", "udp");
    }
    snprintf(state.experiment.scenario, sizeof(state.experiment.scenario), "%s",
             (scenario && scenario[0]) ? scenario : "normal");
    snprintf(state.experiment.flow_id, sizeof(state.experiment.flow_id), "%.52s-%03u",
             state.experiment.protocol, state.experiment.run_seq);
    snprintf(state.experiment.session_id, sizeof(state.experiment.session_id), "session-%03u",
             state.experiment.run_seq);
}

static const char *server_binary_for_protocol(const char *protocol) {
    if (!protocol || strcmp(protocol, "udp-basic") == 0 || strcmp(protocol, "udp-reliable") == 0) {
        return "./bin/server";
    }
    if (strcmp(protocol, "tcp-basic") == 0) {
        return "./bin/tcp_server";
    }
    if (strcmp(protocol, "tls-like") == 0) {
        return "./bin/tls_server";
    }
    if (strcmp(protocol, "http-basic") == 0) {
        return "./bin/http_demo_server";
    }
    if (strcmp(protocol, "websocket-basic") == 0) {
        return "./bin/websocket_demo_server";
    }
    if (strcmp(protocol, "quic-like") == 0) {
        return "./bin/quic_demo_server";
    }
    return NULL;
}

static const char *client_binary_for_protocol(const char *protocol) {
    if (!protocol || strcmp(protocol, "udp-basic") == 0 || strcmp(protocol, "udp-reliable") == 0) {
        return "./bin/client";
    }
    if (strcmp(protocol, "tcp-basic") == 0) {
        return "./bin/tcp_client";
    }
    if (strcmp(protocol, "tls-like") == 0) {
        return "./bin/tls_client";
    }
    if (strcmp(protocol, "http-basic") == 0) {
        return "./bin/http_demo_client";
    }
    if (strcmp(protocol, "websocket-basic") == 0) {
        return "./bin/websocket_demo_client";
    }
    if (strcmp(protocol, "quic-like") == 0) {
        return "./bin/quic_demo_client";
    }
    return NULL;
}

static void appendf(char *buf, size_t cap, const char *fmt, ...) {
    size_t len = strlen(buf);
    va_list args;
    if (len >= cap) {
        return;
    }
    va_start(args, fmt);
    vsnprintf(buf + len, cap - len, fmt, args);
    va_end(args);
}

static void json_escape_to(char *out, size_t cap, const char *text) {
    size_t pos = 0;
    const unsigned char *p = (const unsigned char *)(text ? text : "");
    if (cap == 0) {
        return;
    }
    out[pos++] = '"';
    while (*p && pos + 8 < cap) {
        switch (*p) {
        case '\\':
            out[pos++] = '\\';
            out[pos++] = '\\';
            break;
        case '"':
            out[pos++] = '\\';
            out[pos++] = '"';
            break;
        case '\n':
            out[pos++] = '\\';
            out[pos++] = 'n';
            break;
        case '\r':
            out[pos++] = '\\';
            out[pos++] = 'r';
            break;
        case '\t':
            out[pos++] = '\\';
            out[pos++] = 't';
            break;
        default:
            if (*p < 0x20) {
                pos += (size_t)snprintf(out + pos, cap - pos, "\\u%04x", *p);
            } else {
                out[pos++] = (char)*p;
            }
            break;
        }
        p++;
    }
    if (pos + 1 < cap) {
        out[pos++] = '"';
    }
    out[pos < cap ? pos : cap - 1] = '\0';
}

static void set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
}

static void child_init(ChildProc *proc, const char *name) {
    memset(proc, 0, sizeof(*proc));
    proc->pid = -1;
    proc->stdout_fd = -1;
    proc->stderr_fd = -1;
    proc->stdin_fd = -1;
    snprintf(proc->name, sizeof(proc->name), "%s", name);
    snprintf(proc->result, sizeof(proc->result), "Pending");
}

static int child_running(const ChildProc *proc) {
    return proc->pid > 0;
}

static void close_if_open(int *fd) {
    if (*fd >= 0) {
        close(*fd);
        *fd = -1;
    }
}

static void stop_child(ChildProc *proc) {
    if (child_running(proc)) {
        struct timespec pause_time;
        kill(proc->pid, SIGTERM);
        pause_time.tv_sec = 0;
        pause_time.tv_nsec = 150000000L;
        nanosleep(&pause_time, NULL);
        if (waitpid(proc->pid, NULL, WNOHANG) == 0) {
            kill(proc->pid, SIGKILL);
        }
        waitpid(proc->pid, NULL, WNOHANG);
        proc->pid = -1;
        snprintf(proc->result, sizeof(proc->result), "Stopped");
    }
    close_if_open(&proc->stdout_fd);
    close_if_open(&proc->stderr_fd);
    close_if_open(&proc->stdin_fd);
}

static void reap_child(ChildProc *proc) {
    int status;
    pid_t done;
    if (!child_running(proc)) {
        return;
    }
    done = waitpid(proc->pid, &status, WNOHANG);
    if (done == proc->pid) {
        LogEvent e = log_defaults("INFO", "PROCESS_EXIT", "child process exited");
        e.pid = proc->pid;
        e.result = proc->result;
        experiment_apply_to_event(&e);
        logger_write(&control_logger, &e);
        proc->pid = -1;
        close_if_open(&proc->stdout_fd);
        close_if_open(&proc->stderr_fd);
        close_if_open(&proc->stdin_fd);
    }
}

static int start_child(ChildProc *proc, char *const argv[], int with_stdin,
                       const ChildEnv *envs, size_t env_count) {
    int out_pipe[2];
    int err_pipe[2];
    int in_pipe[2] = {-1, -1};
    pid_t pid;

    if (child_running(proc)) {
        return -1;
    }
    if (pipe(out_pipe) != 0 || pipe(err_pipe) != 0) {
        return -1;
    }
    if (with_stdin && pipe(in_pipe) != 0) {
        close(out_pipe[0]);
        close(out_pipe[1]);
        close(err_pipe[0]);
        close(err_pipe[1]);
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        close(out_pipe[0]);
        close(out_pipe[1]);
        close(err_pipe[0]);
        close(err_pipe[1]);
        close_if_open(&in_pipe[0]);
        close_if_open(&in_pipe[1]);
        return -1;
    }
    if (pid == 0) {
        size_t i;
        if (with_stdin) {
            dup2(in_pipe[0], STDIN_FILENO);
        }
        dup2(out_pipe[1], STDOUT_FILENO);
        dup2(err_pipe[1], STDERR_FILENO);
        close(out_pipe[0]);
        close(out_pipe[1]);
        close(err_pipe[0]);
        close(err_pipe[1]);
        close_if_open(&in_pipe[0]);
        close_if_open(&in_pipe[1]);
        for (i = 0; i < env_count; i += 1) {
            if (envs[i].key && envs[i].value) {
                setenv(envs[i].key, envs[i].value, 1);
            }
        }
        execv(argv[0], argv);
        _exit(127);
    }

    close(out_pipe[1]);
    close(err_pipe[1]);
    close_if_open(&in_pipe[0]);
    proc->pid = pid;
    proc->stdout_fd = out_pipe[0];
    proc->stderr_fd = err_pipe[0];
    proc->stdin_fd = with_stdin ? in_pipe[1] : -1;
    set_nonblock(proc->stdout_fd);
    set_nonblock(proc->stderr_fd);
    if (proc->stdin_fd >= 0) {
        set_nonblock(proc->stdin_fd);
    }
    snprintf(proc->result, sizeof(proc->result), "Pending");

    LogEvent e = log_defaults("INFO", "PROCESS_START", "child process started");
    e.pid = pid;
    experiment_apply_to_event(&e);
    logger_write(&control_logger, &e);
    return 0;
}

static void handle_child_output(ChildProc *proc, int fd, const char *stream_name) {
    char buf[512];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0) {
        return;
    }
    buf[n] = '\0';
    snprintf(proc->last_output, sizeof(proc->last_output), "%s", buf);
    if (strstr(buf, "OK")) {
        snprintf(proc->result, sizeof(proc->result), "OK");
    } else if (strstr(buf, "ABORT")) {
        snprintf(proc->result, sizeof(proc->result), "ABORT");
    }
    LogEvent e = log_defaults(strcmp(stream_name, "stderr") == 0 ? "WARN" : "INFO",
                              "PROCESS_OUTPUT", buf);
    e.pid = proc->pid;
    e.peer = stream_name;
    e.result = proc->result;
    experiment_apply_to_event(&e);
    logger_write(&control_logger, &e);
}

static const char *mime_for(const char *path) {
    const char *dot = strrchr(path, '.');
    if (!dot) {
        return "text/plain";
    }
    if (strcmp(dot, ".html") == 0) {
        return "text/html; charset=utf-8";
    }
    if (strcmp(dot, ".css") == 0) {
        return "text/css; charset=utf-8";
    }
    if (strcmp(dot, ".js") == 0) {
        return "application/javascript; charset=utf-8";
    }
    if (strcmp(dot, ".json") == 0) {
        return "application/json; charset=utf-8";
    }
    return "application/octet-stream";
}

static void send_http(int fd, const char *status, const char *mime, const char *body) {
    char header[512];
    size_t len = body ? strlen(body) : 0;
    snprintf(header, sizeof(header),
             "HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
             "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET,POST,OPTIONS\r\n"
             "Access-Control-Allow-Headers: Content-Type\r\nConnection: close\r\n\r\n",
             status, mime, len);
    send(fd, header, strlen(header), 0);
    if (body && len > 0) {
        send(fd, body, len, 0);
    }
}

static int read_file_text(const char *path, char **out, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    long len;
    char *buf;
    if (!fp) {
        return -1;
    }
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (len < 0 || len > 4 * 1024 * 1024) {
        fclose(fp);
        return -1;
    }
    buf = malloc((size_t)len + 1);
    if (!buf) {
        fclose(fp);
        return -1;
    }
    if (fread(buf, 1, (size_t)len, fp) != (size_t)len) {
        free(buf);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    buf[len] = '\0';
    *out = buf;
    *out_len = (size_t)len;
    return 0;
}

static void serve_static(int fd, const char *path) {
    char full_path[512];
    char *body = NULL;
    size_t len = 0;
    const char *relative = path;

    if (strcmp(path, "/") == 0) {
        relative = "/index.html";
    }
    if (strstr(relative, "..")) {
        send_http(fd, "403 Forbidden", "application/json", "{\"error\":\"forbidden\"}");
        return;
    }
    if (strncmp(relative, "/protocols/", 11) == 0) {
        snprintf(full_path, sizeof(full_path), ".%s", relative);
    } else {
        snprintf(full_path, sizeof(full_path), "web%s", relative);
    }
    if (read_file_text(full_path, &body, &len) != 0) {
        (void)len;
        send_http(fd, "404 Not Found", "application/json", "{\"error\":\"not found\"}");
        return;
    }
    send_http(fd, "200 OK", mime_for(full_path), body);
    free(body);
}

static int json_get_string(const char *body, const char *key, char *out, size_t out_size,
                           const char *fallback) {
    char pattern[96];
    const char *p;
    size_t pos = 0;
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    p = strstr(body ? body : "", pattern);
    if (!p) {
        snprintf(out, out_size, "%s", fallback ? fallback : "");
        return fallback ? 0 : -1;
    }
    p = strchr(p + strlen(pattern), ':');
    if (!p) {
        return -1;
    }
    p++;
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    if (*p != '"') {
        return -1;
    }
    p++;
    while (*p && *p != '"' && pos + 1 < out_size) {
        if (*p == '\\' && p[1]) {
            p++;
        }
        out[pos++] = *p++;
    }
    out[pos] = '\0';
    return 0;
}

static int json_get_int(const char *body, const char *key, int fallback) {
    char value[64];
    char pattern[96];
    const char *p;
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    p = strstr(body ? body : "", pattern);
    if (!p) {
        return fallback;
    }
    p = strchr(p + strlen(pattern), ':');
    if (!p) {
        return fallback;
    }
    p++;
    while (*p == ' ' || *p == '\t' || *p == '"') {
        p++;
    }
    snprintf(value, sizeof(value), "%s", p);
    return atoi(value);
}

static int is_windows_drive_path(const char *path) {
    if (!path || !path[0] || path[1] != ':') {
        return 0;
    }
    return ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) &&
           (path[2] == '/' || path[2] == '\\');
}

static int is_abs_path(const char *path) {
    return path && (path[0] == '/' || path[0] == '\\' || is_windows_drive_path(path));
}

static int path_is_blank(const char *path) {
    const char *p = path;
    if (!p) {
        return 1;
    }
    while (*p) {
        if (*p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') {
            return 0;
        }
        p++;
    }
    return 1;
}

static int validate_relative_path(const char *path, const char *kind, char *error, size_t error_size) {
    if (path_is_blank(path)) {
        snprintf(error, error_size, "%s path is empty", kind);
        return -1;
    }
    if (is_abs_path(path)) {
        snprintf(error, error_size, "%s path must be relative: %.420s", kind, path);
        return -1;
    }
    if (strlen(path) >= PATH_MAX) {
        snprintf(error, error_size, "%s path is too long", kind);
        return -1;
    }
    return 0;
}

static void path_error(char *error, size_t error_size, const char *prefix, const char *path) {
    snprintf(error, error_size, "%s%.420s", prefix, path ? path : "");
}

static int parent_dir(const char *path, char *out, size_t out_size) {
    const char *slash = strrchr(path, '/');
    if (!slash) {
        snprintf(out, out_size, ".");
        return 0;
    }
    if (slash == path) {
        snprintf(out, out_size, "/");
        return 0;
    }
    if ((size_t)(slash - path) >= out_size) {
        return -1;
    }
    memcpy(out, path, (size_t)(slash - path));
    out[slash - path] = '\0';
    return 0;
}

static int resolve_input_path(const char *path, char *out, size_t out_size, char *error, size_t error_size) {
    struct stat st;
    if (validate_relative_path(path, "input", error, error_size) != 0) {
        return -1;
    }
    if (snprintf(out, out_size, "%s", path) >= (int)out_size) {
        snprintf(error, error_size, "input path is too long");
        return -1;
    }
    if (stat(out, &st) != 0) {
        path_error(error, error_size, "input file not found: ", out);
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        path_error(error, error_size, "input path is not a regular file: ", out);
        return -1;
    }
    if (access(out, R_OK) != 0) {
        path_error(error, error_size, "input file is not readable: ", out);
        return -1;
    }
    return 0;
}

static int resolve_output_path(const char *path, char *out, size_t out_size, char *error, size_t error_size) {
    struct stat st;
    char dir[PATH_MAX];
    if (validate_relative_path(path, "output", error, error_size) != 0) {
        return -1;
    }
    if (snprintf(out, out_size, "%s", path) >= (int)out_size) {
        snprintf(error, error_size, "output path is too long");
        return -1;
    }
    if (stat(out, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            path_error(error, error_size, "output path is a directory: ", out);
            return -1;
        }
        if (access(out, W_OK) != 0) {
            path_error(error, error_size, "output file is not writable: ", out);
            return -1;
        }
    }
    if (parent_dir(out, dir, sizeof(dir)) != 0) {
        snprintf(error, error_size, "output path is too long");
        return -1;
    }
    if (stat(dir, &st) != 0) {
        path_error(error, error_size, "output directory not found: ", dir);
        return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        path_error(error, error_size, "output parent is not a directory: ", dir);
        return -1;
    }
    if (access(dir, W_OK) != 0) {
        path_error(error, error_size, "output directory is not writable: ", dir);
        return -1;
    }
    return 0;
}

static void send_error_json(int fd, const char *status, const char *error) {
    char escaped[SMALL_BUF * 2];
    char json[SMALL_BUF * 2 + 64];
    json_escape_to(escaped, sizeof(escaped), error);
    snprintf(json, sizeof(json), "{\"ok\":false,\"error\":%s}", escaped);
    send_http(fd, status, "application/json; charset=utf-8", json);
}

static void append_log_array(char *json, size_t cap, const char *key, const char *path) {
    FILE *fp = fopen(path, "r");
    char line[8192];
    int first = 1;
    appendf(json, cap, "\"%s\":[", key);
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            size_t len = strlen(line);
            while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
                line[--len] = '\0';
            }
            if (line[0] != '{') {
                continue;
            }
            appendf(json, cap, "%s%s", first ? "" : ",", line);
            first = 0;
        }
        fclose(fp);
    }
    appendf(json, cap, "]");
}

/* packets.jsonl 的设计（被 api_packets() 维护）：
   每个 wire packet 一条记录，由 api_packets() 调用时按 packet_uid 合并 + sender-side
   优选后写入。每次调用都整文件重写：
   - 当前 logs 里出现的每个 uid：选 sender-side 行（role 与 direction 的 from 端匹配）
   - 当前 logs 里不存在的旧 uid：保留为 orphan（属于历史 flow）
   - role 字段在 packets.jsonl 里表示"该包的发送方角色"（client 或 server）
   跨 run / 跨 flow 的最终去重交给前端的 buildRealPackets（key = flow_id + packet_uid）。*/

static void append_packet_array(char *json, size_t cap, const char *path) {
    FILE *fp = fopen(path, "r");
    char line[8192];
    int first = 1;
    appendf(json, cap, "[");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            size_t len = strlen(line);
            while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
                line[--len] = '\0';
            }
            if (line[0] != '{') {
                continue;
            }
            appendf(json, cap, "%s%s", first ? "" : ",", line);
            first = 0;
        }
        fclose(fp);
    }
    appendf(json, cap, "]");
}

static void truncate_packets(void) {
    FILE *fp = fopen("logs/packets.jsonl", "w");
    if (fp) fclose(fp);
    state.packets_log_offset = 0;
}

/* 从一行日志中提取 packet_type；若非数据包事件则返回 0 */
static int is_packet_log_line(const char *line) {
    if (!line) return 0;
    /* 至少需要 packet_type 字段且非空 */
    const char *p = strstr(line, "\"packet_type\":\"");
    if (!p) return 0;
    p += 15;
    return (*p && *p != '"') ? 1 : 0;
}

/* 从一行日志里提取 packet_uid（若有），用于跨文件 dedup */
static void line_uid_key(const char *line, char *out, size_t out_size) {
    out[0] = '\0';
    if (!line) return;
    const char *p = strstr(line, "\"packet_uid\":\"");
    if (p) {
        p += 14;
        const char *end = strchr(p, '"');
        if (end && (size_t)(end - p) < out_size) {
            size_t n = (size_t)(end - p);
            memcpy(out, p, n);
            out[n] = '\0';
        }
    }
}

/* 从一行日志里提取 direction 字段（"Client -> Server" / "Server -> Client"）。
   用于 api_packets 选取 sender-side 记录：direction 描述包在网络中的真实方向，
   由此可推知发送方角色（"from" 端）。 */
static void line_direction(const char *line, char *out, size_t out_size) {
    out[0] = '\0';
    if (!line) return;
    const char *p = strstr(line, "\"direction\":\"");
    if (!p) return;
    p += 13;
    const char *end = strchr(p, '"');
    if (end && (size_t)(end - p) < out_size) {
        size_t n = (size_t)(end - p);
        memcpy(out, p, n);
        out[n] = '\0';
    }
}

static void api_packets(int fd) {
    char *json = calloc(1, JSON_BUF);
    if (!json) {
        send_http(fd, "500 Internal Server Error", "application/json", "{\"error\":\"oom\"}");
        return;
    }
    /* packets.jsonl 维护策略：
       每次请求都扫描 server.jsonl + client.jsonl，按 packet_uid 合并成 pair，
       然后为每个 pair 选 sender-side 记录（role 与 direction 的 from 端匹配）。
       最后把 packets.jsonl 整文件重写：
         - 老记录里 uid 在当前 logs 中仍有 → 替换为新算法选出的 sender-side 行
         - 老记录里 uid 在当前 logs 中已无（orphan from old runs）→ 保留
       这样算法一旦更新（比如 sender-side 选择变了），旧记录会被自动替换；
       而属于"历史 flow 但当前没在 logs"的记录不会丢失。 */
    typedef struct {
        char uid[64];
        char server_line[8192];
        char client_line[8192];
    } PacketPair;
    PacketPair *pairs = NULL;
    size_t pairs_n = 0;
    size_t pairs_cap = 0;
    const char *log_paths[] = {"logs/server.jsonl", "logs/client.jsonl"};
    for (size_t li = 0; li < sizeof(log_paths) / sizeof(log_paths[0]); li++) {
        FILE *lfp = fopen(log_paths[li], "r");
        if (!lfp) continue;
        char line[8192];
        while (fgets(line, sizeof(line), lfp)) {
            if (!is_packet_log_line(line)) continue;
            size_t len = strlen(line);
            while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
                line[--len] = '\0';
            }
            char uid[64];
            line_uid_key(line, uid, sizeof(uid));
            if (!uid[0]) continue;
            size_t idx = pairs_n;
            for (size_t i = 0; i < pairs_n; i++) {
                if (strcmp(pairs[i].uid, uid) == 0) { idx = i; break; }
            }
            if (idx == pairs_n) {
                if (pairs_n >= pairs_cap) {
                    size_t new_cap = pairs_cap ? pairs_cap * 2 : 32;
                    PacketPair *new_arr = realloc(pairs, new_cap * sizeof(PacketPair));
                    if (!new_arr) break;
                    pairs = new_arr;
                    pairs_cap = new_cap;
                }
                memset(&pairs[idx], 0, sizeof(PacketPair));
                snprintf(pairs[idx].uid, sizeof(pairs[idx].uid), "%s", uid);
                pairs_n++;
            }
            if (li == 0) {
                snprintf(pairs[idx].server_line, sizeof(pairs[idx].server_line), "%s", line);
            } else {
                snprintf(pairs[idx].client_line, sizeof(pairs[idx].client_line), "%s", line);
            }
        }
        fclose(lfp);
    }

    /* 读取 packets.jsonl 已有的所有行（用于识别 orphan） */
    typedef struct {
        char uid[64];
        char line[8192];
    } ExistingLine;
    ExistingLine *existing_lines = NULL;
    size_t existing_lines_n = 0;
    size_t existing_lines_cap = 0;
    FILE *rfp = fopen("logs/packets.jsonl", "r");
    if (rfp) {
        char line[8192];
        while (fgets(line, sizeof(line), rfp)) {
            size_t len = strlen(line);
            while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
                line[--len] = '\0';
            }
            if (line[0] != '{') continue;
            char uid[64];
            line_uid_key(line, uid, sizeof(uid));
            if (!uid[0]) continue;
            if (existing_lines_n >= existing_lines_cap) {
                size_t new_cap = existing_lines_cap ? existing_lines_cap * 2 : 32;
                ExistingLine *new_arr = realloc(existing_lines, new_cap * sizeof(ExistingLine));
                if (!new_arr) break;
                existing_lines = new_arr;
                existing_lines_cap = new_cap;
            }
            snprintf(existing_lines[existing_lines_n].uid,
                     sizeof(existing_lines[existing_lines_n].uid), "%s", uid);
            snprintf(existing_lines[existing_lines_n].line,
                     sizeof(existing_lines[existing_lines_n].line), "%s", line);
            existing_lines_n++;
        }
        fclose(rfp);
    }

    /* 重写 packets.jsonl：先写 orphan（uid 不在当前 logs 的旧记录），再写每个 pair 的 sender-side */
    FILE *wfp = fopen("logs/packets.jsonl.tmp", "w");
    if (wfp) {
        for (size_t i = 0; i < existing_lines_n; i++) {
            int is_replaced = 0;
            for (size_t j = 0; j < pairs_n; j++) {
                if (strcmp(existing_lines[i].uid, pairs[j].uid) == 0) {
                    is_replaced = 1;
                    break;
                }
            }
            if (!is_replaced) {
                fputs(existing_lines[i].line, wfp);
                fputc('\n', wfp);
            }
        }
        for (size_t i = 0; i < pairs_n; i++) {
            const char *picked = NULL;
            int have_server = pairs[i].server_line[0] != '\0';
            int have_client = pairs[i].client_line[0] != '\0';
            if (have_server && have_client) {
                char dir[32] = "";
                line_direction(pairs[i].server_line, dir, sizeof(dir));
                if (strcmp(dir, "Server -> Client") == 0) {
                    picked = pairs[i].server_line;
                } else if (strcmp(dir, "Client -> Server") == 0) {
                    picked = pairs[i].client_line;
                } else {
                    picked = pairs[i].server_line;
                }
            } else if (have_server) {
                picked = pairs[i].server_line;
            } else if (have_client) {
                picked = pairs[i].client_line;
            }
            if (picked) {
                fputs(picked, wfp);
                fputc('\n', wfp);
            }
        }
        fclose(wfp);
        rename("logs/packets.jsonl.tmp", "logs/packets.jsonl");
    }

    free(pairs);
    free(existing_lines);
    appendf(json, JSON_BUF, "{\"ok\":true,\"packets\":");
    append_packet_array(json, JSON_BUF, "logs/packets.jsonl");
    appendf(json, JSON_BUF, ",\"count\":");
    int count = 0;
    FILE *cfp = fopen("logs/packets.jsonl", "r");
    if (cfp) {
        char buf[512];
        while (fgets(buf, sizeof(buf), cfp)) {
            if (buf[0] == '{') count++;
        }
        fclose(cfp);
    }
    appendf(json, JSON_BUF, "%d", count);
    appendf(json, JSON_BUF, "}");
    send_http(fd, "200 OK", "application/json; charset=utf-8", json);
    free(json);
}

static void api_logs(int fd) {
    char *json = calloc(1, JSON_BUF);
    if (!json) {
        send_http(fd, "500 Internal Server Error", "application/json", "{\"error\":\"oom\"}");
        return;
    }
    appendf(json, JSON_BUF, "{");
    append_log_array(json, JSON_BUF, "server", "logs/server.jsonl");
    appendf(json, JSON_BUF, ",");
    append_log_array(json, JSON_BUF, "client", "logs/client.jsonl");
    appendf(json, JSON_BUF, ",");
    append_log_array(json, JSON_BUF, "control", "logs/control.jsonl");
    appendf(json, JSON_BUF, "}");
    send_http(fd, "200 OK", "application/json; charset=utf-8", json);
    free(json);
}

static void api_status(int fd) {
    char json[4096] = {0};
    char server_last[SMALL_BUF];
    char client_last[SMALL_BUF];
    char protocol[128];
    char transport[128];
    char scenario[128];
    char flow_id[128];
    char session_id[128];
    experiment_set_default_protocol();
    json_escape_to(server_last, sizeof(server_last), state.server.last_output);
    json_escape_to(client_last, sizeof(client_last), state.client.last_output);
    json_escape_to(protocol, sizeof(protocol), state.experiment.protocol);
    json_escape_to(transport, sizeof(transport), state.experiment.transport);
    json_escape_to(scenario, sizeof(scenario), state.experiment.scenario);
    json_escape_to(flow_id, sizeof(flow_id), state.experiment.flow_id);
    json_escape_to(session_id, sizeof(session_id), state.experiment.session_id);
    appendf(json, sizeof(json),
            "{\"server\":{\"running\":%s,\"pid\":%ld,\"result\":\"%s\",\"last_output\":%s},"
            "\"client\":{\"running\":%s,\"pid\":%ld,\"result\":\"%s\",\"last_output\":%s},"
            "\"websocket\":%s,"
            "\"experiment\":{\"protocol\":%s,\"transport\":%s,\"scenario\":%s,"
            "\"flow_id\":%s,\"session_id\":%s}}",
            child_running(&state.server) ? "true" : "false", (long)state.server.pid,
            state.server.result, server_last,
            child_running(&state.client) ? "true" : "false", (long)state.client.pid,
            state.client.result, client_last,
            state.ws_fd >= 0 ? "true" : "false",
            protocol, transport, scenario, flow_id, session_id);
    send_http(fd, "200 OK", "application/json; charset=utf-8", json);
}

static void truncate_logs(void) {
    FILE *fp;
    fp = fopen("logs/server.jsonl", "w");
    if (fp) fclose(fp);
    fp = fopen("logs/client.jsonl", "w");
    if (fp) fclose(fp);
    fp = fopen("logs/control.jsonl", "w");
    if (fp) fclose(fp);
    /* 同时清空结构化包记录 */
    fp = fopen("logs/packets.jsonl", "w");
    if (fp) fclose(fp);
    state.server_log_offset = 0;
    state.client_log_offset = 0;
    state.control_log_offset = 0;
    state.packets_log_offset = 0;
}

static size_t build_protocol_envs(ChildEnv *envs, size_t cap) {
    size_t count = 0;
    if (cap < 6) {
        return 0;
    }
    envs[count++] = (ChildEnv){"UDP_SECURE_SCHEMA_VERSION", "2"};
    envs[count++] = (ChildEnv){"UDP_SECURE_PROTOCOL", state.experiment.protocol};
    envs[count++] = (ChildEnv){"UDP_SECURE_TRANSPORT", state.experiment.transport};
    envs[count++] = (ChildEnv){"UDP_SECURE_SCENARIO", state.experiment.scenario};
    envs[count++] = (ChildEnv){"UDP_SECURE_FLOW_ID", state.experiment.flow_id};
    envs[count++] = (ChildEnv){"UDP_SECURE_SESSION_ID", state.experiment.session_id};
    if (strcmp(state.experiment.protocol, "udp-reliable") == 0 && count + 5 <= cap) {
        const char *loss_ids = "";
        const char *dup_ids = "";
        const char *reorder_ids = "";
        envs[count++] = (ChildEnv){"UDP_SECURE_WINDOW_SIZE", "4"};
        envs[count++] = (ChildEnv){"UDP_SECURE_RELIABLE_TIMEOUT_MS", "250"};
        if (strcmp(state.experiment.scenario, "loss-recovery") == 0) {
            loss_ids = "1,3";
        } else if (strcmp(state.experiment.scenario, "reorder-recovery") == 0) {
            reorder_ids = "1,3";
        } else if (strcmp(state.experiment.scenario, "duplicate-recovery") == 0) {
            dup_ids = "2";
        }
        envs[count++] = (ChildEnv){"UDP_SECURE_RELIABLE_LOSS_IDS", loss_ids};
        envs[count++] = (ChildEnv){"UDP_SECURE_RELIABLE_DUP_IDS", dup_ids};
        envs[count++] = (ChildEnv){"UDP_SECURE_RELIABLE_REORDER_IDS", reorder_ids};
    }
    if (strcmp(state.experiment.protocol, "tcp-basic") == 0 && count + 1 <= cap) {
        const char *fragment = strcmp(state.experiment.scenario, "stream-fragmentation") == 0 ? "1" : "0";
        envs[count++] = (ChildEnv){"UDP_SECURE_STREAM_FRAGMENTATION", fragment};
    }
    if (strcmp(state.experiment.protocol, "tls-like") == 0 && count + 2 <= cap) {
        const char *tampered_finished = strcmp(state.experiment.scenario, "tampered-finished") == 0 ? "1" : "0";
        const char *tampered_app = strcmp(state.experiment.scenario, "tampered-app-data") == 0 ? "1" : "0";
        envs[count++] = (ChildEnv){"UDP_SECURE_TAMPER_FINISHED", tampered_finished};
        envs[count++] = (ChildEnv){"UDP_SECURE_TAMPER_APP_DATA", tampered_app};
    }
    if (strcmp(state.experiment.protocol, "quic-like") == 0 && count + 4 <= cap) {
        const char *loss = strcmp(state.experiment.scenario, "loss-recovery") == 0 ? "1,4" : "";
        const char *reorder = strcmp(state.experiment.scenario, "stream-reorder") == 0 ? "1:2,2:1" : "";
        const char *zero_rtt = strcmp(state.experiment.scenario, "zero-rtt-replay-risk") == 0 ? "1" : "0";
        envs[count++] = (ChildEnv){"UDP_SECURE_QUIC_LOSS", loss};
        envs[count++] = (ChildEnv){"UDP_SECURE_QUIC_REORDER", reorder};
        envs[count++] = (ChildEnv){"UDP_SECURE_QUIC_ZERO_RTT", zero_rtt};
        envs[count++] = (ChildEnv){"UDP_SECURE_QUIC_WINDOW", "4"};
    }
    return count;
}

static void api_server_start(int fd, const char *body) {
    static char port[32], password[256], input[PATH_MAX], checked_input[PATH_MAX];
    static char protocol[64], scenario[64];
    char error[SMALL_BUF];
    ChildEnv envs[16];
    const char *binary = NULL;
    char *args[] = {(char *)"", port, password, checked_input, NULL};
    int port_num = json_get_int(body, "port", 9000);
    snprintf(port, sizeof(port), "%d", port_num);
    if (json_get_string(body, "password", password, sizeof(password), "secret") != 0 ||
        json_get_string(body, "inputFile", input, sizeof(input), "test/input.txt") != 0 ||
        json_get_string(body, "protocol", protocol, sizeof(protocol), "udp-basic") != 0 ||
        json_get_string(body, "scenario", scenario, sizeof(scenario), "normal") != 0) {
        send_http(fd, "400 Bad Request", "application/json", "{\"ok\":false,\"error\":\"invalid body\"}");
        return;
    }
    if (resolve_input_path(input, checked_input, sizeof(checked_input), error, sizeof(error)) != 0) {
        send_error_json(fd, "400 Bad Request", error);
        return;
    }
    binary = server_binary_for_protocol(protocol);
    if (!binary) {
        send_http(fd, "400 Bad Request", "application/json", "{\"ok\":false,\"error\":\"unsupported protocol\"}");
        return;
    }
    args[0] = (char *)binary;
    if (child_running(&state.server)) {
        send_http(fd, "409 Conflict", "application/json", "{\"ok\":false,\"error\":\"server already running or failed\"}");
        return;
    }
    experiment_configure(protocol, scenario);
    if (start_child(&state.server, args, 0, envs, build_protocol_envs(envs, 16)) != 0) {
        send_http(fd, "409 Conflict", "application/json", "{\"ok\":false,\"error\":\"server already running or failed\"}");
        return;
    }
    send_http(fd, "200 OK", "application/json", "{\"ok\":true}");
}

static void api_client_start(int fd, const char *body) {
    static char host[256], port[32], out[PATH_MAX], checked_out[PATH_MAX], pwd1[256], pwd2[256], pwd3[256], mode[32];
    static char protocol[64], scenario[64];
    char error[SMALL_BUF];
    ChildEnv envs[16];
    const char *binary = NULL;
    char *args_compat[] = {(char *)"", host, port, pwd1, pwd2, pwd3, checked_out, NULL};
    char *args_interactive[] = {(char *)"", host, port, checked_out, NULL};
    int port_num = json_get_int(body, "port", 9000);
    snprintf(port, sizeof(port), "%d", port_num);
    json_get_string(body, "host", host, sizeof(host), "127.0.0.1");
    json_get_string(body, "outputFile", out, sizeof(out), "output/web-output.bin");
    json_get_string(body, "mode", mode, sizeof(mode), "compat");
    json_get_string(body, "pwd1", pwd1, sizeof(pwd1), "");
    json_get_string(body, "pwd2", pwd2, sizeof(pwd2), "");
    json_get_string(body, "pwd3", pwd3, sizeof(pwd3), "");
    json_get_string(body, "protocol", protocol, sizeof(protocol), "udp-basic");
    json_get_string(body, "scenario", scenario, sizeof(scenario), "normal");
    if (resolve_output_path(out, checked_out, sizeof(checked_out), error, sizeof(error)) != 0) {
        send_error_json(fd, "400 Bad Request", error);
        return;
    }
    binary = client_binary_for_protocol(protocol);
    if (!binary) {
        send_http(fd, "400 Bad Request", "application/json", "{\"ok\":false,\"error\":\"unsupported protocol\"}");
        return;
    }
    args_compat[0] = (char *)binary;
    args_interactive[0] = (char *)binary;
    if (child_running(&state.client)) {
        send_http(fd, "409 Conflict", "application/json", "{\"ok\":false,\"error\":\"client already running or failed\"}");
        return;
    }
    if (!state.experiment.flow_id[0] || !child_running(&state.server)) {
        experiment_configure(protocol, scenario);
    }
    if (strcmp(mode, "interactive") == 0) {
        if (start_child(&state.client, args_interactive, 1, envs, build_protocol_envs(envs, 16)) != 0) {
            send_http(fd, "409 Conflict", "application/json", "{\"ok\":false,\"error\":\"client already running or failed\"}");
            return;
        }
    } else {
        if (start_child(&state.client, args_compat, 0, envs, build_protocol_envs(envs, 16)) != 0) {
            send_http(fd, "409 Conflict", "application/json", "{\"ok\":false,\"error\":\"client already running or failed\"}");
            return;
        }
    }
    send_http(fd, "200 OK", "application/json", "{\"ok\":true}");
}

static void api_send_password(int fd, const char *body) {
    char password[256];
    char line[300];
    if (state.client.stdin_fd < 0 ||
        json_get_string(body, "password", password, sizeof(password), "") != 0) {
        send_http(fd, "400 Bad Request", "application/json", "{\"ok\":false,\"error\":\"interactive client stdin unavailable\"}");
        return;
    }
    snprintf(line, sizeof(line), "%s\n", password);
    if (write(state.client.stdin_fd, line, strlen(line)) < 0) {
        send_http(fd, "500 Internal Server Error", "application/json", "{\"ok\":false,\"error\":\"write failed\"}");
        return;
    }
    send_http(fd, "200 OK", "application/json", "{\"ok\":true}");
}

static void api_run_tests(int fd) {
    FILE *pipe_fp;
    FILE *out_fp;
    char chunk[1024];
    char result[8192] = {0};

    stop_child(&state.server);
    stop_child(&state.client);
    pipe_fp = popen("./test/run_tests.sh --json 2>&1", "r");
    if (!pipe_fp) {
        send_http(fd, "500 Internal Server Error", "application/json", "{\"ok\":false,\"error\":\"cannot run tests\"}");
        return;
    }
    while (fgets(chunk, sizeof(chunk), pipe_fp)) {
        if (strlen(result) + strlen(chunk) + 1 < sizeof(result)) {
            strcat(result, chunk);
        }
    }
    pclose(pipe_fp);
    snprintf(state.last_test_result, sizeof(state.last_test_result), "%s", result);
    out_fp = fopen("logs/test-results.json", "w");
    if (out_fp) {
        fputs(result, out_fp);
        fclose(out_fp);
    }
    send_http(fd, "200 OK", "application/json; charset=utf-8", result[0] ? result : "{\"ok\":false}");
}

static void api_test_result(int fd) {
    char *body = NULL;
    size_t len = 0;
    if (read_file_text("logs/test-results.json", &body, &len) == 0) {
        (void)len;
        send_http(fd, "200 OK", "application/json; charset=utf-8", body);
        free(body);
    } else {
        send_http(fd, "200 OK", "application/json", "{\"ok\":false,\"tests\":[]}");
    }
}

static void route_api(int fd, const char *method, const char *path, const char *body) {
    if (strcmp(method, "OPTIONS") == 0) {
        send_http(fd, "204 No Content", "text/plain", "");
    } else if (strcmp(path, "/api/status") == 0) {
        api_status(fd);
    } else if (strcmp(path, "/api/logs") == 0 && strcmp(method, "GET") == 0) {
        api_logs(fd);
    } else if (strcmp(path, "/api/packets") == 0 && strcmp(method, "GET") == 0) {
        api_packets(fd);
    } else if (strcmp(path, "/api/packets/clear") == 0 && strcmp(method, "POST") == 0) {
        truncate_packets();
        send_http(fd, "200 OK", "application/json", "{\"ok\":true}");
    } else if (strcmp(path, "/api/server/start") == 0 && strcmp(method, "POST") == 0) {
        api_server_start(fd, body);
    } else if (strcmp(path, "/api/server/stop") == 0 && strcmp(method, "POST") == 0) {
        stop_child(&state.server);
        send_http(fd, "200 OK", "application/json", "{\"ok\":true}");
    } else if (strcmp(path, "/api/client/start") == 0 && strcmp(method, "POST") == 0) {
        api_client_start(fd, body);
    } else if (strcmp(path, "/api/client/stop") == 0 && strcmp(method, "POST") == 0) {
        stop_child(&state.client);
        send_http(fd, "200 OK", "application/json", "{\"ok\":true}");
    } else if (strcmp(path, "/api/client/send-password") == 0 && strcmp(method, "POST") == 0) {
        api_send_password(fd, body);
    } else if (strcmp(path, "/api/reset") == 0 && strcmp(method, "POST") == 0) {
        stop_child(&state.server);
        stop_child(&state.client);
        child_init(&state.server, "server");
        child_init(&state.client, "client");
        experiment_clear();
        /* 重置时同时清空所有日志文件（保留日志目录） */
        truncate_logs();
        send_http(fd, "200 OK", "application/json", "{\"ok\":true}");
    } else if (strcmp(path, "/api/test/list") == 0) {
        send_http(fd, "200 OK", "application/json",
                  "{\"tests\":[\"first_password_ok\",\"second_password_ok\",\"third_password_ok\","
                  "\"three_passwords_wrong\",\"big_file_transfer\",\"reliable_basic\","
                  "\"reliable_loss_recovery\",\"reliable_reorder_recovery\",\"reliable_duplicate_recovery\","
                  "\"server_timeout\",\"missing_input\",\"sequence_error\"]}");
    } else if (strcmp(path, "/api/test/run") == 0 && strcmp(method, "POST") == 0) {
        api_run_tests(fd);
    } else if (strcmp(path, "/api/test/result") == 0) {
        api_test_result(fd);
    } else {
        send_http(fd, "404 Not Found", "application/json", "{\"error\":\"unknown api\"}");
    }
}

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void base64_encode(const uint8_t *in, size_t len, char *out, size_t out_size) {
    size_t i = 0;
    size_t pos = 0;
    while (i < len && pos + 4 < out_size) {
        uint32_t octet_a = i < len ? in[i++] : 0;
        uint32_t octet_b = i < len ? in[i++] : 0;
        uint32_t octet_c = i < len ? in[i++] : 0;
        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;
        out[pos++] = b64_table[(triple >> 18) & 0x3f];
        out[pos++] = b64_table[(triple >> 12) & 0x3f];
        out[pos++] = (i - 1 > len) ? '=' : b64_table[(triple >> 6) & 0x3f];
        out[pos++] = (i > len) ? '=' : b64_table[triple & 0x3f];
    }
    out[pos] = '\0';
    if (len % 3 == 1 && pos >= 2) {
        out[pos - 2] = '=';
        out[pos - 1] = '=';
    } else if (len % 3 == 2 && pos >= 1) {
        out[pos - 1] = '=';
    }
}

static int websocket_send_text(const char *text) {
    uint8_t header[10];
    size_t len;
    size_t header_len;
    if (state.ws_fd < 0 || !text) {
        return -1;
    }
    len = strlen(text);
    header[0] = 0x81;
    if (len < 126) {
        header[1] = (uint8_t)len;
        header_len = 2;
    } else if (len <= 65535) {
        header[1] = 126;
        header[2] = (uint8_t)((len >> 8) & 0xff);
        header[3] = (uint8_t)(len & 0xff);
        header_len = 4;
    } else {
        return -1;
    }
    if (send(state.ws_fd, header, header_len, 0) < 0 ||
        send(state.ws_fd, text, len, 0) < 0) {
        close(state.ws_fd);
        state.ws_fd = -1;
        return -1;
    }
    return 0;
}

static void websocket_handshake(int fd, const char *request) {
    const char *key_start = strstr(request, "Sec-WebSocket-Key:");
    char key[128] = {0};
    char accept[128];
    char response[512];
    Sha1Context ctx;
    uint8_t digest[SHA1_DIGEST_LENGTH];
    const char *magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    size_t i = 0;

    if (!key_start) {
        close(fd);
        return;
    }
    key_start += strlen("Sec-WebSocket-Key:");
    while (*key_start == ' ' || *key_start == '\t') {
        key_start++;
    }
    while (*key_start && *key_start != '\r' && *key_start != '\n' && i + 1 < sizeof(key)) {
        key[i++] = *key_start++;
    }
    key[i] = '\0';
    sha1_init(&ctx);
    sha1_update(&ctx, (const uint8_t *)key, strlen(key));
    sha1_update(&ctx, (const uint8_t *)magic, strlen(magic));
    sha1_final(&ctx, digest);
    base64_encode(digest, sizeof(digest), accept, sizeof(accept));
    snprintf(response, sizeof(response),
             "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
             "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
             accept);
    send(fd, response, strlen(response), 0);
    if (state.ws_fd >= 0) {
        close(state.ws_fd);
    }
    state.ws_fd = fd;
    set_nonblock(state.ws_fd);
    websocket_send_text("{\"type\":\"hello\",\"message\":\"control websocket connected\"}");
}

static int read_http_request(int fd, char *buf, size_t cap) {
    ssize_t n;
    size_t used = 0;
    int content_length = 0;
    char *body;
    while (used + 1 < cap) {
        n = recv(fd, buf + used, cap - used - 1, 0);
        if (n <= 0) {
            return -1;
        }
        used += (size_t)n;
        buf[used] = '\0';
        body = strstr(buf, "\r\n\r\n");
        if (body) {
            char *cl = strstr(buf, "Content-Length:");
            if (cl) {
                content_length = atoi(cl + strlen("Content-Length:"));
            }
            body += 4;
            if ((int)(used - (size_t)(body - buf)) >= content_length) {
                return (int)used;
            }
        }
    }
    return -1;
}

static void handle_http_client(int fd) {
    char request[HTTP_BUF];
    char method[16] = {0};
    char path[512] = {0};
    char *body;
    if (read_http_request(fd, request, sizeof(request)) < 0) {
        close(fd);
        return;
    }
    sscanf(request, "%15s %511s", method, path);
    body = strstr(request, "\r\n\r\n");
    body = body ? body + 4 : request + strlen(request);
    if (strcmp(path, "/ws") == 0) {
        websocket_handshake(fd, request);
        return;
    }
    if (strncmp(path, "/api/", 5) == 0) {
        route_api(fd, method, path, body);
    } else {
        serve_static(fd, path);
    }
    close(fd);
}

static void push_log_tail(const char *role, const char *path, long *offset) {
    FILE *fp = fopen(path, "r");
    char line[8192];
    char msg[9000];
    if (!fp) {
        return;
    }
    fseek(fp, *offset, SEEK_SET);
    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
        if (line[0] == '{') {
            snprintf(msg, sizeof(msg), "{\"type\":\"log\",\"source\":\"%s\",\"entry\":%s}", role, line);
            websocket_send_text(msg);
        }
    }
    *offset = ftell(fp);
    fclose(fp);
}

static void push_status(void) {
    char msg[1024];
    char protocol[128];
    char transport[128];
    char scenario[128];
    char flow_id[128];
    char session_id[128];
    experiment_set_default_protocol();
    json_escape_to(protocol, sizeof(protocol), state.experiment.protocol);
    json_escape_to(transport, sizeof(transport), state.experiment.transport);
    json_escape_to(scenario, sizeof(scenario), state.experiment.scenario);
    json_escape_to(flow_id, sizeof(flow_id), state.experiment.flow_id);
    json_escape_to(session_id, sizeof(session_id), state.experiment.session_id);
    snprintf(msg, sizeof(msg),
             "{\"type\":\"status\",\"server\":{\"running\":%s,\"result\":\"%s\"},"
             "\"client\":{\"running\":%s,\"result\":\"%s\"},"
             "\"experiment\":{\"protocol\":%s,\"transport\":%s,\"scenario\":%s,"
             "\"flow_id\":%s,\"session_id\":%s}}",
             child_running(&state.server) ? "true" : "false", state.server.result,
             child_running(&state.client) ? "true" : "false", state.client.result,
             protocol, transport, scenario, flow_id, session_id);
    websocket_send_text(msg);
}

static int create_listener(int port) {
    int fd;
    int yes = 1;
    struct sockaddr_in addr;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(fd, 16) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int main(int argc, char **argv) {
    int port = CONTROL_PORT;
    int listen_fd;
    int maxfd;
    fd_set readfds;
    struct timeval tv;
    time_t last_status = 0;

    if (argc == 2) {
        port = atoi(argv[1]);
    }

    ensure_runtime_dirs();
    child_init(&state.server, "server");
    child_init(&state.client, "client");
    experiment_clear();
    state.ws_fd = -1;
    if (logger_open(&control_logger, "control", "logs/control.jsonl") != 0) {
        fprintf(stderr, "Cannot open control log\n");
        return 1;
    }

    listen_fd = create_listener(port);
    if (listen_fd < 0) {
        fprintf(stderr, "Cannot listen on 127.0.0.1:%d: %s\n", port, strerror(errno));
        return 1;
    }
    printf("Control server listening on http://127.0.0.1:%d\n", port);
    fflush(stdout);

    for (;;) {
        int client_fd;
        FD_ZERO(&readfds);
        FD_SET(listen_fd, &readfds);
        maxfd = listen_fd;
        if (state.server.stdout_fd >= 0) {
            FD_SET(state.server.stdout_fd, &readfds);
            if (state.server.stdout_fd > maxfd) maxfd = state.server.stdout_fd;
        }
        if (state.server.stderr_fd >= 0) {
            FD_SET(state.server.stderr_fd, &readfds);
            if (state.server.stderr_fd > maxfd) maxfd = state.server.stderr_fd;
        }
        if (state.client.stdout_fd >= 0) {
            FD_SET(state.client.stdout_fd, &readfds);
            if (state.client.stdout_fd > maxfd) maxfd = state.client.stdout_fd;
        }
        if (state.client.stderr_fd >= 0) {
            FD_SET(state.client.stderr_fd, &readfds);
            if (state.client.stderr_fd > maxfd) maxfd = state.client.stderr_fd;
        }
        if (state.ws_fd >= 0) {
            FD_SET(state.ws_fd, &readfds);
            if (state.ws_fd > maxfd) maxfd = state.ws_fd;
        }
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        if (select(maxfd + 1, &readfds, NULL, NULL, &tv) < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (FD_ISSET(listen_fd, &readfds)) {
            client_fd = accept(listen_fd, NULL, NULL);
            if (client_fd >= 0) {
                handle_http_client(client_fd);
            }
        }
        if (state.server.stdout_fd >= 0 && FD_ISSET(state.server.stdout_fd, &readfds)) {
            handle_child_output(&state.server, state.server.stdout_fd, "stdout");
        }
        if (state.server.stderr_fd >= 0 && FD_ISSET(state.server.stderr_fd, &readfds)) {
            handle_child_output(&state.server, state.server.stderr_fd, "stderr");
        }
        if (state.client.stdout_fd >= 0 && FD_ISSET(state.client.stdout_fd, &readfds)) {
            handle_child_output(&state.client, state.client.stdout_fd, "stdout");
        }
        if (state.client.stderr_fd >= 0 && FD_ISSET(state.client.stderr_fd, &readfds)) {
            handle_child_output(&state.client, state.client.stderr_fd, "stderr");
        }
        if (state.ws_fd >= 0 && FD_ISSET(state.ws_fd, &readfds)) {
            char discard[256];
            ssize_t n = recv(state.ws_fd, discard, sizeof(discard), 0);
            if (n <= 0) {
                close(state.ws_fd);
                state.ws_fd = -1;
            }
        }
        reap_child(&state.server);
        reap_child(&state.client);
        if (state.ws_fd >= 0) {
            push_log_tail("server", "logs/server.jsonl", &state.server_log_offset);
            push_log_tail("client", "logs/client.jsonl", &state.client_log_offset);
            push_log_tail("control", "logs/control.jsonl", &state.control_log_offset);
            if (time(NULL) != last_status) {
                last_status = time(NULL);
                push_status();
            }
        }
    }

    stop_child(&state.server);
    stop_child(&state.client);
    if (state.ws_fd >= 0) {
        close(state.ws_fd);
    }
    close(listen_fd);
    logger_close(&control_logger);
    return 0;
}
