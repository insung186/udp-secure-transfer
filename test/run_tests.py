#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENV = os.environ.copy()
ENV["UDP_SECURE_TIMEOUT_MS"] = ENV.get("UDP_SECURE_TIMEOUT_MS", "1500")


def free_udp_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def free_tcp_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def run_cmd(args, timeout=12, env=None):
    return subprocess.run(
        args,
        cwd=ROOT,
        env=env or ENV,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def start_process(args, env=None):
    return subprocess.Popen(
        args,
        cwd=ROOT,
        env=env or ENV,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def start_server(port, password, input_file, env=None):
    return start_process(["./bin/server", str(port), password, str(input_file)], env=env)


def wait_for_server_start(port, timeout=4.0):
    deadline = time.time() + timeout
    marker = f'"port":{port}'
    log_path = ROOT / "logs" / "server.jsonl"
    while time.time() < deadline:
        if log_path.exists() and marker in log_path.read_text(encoding="utf-8", errors="ignore"):
            return True
        time.sleep(0.03)
    return False


def collect_process(proc, timeout=8):
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            stdout, stderr = proc.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate(timeout=1)
    return proc.returncode, stdout or "", stderr or ""


def packet(packet_type, payload=b""):
    return struct.pack("!HI", packet_type, len(payload)) + payload


def data_packet(packet_id, payload=b"bad"):
    return struct.pack("!HII", 5, len(payload), packet_id) + payload


def make_inputs():
    (ROOT / "test" / "cases").mkdir(parents=True, exist_ok=True)
    (ROOT / "output").mkdir(parents=True, exist_ok=True)
    small = ROOT / "test" / "cases" / "small.txt"
    small.write_text("Secure UDP transfer test file.\n" * 4, encoding="utf-8")
    big = ROOT / "test" / "cases" / "big.bin"
    pattern = bytes((i % 251 for i in range(64 * 1024 + 333)))
    big.write_bytes(pattern)
    return small, big


def reset_logs():
    (ROOT / "logs").mkdir(exist_ok=True)
    for name in ["server.jsonl", "client.jsonl", "control.jsonl", "test-results.json"]:
        path = ROOT / "logs" / name
        path.write_text("", encoding="utf-8")


def result(case_id, name, passed, message, **extra):
    item = {"id": case_id, "name": name, "pass": bool(passed), "message": message}
    item.update(extra)
    return item


def run_pair(case_id, name, input_file, password, attempts, expect_ok=True, env_overrides=None):
    port = free_udp_port()
    output = ROOT / "output" / f"{case_id}.out"
    output.unlink(missing_ok=True)
    pair_env = ENV.copy()
    if env_overrides:
        pair_env.update(env_overrides)
    server = start_server(port, password, input_file, env=pair_env)
    wait_for_server_start(port)
    client = run_cmd(["./bin/client", "127.0.0.1", str(port), *attempts, str(output)], timeout=8, env=pair_env)
    server_rc, server_out, server_err = collect_process(server, timeout=8)
    client_ok = "OK" in client.stdout
    server_ok = "OK" in server_out
    client_abort = "ABORT" in client.stdout
    server_abort = "ABORT" in server_out
    same_file = output.exists() and input_file.read_bytes() == output.read_bytes()
    if expect_ok:
        passed = client.returncode == 0 and server_rc == 0 and client_ok and server_ok and same_file
        message = "client/server OK and output matches input" if passed else "expected OK transfer"
    else:
        passed = client.returncode != 0 and server_rc != 0 and client_abort and server_abort
        message = "client/server ABORT after authentication failure" if passed else "expected REJECT/ABORT"
    return result(
        case_id,
        name,
        passed,
        message,
        client_stdout=client.stdout.strip(),
        client_stderr=client.stderr.strip(),
        server_stdout=server_out.strip(),
        server_stderr=server_err.strip(),
    )


def run_demo_pair(case_id, name, server_bin, client_bin, input_file, output_file, port_kind,
                  env_overrides=None, attempts=None, expect_ok=True, verify_output=False,
                  expect_client_status=None, expect_server_status=None, timeout=8,
                  require_log_text=None):
    port = free_tcp_port() if port_kind == "tcp" else free_udp_port()
    pair_env = ENV.copy()
    pair_env.update(env_overrides or {})
    output_path = ROOT / "output" / output_file
    output_path.unlink(missing_ok=True)
    server = start_process([server_bin, str(port), "secret", str(input_file)], env=pair_env)
    wait_for_server_start(port)
    client_args = [client_bin, "127.0.0.1", str(port)]
    if attempts:
      client_args.extend(attempts)
      client_args.append(str(output_path))
    else:
      client_args.extend(["secret", "x", "x", str(output_path)])
    client = run_cmd(client_args, timeout=timeout, env=pair_env)
    server_rc, server_out, server_err = collect_process(server, timeout=timeout)
    server_stdout = server_out.strip()
    client_stdout = client.stdout.strip()
    client_ok = "OK" in client_stdout
    server_ok = "OK" in server_stdout
    client_abort = "ABORT" in client_stdout
    server_abort = "ABORT" in server_stdout
    file_ok = True
    if verify_output:
        file_ok = output_path.exists() and input_file.read_bytes() == output_path.read_bytes()
    if expect_ok:
        passed = client.returncode == 0 and server_rc == 0 and client_ok and server_ok and file_ok
    else:
        passed = client.returncode != 0 and server_rc != 0 and client_abort and server_abort
    if expect_client_status is not None:
        passed = passed and expect_client_status in client_stdout
    if expect_server_status is not None:
        passed = passed and expect_server_status in server_stdout
    if require_log_text:
        log_text = (ROOT / "logs" / "server.jsonl").read_text(encoding="utf-8", errors="ignore")
        passed = passed and require_log_text in log_text
    message = "demo pair completed" if passed else "demo pair failed"
    return result(
        case_id,
        name,
        passed,
        message,
        client_stdout=client_stdout,
        client_stderr=client.stderr.strip(),
        server_stdout=server_stdout,
        server_stderr=server_err.strip(),
    )


def test_reliable_pair(case_id, name, input_file, env_overrides=None):
    log_path = ROOT / "logs" / "server.jsonl"
    before = log_path.read_text(encoding="utf-8", errors="ignore") if log_path.exists() else ""
    item = run_pair(
        case_id,
        name,
        input_file,
        "secret",
        ["secret", "x", "x"],
        True,
        env_overrides={"UDP_SECURE_PROTOCOL": "udp-reliable", **(env_overrides or {})},
    )
    after = log_path.read_text(encoding="utf-8", errors="ignore") if log_path.exists() else ""
    delta = after[len(before):]
    item["has_ack"] = '"packet_type":"ACK"' in after or '"packet_type":"ACK"' in delta
    item["has_retransmit"] = "RETRANSMIT_DATA" in after or "SIMULATED_DROP" in after
    if not item["has_ack"]:
        item["pass"] = False
        item["message"] = f"{item['message']}; missing ACK logs"
    return item


def test_missing_input():
    port = free_udp_port()
    proc = run_cmd(["./bin/server", str(port), "secret", "test/cases/missing-file.bin"], timeout=3)
    passed = proc.returncode != 0 and "ABORT" in proc.stdout
    return result(
        "missing_input",
        "服务器输入文件不存在",
        passed,
        "server prints ABORT for missing input" if passed else "expected server ABORT",
        server_stdout=proc.stdout.strip(),
        server_stderr=proc.stderr.strip(),
    )


def test_timeout():
    port = free_udp_port()
    output = ROOT / "output" / "timeout.out"
    output.unlink(missing_ok=True)
    proc = run_cmd(
        ["./bin/client", "127.0.0.1", str(port), "secret", "secret", "secret", str(output)],
        timeout=5,
    )
    passed = proc.returncode != 0 and "ABORT" in proc.stdout
    return result(
        "timeout",
        "服务器未启动客户端超时",
        passed,
        "client prints ABORT on network timeout" if passed else "expected client timeout ABORT",
        client_stdout=proc.stdout.strip(),
        client_stderr=proc.stderr.strip(),
    )


def test_malformed_packet(input_file):
    port = free_udp_port()
    server = start_server(port, "secret", input_file)
    wait_for_server_start(port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(packet(99), ("127.0.0.1", port))
    sock.close()
    server_rc, server_out, server_err = collect_process(server, timeout=5)
    passed = server_rc != 0 and "ABORT" in server_out
    return result(
        "malformed_packet",
        "未知包类型触发服务器异常退出",
        passed,
        "server prints ABORT for unknown packet type" if passed else "expected server parse ABORT",
        server_stdout=server_out.strip(),
        server_stderr=server_err.strip(),
    )


def fake_sequence_server(port, password):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.bind(("127.0.0.1", port))
    try:
        _, client = sock.recvfrom(2048)
        sock.sendto(packet(2), client)
        _, client = sock.recvfrom(2048)
        sock.sendto(packet(4), client)
        sock.sendto(data_packet(1, b"out-of-order"), client)
    finally:
        sock.close()


def test_sequence_error():
    port = free_udp_port()
    output = ROOT / "output" / "sequence-error.out"
    output.unlink(missing_ok=True)
    thread = threading.Thread(target=fake_sequence_server, args=(port, "secret"), daemon=True)
    thread.start()
    proc = run_cmd(
        ["./bin/client", "127.0.0.1", str(port), "secret", "secret", "secret", str(output)],
        timeout=6,
    )
    thread.join(timeout=1)
    passed = proc.returncode != 0 and "ABORT" in proc.stdout
    return result(
        "sequence_error",
        "DATA packet_id 不连续",
        passed,
        "client prints ABORT for non-continuous DATA packet id" if passed else "expected sequence ABORT",
        client_stdout=proc.stdout.strip(),
        client_stderr=proc.stderr.strip(),
    )


def run_all():
    build = subprocess.run(
        ["make"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    tests = []
    if build.returncode != 0:
        return {
            "ok": False,
            "tests": [
                result(
                    "build",
                    "make",
                    False,
                    "build failed",
                    stdout=build.stdout,
                    stderr=build.stderr,
                )
            ],
        }

    reset_logs()
    small, big = make_inputs()
    tests.append(run_pair("first_password_ok", "第一次密码正确", small, "secret", ["secret", "wrong", "wrong"], True))
    tests.append(run_pair("second_password_ok", "第二次密码正确", small, "secret", ["wrong", "secret", "wrong"], True))
    tests.append(run_pair("third_password_ok", "第三次密码正确", small, "secret", ["wrong", "wrong", "secret"], True))
    tests.append(run_pair("three_passwords_wrong", "三次密码全部错误", small, "secret", ["bad1", "bad2", "bad3"], False))
    tests.append(run_pair("big_file_transfer", "大文件多分片传输", big, "secret", ["secret", "x", "x"], True))
    tests.append(test_reliable_pair("reliable_basic", "Reliable UDP 正常传输", big))
    tests.append(test_reliable_pair(
        "reliable_loss_recovery",
        "Reliable UDP 丢包后恢复",
        big,
        {"UDP_SECURE_RELIABLE_LOSS_IDS": "1,3", "UDP_SECURE_RELIABLE_TIMEOUT_MS": "180"},
    ))
    tests.append(test_reliable_pair(
        "reliable_reorder_recovery",
        "Reliable UDP 乱序后恢复",
        big,
        {"UDP_SECURE_RELIABLE_REORDER_IDS": "1,3"},
    ))
    tests.append(test_reliable_pair(
        "reliable_duplicate_recovery",
        "Reliable UDP 重复包后恢复",
        big,
        {"UDP_SECURE_RELIABLE_DUP_IDS": "2,4"},
    ))
    tests.append(run_demo_pair(
        "tcp_basic_normal",
        "TCP Basic 正常传输",
        "./bin/tcp_server",
        "./bin/tcp_client",
        small,
        "tcp-basic.out",
        "tcp",
        env_overrides={"UDP_SECURE_PROTOCOL": "tcp-basic", "UDP_SECURE_SCENARIO": "normal"},
        verify_output=True,
    ))
    tests.append(run_demo_pair(
        "tcp_fragmentation",
        "TCP Basic 半包 / 粘包",
        "./bin/tcp_server",
        "./bin/tcp_client",
        small,
        "tcp-fragment.out",
        "tcp",
        env_overrides={
            "UDP_SECURE_PROTOCOL": "tcp-basic",
            "UDP_SECURE_SCENARIO": "stream-fragmentation",
            "UDP_SECURE_STREAM_FRAGMENTATION": "1",
        },
        verify_output=True,
    ))
    tests.append(run_demo_pair(
        "tcp_mid_close",
        "TCP Basic 中途断连",
        "./bin/tcp_server",
        "./bin/tcp_client",
        small,
        "tcp-mid-close.out",
        "tcp",
        env_overrides={"UDP_SECURE_PROTOCOL": "tcp-basic", "UDP_SECURE_SCENARIO": "connection-close-mid-transfer"},
        expect_ok=False,
    ))
    tests.append(run_demo_pair(
        "tls_like_normal",
        "TLS-like 正常握手与传输",
        "./bin/tls_server",
        "./bin/tls_client",
        small,
        "tls-like.out",
        "tcp",
        env_overrides={"UDP_SECURE_PROTOCOL": "tls-like", "UDP_SECURE_SCENARIO": "normal"},
        verify_output=True,
    ))
    tests.append(run_demo_pair(
        "tls_like_bad_finished",
        "TLS-like 篡改 Finished",
        "./bin/tls_server",
        "./bin/tls_client",
        small,
        "tls-like-finished.out",
        "tcp",
        env_overrides={
            "UDP_SECURE_PROTOCOL": "tls-like",
            "UDP_SECURE_SCENARIO": "tampered-finished",
            "UDP_SECURE_TAMPER_FINISHED": "1",
        },
        expect_ok=False,
    ))
    tests.append(run_demo_pair(
        "tls_like_bad_app_data",
        "TLS-like 篡改 APP_DATA",
        "./bin/tls_server",
        "./bin/tls_client",
        small,
        "tls-like-appdata.out",
        "tcp",
        env_overrides={
            "UDP_SECURE_PROTOCOL": "tls-like",
            "UDP_SECURE_SCENARIO": "tampered-app-data",
            "UDP_SECURE_TAMPER_APP_DATA": "1",
        },
        expect_ok=False,
    ))
    tests.append(run_demo_pair(
        "tls_like_replay",
        "TLS-like Replay 检测",
        "./bin/tls_server",
        "./bin/tls_client",
        small,
        "tls-like-replay.out",
        "tcp",
        env_overrides={"UDP_SECURE_PROTOCOL": "tls-like", "UDP_SECURE_SCENARIO": "replay"},
        expect_ok=False,
    ))
    tests.append(run_demo_pair(
        "http_basic_normal",
        "HTTP Basic 正常请求链路",
        "./bin/http_demo_server",
        "./bin/http_demo_client",
        small,
        "http-basic.out",
        "tcp",
        env_overrides={"UDP_SECURE_PROTOCOL": "http-basic", "UDP_SECURE_SCENARIO": "normal"},
    ))
    tests.append(run_demo_pair(
        "http_basic_bad_auth",
        "HTTP Basic 错误密码",
        "./bin/http_demo_server",
        "./bin/http_demo_client",
        small,
        "http-bad-auth.out",
        "tcp",
        env_overrides={"UDP_SECURE_PROTOCOL": "http-basic", "UDP_SECURE_SCENARIO": "bad-auth"},
        expect_ok=False,
    ))
    tests.append(run_demo_pair(
        "http_basic_payload_large",
        "HTTP Basic 过大请求体",
        "./bin/http_demo_server",
        "./bin/http_demo_client",
        small,
        "http-payload-large.out",
        "tcp",
        env_overrides={"UDP_SECURE_PROTOCOL": "http-basic", "UDP_SECURE_SCENARIO": "payload-too-large"},
        expect_ok=False,
    ))
    tests.append(run_demo_pair(
        "http_basic_bad_method",
        "HTTP Basic 错误方法",
        "./bin/http_demo_server",
        "./bin/http_demo_client",
        small,
        "http-bad-method.out",
        "tcp",
        env_overrides={"UDP_SECURE_PROTOCOL": "http-basic", "UDP_SECURE_SCENARIO": "bad-method"},
        expect_ok=False,
    ))
    tests.append(run_demo_pair(
        "websocket_basic_normal",
        "WebSocket Basic 正常升级与消息",
        "./bin/websocket_demo_server",
        "./bin/websocket_demo_client",
        small,
        "websocket-basic.out",
        "tcp",
        env_overrides={"UDP_SECURE_PROTOCOL": "websocket-basic", "UDP_SECURE_SCENARIO": "normal"},
    ))
    tests.append(run_demo_pair(
        "websocket_bad_upgrade",
        "WebSocket Basic 错误 Upgrade",
        "./bin/websocket_demo_server",
        "./bin/websocket_demo_client",
        small,
        "websocket-bad-upgrade.out",
        "tcp",
        env_overrides={"UDP_SECURE_PROTOCOL": "websocket-basic", "UDP_SECURE_SCENARIO": "bad-upgrade"},
        expect_ok=False,
    ))
    tests.append(run_demo_pair(
        "websocket_ping_timeout",
        "WebSocket Basic Ping Timeout",
        "./bin/websocket_demo_server",
        "./bin/websocket_demo_client",
        small,
        "websocket-ping-timeout.out",
        "tcp",
        env_overrides={"UDP_SECURE_PROTOCOL": "websocket-basic", "UDP_SECURE_SCENARIO": "ping-timeout"},
        expect_ok=False,
    ))
    tests.append(run_demo_pair(
        "websocket_unexpected_close",
        "WebSocket Basic Unexpected Close",
        "./bin/websocket_demo_server",
        "./bin/websocket_demo_client",
        small,
        "websocket-unexpected-close.out",
        "tcp",
        env_overrides={"UDP_SECURE_PROTOCOL": "websocket-basic", "UDP_SECURE_SCENARIO": "unexpected-close"},
        expect_ok=False,
    ))
    tests.append(run_demo_pair(
        "quic_like_normal",
        "QUIC-like 正常单流",
        "./bin/quic_demo_server",
        "./bin/quic_demo_client",
        small,
        "quic-like.out",
        "udp",
        env_overrides={"UDP_SECURE_PROTOCOL": "quic-like", "UDP_SECURE_SCENARIO": "normal"},
        verify_output=True,
    ))
    tests.append(run_demo_pair(
        "quic_like_stream_reorder",
        "QUIC-like 多流乱序",
        "./bin/quic_demo_server",
        "./bin/quic_demo_client",
        small,
        "quic-like-reorder.out",
        "udp",
        env_overrides={"UDP_SECURE_PROTOCOL": "quic-like", "UDP_SECURE_SCENARIO": "stream-reorder"},
        verify_output=True,
    ))
    tests.append(run_demo_pair(
        "quic_like_loss_recovery",
        "QUIC-like 丢包恢复",
        "./bin/quic_demo_server",
        "./bin/quic_demo_client",
        small,
        "quic-like-loss.out",
        "udp",
        env_overrides={"UDP_SECURE_PROTOCOL": "quic-like", "UDP_SECURE_SCENARIO": "loss-recovery"},
        verify_output=True,
    ))
    tests.append(run_demo_pair(
        "quic_like_zero_rtt",
        "QUIC-like 0-RTT 风险日志",
        "./bin/quic_demo_server",
        "./bin/quic_demo_client",
        small,
        "quic-like-zero-rtt.out",
        "udp",
        env_overrides={"UDP_SECURE_PROTOCOL": "quic-like", "UDP_SECURE_SCENARIO": "zero-rtt-replay-risk"},
        verify_output=True,
        require_log_text="ZERO_RTT_REPLAY_RISK",
    ))
    # ===== Phase 2 protocols (DNS, OAuth2, MQTT, HTTP/2, SIP, RADIUS) =====
    # DNS
    tests.append(run_demo_pair(
        "dns_normal",
        "DNS 正常 A 查询",
        "./bin/dns_demo_server",
        "./bin/dns_demo_client",
        small,
        "dns.out",
        "udp",
        env_overrides={"UDP_SECURE_PROTOCOL": "dns", "UDP_SECURE_SCENARIO": "normal"},
    ))
    tests.append(run_demo_pair(
        "dns_spoofed_response",
        "DNS 应答伪造告警",
        "./bin/dns_demo_server",
        "./bin/dns_demo_client",
        small,
        "dns-spoof.out",
        "udp",
        env_overrides={"UDP_SECURE_PROTOCOL": "dns", "UDP_SECURE_SCENARIO": "spoofed-response"},
        require_log_text="SPOOFED_RESPONSE_SENT",
    ))
    tests.append(run_demo_pair(
        "dns_nxdomain",
        "DNS NXDOMAIN 重定向",
        "./bin/dns_demo_server",
        "./bin/dns_demo_client",
        small,
        "dns-nx.out",
        "udp",
        env_overrides={"UDP_SECURE_PROTOCOL": "dns", "UDP_SECURE_SCENARIO": "nxdomain-redir"},
    ))
    # OAuth 2.0
    tests.append(run_demo_pair(
        "oauth2_auth_code",
        "OAuth 2.0 授权码流",
        "./bin/oauth2_demo_server",
        "./bin/oauth2_demo_client",
        small,
        "oauth2.out",
        "tcp",
        env_overrides={"UDP_SECURE_PROTOCOL": "oauth2", "UDP_SECURE_SCENARIO": "auth-code"},
    ))
    tests.append(run_demo_pair(
        "oauth2_pkce",
        "OAuth 2.0 PKCE 强制",
        "./bin/oauth2_demo_server",
        "./bin/oauth2_demo_client",
        small,
        "oauth2-pkce.out",
        "tcp",
        env_overrides={"UDP_SECURE_PROTOCOL": "oauth2", "UDP_SECURE_SCENARIO": "pkce"},
    ))
    tests.append(run_demo_pair(
        "oauth2_token_replay",
        "OAuth 2.0 Token 重放",
        "./bin/oauth2_demo_server",
        "./bin/oauth2_demo_client",
        small,
        "oauth2-replay.out",
        "tcp",
        env_overrides={"UDP_SECURE_PROTOCOL": "oauth2", "UDP_SECURE_SCENARIO": "token-replay"},
        expect_ok=False,
        require_log_text="REPLAY_DETECTED",
    ))
    # MQTT
    tests.append(run_demo_pair(
        "mqtt_normal",
        "MQTT 正常 pub/sub",
        "./bin/mqtt_demo_server",
        "./bin/mqtt_demo_client",
        small,
        "mqtt.out",
        "tcp",
        env_overrides={"UDP_SECURE_PROTOCOL": "mqtt", "UDP_SECURE_SCENARIO": "normal"},
    ))
    tests.append(run_demo_pair(
        "mqtt_qos2_replay",
        "MQTT QoS 2 防重放",
        "./bin/mqtt_demo_server",
        "./bin/mqtt_demo_client",
        small,
        "mqtt-qos2.out",
        "tcp",
        env_overrides={"UDP_SECURE_PROTOCOL": "mqtt", "UDP_SECURE_SCENARIO": "qos2-replay"},
        expect_ok=False,
        require_log_text="QOS2_DUP_DETECTED",
    ))
    tests.append(run_demo_pair(
        "mqtt_unauth_subscribe",
        "MQTT 受限主题订阅",
        "./bin/mqtt_demo_server",
        "./bin/mqtt_demo_client",
        small,
        "mqtt-unauth.out",
        "tcp",
        env_overrides={"UDP_SECURE_PROTOCOL": "mqtt", "UDP_SECURE_SCENARIO": "unauth-subscribe"},
        expect_ok=False,
        require_log_text="SUBSCRIBE_DENIED",
    ))
    # HTTP/2
    tests.append(run_demo_pair(
        "http2_normal",
        "HTTP/2 单连接多 stream",
        "./bin/http2_demo_server",
        "./bin/http2_demo_client",
        small,
        "http2.out",
        "tcp",
        env_overrides={"UDP_SECURE_PROTOCOL": "http2", "UDP_SECURE_SCENARIO": "normal"},
    ))
    tests.append(run_demo_pair(
        "http2_multiplex",
        "HTTP/2 6 路并发 stream",
        "./bin/http2_demo_server",
        "./bin/http2_demo_client",
        small,
        "http2-mux.out",
        "tcp",
        env_overrides={"UDP_SECURE_PROTOCOL": "http2", "UDP_SECURE_SCENARIO": "multiplex"},
    ))
    tests.append(run_demo_pair(
        "http2_hpack_overflow",
        "HTTP/2 HPACK 错误",
        "./bin/http2_demo_server",
        "./bin/http2_demo_client",
        small,
        "http2-hpack.out",
        "tcp",
        env_overrides={"UDP_SECURE_PROTOCOL": "http2", "UDP_SECURE_SCENARIO": "hpack-overflow"},
        expect_ok=False,
        require_log_text="HPACK_DECODE_ERROR",
    ))
    # SIP
    tests.append(run_demo_pair(
        "sip_register",
        "SIP 注册",
        "./bin/sip_demo_server",
        "./bin/sip_demo_client",
        small,
        "sip-reg.out",
        "udp",
        env_overrides={"UDP_SECURE_PROTOCOL": "sip", "UDP_SECURE_SCENARIO": "register"},
    ))
    tests.append(run_demo_pair(
        "sip_invite_bye",
        "SIP INVITE 完整流程",
        "./bin/sip_demo_server",
        "./bin/sip_demo_client",
        small,
        "sip-invite.out",
        "udp",
        env_overrides={"UDP_SECURE_PROTOCOL": "sip", "UDP_SECURE_SCENARIO": "invite-bye"},
    ))
    tests.append(run_demo_pair(
        "sip_no_sips_downgrade",
        "SIP SIPS 降级告警",
        "./bin/sip_demo_server",
        "./bin/sip_demo_client",
        small,
        "sip-sips.out",
        "udp",
        env_overrides={"UDP_SECURE_PROTOCOL": "sip", "UDP_SECURE_SCENARIO": "no-sips-downgrade"},
        require_log_text="SIPS_DOWNGRADE_DETECTED",
    ))
    # RADIUS
    tests.append(run_demo_pair(
        "radius_normal",
        "RADIUS PAP 认证通过",
        "./bin/radius_demo_server",
        "./bin/radius_demo_client",
        small,
        "radius.out",
        "udp",
        env_overrides={"UDP_SECURE_PROTOCOL": "radius", "UDP_SECURE_SCENARIO": "normal"},
    ))
    tests.append(run_demo_pair(
        "radius_shared_secret_leak",
        "RADIUS 共享密钥错误",
        "./bin/radius_demo_server",
        "./bin/radius_demo_client",
        small,
        "radius-secret.out",
        "udp",
        env_overrides={"UDP_SECURE_PROTOCOL": "radius", "UDP_SECURE_SCENARIO": "shared-secret-leak"},
        expect_ok=False,
        require_log_text="AUTHENTICATOR_INVALID",
    ))
    tests.append(run_demo_pair(
        "radius_chap_vs_pap",
        "RADIUS CHAP 替代 PAP",
        "./bin/radius_demo_server",
        "./bin/radius_demo_client",
        small,
        "radius-chap.out",
        "udp",
        env_overrides={"UDP_SECURE_PROTOCOL": "radius", "UDP_SECURE_SCENARIO": "chap-vs-pap"},
    ))
    tests.append(run_demo_pair(
        "radius_replay_attack",
        "RADIUS 重放检测",
        "./bin/radius_demo_server",
        "./bin/radius_demo_client",
        small,
        "radius-replay.out",
        "udp",
        env_overrides={"UDP_SECURE_PROTOCOL": "radius", "UDP_SECURE_SCENARIO": "replay-attack"},
        expect_ok=False,
        require_log_text="REPLAY_DETECTED",
    ))
    tests.append(test_missing_input())
    tests.append(test_timeout())
    tests.append(test_malformed_packet(small))
    tests.append(test_sequence_error())
    return {"ok": all(item["pass"] for item in tests), "tests": tests}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="print JSON only")
    args = parser.parse_args()
    report = run_all()
    if args.json:
        print(json.dumps(report, ensure_ascii=False))
        return 0 if report["ok"] else 1
    for item in report["tests"]:
        status = "PASS" if item["pass"] else "FAIL"
        print(f"[{status}] {item['id']}: {item['name']} - {item['message']}")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
