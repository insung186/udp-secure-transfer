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


def run_cmd(args, timeout=8):
    return subprocess.run(
        args,
        cwd=ROOT,
        env=ENV,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def start_server(port, password, input_file):
    return subprocess.Popen(
        ["./server", str(port), password, str(input_file)],
        cwd=ROOT,
        env=ENV,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def wait_for_server_start(port, timeout=2.5):
    deadline = time.time() + timeout
    marker = f'"port":{port}'
    log_path = ROOT / "logs" / "server.jsonl"
    while time.time() < deadline:
        if log_path.exists() and marker in log_path.read_text(encoding="utf-8", errors="ignore"):
            return True
        time.sleep(0.03)
    return False


def collect_process(proc, timeout=6):
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


def run_pair(case_id, name, input_file, password, attempts, expect_ok=True):
    port = free_udp_port()
    output = ROOT / "output" / f"{case_id}.out"
    output.unlink(missing_ok=True)
    server = start_server(port, password, input_file)
    wait_for_server_start(port)
    client = run_cmd(["./client", "127.0.0.1", str(port), *attempts, str(output)], timeout=8)
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


def test_missing_input():
    port = free_udp_port()
    proc = run_cmd(["./server", str(port), "secret", "test/cases/missing-file.bin"], timeout=3)
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
        ["./client", "127.0.0.1", str(port), "secret", "secret", "secret", str(output)],
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
        ["./client", "127.0.0.1", str(port), "secret", "secret", "secret", str(output)],
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
