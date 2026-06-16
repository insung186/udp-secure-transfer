# Multi-Protocol Teaching Lab

本目录现在是一个“统一实验台里的多协议教学演示平台”。它在原有 `udp-basic` 和 `udp-reliable` 之上，继续接入：

- `tcp-basic`
- `tls-like`
- `http-basic`
- `websocket-basic`
- `quic-like`

整个平台复用同一套协议目录、控制后端、日志 schema、前端面板与测试脚本：

- `protocols/<id>/schema.json + scenarios.json`
- `control_server` 统一拉起对应 demo 二进制
- Web 控制台统一展示时序、Inspector、传输视图、日志与测试
- schema v2 统一输出 `protocol / transport / flow_id / session_id / scenario`

## 实验环境

- OS: WSL2 Ubuntu 24.04 LTS
- 编译器: `gcc`
- 构建工具: `make`
- 语言: C11, HTML, CSS, JavaScript, Python 3 测试脚本
- 通信: UDP, TCP, 本地 HTTP/WebSocket
- 日志: JSON Lines
- 依赖: 不依赖 OpenSSL，SHA1 使用项目内 C 实现

## 编译方式

```bash
cd udp-secure-transfer
make
make clean
```

`make` 会生成在 `bin/` 子目录：

- `bin/server` / `bin/client`
- `bin/tcp_server` / `bin/tcp_client`
- `bin/tls_server` / `bin/tls_client`
- `bin/http_demo_server` / `bin/http_demo_client`
- `bin/websocket_demo_server` / `bin/websocket_demo_client`
- `bin/quic_demo_server` / `bin/quic_demo_client`
- `bin/control_server`

## 命令行运行方式

服务器保持实验要求格式：

```bash
./bin/server <serverport> <password> <inputfile>
```

示例：

```bash
./bin/server 9000 secret test/input.txt
```

客户端保持实验要求格式：

```bash
./bin/client <servername> <serverport> <clientpwd1> <clientpwd2> <clientpwd3> <outputfile>
```

示例：

```bash
./bin/client 127.0.0.1 9000 wrong secret ignored output/result.txt
```

兼容拓展：Web 前端可使用交互式密码输入，命令行也可直接运行：

```bash
./bin/client <servername> <serverport> <outputfile>
```

交互模式不会破坏基础验收格式。

## 协议范围

真实传输演示：

- `udp-basic`
- `udp-reliable`
- `tcp-basic`
- `http-basic`
- `websocket-basic`

教学版协议：

- `tls-like`
- `quic-like`

说明：

- `tls-like` 不是 TLS，只演示握手、HMAC 完整性与“有加密 / 无加密”的教学概念
- `quic-like` 不是完整 QUIC，只演示连接 ID、多 stream、ACK / 重传、0-RTT 风险
- 这些安全性质仅用于课堂演示，不代表生产级安全

## UDP / TCP 基础消息格式

严格实现流程：

```text
JOIN_REQ -> PASS_REQ -> PASS_RESP -> PASS_ACCEPT -> DATA -> TERMINATE
```

三次密码错误后：

```text
JOIN_REQ -> PASS_REQ -> PASS_RESP -> PASS_REQ -> PASS_RESP -> PASS_REQ -> PASS_RESP -> REJECT
```

包类型：

| Type | Code |
| --- | ---: |
| `JOIN_REQ` | 1 |
| `PASS_REQ` | 2 |
| `PASS_RESP` | 3 |
| `PASS_ACCEPT` | 4 |
| `DATA` | 5 |
| `TERMINATE` | 6 |
| `REJECT` | 7 |

通用头部：

```text
2 bytes packet type + 4 bytes payload length
```

`DATA` 包：

```text
2 bytes type + 4 bytes payload length + 4 bytes packet_id + data
```

注意：`DATA.payload_length` 只表示 data 字节数，不包含 `packet_id`。所有多字节字段均使用网络字节序。

`TERMINATE` 携带 20 字节二进制 SHA1 摘要。客户端收到后计算输出文件 SHA1，匹配则打印 `OK`，不匹配则打印 `ABORT`。

## Web 前端启动方式

```bash
cd udp-secure-transfer
make
./bin/control_server
```

浏览器打开：

```text
http://127.0.0.1:8080/
```

也可以指定控制服务端口：

```bash
./bin/control_server 18080
```

控制台采用左侧可折叠控制边栏 + 右侧多 Tab 展示区：

- 左侧边栏: 协议/场景选择、server/client 配置、启动/停止、重置、兼容三密码、交互式密码输入
- Dashboard: 总览状态、协议阶段、传输摘要、SHA1 摘要、最近日志
- Protocol: 协议时序图、包列表、Packet Inspector
- Transfer: 文件型协议显示进度 / 分片矩阵；HTTP / WebSocket 显示事务 / 消息视图
- Logs & Test: 实时日志、过滤搜索、异常模拟、测试结果

## 协议配置目录

```text
protocols/
  catalog.json
  udp-basic/
    schema.json
    scenarios.json
  udp-reliable/
    schema.json
    scenarios.json
  tcp-basic/
    schema.json
    scenarios.json
  tls-like/
    schema.json
    scenarios.json
  http-basic/
    schema.json
    scenarios.json
  websocket-basic/
    schema.json
    scenarios.json
  quic-like/
    schema.json
    scenarios.json
```

- `catalog.json`: 当前可接入协议列表
- `schema.json`: 包类型、状态机、日志字段等协议 schema
- `scenarios.json`: 正常传输、认证失败、超时等场景配置

其中新增协议额外字段：

- `tcp-basic`: `stream_offset`
- `tls-like`: `security.encrypted / mac_valid / replay / handshake_phase`
- `http-basic`: `method / path / status_code / header_summary`
- `websocket-basic`: `frame_type`
- `quic-like`: `connection_id / stream_id / seq / ack / retransmit_count`

## HTTP/WebSocket 接口

默认监听 `127.0.0.1:8080`。

HTTP:

| Method | Path | 说明 |
| --- | --- | --- |
| `GET` | `/api/status` | 当前 server/client 进程状态 |
| `POST` | `/api/server/start` | 启动 server |
| `POST` | `/api/server/stop` | 停止 server |
| `POST` | `/api/client/start` | 启动 client |
| `POST` | `/api/client/stop` | 停止 client |
| `POST` | `/api/client/send-password` | 向交互式 client 写入密码 |
| `POST` | `/api/reset` | 停止进程并重置状态 |
| `GET` | `/api/logs` | 返回 server/client/control JSONL 日志 |
| `POST` | `/api/logs/clear` | 清空日志 |
| `GET` | `/api/test/list` | 测试用例名称 |
| `POST` | `/api/test/run` | 运行测试脚本 |
| `GET` | `/api/test/result` | 最近一次测试结果 |

WebSocket:

```text
ws://127.0.0.1:8080/ws
```

推送类型：

- `log`: 新增结构化日志
- `status`: server/client 运行状态
- `hello`: WebSocket 连接确认

## 测试方式

```bash
cd udp-secure-transfer
./test/run_tests.sh
./test/run_tests.sh --json
```

当前测试覆盖：

- 第一次密码正确
- 第二次密码正确
- 第三次密码正确
- 三次密码全部错误，server 发送 `REJECT`，双方 `ABORT`
- 大文件多 DATA 分片传输
- Reliable UDP 正常传输
- Reliable UDP 丢包后恢复
- Reliable UDP 乱序后恢复
- Reliable UDP 重复包后恢复
- TCP Basic 正常传输 / 半包粘包 / 中途断连
- TLS-like 正常握手 / 篡改 Finished / 篡改 APP_DATA / replay
- HTTP Basic 正常请求链路 / 错误密码 / 过大 body / 错误方法
- WebSocket Basic 正常升级 / 错误 Upgrade / Ping 超时 / 异常关闭
- QUIC-like 正常单流 / 多 stream 乱序 / 丢包恢复 / 0-RTT replay 风险日志
- 服务器输入文件不存在
- 客户端连接未启动服务器触发超时
- 未知包类型触发解析异常
- DATA `packet_id` 不连续触发客户端 `ABORT`

## 日志格式

日志路径：

```text
logs/server.jsonl
logs/client.jsonl
logs/control.jsonl
```

每行一个 JSON 对象，常见字段：

```json
{
  "time": "2026-06-06T00:00:00.000",
  "schema_version": "2",
  "protocol": "udp-basic",
  "transport": "udp",
  "role": "client",
  "flow_id": "udp-basic-001",
  "session_id": "session-001",
  "scenario": "normal",
  "level": "DATA",
  "event": "RECV_TRANSFER_PACKET",
  "peer": "127.0.0.1:9000",
  "state": "DATA_TRANSFER",
  "packet_type": "DATA",
  "packet_id": 3,
  "seq": 3,
  "ack": 4,
  "window_size": 4,
  "retransmit_count": 1,
  "payload_length": 1000,
  "bytes": 1000,
  "wire_hex": "0005000003e800000003...",
  "message": "packet event; wire_hex preview truncated"
}
```

说明：

- `flow_id` / `session_id` 由控制后端在一次实验 run 内统一分配，server/client 日志天然对齐。
- Reliable UDP 会额外记录 `ACK` / `NACK`，以及 `seq / ack / window_size / retransmit_count`。
- `PASS_RESP` 不记录密码明文，只记录类型和长度。
- `DATA.wire_hex` 对大载荷只保留预览，避免日志过大；字段解析仍保留 type、payload length、packet id 和字节数。
- 认证、异常、摘要、最终状态使用 `AUTH_*`、`TIMEOUT`、`SEQUENCE_ERROR`、`DIGEST_MATCH`、`FINAL_OK`、`FINAL_ABORT` 等事件。

## 已完成的基础要求

- UDP server/client 分文件实现。
- 保留规定命令行格式。
- 实现 `JOIN_REQ -> PASS_REQ -> PASS_RESP -> PASS_ACCEPT -> DATA -> TERMINATE`。
- 三次密码错误后 server 发送 `REJECT`，双方输出 `ABORT`。
- 严格按 2 字节 type、4 字节 payload length、DATA 额外 4 字节 packet id 的格式解析。
- 所有多字节字段使用 `htons`、`htonl`、`ntohs`、`ntohl`。
- `DATA.payload_length` 不包含 packet id。
- 正常完成输出 `OK`，异常输出 `ABORT`。
- 实现 SHA1 文件摘要校验。
- 实现超时、未知包、长度异常、意外包、序号不连续、认证失败、文件错误等异常处理。

## 已完成的拓展要求

- 本地 C 控制后端 `control_server`。
- HTTP 接口启动/停止 server/client、发送交互式密码、读取日志、运行测试。
- WebSocket 推送日志和状态。
- Web 控制台左侧可折叠控制边栏 + 多 Tab 展示区。
- Dashboard、Protocol、Transfer、Logs & Test 四个展示页面，配置与控制集中在左侧边栏。
- Packet Inspector 显示包字段和十六进制预览。
- 分片矩阵、传输进度、吞吐率和 SHA1 校验展示。
- JSON Lines 结构化日志。
- 自动测试脚本和异常模拟入口。

## 已知限制和可改进方向

- UDP 本身不可靠，本实验按要求不实现 ACK/重传；丢包、乱序或重复会导致 `ABORT`。
- server 一次只处理一个 client，符合实验假设。
- Web 控制服务是本地实验工具，只绑定 `127.0.0.1`，未设计为公网服务。
- Packet Inspector 展示日志中的十六进制预览，不替代 Wireshark 抓包。
- Web 前端使用原生 HTML/CSS/JS，没有引入大型框架，适合实验展示但不是生产后台系统。

需要用户手动检查：

- 使用 Wireshark/tcpdump 抓包确认网络上的 UDP 字段与文档一致。
- 在两台不同字节序机器之间运行，验证跨架构解析。
- 人工浏览 Web 前端，确认实际展示效果和演示节奏。
- 如需课程报告截图，需要自行截取运行界面和抓包界面。
