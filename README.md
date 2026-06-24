# UDP Secure Transfer 多协议安全通信教学平台

仓库地址：<https://github.com/insung186/udp-secure-transfer>

本项目是信息安全综合实验“Client-Server 的简单安全通信协议”的实现与扩展。基础部分严格按照实验要求完成：客户端通过 UDP 向服务器发起连接，最多进行三次口令认证；认证成功后，服务器将文件分片发送给客户端；传输结束时服务器发送 SHA1 摘要，客户端据此校验文件完整性。

在基础 UDP 文件传输之外，项目还提供了一个本地 Web 控制台和多协议教学演示环境。用户可以在浏览器中启动 server/client、选择协议场景、查看结构化日志、观察协议时序和包字段，并运行自动化测试。

> 说明：本项目用于课程实验和协议教学。部分协议如 `tls-like`、`quic-like` 是教学版模拟实现，不代表生产级安全协议。

## 功能概览

- 基础 UDP Client-Server 文件传输
  - `JOIN_REQ -> PASS_REQ -> PASS_RESP -> PASS_ACCEPT -> DATA -> TERMINATE`
  - 三次密码错误后发送 `REJECT`
  - `DATA` 分片携带连续 `packet_id`
  - `TERMINATE` 携带 20 字节 SHA1 摘要
  - 双方按要求输出 `OK` 或 `ABORT`
- 跨字节序处理
  - 所有多字节字段均使用网络字节序
  - 避免直接发送 C 结构体造成 endian 问题
- 异常处理
  - 网络超时
  - 未知包类型
  - 包长度不匹配
  - 认证失败
  - DATA 序号不连续
  - 文件无法读取或写入
  - 摘要校验失败
- Reliable UDP 扩展
  - ACK/NACK
  - 滑动窗口
  - 超时重传
  - 乱序缓存
  - 重复包去重
  - 丢包、乱序、重复包模拟
- 多协议教学演示
  - TCP Basic
  - TLS-like
  - HTTP Basic
  - WebSocket Basic
  - QUIC-like
  - DNS
  - OAuth 2.0
  - MQTT
  - HTTP/2
  - SIP
  - RADIUS
- Web 控制台
  - 协议和场景选择
  - server/client 启动与停止
  - 兼容三密码模式和交互式密码输入
  - Dashboard、Protocol、Transfer、Logs & Test 多视图
  - 协议时序图、Packet Inspector、分片矩阵、日志过滤、测试结果展示
- 结构化日志
  - JSON Lines 格式
  - 统一记录时间、角色、协议、场景、包类型、方向、序号、ACK、重传、安全字段等
  - `PASS_RESP` 不输出密码明文
- 自动化测试
  - 端到端启动真实 server/client 进程
  - 覆盖正常流程、错误流程、可靠传输和多协议安全场景

## 项目结构

```text
udp-secure-transfer/
  include/                 公共头文件
  src/                     C 源码
    server.c               基础 UDP 服务端
    client.c               基础 UDP 客户端
    protocol.c             UDP 包编码、解析、收发工具
    logger.c               JSONL 结构化日志
    sha1_util.c            项目内 SHA1 实现
    demo_util.c            多协议 demo 公共工具
    control_server.c       本地 HTTP/WebSocket 控制后端
    *_demo_server.c        协议演示服务端
    *_demo_client.c        协议演示客户端
  protocols/               协议 catalog、schema 和场景配置
  web/                     Web 控制台
    index.html
    css/
    js/
  test/                    自动化测试脚本和测试输入
  logs/                    运行时日志目录
  output/                  客户端输出目录
  Makefile                 构建脚本
```

## 环境要求

推荐环境：

- OS：Linux 或 WSL2 Ubuntu
- 编译器：`gcc`
- 构建工具：`make`
- Python：Python 3，用于自动化测试
- 浏览器：用于访问本地 Web 控制台

项目不依赖 OpenSSL。SHA1、HMAC-SHA1 等教学所需函数由项目内代码实现。

## 构建

```bash
cd udp-secure-transfer
make
```

清理构建产物：

```bash
make clean
```

构建成功后，`bin/` 目录会生成以下程序：

```text
server / client
tcp_server / tcp_client
tls_server / tls_client
http_demo_server / http_demo_client
websocket_demo_server / websocket_demo_client
quic_demo_server / quic_demo_client
dns_demo_server / dns_demo_client
oauth2_demo_server / oauth2_demo_client
mqtt_demo_server / mqtt_demo_client
http2_demo_server / http2_demo_client
sip_demo_server / sip_demo_client
radius_demo_server / radius_demo_client
control_server
```

## 基础 UDP 命令行运行

服务端命令格式与实验要求保持一致：

```bash
./bin/server <serverport> <password> <inputfile>
```

示例：

```bash
./bin/server 9000 secret test/input.txt
```

客户端命令格式与实验要求保持一致：

```bash
./bin/client <servername> <serverport> <clientpwd1> <clientpwd2> <clientpwd3> <outputfile>
```

示例：

```bash
./bin/client 127.0.0.1 9000 wrong secret ignored output/result.txt
```

如果第二次密码正确，剩余密码会被忽略。正常传输完成时，server 和 client 都会输出：

```text
OK
```

三次密码均错误、摘要不匹配、收到意外包或超时时，程序输出：

```text
ABORT
```

项目也支持交互式密码输入，主要供 Web 控制台使用：

```bash
./bin/client <servername> <serverport> <outputfile>
```

## 基础 UDP 协议格式

成功认证和传输流程：

```text
JOIN_REQ -> PASS_REQ -> PASS_RESP -> PASS_ACCEPT -> DATA -> TERMINATE
```

三次认证失败流程：

```text
JOIN_REQ -> PASS_REQ -> PASS_RESP -> PASS_REQ -> PASS_RESP -> PASS_REQ -> PASS_RESP -> REJECT
```

包类型：

| Type | Code | Payload |
| --- | ---: | --- |
| `JOIN_REQ` | 1 | 空 |
| `PASS_REQ` | 2 | 空 |
| `PASS_RESP` | 3 | 密码字符串 |
| `PASS_ACCEPT` | 4 | 空 |
| `DATA` | 5 | 文件分片数据 |
| `TERMINATE` | 6 | 20 字节 SHA1 摘要 |
| `REJECT` | 7 | 空 |
| `ACK` | 8 | Reliable UDP 使用 |
| `NACK` | 9 | Reliable UDP 使用 |

通用头部：

```text
2 bytes packet type
4 bytes payload length
```

`DATA` 包：

```text
2 bytes packet type
4 bytes payload length
4 bytes packet_id
N bytes data
```

注意：`DATA.payload_length` 只表示 data 字节数，不包含 `packet_id`。所有多字节字段均使用网络字节序。

## Web 控制台

启动控制后端：

```bash
cd udp-secure-transfer
make
./bin/control_server
```

浏览器访问：

```text
http://127.0.0.1:8080/
```

也可以指定端口：

```bash
./bin/control_server 18080
```

控制台主要区域：

- 左侧控制栏
  - 协议选择
  - 场景选择
  - server/client 参数
  - 启动、停止、重置
  - 兼容三密码和交互式密码输入
- Dashboard
  - 当前运行状态
  - 协议阶段
  - 传输摘要
  - 最近日志
- Protocol
  - 协议时序图
  - 包列表
  - Packet Inspector
- Transfer
  - 文件传输进度
  - 分片矩阵
  - SHA1 校验结果
- Logs & Test
  - 实时日志
  - 日志过滤和搜索
  - 自动化测试结果

## HTTP 与 WebSocket 接口

`control_server` 默认监听 `127.0.0.1:8080`。

常用 HTTP API：

| Method | Path | 说明 |
| --- | --- | --- |
| `GET` | `/api/status` | 查询当前 server/client 状态 |
| `POST` | `/api/server/start` | 启动服务端 |
| `POST` | `/api/server/stop` | 停止服务端 |
| `POST` | `/api/client/start` | 启动客户端 |
| `POST` | `/api/client/stop` | 停止客户端 |
| `POST` | `/api/client/send-password` | 向交互式客户端写入密码 |
| `POST` | `/api/reset` | 停止进程并重置状态 |
| `GET` | `/api/logs` | 读取 server/client/control 日志 |
| `GET` | `/api/packets` | 读取去重后的网络包记录 |
| `POST` | `/api/packets/clear` | 清空包记录 |
| `GET` | `/api/test/list` | 查看测试列表 |
| `POST` | `/api/test/run` | 后台运行测试脚本 |
| `GET` | `/api/test/result` | 获取测试结果 |

WebSocket 地址：

```text
ws://127.0.0.1:8080/ws
```

推送消息包括：

- `hello`：连接确认
- `status`：server/client 运行状态
- `log`：新增结构化日志

## 协议与场景配置

协议入口由 `protocols/catalog.json` 管理。每个协议目录包含：

```text
schema.json      包类型、展示字段、协议说明
scenarios.json   可运行场景和说明
```

已接入协议：

| 协议 | 传输层 | 主要教学点 |
| --- | --- | --- |
| `udp-basic` | UDP | 口令认证、文件分片、SHA1 校验 |
| `udp-reliable` | UDP | ACK/NACK、窗口、重传、乱序恢复 |
| `tcp-basic` | TCP | 流式传输、半包/粘包、中途断连 |
| `tls-like` | TCP | 握手、HMAC、简单加密、篡改和重放检测 |
| `http-basic` | TCP | HTTP 请求认证、错误方法、过大请求体 |
| `websocket-basic` | TCP | Upgrade、帧、Ping/Pong、异常关闭 |
| `quic-like` | UDP | connection id、多 stream、ACK、0-RTT 风险 |
| `dns` | UDP | DNS 查询、应答伪造、NXDOMAIN、DoH 降级提示 |
| `oauth2` | TCP | 授权码流、PKCE、token 重放 |
| `mqtt` | TCP | pub/sub、QoS、ACL、明文风险 |
| `http2` | TCP | 二进制分帧、多路复用、HPACK 错误 |
| `sip` | UDP | REGISTER、INVITE/BYE、SIPS 降级、重放检测 |
| `radius` | UDP | AAA、共享密钥、PAP/CHAP、重放检测 |

## 日志

运行日志写入：

```text
logs/server.jsonl
logs/client.jsonl
logs/control.jsonl
logs/packets.jsonl
```

每行是一个 JSON 对象。常见字段：

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
  "packet_uid": "e0a1f8c3c2d45119",
  "direction": "Server -> Client",
  "packet_id": 3,
  "seq": 3,
  "ack": 4,
  "window_size": 4,
  "retransmit_count": 1,
  "payload_length": 1000,
  "bytes": 1000,
  "wire_hex": "0005000003e800000003..."
}
```

说明：

- `flow_id` 和 `session_id` 用于把同一次实验中的 server/client 日志对齐。
- `packet_uid` 用于合并双端日志，避免前端把同一个网络包画两次。
- `PASS_RESP` 不记录密码明文。
- 大 payload 的 `wire_hex` 只保留预览，避免日志过大。
- Reliable UDP 会额外记录 ACK、NACK、窗口和重传次数。
- 安全相关 demo 会记录 `security.encrypted`、`security.mac_valid`、`security.replay` 等字段。

## 自动化测试

运行测试：

```bash
cd udp-secure-transfer
./test/run_tests.sh
```

输出 JSON：

```bash
./test/run_tests.sh --json
```

测试内容包括：

- 第一次、第二次、第三次密码正确
- 三次密码全部错误
- 大文件多分片传输
- Reliable UDP 正常、丢包恢复、乱序恢复、重复包恢复
- TCP Basic 正常传输、半包/粘包、中途断连
- TLS-like 正常握手、Finished 篡改、APP_DATA 篡改、重放检测
- HTTP Basic 正常请求、错误密码、过大请求体、错误方法
- WebSocket Basic 正常升级、错误 Upgrade、Ping 超时、异常关闭
- QUIC-like 正常单流、多 stream 乱序、丢包恢复、0-RTT 风险日志
- DNS 正常查询、应答伪造、NXDOMAIN
- OAuth2 授权码流、PKCE、token 重放
- MQTT 正常 pub/sub、QoS 2 防重放、受限主题订阅
- HTTP/2 单连接多 stream、并发 stream、HPACK 错误
- SIP 注册、INVITE/BYE、SIPS 降级告警
- RADIUS PAP 认证、共享密钥错误、CHAP 对比、重放检测
- 缺失输入文件
- 客户端超时
- 未知包类型
- DATA 序号不连续

## 常用环境变量

基础超时：

```bash
UDP_SECURE_TIMEOUT_MS=1500
```

选择协议：

```bash
UDP_SECURE_PROTOCOL=udp-reliable
```

Reliable UDP 参数：

```bash
UDP_SECURE_WINDOW_SIZE=4
UDP_SECURE_RELIABLE_TIMEOUT_MS=250
UDP_SECURE_RELIABLE_LOSS_IDS=1,3
UDP_SECURE_RELIABLE_DUP_IDS=2
UDP_SECURE_RELIABLE_REORDER_IDS=1,3
```

部分协议场景会读取：

```bash
UDP_SECURE_SCENARIO=<scenario-id>
```

通常不需要手动设置这些变量；Web 控制台会根据协议和场景自动注入。

## 安全说明与限制

- 基础 UDP 协议实现了口令认证和 SHA1 完整性校验，但没有加密传输，无法防止窃听。
- SHA1 按实验要求用于文件摘要校验，不建议用于现代生产系统中的抗碰撞安全需求。
- server 一次只处理一个 client，符合实验假设。
- Reliable UDP 是教学实现，不包含完整拥塞控制。
- `tls-like` 不是 TLS，没有证书、PKI 和真正的服务端身份认证。
- `quic-like` 不是完整 QUIC，只演示 connection id、多 stream、ACK、重传和 0-RTT 风险。
- Web 控制服务只绑定本地回环地址，面向本地实验，不建议作为公网服务部署。
- Packet Inspector 展示的是程序日志中的 wire 预览，不替代 Wireshark/tcpdump 抓包。
