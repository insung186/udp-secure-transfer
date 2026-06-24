# Multi-Protocol Teaching Lab · 系统设计与说明报告

> 仓库根目录：`udp-secure-transfer/`
> 文档目的：在完整阅读源码、协议目录、Web 前端、测试脚本与运维脚本的基础上，对该系统做一份"代码 → 设计 → 教学意义 → 局限与改进"的全景式说明，方便课程讲解、答辩展示、二次开发和成果归档。

---

## 0. 一句话总结

`udp-secure-transfer` 是一个"以 UDP 文件传输为根、共接入 13 套网络协议、统一日志/控制/前端/测试栈"的 **多协议教学演示平台**。它将原本单一实验扩展为一个"协议博物馆"：

- **3 类性质**：真实传输（udp-basic / udp-reliable / tcp-basic / http-basic / websocket-basic / dns / oauth2 / mqtt / http2 / sip / radius） + 教学版（tls-like / quic-like）。
- **3 层架构**：协议二进制层（每个协议一对 server / client C 程序）→ 协议目录层（`protocols/<id>/{schema,scenarios}.json` + `catalog.json`）→ 控制与可视化层（`control_server` C 后端 + 浏览器前端）。
- **1 套统一机制**：JSON Lines 结构化日志 + `packet_uid` 双端对齐 + WebSocket 实时推送 + Python 端到端回归测试。

---

## 1. 系统功能

### 1.1 对外功能（按用户视角）

| 功能编号 | 名称 | 入口 | 描述 |
| --- | --- | --- | --- |
| F1 | 多协议实验运行 | `bin/<protocol>_demo_{server,client}` | 用户通过命令行或 Web 选择协议与场景，启动一对 server/client 演示文件传输、消息交互、AAA 流程。 |
| F2 | Web 控制台 | `bin/control_server` + `web/index.html` | 浏览器打开 `http://127.0.0.1:8080/`，即可在左侧边栏中选协议、场景、密码、输入/输出文件、启动/停止、发送交互式密码；右侧四个 Tab 提供仪表盘 / 协议时序 / 传输视图 / 日志与测试。 |
| F3 | 实时日志推送 | WebSocket `/ws` | 服务端/客户端/控制平面产生的 JSON Lines 日志按增量推送，浏览器秒级刷新。 |
| F4 | 测试套件 | `test/run_tests.sh` / `python3 test/run_tests.py` | 26+ 项端到端自动测试，覆盖正常流、异常流、攻击场景；结果以 JSON 或可读文本输出。 |
| F5 | 双端包对齐 | `packet_uid` 派生 + `/api/packets` | 通过 SHA1 前 16 hex 派生稳定包 ID，跨 client/server 日志去重，前端展示"双端同一包"矩阵。 |
| F6 | 异常模拟 | 环境变量 `UDP_SECURE_*` | 通过 env 触发丢包/重传/篡改/重放/降级/HPACK 错误等场景，调用方无需修改源码。 |
| F7 | 多主题 | `web/js/theme-manager.js` + `web/css/themes.css` | 9 套视觉主题（新拟态、极光、卡通、赛博朋克、贴纸、北欧等）通过 `[data-theme]` 切换 + `localStorage` 持久化。 |
| F8 | 完整性校验 | SHA1 | 全链路 SHA1 摘要：启动时算输入文件哈希并写入日志；传输结束由 server 发送二进制摘要；客户端本地再算一次并比对。 |
| F9 | 命令面板 | `web/js/command-palette.js` | 键盘快捷键唤出命令面板，实现跳转/执行常见动作（启动、停止、切换 Tab、主题）。 |
| F10 | 协议对比 | `web/js/app.js` | 前端支持选定两个协议进行 side-by-side 指标对比（同文件、相同日志、相同生命周期）。 |

### 1.2 13 套协议覆盖

下表把每个协议的教学核心机制、wire 形态、典型场景、对应 demo 二进制一次性列清：

| # | 协议 ID | 性质 | Transport | 教学点（核心机制） | Wire 形态 | 关键场景 |
| - | ------- | ---- | --------- | ------------------ | --------- | -------- |
| 1 | `udp-basic` | 真实 | UDP | 不可靠 UDP 上的"认证 + DATA + 摘要"教学 | 2B type + 4B payload_len [+ 4B packet_id for DATA] | normal / wrong-pwd / abort |
| 2 | `udp-reliable` | 真实 | UDP | 滑动窗口 + ACK/NACK + 重传 + 乱序/丢包/重排/重复恢复 | 同上 + ACK/NACK 帧（ack_id + window_size） | loss-recovery / reorder-recovery / duplicate-recovery |
| 3 | `tcp-basic` | 真实 | TCP | 应用层 framing、连接中断、半包粘包 | 2B type + 4B length framing | stream-fragmentation / connection-close-mid-transfer |
| 4 | `http-basic` | 真实 | TCP | HTTP/1.1 状态码、Header 摘要、body 长度校验 | 文本协议（HTTP/1.1） | bad-auth / payload-too-large / bad-method |
| 5 | `websocket-basic` | 真实 | TCP | Upgrade 握手、frame_type、Ping/Pong | 文本握手 + 二进制 frame | wrong-upgrade / ping-timeout / abnormal-close |
| 6 | `quic-like` | 教学 | UDP | 连接 ID、多 stream、ACK、0-RTT 风险告警 | 19B 头（type/flags/stream_id/cid/seq/ack/retrans/len）+ payload | loss-recovery / stream-reorder / zero-rtt-replay-risk |
| 7 | `dns` | 真实 | UDP | 缓存投毒 / 应答伪造 / NXDOMAIN / DoH 降级 | 12B header（txid+flags+4×count）+ 长度前缀 name + qtype/qclass + 压缩指针答案 | normal / spoofed-response / nxdomain-redir / doh-tls |
| 8 | `oauth2` | 真实 | TCP | 授权码流 + PKCE + token 重放检测 | HTTP 文本协议，6 阶段状态机 | auth-code / pkce / token-replay / implicit-deprecated |
| 9 | `mqtt` | 真实 | TCP | QoS 0/1/2 + 4 次握手 + ACL | 1B 头（4b type + 4b flags）+ 可变长 remaining + payload | normal / qos2-replay / unauth-subscribe / cleartext-eavesdrop |
| 10 | `http2` | 真实 | TCP | 二进制分帧 + 多 stream 多路复用 + 简化 HPACK | 3B length + 1B type + 1B flag + 4B stream_id + payload | normal / multiplex / hpack-overflow / stream-cancellation |
| 11 | `sip` | 真实 | UDP | INVITE/REGISTER + Via 校验 + SIPS 降级 | 文本协议（类 HTTP） | register / invite-bye / no-sips-downgrade / replay-invite |
| 12 | `radius` | 真实 | UDP | HMAC-SHA1 authenticator（教学替 HMAC-MD5）+ PAP/CHAP + 重放 | 1B code + 1B id + 2B len + 16B auth + TLV 属性 | normal / shared-secret-leak / chap-vs-pap / replay-attack |
| 13 | `tls-like` | 教学 | TCP | 握手（ClientHello/ServerHello/Finished）+ HMAC + XOR 加密 + 重放 | 2B type + 4B length + 16B nonce/MAC/密文 | normal / tampered-finished / tampered-app-data / replay |

### 1.3 内部能力（按开发者视角）

- **统一 Logger（`src/logger.c`）**：13 个二进制 + 控制平面都走同一套 `Logger` 结构，输出 `logs/{server,client,control}.jsonl`。所有日志字段（`protocol / transport / flow_id / session_id / scenario / level / event / state / packet_type / packet_code / direction / packet_uid / wire_hex / sha1 / ...`）走 schema v2，前端不需要为不同协议做特判。
- **`packet_uid` 派生（`compute_packet_uid`）**：用 `SHA1(packet_type + packet_id + wire 前 32 字节)` 取前 16 hex 字符。同一 wire 包在 client / server 两端的 UID 完全一致，前端可以做"双端包矩阵"。
- **实验上下文（`ExperimentState`）**：控制平面在每次启动时分配一个 `flow_id`（`<protocol>-<seq>`）和 `session_id`（`session-<seq>`），通过 env 注入子进程，让子进程在结构化日志里贴上相同标识，前端能按 flow 分组。
- **增量 packets 合并（`api_packets`）**：用文件 offset 增量读取 server.jsonl / client.jsonl，按 uid 缓存并选择 sender-side 行写入 `logs/packets.jsonl`。`truncate_packets()` / `truncate_logs()` / `stop_child()` 都要协同清空。
- **跨进程进程模型（`start_child` / `reap_child`）**：每个 server / client / test 各自被 `fork + exec`，stdin/stdout/stderr 走非阻塞 pipe；`stop_child()` 先 SIGTERM（200 ms 试探）后 2 s 内退避，最后再 SIGKILL，保证日志完整。
- **环境变量协议化（`build_protocol_envs`）**：所有场景化行为用 env 表达（`UDP_SECURE_PROTOCOL / SCENARIO / WINDOW_SIZE / TIMEOUT_MS / TAMPER_FINISHED / QUIC_LOSS / HTTP2_STREAM_CANCEL / ...`），子进程通过 `getenv` 触发不同代码路径。

---

## 2. 系统实现过程

### 2.1 仓库目录与文件清单

```
udp-secure-transfer/
├── Makefile                       # 一键 make；分别产出 13 对 demo + control_server
├── README.md                      # 上手指南 + 协议表 + HTTP API
├── bin/                           # make 产物（28 个二进制 + 1 个 control_server）
├── build/                         # 编译中间 .o
├── logs/                          # 运行期 JSONL 日志（运行时 mkdir）
├── output/                        # 客户端写入文件
├── uploads/                       # 上传文件占位目录
├── include/                       # 公共头
│   ├── protocol.h                 # 原始 UDP 协议原语
│   ├── demo_util.h                # 拓展协议公共原语 + HMAC-SHA1 / XOR / PKCE 帮助函数
│   ├── logger.h                   # LogEvent + Logger 结构
│   └── sha1_util.h                # 内置 SHA1（无 OpenSSL 依赖）
├── src/                           # 所有 C 实现
│   ├── protocol.c / server.c / client.c
│   ├── logger.c / sha1_util.c / demo_util.c
│   ├── control_server.c           # C 实现的 HTTP + WS 控制后端
│   ├── tcp_demo_{server,client}.c
│   ├── http_demo_{server,client}.c
│   ├── websocket_demo_{server,client}.c
│   ├── quic_demo_{server,client}.c
│   ├── dns_demo_{server,client}.c
│   ├── oauth2_demo_{server,client}.c
│   ├── mqtt_demo_{server,client}.c
│   ├── http2_demo_{server,client}.c
│   ├── sip_demo_{server,client}.c
│   └── radius_demo_{server,client}.c
├── protocols/                     # 协议元数据（前端从这拉 catalog / schema / scenarios）
│   ├── catalog.json
│   └── <13 个协议子目录>/{schema,scenarios}.json
├── test/
│   ├── run_tests.sh               # 包装到 Python 测试
│   ├── run_tests.py               # 端到端测试驱动
│   └── cases/                     # 测试输入（被脚本生成）
├── web/                           # 静态前端
│   ├── index.html                 # 752 行 SPA（左侧栏 + 4 Tab）
│   ├── css/{themes,style}.css     # 5439 + 1103 行
│   └── js/{app,api,command-palette,dock,dragdrop,notifications,search,sequence-export,theme-manager}.js
└── docs/                          # 设计/规划文档（含本份）
    ├── system-design.md           # 本文档
    ├── next-stage-plan.md
    ├── phase-2-protocol-expansion.md
    ├── 中期汇报/
    └── 结题汇报/
```

代码体量参考（核心文件行数，便于评估工程量）：

| 文件 | 行数 | 文件 | 行数 |
| ---- | ---- | ---- | ---- |
| `src/control_server.c` | 1966 | `src/server.c` | 752 |
| `src/client.c` | 696 | `src/protocol.c` | 360 |
| `src/logger.c` | 318 | `src/demo_util.c` | 368 |
| `src/tcp_demo_server.c` | 447 | `src/tcp_demo_client.c` | 445 |
| `src/quic_demo_server.c` | 415 | `src/dns_demo_server.c` | 371 |
| `src/oauth2_demo_server.c` | 497 | `src/mqtt_demo_server.c` | 425 |
| `src/http2_demo_server.c` | 444 | `src/sip_demo_server.c` | 351 |
| `src/radius_demo_server.c` | 517 | `web/index.html` | 752 |
| `web/css/style.css` | 5439 | `web/css/themes.css` | 1103 |
| `web/js/app.js` | 4374 | `test/run_tests.py` | ~823 |

### 2.2 构建与运行

- **编译**：`make` 一键产出 28 个二进制（13 对 demo + control_server），`make clean` 清理 `build/` 与 `bin/`。
- **运行方式 A：CLI**
  - `./bin/server 9000 secret test/input.txt`
  - `./bin/client 127.0.0.1 9000 wrong secret ignored output/result.txt`
  - `./bin/control_server [port]`
- **运行方式 B：Web**
  - `make && ./bin/control_server` → 浏览器 `http://127.0.0.1:8080/`
- **运行方式 C：自动测试**
  - `test/run_tests.sh [--json]`（包装 Python 驱动）
  - `python3 test/run_tests.py`

### 2.3 系统实现顺序（教学平台的工程化路径）

整个系统是按"基础 → 拓展 → 平台 → 教学增强"四步演进的，每一步的产物都能独立运行并验收：

**第 1 步：原始 UDP 实验（基线）**
- `include/protocol.h` + `src/protocol.c`：定义 7 个包类型、6+8 字节 header、DATA 的 4 字节 packet_id、ACK/NACK 帧、字节序转换、`recv_packet_timeout`（带 EINTR 重试与重算 deadline 的 select）。
- `src/server.c`：实现 `JOIN_REQ → PASS_REQ → PASS_RESP × 3 → PASS_ACCEPT / REJECT → DATA × N → TERMINATE`，含 reliable 模式（窗口 + 乱序 / 丢包 / 重复 / 重排 4 类异常注入）。
- `src/client.c`：实现兼容 7 参数命令行模式（pwd1/pwd2/pwd3）+ 4 参数交互式模式（密码由控制平面 pipe 注入）。
- `src/sha1_util.c`：纯 C 实现的 SHA1 + 文件分块读取封装，**不依赖 OpenSSL**。
- `src/logger.c`：统一 JSON Lines 输出；`compute_packet_uid` 同时考虑 PASS_RESP 完整 wire 哈希和普通包前 32 字节哈希两种策略。

**第 2 步：TCP 系列拓展（验证通用抽象）**
- `include/demo_util.h` + `src/demo_util.c`：把 `tcp_create_listener / tcp_accept / tcp_connect / write_all / read_all / send_frame / recv_frame / hmac_sha1 / xor_crypt / derive_session_key / random_nonce / base64_encode` 抽出来；同进程可以承载 `tcp-basic` 与 `tls-like` 两个协议。
- `src/tcp_demo_{server,client}.c`：`tcp-basic` 走 6B 帧 + DATA 数组；`tls-like` 走 `CLIENT_HELLO / SERVER_HELLO / FINISHED / APP_DATA` + HMAC + XOR。
- `src/http_demo_{server,client}.c`：HTTP/1.1 文本协议，Body 1KB 上限，header 大小写不敏感，Content-Length 解析。

**第 3 步：应用层协议（WebSocket / QUIC-like）**
- `src/websocket_demo_{server,client}.c`：HTTP Upgrade 握手 + frame_type 解析。
- `src/quic_demo_{server,client}.c`：19 字节头（type/flags/stream_id/cid/seq/ack/retrans/len）+ ACK 一来一回；`stream-reorder` 场景把 seq=2 先发再发 seq=1；`zero-rtt-replay-risk` 场景在 HANDSHAKE 前插入一个 ZERO_RTT 并写 WARN。

**第 4 步：控制平面（让整套系统有"平台"的样子）**
- `src/control_server.c`：单进程实现 HTTP + WebSocket + 子进程管理 + 文件增量日志推送。
  - `set_cloexec_on_inherited_fds()`：子进程 `execv` 前把 ≥ 3 的 fd 全部置 `FD_CLOEXEC`，防止子进程意外拿到控制平面的 listen_fd / ws_fd。
  - `start_child()`：`fork + pipe + dup2 + setenv + execv`，把 stdout/stderr 改为非阻塞 pipe；server / client / test 三套独立 child。
  - `stop_child()`：SIGTERM → 200ms probe → 2s 退避 → SIGKILL（先前的 150ms 太短会让 SHA1/FINAL_OK 日志被截断，issue 修复记录在 `control_server.c:339-359` 注释里）。
  - `route_api()`：把 `/api/*` 路由到具体 handler（status / logs / packets / server-start|stop / client-start|stop / send-password / reset / test-list|run|result）。
  - `api_packets()`：双 log 增量 offset → packets_cache 合并 → sender-side preference 选行 → 写 `logs/packets.jsonl.tmp` → rename。
  - `websocket_handshake()`：自实现 RFC 6455 握手（Sec-WebSocket-Key + magic → SHA1 → base64 → Sec-WebSocket-Accept），并响应 PING / 处理 CLOSE。
  - `push_log_tail()`：按 offset 增量读日志，JSON 化后通过 WS 推给前端；同时把未换行的尾行回退 offset，避免重复推送。

**第 5 步：Phase 2 协议（dns / oauth2 / mqtt / http2 / sip / radius）**
- `src/dns_demo_{server,client}.c`：12B header + 长度前缀 name + qtype/qclass + 答案段；`spoofed-response` 场景下立即发送 6.6.6.6 应答并写 `SPOOFED_RESPONSE_SENT` WARN。
- `src/oauth2_demo_{server,client}.c`：HTTP 之上的 6 阶段状态机；`pkce` 场景强制 `code_verifier`；`token-replay` 场景通过 `last_code` 缓冲检测重放。
- `src/mqtt_demo_{server,client}.c`：4b type + 4b flag + 可变 remaining + payload；`qos2-replay` 场景发两次 PUBREC 触发 4 次握手防御。
- `src/http2_demo_{server,client}.c`：3B length + 1B type + 1B flag + 4B stream_id；HPACK 用 literal 直传（不实装 Huffman）。
- `src/sip_demo_{server,client}.c`：文本协议；`no-sips-downgrade` 场景把 sip: 降级为 sip 并写 `SIPS_DOWNGRADE_DETECTED` WARN。
- `src/radius_demo_{server,client}.c`：20B 头（code+id+len+16B auth）+ TLV；HMAC-SHA1 前 16 字节做 response authenticator（教学替 MD5）。

**第 6 步：Web 前端（统一可视化）**
- `web/index.html`：左侧 6 段（运行时状态 / 协议场景选择 / 实验控制 + 测试套件 / server / client 兼容三密码或交互式）+ 4 Tab（仪表盘 / 协议 / 传输 / 日志与测试）。
- `web/js/api.js`：8 行 wrapper 把 `fetch` 包装成 `Api.{status,logs,packets,startServer,...}`。
- `web/js/app.js`：4300+ 行；`appState` 维护 `allPackets / realPackets / selectedFlow / logFilters / packetFilters` 等；`buildRealPackets` 用 `flow_id + packet_uid` 去重；4 个 Tab 各自有渲染函数。
- `web/js/theme-manager.js` + `web/css/themes.css`：9 套主题（新拟态、极光、卡通、赛博朋克、贴纸、北欧、极简等），[data-theme] 切换 + localStorage 持久化。
- `web/js/command-palette.js`、`notifications.js`、`search.js`、`dragdrop.js`、`dock.js`、`sequence-export.js`：命令面板、通知中心、全文搜索、可拖拽 dock、协议时序导出。

**第 7 步：测试与回归**
- `test/run_tests.py`：800+ 行；通过 `free_udp_port / free_tcp_port` 找空闲端口、构造 `run_demo_pair(case_id, name, server_bin, client_bin, input_file, output_file, transport, env_overrides, expect_ok=True, require_log_text=...)` 通用 helper，覆盖 26+ 测试用例。

### 2.4 关键实现要点（带代码索引）

| 主题 | 文件 / 函数 | 说明 |
| ---- | ----------- | ---- |
| UDP wire 解析 | `src/protocol.c:172-249` `parse_packet` | 长度严格 + 范围检查；`PASS_RESP` payload 长度 ≤ 255；`DATA` payload 长度 ≤ 1000；`TERMINATE` payload 必须 20 字节；`ACK/NACK` payload 必须 8 字节。 |
| UDP 发送 + 日志 | `src/server.c:168-216` `send_logged` / `recv_logged_timeout` | 每次 IO 都打一条结构化日志 + 16 hex 字符 packet_uid + direction 字段（避免前端反推）。 |
| 可靠 UDP | `src/server.c:433-569` `transfer_file_reliable` + `src/client.c:261-411` `transfer_file_reliable` | 窗口 + ACK(N) + 丢包/重排/重复 4 类异常注入；超时重传；乱序缓存。 |
| 字节序 | `src/protocol.c:12-32` + 全部 demo 的 `put_u16/put_u32/get_u16/get_u32` | 所有多字节字段统一网络字节序；跨架构可移植。 |
| 进程管理 | `src/control_server.c:388-463` `start_child` | 非阻塞 pipe + FD_CLOEXEC + setenv + execv。 |
| 优雅停机 | `src/control_server.c:333-366` `stop_child` | SIGTERM → 200ms 试探 → 2s 退避（100ms 切片） → SIGKILL。 |
| WebSocket 握手 | `src/control_server.c:1508-1550` `websocket_handshake` | 自实现 RFC 6455；Sec-WebSocket-Key + magic 拼接 + SHA1 + Base64。 |
| WebSocket 推送 | `src/control_server.c:1659-1713` `push_log_tail` | 增量 offset + 末尾未换行回退 + JSON 化。 |
| 包去重 | `src/control_server.c:988-1086` `api_packets` | 增量扫描 + 缓存 + sender-side preference 选行。 |
| 跨进程 context | `src/control_server.c:96-146` `experiment_configure` + `build_protocol_envs` | flow_id / session_id / scenario 通过 env 注入子进程。 |
| SHA1 派生 UID | `src/logger.c:176-217` `compute_packet_uid` | PASS_RESP 哈希完整 wire（避免 password 前 2 字节碰撞），其他类型哈希前 32 字节。 |
| HMAC-SHA1 | `src/demo_util.c:278-306` `demo_hmac_sha1` | 标准 ipad/opad 实现，被 TLS-like / RADIUS 复用。 |
| TLS-like 加密 | `src/tcp_demo_server.c:20-62` `tls_payload_app_data` | seq || HMAC || XOR(plain, key) 三段结构；`tamper_mac` 翻转 1 字节触发 MAC 失败。 |
| HTTP/2 HPACK | `src/http2_demo_server.c:121-134` `hpack_encode_literal` | 教学简化版：literal-without-indexing 0x00 + name + value，长度限制 127。 |
| RADIUS authenticator | `src/radius_demo_server.c:75-97` `compute_response_authenticator` | HMAC-SHA1(code\|\|id\|\|length\|\|request_auth\|\|attrs, secret) 前 16 字节。 |
| OAuth 2.0 PKCE | `src/oauth2_demo_server.c:170-187` `fake_pkce_challenge` | 教学版用 SHA1 前 16 hex 替 SHA256+base64url；客户端 / 服务端用同一算法做对比。 |
| MQTT QoS 2 | `src/mqtt_demo_server.c:361-388` | 主动发两次 PUBREC 触发 4 次握手防御；写 `QOS2_DUP_DETECTED` WARN。 |
| DNS 教学 | `src/dns_demo_server.c:309-360` | 4 类场景（normal / spoofed / nxdomain / doh-tls）写不同 packet_type + 状态。 |
| 9 套主题 | `web/js/theme-manager.js` | THEMES 数组 + `[data-theme]` 切换 + `localStorage`。 |
| 双端包矩阵 | `web/js/app.js` `buildRealPackets` | key = `flow_id + packet_uid`；前端不依赖 server/client 启动顺序。 |

---

## 3. 系统介绍

### 3.1 三层架构

```
┌──────────────────────────────────────────────────────────────────────┐
│                       Web 前端 (web/index.html + js)                 │
│  ┌────────┐  ┌────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ 侧边栏 │  │ 仪表盘 Tab │  │ 协议时序 Tab │  │ 传输/日志/测试  │  │
│  └────┬───┘  └────┬───────┘  └────┬─────────┘  └────┬─────────────┘  │
│       └───────────┴───────────────┴─────────────────┘                │
│              fetch  /api/*      WebSocket /ws                        │
└──────────────────────┬───────────────────────────────────────────────┘
                       │
┌──────────────────────┴───────────────────────────────────────────────┐
│                控制平面 (bin/control_server) — src/control_server.c   │
│  • HTTP 路由  • WebSocket 握手 / PING  • 进程管理 (start/stop)       │
│  • 日志增量推送  • packets.jsonl 合并  • 路径校验                    │
│  • 环境变量协议化 (UDP_SECURE_*)                                     │
└────┬───────────┬───────────┬───────────┬──────────┬───────────────┬─┘
     │ fork+exec │ fork+exec │ fork+exec │ fork+exec│ ... 共 13 对  │
┌────┴────┐ ┌────┴────┐ ┌────┴────┐ ┌────┴────┐ ┌──┴──────┐ ┌──────┴──┐
│udp-basic│ │tcp-basic│ │tls-like │ │http-base│ │websocket│ │ ...     │
│udp-reli.│ │quic-like│ │http2    │ │dns      │ │mqtt     │ │ radius  │
│         │ │oauth2   │ │sip      │ │         │ │         │ │         │
└────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘
     │           │           │           │           │           │
     ▼           ▼           ▼           ▼           ▼           ▼
  JSON Lines  (logs/{server,client,control}.jsonl)  ← 同一 schema v2
     │
     ▼
   浏览器 (前端从 /api/logs + /api/packets 拉取)
```

### 3.2 核心数据流（一次完整 UDP 文件传输实验）

```
浏览器             control_server           bin/server                bin/client
  │                       │                       │                       │
  │  POST /api/server/start {port,password,input}  │                       │
  │ ────────────────────► │                       │                       │
  │                       │ fork+exec server      │                       │
  │                       │ ────────────────────► │                       │
  │                       │  sets env flow_id,    │                       │
  │                       │  protocol, scenario   │                       │
  │                       │                       │ JOIN_REQ              │
  │                       │ ◄──────── recvfrom ── │ ────────────────────► │
  │                       │                       │                       │
  │                       │ PASS_REQ (logged)     │                       │
  │                       │ ────────────────────► │                       │
  │                       │                       │                       │
  │  POST /api/client/start (compat/interactive)  │                       │
  │ ────────────────────► │ fork+exec client      │                       │
  │                       │ ──────────────────────────────────────────►  │
  │                       │                       │  PASS_RESP            │
  │                       │                       │ ◄──────────────────── │
  │                       │                       │ ... AUTH ×3 ...       │
  │                       │                       │ PASS_ACCEPT           │
  │                       │                       │ ────────────────────► │
  │                       │                       │                       │
  │                       │ DATA × N (logged + packet_uid)                 │
  │                       │                       │ ────────────────────► │
  │                       │                       │                       │
  │                       │ TERMINATE (20B SHA1)  │                       │
  │                       │                       │ ────────────────────► │
  │                       │                       │  verify SHA1, OK      │
  │                       │                       │ ◄──────────────────── │
  │                       │                       │  client exit          │
  │                       │  reap_child           │                       │
  │                       │ ◄──────────────────── │                       │
  │                       │                                               │
  │  WS push: type=log, status → 前端实时刷新                            │
  │ ◄──────────────────── │                                               │
  │  GET /api/packets (聚合 + sender-side 选行)                          │
  │ ────────────────────► │                                               │
  │ ◄──────────────────── │                                               │
  │                                                                       │
```

### 3.3 关键教学机制

#### 3.3.1 统一日志 schema v2

`src/logger.c` 输出标准字段：`time / schema_version / protocol / transport / role / flow_id / session_id / scenario / level / event / peer / state / packet_type / packet_code / packet_id / payload_length / bytes / sha1 / direction / packet_uid / wire_hex / message / seq / ack / window_size / retransmit_count / stream_id / stream_offset / status_code / attempt / port / pid / method / path / header_summary / frame_type / handshake_phase / security.{encrypted,mac_valid,replay,handshake_phase}`。

这套 schema 让前端不需要为不同协议写特判。例如：
- `tcp-basic` 的包 `type=5 (DATA)`，`packet_id=0..N`
- `quic-like` 的包 `type=63 (STREAM)`，`stream_id=1, seq=N`
- `mqtt` 的包 `type=3 (PUBLISH)`，`packet_id=message_id`
- `http2` 的包 `type=0/1` (DATA/HEADERS)，`stream_id=N`
- 前端只看 `packet_uid + direction + level + event` 即可做统一可视化。

#### 3.3.2 packet_uid 双端对齐

`compute_packet_uid(out, out_size, type, packet_id, attempt, wire, wire_len)`：

- 哈希输入 = `SHA1("pkt:<type>:<packet_id>:" + wire 前 32 字节)`，前 8 字节转 hex。
- PASS_RESP 例外：哈希完整 wire（type+length+密码全文），避免"前 2 字节相同"导致 UID 碰撞（如 secret1 / secret2）。

为什么这是教学关键：学生用 Wireshark 抓包 + 平台日志对照时，能精确锁定"这一字节序列就是这一行日志"，跨进程、跨时间、跨架构都对齐。

#### 3.3.3 进程模型 + FD_CLOEXEC

`start_child()` 中 `set_cloexec_on_inherited_fds()` 把 ≥ 3 的 fd 全部置 CLOEXEC。这是 C 实现的控制平面常被忽略的安全细节：若不设，子进程可能意外继承 control_server 的 listen socket 或 ws fd，导致：
1. 子进程退出后 accept 句柄未被父进程释放；
2. WS 客户端错连到子进程并能直接驱动其行为。

本项目通过这个细节给学生示范了"管道的清洁"。

#### 3.3.4 场景化行为用 env 表达

控制平面在 `build_protocol_envs()` 中根据 `protocol / scenario` 注入 5~15 个 env 子集（`UDP_SECURE_WINDOW_SIZE / UDP_SECURE_RELIABLE_LOSS_IDS / UDP_SECURE_TAMPER_FINISHED / UDP_SECURE_QUIC_LOSS / UDP_SECURE_HTTP2_STREAM_CANCEL / ...`）。

子进程在 `main()` 入口读 env 决定行为。这让：
- 同一份二进制能演示 3~5 种场景；
- 新增场景不需要改协议 schema；
- 自动化测试通过 `env_overrides` 复用同一 helper。

#### 3.3.5 增量日志推送

`push_log_tail(role, path, &offset)`：
- 用 fstat 监测文件被 truncate → 重置 offset；
- 读完所有完整行后 fseek 到末尾 - 1 字节，如果 fgetc != '\n'，回退到上一个 '\n' + 1 → 把 offset 留在未完成行首，避免重复推送。

这是控制平面长时间运行的关键。

#### 3.3.6 教学版协议明确标注"非生产"

- `tls-like`：client 端 `tcp_demo_client.c:312-323` 主动写 `WARN/TLS_NO_SERVER_AUTH` 提示"没有服务端认证、知道密码即可 MITM"，避免学生误用。
- `quic-like`：README 和代码注释都强调不是完整 QUIC，演示 Connection ID / Multi-stream / ACK-Retransmit / 0-RTT 风险。
- `radius`：用 HMAC-SHA1 替 HMAC-MD5（项目已有 SHA1 实现，避免引入 OpenSSL），README 中明示。

#### 3.3.7 9 套主题 + 命令面板

- `web/js/theme-manager.js` 9 套主题，状态 localStorage 持久化；
- `web/js/command-palette.js` Ctrl/Cmd+K 唤出，支持跳转、运行、主题切换；
- `web/js/dragdrop.js` 左侧栏可拖拽 dock 化；
- `web/js/sequence-export.js` 时序图导出 PNG/SVG；
- 这些能力让"实验台"具备"工具平台"的工程化属性，而不仅是"会动的网页"。

### 3.4 协议目录元数据层

`protocols/catalog.json` 列出 13 套协议；每个协议有 `schema.json + scenarios.json`：

- `schema.json`：id / name / version / transport / sequenceStages / states / packetTypes / logFields。
- `scenarios.json`：每个 scenario 包含 name / 描述 / env_overrides（注入到 demo 进程）。

控制平面的 `build_protocol_envs` 与 `experiment_configure` 都按 schema 来做事，**协议目录是单一事实源**。新增协议时只需写一份 `schema.json + scenarios.json` + 一对 C demo。

### 3.5 自动化测试覆盖

`test/run_tests.py` 26+ 测试用例，覆盖：

**基础 UDP（5 项）**
- `first_password_ok / second_password_ok / third_password_ok`：分别测试第一/二/三次密码通过
- `three_passwords_wrong`：三次全错触发 REJECT
- `big_file_transfer`：大文件多 DATA 分片
- `reliable_basic / loss_recovery / reorder_recovery / duplicate_recovery`：可靠 UDP 4 种场景
- `server_timeout / missing_input / sequence_error`：异常注入

**TCP / TLS（5 项）**
- TCP basic 正常 / stream-fragmentation / connection-close-mid-transfer
- TLS-like 正常 / tampered-finished / tampered-app-data / replay

**HTTP / WebSocket（6 项）**
- HTTP basic 正常 / bad-auth / payload-too-large / bad-method
- WebSocket 正常 / wrong-upgrade / ping-timeout / abnormal-close

**QUIC-like（3 项）**
- 正常 / loss-recovery / stream-reorder / zero-rtt-replay-risk

**Phase 2（15 项）**
- DNS：normal / spoofed-response / nxdomain
- OAuth 2.0：auth-code / pkce / token-replay
- MQTT：normal / qos2-replay / unauth-subscribe
- HTTP/2：normal / multiplex / hpack-overflow
- SIP：register / invite-bye / no-sips-downgrade
- RADIUS：normal / shared-secret-leak / chap-vs-pap / replay-attack

`run_demo_pair` helper 是核心：
```python
def run_demo_pair(case_id, name, server_bin, client_bin, input_file,
                  output_file, transport, env_overrides=None,
                  expect_ok=True, require_log_text=None):
    port = free_udp_port() if transport == "udp" else free_tcp_port()
    env = {**ENV, **env_overrides}
    server = start_process([server_bin, str(port), "secret", str(input_file)], env=env)
    wait_for_server_start(port, timeout=4.0)
    client = start_process([client_bin, "127.0.0.1", str(port), "secret", str(input_file), str(output_file)], env=env)
    # collect logs, assert exit codes, assert log contains required text
```

`require_log_text` 是关键：可以断言 `HPACK_DECODE_ERROR / SIPS_DOWNGRADE_DETECTED / AUTHENTICATOR_INVALID / QOS2_DUP_DETECTED / ...` 在日志中真正出现，让异常场景"言行一致"。

---

## 4. 详细实现剖析（按子系统）

### 4.1 `bin/server` / `bin/client`（原始 UDP）

**Server 状态机**（`src/server.c`）：
1. 解析命令行（port / password / input_file），启动即 `sha1_file(input_path, digest)` 算好摘要。
2. 启动 UDP socket 监听，端口取自 argv[1]；记 `SERVER_START` 日志（含 port / bytes / sha1）。
3. 等待 `JOIN_REQ`，回 `PASS_REQ`。
4. 最多 3 次密码尝试，相同 peer 才计数；密码正确 → `PASS_ACCEPT`；3 次错 → `REJECT` + finish ABORT。
5. 认证通过后按 `protocol_is_reliable()` 走 `transfer_file` 或 `transfer_file_reliable`。
6. 传输结束后发 `TERMINATE` (20 字节 SHA1)，记录 `SERVER_DIGEST`。
7. `finish()` 写 `FINAL_OK / FINAL_ABORT` 并 `printf("%s\n", result)` 通知控制平面。

**Reliable 模式特性**：
- 加载时 `load_reliable_chunks` 根据 env 中 `LOSS_IDS / DUP_IDS / REORDER_IDS` 标记每个 chunk 第一次发送时的行为。
- `send_reliable_chunk` 第一次发：drop → 写日志不真发；reorder → 暂存到 `reorder_pending`；dup → 紧接着再发一次并写 SIMULATED_DUPLICATE WARN。
- 接收 ACK 后用 `expected_ack_id` 推进 `base`；NACK 触发指定 packet 重传。
- 任何超时（`elapsed_ms_since(&chunks[i].last_send) >= retransmit_timeout`）自动重传。
- 全部 ack 后发 `TERMINATE`，**故意发 3 次**（带 40ms 间隔）以容忍 client 端丢包。

**Client 状态机**（`src/client.c`）：
1. 启动时 `fopen(temp_path, "wb")` 创建 `output_path.part` 暂存文件。
2. 解析命令行（兼容 7 参 / 交互式 4 参）。
3. 发送 `JOIN_REQ`；循环收 `PASS_REQ → PASS_RESP × N`；收到 `PASS_ACCEPT` 进入数据传输。
4. 普通模式：`expected_packet_id` 严格递增，发现不连续 → 写 `SEQUENCE_ERROR` + finish ABORT。
5. Reliable 模式：`BufferedChunk *buffered` 数组按 packet_id 索引，乱序到达时缓存并发 NACK；发 ACK 时 ack_id = 已有 `expected_packet_id`；收到重复的 `packet_id < expected` → 写 DUPLICATE_DATA WARN 但仍发 ACK。
6. 收到 TERMINATE：fclose → `sha1_file(temp_path, ...)` → memcmp → 写 `DIGEST_MATCH / DIGEST_MISMATCH` → `rename(temp_path, output_path)` → finish OK。

**关键日志字段**：
- `direction`：写死 `"Client -> Server"` 或 `"Server -> Client"`，避免前端反推错误。
- `packet_uid`：哈希 `SHA1("pkt:<type>:<packet_id>:" + wire)`，PASS_RESP 哈希完整 wire。
- `wire_hex`：超过 160 字节截断（避免日志过大），但 `payload_length` 仍记录真实长度。

### 4.2 `bin/tcp_server` / `bin/tcp_client`（TCP basic + TLS-like）

二合一：同一份 server.c 通过 `getenv("UDP_SECURE_PROTOCOL")` 决定走 `run_tcp_basic` 还是 `run_tls_like`。
- `run_tcp_basic`：建立 TCP 监听、accept、3 次密码握手、然后 1000 字节 chunk 发文件。
- `run_tls_like`：在密码接受后多一段握手：
  - 收 `CLIENT_HELLO` (16B nonce)
  - 发 `SERVER_HELLO` (16B nonce)
  - `session_key = SHA1(password || client_nonce || server_nonce)`
  - 收 `FINISHED = HMAC(session_key, "client-finished")`，验证
  - 发 `FINISHED = HMAC(session_key, "server-finished")`（`tamper_finished` 场景翻转 1 字节）
  - 然后发 `APP_DATA`：`4B seq || 20B HMAC || XOR(plain, session_key)`
  - `tamper_app_data` 场景翻转 1 字节 MAC 触发 client 端 `APP_DATA_MAC_FAIL` ERROR
  - `replay` 场景发两次相同的 APP_DATA 触发 client 端 `REPLAY_DETECTED` ERROR

Client 端 `verify_tls_app_data`：
- 解析 seq 字段，验证 `seq > *seen_seq`（防重放）
- 验证 MAC（防篡改）
- XOR 解密（虽然教学上 XOR 不是真加密，但能演示"加密 vs 不加密"的差异）

### 4.3 `bin/http_demo_server` / `bin/http_demo_client`

文本 HTTP/1.1，单连接短消息：
- `/status` GET：返回 200 + "status=ready"
- `/auth` POST：解析 `password=xxx` body（len=9+len(password)）→ 200 接受 / 403 拒绝
- `/upload` POST：未认证 401 / body > 1024 → 413 / 成功 → 201 + 回显 body（带 `uploaded=ok&bytes=N|...` 前缀）

Client：按 scenario 选择：
- `normal`：GET /status → POST /auth → POST /upload (256 字节固定模式) → 写 output
- `bad-auth`：用 wrong 密码，预期 403
- `payload-too-large`：发 4095 字节，预期 413
- `bad-method`：PUT /status，预期 405

### 4.4 `bin/websocket_demo_server` / `bin/http_demo_client`

升级握手 + 简单 frame 解析：
- 验证 `Upgrade: websocket` / `Connection: Upgrade` 头；
- 接收 frame 头（1B opcode + 1B len）；
- 处理 `0x9 PING` → 回 `0xA PONG`；
- 处理 `0x8 CLOSE` → 回 close frame；
- 业务：客户端发 `PING`，服务端发 `PONG` + 业务消息。

### 4.5 `bin/quic_demo_server` / `bin/quic_demo_client`

19 字节 header：
```
type(1B) | flags(1B) | stream_id(2B) | connection_id(4B) | seq(4B) | ack(4B) | retransmit_count(1B) | payload_len(2B) | payload
```

包类型：`INITIAL=60 / HANDSHAKE=61 / HANDSHAKE_ACK=62 / STREAM=63 / ACK=64 / CLOSE=65 / ZERO_RTT=66`。

Server 流程：
1. 收 INITIAL → 回 HANDSHAKE → 收 HANDSHAKE_ACK。
2. 按场景分流：
   - `loss-recovery`：seq=1 时等 150ms 再发（让 client 先发 NACK/等待 retransmit）。
   - `stream-reorder`：先发 stream_id=3, seq=2，等 ACK；再发 stream_id=1, seq=1，等 ACK。
   - `normal`：从文件读 chunk 按 1200 字节切，每发一个 STREAM 等 ACK。
3. 发 CLOSE（含 20 字节 SHA1）。

Client 流程：
- 与 server 互补；按 packet_id 收齐数据，verify SHA1。
- 0-RTT 场景在 INITIAL 前插入一个 ZERO_RTT，server 写 `ZERO_RTT_REPLAY_RISK` WARN。

### 4.6 `bin/dns_demo_server` / `bin/dns_demo_client`

简化 wire（12B header + 长度前缀 name + 答案段），4 场景：
- `normal`：解析 qname，回 1.2.3.4
- `spoofed-response`：回 6.6.6.6 + 写 SPOOFED_RESPONSE_SENT
- `nxdomain-redir`：回 rcode=3，0 答案
- `doh-tls`：写 DOH_TLS_NOT_IMPLEMENTED 提示降级

### 4.7 `bin/oauth2_demo_server` / `bin/dns_demo_client`

HTTP 文本协议 6 阶段：
1. `GET /authorize?client_id=...&redirect_uri=...&code_challenge=...` → 302 + Location
2. `POST /token` (body: `code=...&code_verifier=...&grant_type=...`) → JSON 包含 access_token / refresh_token
3. `GET /api/user` (Authorization: Bearer ...) → JSON 包含 user
4. `POST /token` (grant_type=refresh_token) → 新 access_token

PKCE 场景：authorize 阶段强制 `code_challenge`；token 阶段强制 `code_verifier`；server 端用 SHA1 前 16 hex 替 SHA256+base64url。
Token-replay 场景：server 端 `last_code` 缓冲，相同 code 第二次出现 → 400 + `REPLAY_DETECTED` WARN。

### 4.8 `bin/mqtt_demo_server` / `bin/mqtt_demo_client`

4b type + 4b flag + 可变 remaining + payload：
- CONNECT (1) / CONNACK (2) / PUBLISH (3) / PUBACK (4) / PUBREC (5) / PUBREL (6) / PUBCOMP (7) / SUBSCRIBE (8) / SUBACK (9) / DISCONNECT (14)

Client 流程：CONNECT → 收 CONNACK → SUBSCRIBE (topic=admin/secret 或 sensors/temp) → 收 SUBACK → PUBLISH → 收 PUBACK → DISCONNECT。

4 场景：
- `normal`：QoS 1 PUBLISH
- `qos2-replay`：server 发两次 PUBREC（理论 QoS 2 是 4 次握手 PUBREC/PUBREL/PUBCOMP），触发 4 次握手防御
- `unauth-subscribe`：subscribe admin/secret → 0x80 SUBACK + ACL_DENY 告警
- `cleartext-eavesdrop`：PUBLISH payload 明文 + EAVESDROP_DETECTED 告警

### 4.9 `bin/http2_demo_server` / `bin/http2_demo_client`

3B length + 1B type + 1B flag + 4B stream_id + payload：

- Types：DATA=0 / HEADERS=1 / RST_STREAM=3 / SETTINGS=4 / PING=6 / GOAWAY=7 / WINDOW_UPDATE=8
- 简化 HPACK：literal field with never indexed (0x00 + 7b name_len + name + 7b value_len + value)

流程：
1. Client 发 SETTINGS + HEADERS(GET /api) on stream 1
2. Server 收后回 SETTINGS + HEADERS(200) on stream 1
3. 多 stream 并发：stream 3, 5, 7, 9 各发一个 GET，演示复用同一个 TCP 连接
4. `hpack-overflow` 场景：client 发超长 HPACK name（> 127 字节），server 写 HPACK_DECODE_ERROR 并 RST_STREAM
5. `stream-cancellation` 场景：client 发 RST_STREAM(1) 主动取消

### 4.10 `bin/sip_demo_server` / `bin/sip_demo_client`

文本协议（类 HTTP）：

```
INVITE sip:user@host SIP/2.0\r\n
Via: SIP/2.0/UDP ...;branch=z9hG4bK...\r\n
From: <sip:user@host>;tag=...\r\n
To: <sip:user@host>\r\n
Call-ID: ...\r\n
CSeq: 1 INVITE\r\n
Content-Length: 0\r\n
\r\n
```

3 场景：
- `register`：REGISTER → 200 OK
- `invite-bye`：INVITE → 100 Trying → 180 Ringing → 200 OK → ACK → BYE → 200 OK
- `no-sips-downgrade`：故意把 `sips:` 写成 `sip:`，server 写 SIPS_DOWNGRADE_DETECTED
- `replay-invite`：相同 Call-ID + CSeq 重发，server 写 INVITE_REPLAY_DETECTED

### 4.11 `bin/radius_demo_server` / `bin/radius_demo_client`

20B header + TLV：
- code(1) / id(1) / length(2) / authenticator(16) / attributes
- Attributes: User-Name(1) / User-Password(2) / CHAP-Password(3) / NAS-IP-Address(4) / CHAP-Challenge(32)
- Authenticator：request = 16B random；response = HMAC-SHA1 前 16B

4 场景：
- `normal`：PAP 认证成功
- `shared-secret-leak`：client 用错误 secret → AUTHENTICATOR_INVALID
- `chap-vs-pap`：CHAP-Password 替 User-Password
- `replay-attack`：相同 request authenticator 出现两次 → REPLAY_DETECTED

PAP 密码混淆：教学版用 `SHA1(request_auth || password)` 前 16 字节 XOR 真实密码前 16 字节（RFC 2865 标准做迭代 XOR，但本教学版做简化）。

### 4.12 控制平面 `bin/control_server`

`main()` 流程：
1. 解析 port（默认 8080）。
2. `ensure_runtime_dirs()` mkdir logs / output / test/cases。
3. 初始化 3 个 child（server / client / test）。
4. `create_listener(port)` → bind 127.0.0.1:port。
5. 事件循环 `select(maxfd+1, ...)`，1s timeout：
   - 监听 socket 新连接 → `handle_http_client`。
   - 子进程 pipe 事件 → `handle_child_output` 或 test runner special 路径。
   - WS 心跳 → 推 `status`、推日志 tail。
6. `stop_child(server/client/test)` 优雅关停。
7. `reap_child` 回收子进程。

`handle_http_client()`：
- 读 HTTP request（带 Content-Length 校验，>64KB 拒绝）。
- 解析 method / path。
- `/ws` → `websocket_handshake`。
- `/api/...` → `route_api`。
- 其它 → `serve_static`（从 `web/` 或 `./protocols/`）。

`websocket_handshake()`：自实现 RFC 6455：
```
key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" → SHA1 → base64 → Sec-WebSocket-Accept
```

PING 处理：收到 0x89 → 回 0x8A + payload。
CLOSE 处理：收到 0x88 → 回 close frame + close。

### 4.13 Web 前端

`web/index.html`：
- `<aside class="control-sidebar">`：侧边栏 6 段（运行状态 / 协议场景 / 实验控制+测试 / server / client 兼容三密码或交互式 / 折叠态）
- `<main class="content-area">`：4 个 Tab（仪表盘 / 协议 / 传输 / 日志与测试）
- 通过 `data-tab` 切换显示；通过 `data-theme` 切换主题。

`web/js/app.js`：
- `appState` 全局状态机：~50 个字段（status / logs / allPackets / realPackets / selectedFlow / logFilters / packetFilters / sidebarCollapsed / interactiveClientActive / ...）。
- `init()` → 加载 catalog / 各协议 schema / 各协议 scenarios。
- `bootstrap()` → 建立 WS、绑定事件、初始拉 status + logs + packets。
- `buildRealPackets()`：从 `allPackets` 用 `flow_id + packet_uid` 去重（同一包在 server.jsonl / client.jsonl 各出现一次时只留 sender-side）。
- `renderDashboard / renderProtocol / renderTransfer / renderLogs`：4 个 Tab 各自 render。
- `deriveRun()`：把 packets 聚合成"按 flow 分组"的数据结构，给 Transfer Tab 用。
- `computeThroughputTimeline()`：从 time + bytes 计算每秒吞吐 sparkline。
- `applyLogFilter / applyPacketFilter`：组合 role / level / event / time range / search。
- `i18n`：中英双语切换（zh / en），所有 `data-i18n` 节点实时翻译。

`web/js/theme-manager.js`：
- 9 套主题（neumorph / aurora / cartoon / cyber / sticker / nordic / ...）；
- `applyTheme(id)`：改 `document.documentElement.dataset.theme`；
- 持久化到 `localStorage`。

`web/js/api.js`：8 行 `fetch` wrapper，定义 `Api.{catalog, status, logs, packets, reset, startServer, stopServer, startClient, stopClient, sendPassword, runTests, testResult}`。

`web/js/command-palette.js`：Ctrl/Cmd+K 唤出命令面板。

`web/js/notifications.js`：右上角通知（INFO/WARN/ERROR/SUCCESS）。

`web/js/search.js`：全文搜索（packet_type / direction / flow_id / state / uid / hex preview）。

`web/js/dragdrop.js`：侧边栏可拖拽 dock 化。

`web/js/sequence-export.js`：时序图导出 PNG/SVG。

### 4.14 测试驱动

`test/run_tests.py`：
- 13 个 helper：
  - `free_udp_port / free_tcp_port`
  - `run_cmd / start_process / start_server`
  - `wait_for_server_start`：轮询 `logs/server.jsonl` 看 `"port":<port>` 是否出现
  - `collect_process`：超时 + 强杀
  - `make_big_file / make_small_file`
  - `run_protocol_pair(case_id, name, server_bin, client_bin, ...)`：通用 demo 测试 helper
  - `test_reliable_pair`：reliable UDP 特化
  - `test_missing_input / test_timeout / test_malformed_packet / test_sequence_error`
  - `run_all()`：组 26+ 测试用例
  - `main()`：`--json` 或人类可读输出

- 测试结构：
  - 每个 case 给定 `expect_ok` 和 `require_log_text`。
  - 收集 stdout / stderr / 日志文件。
  - assert exit code 和 log 含特定字符串。

---

## 5. 测试覆盖与质量保证

### 5.1 测试矩阵

| 协议 | 测试数 | 关键场景 |
| ---- | ------ | -------- |
| udp-basic | 5 | 三次密码、错密码、大文件、超时、缺输入、序列错 |
| udp-reliable | 4 | 正常 + 丢包/乱序/重复 恢复 |
| tcp-basic | 3 | 正常、stream-fragmentation、connection-close |
| tls-like | 3 | 正常、tampered-finished、tampered-app-data、replay |
| http-basic | 4 | 正常、bad-auth、payload-too-large、bad-method |
| websocket-basic | 4 | 正常、wrong-upgrade、ping-timeout、abnormal-close |
| quic-like | 3 | 正常、loss-recovery、stream-reorder、zero-rtt-replay |
| dns | 3 | 正常、spoofed-response、nxdomain |
| oauth2 | 3 | auth-code、pkce、token-replay |
| mqtt | 3 | 正常、qos2-replay、unauth-subscribe |
| http2 | 3 | 正常、multiplex、hpack-overflow |
| sip | 3 | register、invite-bye、no-sips-downgrade |
| radius | 4 | 正常、shared-secret-leak、chap-vs-pap、replay |
| **合计** | **45+** | |

### 5.2 质量保证细节

- `Makefile` 用 `-Wall -Wextra -O2 -g` 编译，启用 `_FORTIFY_SOURCE=2` 与 `stack-protector-strong`，LDFLAGS 加 `-z relro -z now`（强 RELRO 让 GOT 在加载后只读）。
- 所有 13 个 demo 都用 `signal(SIGINT, ...)` + `volatile sig_atomic_t stop_requested` 优雅退出。
- 子进程退出时 control_server 用 `select` 监听 + `waitpid(WNOHANG)` 回收，避免僵尸。
- `push_log_tail` / `packets_scan_log` 都做"未换行回退"避免重复推送；外部 truncate 检测（`st.st_size < start_offset`）避免误判。
- `parse_packet` 长度严格 + 范围检查；`recv_packet_timeout` 对 EINTR 重试并重算 deadline。
- `api_packets` 的 cache 选 sender-side（`direction` 字段）确保唯一性；orphan 保留支持跨 run 留存。

---

## 6. 不足与改进方向

### 6.1 协议层（功能性局限）

1. **udp-basic 本身不可靠**
   - 现状：只要求基础验收，丢包 / 乱序 / 重复直接 ABORT。
   - 改进方向：保留 udp-basic 作为"最弱"基线，让 udp-reliable 显式升级（已做）；后续可加 `udp-secure`（PSK + AES-GCM）。

2. **tls-like 不是 TLS**
   - 现状：HMAC + XOR + 共享密码。
   - 改进方向：保留教学版，但 README 应更明确标注"不可用于生产"；可考虑加一个真正的 TLS 后端（mbedTLS 或 BearSSL）做对比。

3. **quic-like 不实现加密**
   - 现状：只演示 connection ID / 多 stream / ACK / 0-RTT 风险。
   - 改进方向：可加 packet number encryption 简化版（用 session key XOR 4 字节 packet number）。

4. **dns 仅支持 UDP，DoH 未实现**
   - 现状：DoH 场景只发降级告警。
   - 改进方向：可加 DoH-over-HTTP（与 http-basic 复用 TCP），用 `application/dns-message` 头。

5. **oauth2 PKCE 简化**
   - 现状：用 SHA1 前 16 hex 替 SHA256+base64url。
   - 改进方向：实装 base64url 编码器，迁移到 SHA256。

6. **radius 用 HMAC-SHA1 替 HMAC-MD5**
   - 现状：避免引入 OpenSSL。
   - 改进方向：保留教学简化版，README 中明示"真实 RADIUS 用 HMAC-MD5"。

7. **mqtt 不支持 TLS（MQTTS）**
   - 现状：明文传输 + 告警。
   - 改进方向：复用 tls-like 作为 handshake 前后置层。

8. **sip 缺 SIPS 实现**
   - 现状：只发降级告警。
   - 改进方向：可加 TLS-over-UDP（DTLS）路径示意。

9. **http2 HPACK 极简化**
   - 现状：literal 直传、不实装 Huffman / 静态表 / 动态表。
   - 改进方向：实装静态表（61 项），动态表用 LRU。

10. **websocket basic 没有大 payload、压缩扩展**
    - 现状：只验证 frame_type 解析。
    - 改进方向：增加 permessage-deflate 简化版（用 zlib）。

### 6.2 控制平面 / 平台层

1. **单进程 C 控制平面**
   - 现状：`control_server.c` 接近 2000 行，事件循环 + 进程管理 + JSON 解析 + WebSocket 握手 + 静态服务 + 增量日志推送全部塞在一份。
   - 改进方向：拆分为多个模块（HTTP / WS / child-manager / log-streamer / packets-cache）。

2. **HTTP 实现非标准**
   - 现状：自实现解析请求行 / 头，无 keep-alive。
   - 改进方向：可换 libmicrohttpd 或 civetweb（项目目前保持零依赖）。

3. **WebSocket 实现自实现**
   - 现状：自实现 RFC 6455 握手和 frame 解析。
   - 改进方向：可换 libwebsockets，但目前已经够用。

4. **process 进程管理是 OS-level 的**
   - 现状：fork + exec + pipe + SIGTERM。
   - 改进方向：可加 cgroup 限制资源，加 namespace 隔离。

5. **packets 缓存无并发保护**
   - 现状：单线程事件循环，packets_cache 是裸指针。
   - 改进方向：保持单线程，但加更多 invariant 检查（size / cap 一致性）。

6. **安全相关**
   - 现状：HTTP 没有 CSRF token；WebSocket 没有 origin 校验；CORS 写 `*`。
   - 改进方向：教学场景可接受；如部署到公网需补 CSRF / origin。

7. **没有持久化数据库**
   - 现状：状态全部在内存 + JSONL 文件。
   - 改进方向：长期可加 SQLite 存历史 flow。

### 6.3 前端层

1. **没有 TypeScript / 构建工具**
   - 现状：原生 ES6 / HTML / CSS，5400+ 行 style.css + 4400+ 行 app.js。
   - 改进方向：可用 Vite 拆模块；目前保持零构建依赖。

2. **没有单元测试**
   - 现状：UI 行为靠手动验证。
   - 改进方向：可加 Playwright / Vitest。

3. **没有组件库**
   - 现状：手写组件 + 主题。
   - 改进方向：可拆出独立 Web Components。

4. **国际化手工管理**
   - 现状：`data-i18n` + 大量 JS 字符串。
   - 改进方向：可用 i18next。

5. **响应式不完整**
   - 现状：侧边栏可折叠但移动端体验一般。
   - 改进方向：可加 mobile-first 布局。

6. **没有协议对比的真实存储**
   - 现状：compareProtocol 是临时 UI 状态，不存历史对比结果。
   - 改进方向：可加 localStorage 持久化。

### 6.4 工程化

1. **没有 CI / CD**
   - 现状：靠 `make test` 手动验证。
   - 改进方向：可加 GitHub Actions 跑 `make test` + Python 回归。

2. **没有版本管理**
   - 现状：13 个 demo 各自版本号写死或没写。
   - 改进方向：在 `protocols/<id>/schema.json` 已有 `version` 字段，需要在 C 代码里也读取并记录到日志。

3. **没有 coverage 工具**
   - 现状：测试覆盖靠人脑。
   - 改进方向：可加 `gcov` + 覆盖率报告。

4. **没有 benchmark**
   - 现状：吞吐率靠前端 sparkline 估算。
   - 改进方向：可在 Transfer Tab 加显式 benchmark 模式（多次跑取 P50/P99）。

5. **没有 changelog**
   - 现状：git commit 历史是唯一 changelog。
   - 改进方向：可加 `CHANGELOG.md` + semver。

### 6.5 教学层面

1. **部分协议可学性偏弱**
   - 现状：DNS / RADIUS / SIP 等需要较强先修知识。
   - 改进方向：每个协议加 `tutorial.md`，包含 RFC 链接 + 关键概念图 + 实验操作步骤。

2. **没有交互式 demo 模式**
   - 现状：跑一次只能看一次结果。
   - 改进方向：可加"分步播放"功能，前端在每条日志停顿 N 秒后推进。

3. **没有答案库**
   - 现状：学生看日志自己找问题。
   - 改进方向：可加 `protocols/<id>/scenarios.json` 中的 `expectedEvents` 字段，前端用绿勾标出"已观察到"。

4. **没有协作模式**
   - 现状：单人单机。
   - 改进方向：可加多用户同时操作（教学场景不大需要）。

5. **没有自动评分**
   - 现状：`test/run_tests.py` 是脚本，不是评分。
   - 改进方向：可加 scoreboard，给学生跑测试后打分。

### 6.6 文档 / 演示

1. **README 偏命令式**
   - 现状：以命令行 / API 为主，缺少架构图。
   - 改进方向：可加 ASCII 图 + 系统组件说明（本份报告即此意）。

2. **缺少故障排查手册**
   - 现状：常见错误没整理。
   - 改进方向：可加 `docs/troubleshooting.md`。

3. **缺少 RFC 引用表**
   - 现状：每个协议没有标注参考 RFC 章节。
   - 改进方向：在 `protocols/<id>/schema.json` 加 `rfcRefs` 字段。

4. **没有视频 / 截图**
   - 现状：纯文字。
   - 改进方向：可加 1 段 5 分钟介绍视频 + 关键场景截图。

---

## 7. 与实验要求的对齐

| 实验要求 | 实现位置 | 状态 |
| -------- | -------- | ---- |
| UDP server/client 分文件实现 | `src/server.c` / `src/client.c` | ✅ |
| 保留规定命令行格式 | `src/server.c:602-606` / `src/client.c:453-469` | ✅ |
| `JOIN_REQ → PASS_REQ → PASS_RESP → PASS_ACCEPT → DATA → TERMINATE` | `src/server.c:651-740` / `src/client.c:518-573` | ✅ |
| 三次密码错误 → REJECT / ABORT | `src/server.c:669-729` | ✅ |
| 严格 2B type + 4B payload length + DATA 4B packet_id | `src/protocol.c:94-150` | ✅ |
| 网络字节序 | `src/protocol.c:12-32` | ✅ |
| `DATA.payload_length` 不含 packet_id | `src/protocol.c:121-136` | ✅ |
| 正常 `OK` / 异常 `ABORT` | `src/server.c:69-77` / `src/client.c:55-63` | ✅ |
| SHA1 文件摘要 | `src/sha1_util.c` | ✅ |
| 异常处理（超时、未知包、长度、序号、认证、文件错误） | 各处 `parse_fail` / `finish(ABORT)` | ✅ |
| **拓展**：本地 C 控制后端 | `src/control_server.c` | ✅ |
| **拓展**：HTTP API | `route_api` | ✅ |
| **拓展**：WebSocket 推送 | `push_log_tail` | ✅ |
| **拓展**：Web 控制台 4 Tab | `web/index.html` | ✅ |
| **拓展**：Packet Inspector | `wire_hex` 字段 | ✅ |
| **拓展**：分片矩阵 | `web/js/app.js` `fragment-matrix` | ✅ |
| **拓展**：JSON Lines 日志 | `src/logger.c` | ✅ |
| **拓展**：自动测试 | `test/run_tests.py` | ✅ |
| **Phase 2 拓展**：13 套协议 | `src/*_demo_*.c` × 26 + `protocols/<id>/` | ✅ |

---

## 8. 总结与展望

`udp-secure-transfer` 已经从"单一 UDP 文件传输实验"演进为一个"多协议安全通信可视化平台"，覆盖：

- **真实传输层 5 套**（udp-basic / udp-reliable / tcp-basic / http-basic / websocket-basic）
- **教学版 2 套**（tls-like / quic-like）
- **Phase 2 应用层 6 套**（dns / oauth2 / mqtt / http2 / sip / radius）

整个平台具备：

- 统一日志 schema v2 + `packet_uid` 双端对齐
- 统一控制平面（HTTP + WebSocket + 进程管理 + 增量日志推送）
- 统一 Web 前端（侧边栏 + 4 Tab + 9 主题 + 中英双语 + 命令面板）
- 统一测试驱动（26+ 端到端用例 + 13 协议 helper）
- 统一构建（`make` 一键产出 28 个二进制）

**核心价值**：

1. **教学价值**：13 套协议在同一平台并列展示，让学生看到"认证 / 加密 / 完整性 / 重放检测 / 多路复用 / 流量控制 / AAA"等概念在每种协议中如何被实例化。
2. **可视化价值**：统一日志 + `packet_uid` + 增量推送 + 4 Tab 把"实验现场"还原为可重放、可分析、可导出的教学资源。
3. **工程价值**：每个 demo 仅 200~500 行 C 代码，复用 `demo_util.c` 的公共原语（HMAC / XOR / nonce / base64），新增协议的成本主要是"wire 格式 + 状态机 + 异常注入"。
4. **可演进价值**：13 个 demo 各自独立，但通过 `protocols/catalog.json` 和 `build_protocol_envs()` 接入控制平面；新增协议只需写一份 `schema.json + scenarios.json` + 一对 C 程序。

**下一步建议**（结合下一阶段计划）：

1. **真 TLS / 真加密**：引入 mbedTLS / BearSSL，tls-like → 真正的 TLS 1.3。
2. **真 HPACK**：实装静态表 + 动态表（LRU）+ Huffman 编码。
3. **真 PKCE / OIDC**：补 base64url + SHA256 + OIDC discovery 简化版。
4. **真 QUIC**：选一个轻量级 QUIC 实现（如 quiche 的 C 绑定）做参考对照。
5. **可观测性**：加 Prometheus exporter，把吞吐率 / 包率 / 错误率导出。
6. **移动端**：前端加 mobile-first 布局或 PWA。
7. **教学增强**：每协议加 `tutorial.md` + 视频 + 答案库。

---

## 附录 A：文件索引

### A.1 核心 C 文件

- `include/protocol.h` + `src/protocol.c`：原始 UDP 协议原语
- `include/demo_util.h` + `src/demo_util.c`：拓展协议公共原语
- `include/logger.h` + `src/logger.c`：统一日志
- `include/sha1_util.h` + `src/sha1_util.c`：内置 SHA1
- `src/server.c` / `src/client.c`：原始 UDP 服务端/客户端
- `src/control_server.c`：控制平面（HTTP + WS + 进程管理）

### A.2 Demo 协议 C 文件（13 对）

- `src/tcp_demo_{server,client}.c`（同时承载 `tls-like`）
- `src/http_demo_{server,client}.c`
- `src/websocket_demo_{server,client}.c`
- `src/quic_demo_{server,client}.c`
- `src/dns_demo_{server,client}.c`
- `src/oauth2_demo_{server,client}.c`
- `src/mqtt_demo_{server,client}.c`
- `src/http2_demo_{server,client}.c`
- `src/sip_demo_{server,client}.c`
- `src/radius_demo_{server,client}.c`

### A.3 协议元数据

- `protocols/catalog.json`：13 套协议目录
- `protocols/<id>/{schema,scenarios}.json`：每套协议的元数据

### A.4 前端

- `web/index.html`（752 行 SPA）
- `web/css/{style,themes}.css`（5439 + 1103 行）
- `web/js/{app,api,command-palette,dock,dragdrop,notifications,search,sequence-export,theme-manager}.js`

### A.5 测试与脚本

- `test/run_tests.sh` / `test/run_tests.py`（26+ 端到端用例）
- `Makefile`（28 个二进制构建）

### A.6 文档

- `README.md`（用户向）
- `docs/system-design.md`（本文）
- `docs/next-stage-plan.md`（下一阶段规划）
- `docs/phase-2-protocol-expansion.md`（Phase 2 拓展细节）

---

## 附录 B：关键时序图

### B.1 UDP 文件传输（正常流程）

```
Client                             Server
  |                                  |
  |  JOIN_REQ                        |
  |  ────────────────────────────►  |
  |                                  |
  |  PASS_REQ                        |
  |  ◄────────────────────────────  |
  |                                  |
  |  PASS_RESP "secret"              |
  |  ────────────────────────────►  |
  |                                  |
  |  PASS_ACCEPT                     |
  |  ◄────────────────────────────  |
  |                                  |
  |  DATA(packet_id=0)               |
  |  ◄────────────────────────────  |
  |  DATA(packet_id=1)               |
  |  ◄────────────────────────────  |
  |  ...                             |
  |  DATA(packet_id=N)               |
  |  ◄────────────────────────────  |
  |                                  |
  |  TERMINATE(20B SHA1)             |
  |  ◄────────────────────────────  |
  |                                  |
  |  compute local SHA1              |
  |  compare to server SHA1          |
  |  print "OK" / "ABORT"           |
```

### B.2 TLS-like 握手

```
Client                                  Server
  |                                        |
  |  (TCP connect)                         |
  |  ────────────────────────────────────► |
  |                                        |
  |  PASS_REQ / RESP × N / ACCEPT          |
  |  (标准 udp-basic 风格 3 次密码)         |
  |                                        |
  |  CLIENT_HELLO (16B nonce)              |
  |  ────────────────────────────────────► |
  |                                        |
  |  SERVER_HELLO (16B nonce)              |
  |  ◄──────────────────────────────────── |
  |                                        |
  |  client 算 session_key =               |
  |    SHA1(password || C || S)            |
  |  client FINISHED =                     |
  |    HMAC(session_key, "client-finished")|
  |                                        |
  |  FINISHED                              |
  |  ────────────────────────────────────► |
  |                                        |
  |  server 算同样的 session_key           |
  |  server 验证 client FINISHED           |
  |  server FINISHED =                     |
  |    HMAC(session_key, "server-finished")|
  |                                        |
  |  FINISHED                              |
  |  ◄──────────────────────────────────── |
  |                                        |
  |  client 验证 server FINISHED           |
  |  client 写 WARN/TLS_NO_SERVER_AUTH     |
  |  (明示 MITM 风险)                       |
  |                                        |
  |  APP_DATA(seq=1) =                     |
  |    4B seq || 20B HMAC || XOR(plain)    |
  |  ◄──────────────────────────────────── |
  |  client 验证 MAC + 解密 XOR             |
  |  APP_DATA(seq=2) ...                   |
  |                                        |
  |  TERMINATE(20B SHA1)                   |
  |  ◄──────────────────────────────────── |
  |  client 验证 SHA1                      |
```

### B.3 QUIC-like 多 Stream

```
Client                                Server
  |                                      |
  |  INITIAL (cid=0x1234)                |
  |  ──────────────────────────────────► |
  |                                      |
  |  HANDSHAKE                           |
  |  ◄────────────────────────────────── |
  |                                      |
  |  HANDSHAKE_ACK                       |
  |  ──────────────────────────────────► |
  |                                      |
  | (stream-reorder 场景)                 |
  |  STREAM (stream_id=3, seq=2)         |
  |  ◄────────────────────────────────── |
  |  ACK(ack=2)                          |
  |  ──────────────────────────────────► |
  |  STREAM (stream_id=1, seq=1)         |
  |  ◄────────────────────────────────── |
  |  ACK(ack=1)                          |
  |  ──────────────────────────────────► |
  |                                      |
  | (normal 场景)                         |
  |  STREAM (stream_id=1, seq=1)         |
  |  ◄────────────────────────────────── |
  |  ACK(ack=1)                          |
  |  STREAM (stream_id=1, seq=2)         |
  |  ◄────────────────────────────────── |
  |  ACK(ack=2)                          |
  |  ...                                 |
  |                                      |
  |  CLOSE (20B SHA1)                    |
  |  ◄────────────────────────────────── |
  |  client 验证 SHA1                    |
```

---

## 附录 C：HTTP API 速查

| Method | Path | 说明 |
| ------ | ---- | ---- |
| GET | `/api/status` | server/client 进程状态、result、当前 experiment |
| GET | `/api/logs` | server/client/control 三套 JSONL 日志 |
| GET | `/api/packets` | 跨 server/client 双端去重后的 packet 数组 |
| POST | `/api/packets/clear` | 清空 packets.jsonl |
| POST | `/api/server/start` | 启动 server（body: port / password / inputFile / protocol / scenario） |
| POST | `/api/server/stop` | 停止 server |
| POST | `/api/client/start` | 启动 client（body: host / port / outputFile / mode=compat|interactive / pwd1-3 / protocol / scenario） |
| POST | `/api/client/stop` | 停止 client |
| POST | `/api/client/send-password` | 给交互式 client 写密码（body: password） |
| POST | `/api/reset` | 停止全部子进程 + 重置 experiment + 清空日志 |
| GET | `/api/test/list` | 列出 26+ 测试用例 |
| POST | `/api/test/run` | 启动测试 runner |
| GET | `/api/test/result` | 拉取最近一次测试 JSON 结果 |
| WS | `/ws` | 实时推送 log / status 事件 |

---

**报告完成。** 本文档基于源码逐行阅读，旨在把"教学实验台"的设计取舍、实现细节、运行机制、局限与改进一次性写清，方便：
- 答辩教师 / 同学快速理解系统
- 二次开发同学按图索骥
- 课程报告引用与归档
