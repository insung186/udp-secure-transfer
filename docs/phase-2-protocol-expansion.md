# 协议拓展设计说明 — 第二阶段路线图

## 一、设计目标

让平台从「覆盖 7 个核心协议」扩展到「覆盖 14 个协议、覆盖 OSI 7 层中 5 层 + 跨层应用层协议」,使课程可以串成完整的"应用层 → 传输层 → 网络层 → 安全机制"学习路径。

**核心原则**:
- 教学价值优先于实现完整性 (每协议演示 1-2 个最关键的安全概念)
- 复用现有架构 (server + client + scenario + catalog.json + 前端),不引入新的执行框架
- 每个新协议控制在 **400-700 行 C 代码**,不破坏构建系统的可读性
- 每个协议 **必须能用 1-2 个场景就讲清它的核心安全意义**

## 二、当前架构

```
protocols/
  catalog.json         # 协议注册表
  <proto-id>/
    schema.json       # 阶段 / 包类型 / 状态机
    scenarios.json    # 默认场景 / 可选场景

src/
  <proto>_demo_server.c   # C 二进制
  <proto>_demo_client.c   # C 二进制
  protocol.c               # 共享 wire 帧定义 (PROTOCOL_HEADER_SIZE 等)
  logger.c                 # 共享 JSONL 日志
  demo_util.c              # 共享 CRC / hex / 帧读写

web/
  js/api.js           # /api/logs / /api/packets / /api/control
  js/app.js           # 协议摘要 / 矩阵 / 仪表盘
  js/theme-manager.js # 9 套主题
  css/themes.css      # 9 套色板
```

每个协议 = `proto / transport / defaultScenario / schema / scenarios`,前端可下拉选择,后端按 env 启动对应二进制。

## 三、新协议候选（按优先级排序）

### 候选池（15 个）

| 协议 | OSI 层 | 核心安全教学点 | 实现复杂度 |
|---|---|---|---|
| **DNS** | 应用层 | 缓存投毒 / 域名劫持 / DoH 加密 | 中 |
| **OAuth 2.0** | 应用层 | 重定向 URI 校验 / PKCE / token 泄漏 | 中 |
| **MQTT** | 应用层 | IoT pub/sub QoS / ACL / TLS 缺失 | 中 |
| **CoAP** | 应用层 | 资源受限 REST / DTLS 选项 / 观察模式 | 中 |
| **HTTP/2** | 应用层 | 二进制分帧 / 多路复用 / HPACK 压缩 | 中 |
| **gRPC** | 应用层 | HTTP/2 + Protobuf / 流式 RPC | 中-高 |
| **SIP** | 应用层 | VoIP 信令 / 中继攻击 / SIPS | 中 |
| **RTP** | 应用层 | 实时媒体 / 序列号乱序 / SRTP 加密 | 中 |
| **SFTP** | 应用层 | SSH 通道上的文件传输 / 鉴权 | 中 |
| **RADIUS** | 应用层 | AAA / 共享密钥 / 接入认证 | 中 |
| **LDAP** | 应用层 | 目录服务 / 匿名绑定 / LDAPS | 中 |
| **Kerberos** | 应用层 | TGT / Service Ticket / 重放 | 高 |
| **BGP** | 应用层 | 路由劫持 / AS-PATH 验证 / RPKI | 高 |
| **DoH** | 应用层 | DNS over HTTPS 加密 | 中 |
| **NTP** | 应用层 | 时间同步 / 延迟攻击 | 中 |

## 四、推荐第二阶段清单（6 个 + 1 备选 = 7 个协议）

按"教学价值 / 实现可行性 / 风险"打分,从候选池筛选 7 个优先级协议。

### ⭐ Tier 1: 必须做（4 个,补齐 OSI 各层 + 现代 Web 安全）

| 协议 | 教学点 | 演示场景 | 估值 LOC |
|---|---|---|---|
| **dns** | 缓存投毒 / 应答伪造 / DoH | normal / spoofed-response / nxdomain-redir / doh-tls | ~600 |
| **oauth2** | 授权码流 / 重定向 URI / PKCE / token 泄漏 | auth-code / pkce / implicit-deprecated / token-replay | ~700 |
| **mqtt** | pub/sub / QoS 0/1/2 / retain / ACL / TLS 缺失 | normal / qos2-replay / unauth-subscribe / cleartext-eavesdrop | ~600 |
| **http2** | 二进制分帧 / 多路复用 / HPACK / 优先级 | normal / multiplex / hpack-overflow / stream-cancellation | ~700 |

### ⭐ Tier 2: 推荐做（2 个,完善实时 + 鉴权)

| 协议 | 教学点 | 演示场景 | 估值 LOC |
|---|---|---|---|
| **sip** | INVITE 流程 / 注册劫持 / SIPS / 中继 | register / invite-bye / no-sips-downgrade / replay-invite | ~700 |
| **radius** | AAA / 共享密钥 / PAP vs CHAP / 接入重放 | normal / shared-secret-leak / chap-vs-pap / replay-attack | ~600 |

### ⭐ Tier 3: 备选（1 个,期末项目用)

| 协议 | 教学点 | 估值 |
|---|---|---|
| **kerberos** | KDC / TGT / Service Ticket / 黄金票据 / 银票据 | ~900 |

## 五、每个协议详细设计

### 5.1 DNS（domain name system）

**学习目标**: 让学生直观看到 DNS 应答欺骗 / 缓存投毒 / DoH 加密。

**Wire 协议**:
- 简化版 DNS over UDP: 自定义 header (txid 2B + flags 2B + qd/an/ns/ar count 2B×4) + 长度前缀 name + qtype 2B + qclass 2B + answer (同结构)
- DoH 模式: HTTP/1.1 POST `/dns-query{?dns=...}` with `application/dns-message` body, 走 TLS
- 简化: 不实现 EDNS, 但支持 A / AAAA / CNAME / NXDOMAIN

**场景**:
- `normal`: query `example.com` A → response 1.2.3.4
- `spoofed-response`: server 在收到 query 后,先**立即**发送伪造响应 (源 IP 模仿 / txid 匹配),再发真实响应
- `cache-poisoning`: server 把客户端的 recursive resolver 模拟为本地 cache,演示攻击者如何塞入 fake A 记录
- `doh-tls`: 走 HTTPS (复用现有 control_server 的 TLS 能力),对比明文 UDP 与加密 DoH 的 wire 差异

**安全事件日志**:
- `DNS_QUERY_SENT` / `DNS_RESPONSE_RECEIVED` / `DNS_RESPONSE_SUSPICIOUS` (前后两条应答 txid 一致但 source IP 不同)
- `DNS_CACHE_HIT` / `DNS_CACHE_POISONED`

### 5.2 OAuth 2.0

**学习目标**: 理解授权码流 / 重定向 URI 验证 / PKCE / 隐式流 (废弃) / token 过期与刷新。

**Wire 协议**: 全部走 HTTP, 复用 `http_demo_*` 的请求/响应框架作为底层。

**阶段**:
- `WAIT_AUTHORIZE` → user-agent (client) 跳转至 `GET /authorize?response_type=code&client_id=...&redirect_uri=...&code_challenge=...`
- `REDIRECT_TO_CLIENT` → server 校验后 302 Location: `redirect_uri?code=AUTH_CODE&state=xyz`
- `TOKEN_EXCHANGE` → client POST `/token` with `code + code_verifier`
- `ACCESS_TOKEN_ISSUED` → server 返回 `access_token + refresh_token + expires_in`
- `RESOURCE_FETCH` → client GET `/api/user` with `Authorization: Bearer ACCESS_TOKEN`
- `REFRESH_TOKEN` → client POST `/token` with `grant_type=refresh_token`

**场景**:
- `auth-code`: 标准授权码流, 成功
- `pkce`: 带 PKCE, 演示 code_challenge 强制绑定 client
- `implicit-deprecated`: 隐式流 (直接返回 access_token in URL fragment), 演示为何废弃
- `token-replay`: 同一 code 第二次使用, server 拒绝

**安全事件日志**:
- `REDIRECT_URI_MISMATCH` (client 传来的 URI 不在 server 白名单)
- `PKCE_VERIFIER_FAILED` (code_verifier 与 code_challenge 对不上)
- `CODE_ALREADY_USED` / `CODE_EXPIRED` / `REPLAY_DETECTED`

### 5.3 MQTT (Message Queuing Telemetry Transport)

**学习目标**: pub/sub 模型 / QoS 0/1/2 区别 / retain 标志 / ACL / TLS 缺失 / 主题通配。

**Wire 协议**:
- 简化 MQTT 3.1.1 over TCP: 2-byte fixed header (control packet type 4b + flags 4b) + variable length (1-4 bytes) + payload
- 支持 CONNECT / CONNACK / PUBLISH / PUBACK / PUBREC / PUBREL / PUBCOMP / SUBSCRIBE / SUBACK / DISCONNECT
- 简化: 不实现 $SYS 主题和遗嘱

**场景**:
- `normal`: 订阅 `sensors/temp`, 发布 QoS 0
- `qos2-replay`: 同一 message id 收到两次 PUBREC, 演示 QoS 2 的 4 次握手防重放
- `unauth-subscribe`: client 未认证就订阅受限主题, server 拒绝
- `cleartext-eavesdrop`: 中间人模拟 (同一台机器上跑 tcpdump-like 拦截器), 演示明文可读

**安全事件日志**:
- `CONNECT_AUTH_FAILED` / `CONNACK_REFUSED`
- `SUBSCRIBE_DENIED` (无 ACL 权限)
- `PUBLISH_QOS_UPGRADE` (client QoS 0 实际按 QoS 1 处理, 演示不一致)
- `EAVESDROP_DETECTED` (教学模式下触发)

### 5.4 HTTP/2

**学习目标**: 二进制分帧层 / 多路复用 / HPACK 头部压缩 / 流量优先级 / 服务器推送 (push) / 流取消。

**Wire 协议**:
- 自定义二进制帧: 3B 长度 (24-bit) + 1B 类型 (DATA=0 / HEADERS=1 / PRIORITY=2 / RST_STREAM=3 / SETTINGS=4 / PING=6 / GOAWAY=7 / WINDOW_UPDATE=8) + 1B flag + 4B stream id (R bit + 31-bit) + payload
- HPACK: 简化版静态表 (61 项) + 动态表 + Huffman 编码 (literal 直接传字符串即可, 不必实装 Huffman)
- TCP 之上; 不实现 TLS (用 HTTP/2 prior knowledge, 即 h2c)

**场景**:
- `normal`: 单连接多 stream 并发请求 `/index.html` `/style.css` `/script.js`
- `multiplex`: 同一连接, 客户端发 6 个 stream, 服务端交错响应, 展示多路复用时延优势
- `hpack-overflow`: 客户端发超长 header name, 触发 server 拒绝 (RST_STREAM COMPRESSION_ERROR)
- `stream-cancellation`: 客户端中途取消一个 stream (RST_STREAM), 服务端停止该 stream

**安全事件日志**:
- `STREAM_OPENED` / `STREAM_CLOSED` / `STREAM_RESET` (with reason)
- `HPACK_DECODE_ERROR` / `FLOW_CONTROL_VIOLATION`
- `HEADERS_TOO_LARGE` (攻击: Slowloris 风格的 header 攻击)

### 5.5 SIP (Session Initiation Protocol)

**学习目标**: VoIP 信令 / INVITE 流程 / 注册劫持 / SIPS (over TLS) / 中继攻击。

**Wire 协议**:
- 文本协议 (类似 HTTP), 走 UDP 或 TCP
- 消息格式: `INVITE/2.0 SIP/2.0\r\nVia: ...\r\nFrom: ...\r\nTo: ...\r\nCall-ID: ...\r\nCSeq: ...\r\nContact: ...\r\nContent-Length: 0\r\n\r\n`
- 简化: 实现 INVITE / 100 Trying / 180 Ringing / 200 OK / ACK / BYE / REGISTER

**场景**:
- `register`: REGISTER → 200 OK, 模拟用户注册
- `invite-bye`: 完整 INVITE → 200 OK → ACK → BYE → 200 OK 流程
- `no-sips-downgrade`: client 走 sips:// (TLS) → server 强转为 sip:// (UDP), 警告
- `replay-invite`: 同一 Call-ID 收到第二次 INVITE, server 检测重放

**安全事件日志**:
- `REGISTER_ACCEPTED` / `REGISTER_REJECTED` (认证失败)
- `INVITE_RECEIVED` / `INVITE_REPLAY_DETECTED`
- `SIPS_DOWNGRADE_DETECTED`
- `VIA_HEADER_SPOOFED` (Via 字段与 source IP 不匹配)

### 5.6 RADIUS (Remote Authentication Dial-In User Service)

**学习目标**: AAA 框架 (Authentication / Authorization / Accounting) / 共享密钥 / PAP vs CHAP / 接入重放 / 字典攻击。

**Wire 协议**:
- 简化 RADIUS over UDP: 1B code + 1B id + 2B length + 1B authenticator (16B) + attributes (TLV)
- 实现: Access-Request (1) / Access-Accept (2) / Access-Reject (3) / Accounting-Request (4) / Accounting-Response (5)
- 共享密钥 HMAC-MD5 验证 Request Authenticator

**场景**:
- `normal`: 用户名 `alice` / 密码 `secret` → Access-Accept
- `shared-secret-leak`: server 与 NAS 配置不一致, client 收到 reject
- `chap-vs-pap`: PAP 明文密码 vs CHAP 挑战-响应, 演示 PAP 容易嗅探
- `replay-attack`: 抓取合法 Access-Request 重新发送, server 检测 Replay-Lock 不一致

**安全事件日志**:
- `ACCESS_REQUEST_SENT` / `ACCESS_ACCEPT_RECEIVED` / `ACCESS_REJECT_RECEIVED`
- `AUTHENTICATOR_INVALID` (共享密钥错)
- `REPLAY_DETECTED` (Authenticator 重复)
- `PASSWORD_SENT_IN_CLEARTEXT` (PAP 模式警告)

## 六、架构扩展

### 6.1 目录结构

```
protocols/
  catalog.json                 # 增加 7 个新协议
  dns/
    schema.json               # 阶段: IDLE → QUERY → RESPONSE
    scenarios.json            # 4 个场景
  oauth2/
  mqtt/
  http2/
  sip/
  radius/

src/
  dns_demo_server.c
  dns_demo_client.c
  oauth2_demo_server.c
  oauth2_demo_client.c
  mqtt_demo_server.c
  mqtt_demo_client.c
  http2_demo_server.c
  http2_demo_client.c
  sip_demo_server.c
  sip_demo_client.c
  radius_demo_server.c
  radius_demo_client.c

  dns_common.h                # (可选) 协议特定共享定义

web/
  (前端自动适配新协议, 无代码改动 — 走协议 schema 动态渲染)
```

### 6.2 catalog.json 扩展

```json
{
  "version": 2,
  "protocols": [
    { "id": "dns",    "name": "DNS",    "transport": "udp", "schema": "/protocols/dns/schema.json",    "scenarios": "/protocols/dns/scenarios.json",    "defaultScenario": "normal" },
    { "id": "oauth2", "name": "OAuth 2.0", "transport": "tcp", "schema": "/protocols/oauth2/schema.json", "scenarios": "/protocols/oauth2/scenarios.json", "defaultScenario": "auth-code" },
    ... 其余 5 个
  ]
}
```

### 6.3 HTTP API 扩展（最小）

- `/api/protocols` 返回 catalog.json 内容 — 现有 control_server 可直接读取本地文件
- 无需新 endpoint, 现有 `/api/server/start` `/api/client/start` 已经支持任意 (binary_path, env) 组合

### 6.4 前端 (最小改动)

- 协议下拉框自动从 catalog.json 加载, 新协议**自动出现**
- 协议摘要卡 (`renderProtocolSummaryCard`) 当前用 `protocolSummary` 通用模板, 新协议**自动支持**
- 阶段条 (`renderLifecycle`) 走 schema.json 的 `stages[]` 字段, **自动支持**
- 矩阵 (`renderFragmentMatrix`) 只对 file-view 协议显示; transaction / message 协议显示 protocol-event-list — **自动支持**

唯一**必须**改的: i18n 字符串 (每协议 4-6 个新 key, zh + en)。

### 6.5 control_server 扩展

control_server.c 需要:
- 增加 `oauth2` / `mqtt` / `http2` / `dns` / `sip` / `radius` 的 `server_binary_for_protocol` / `client_binary_for_protocol` 映射
- 每协议 6-10 行 C 代码, 总共 ~50 行新增

```c
static const char *server_binary_for_protocol(const char *proto) {
    if (!strcmp(proto, "dns"))    return "bin/dns_demo_server";
    if (!strcmp(proto, "oauth2")) return "bin/oauth2_demo_server";
    if (!strcmp(proto, "mqtt"))   return "bin/mqtt_demo_server";
    if (!strcmp(proto, "http2"))  return "bin/http2_demo_server";
    if (!strcmp(proto, "sip"))    return "bin/sip_demo_server";
    if (!strcmp(proto, "radius")) return "bin/radius_demo_server";
    return server_binary_for_protocol_legacy(proto);
}
```

## 七、实施路线

**Phase A (2 周) — DNS + OAuth 2.0**: 教学最核心的两个应用层安全协议
- DNS 是所有网络通信的基础
- OAuth 2.0 是现代 Web 应用最常见的鉴权漏洞靶子
- 优先暴露 DNS 缓存投毒 + OAuth 重定向 URI 校验 两个核心攻击

**Phase B (2 周) — MQTT + HTTP/2**: 现代化协议
- MQTT 引入 IoT/嵌入式视角
- HTTP/2 引入二进制协议工程化思维 (HPACK 压缩, 流量优先级)

**Phase C (1 周) — SIP + RADIUS**: 鉴权与实时
- SIP 引入 VoIP 与中继攻击
- RADIUS 补齐 AAA 协议

**Phase D (1 周, 备选) — Kerberos**: 期末项目 / 高级专题

## 八、测试策略

每个新协议:
1. 单元测试 (C-level): 帧解析、状态机、加密验证
2. 场景测试 (run_tests.py): 4 个场景中至少 3 个通过
3. 矩阵测试: packet_uid 在 server/client 跨端一致 (借鉴 QUIC bug 修复时的发现)
4. 端到端: 启动 control_server, 在 web 端验证 scenario 下拉框、阶段条、矩阵正确
5. 安全事件日志: 每个场景至少产生 1 个 "suspicious" / "denied" 事件, 让学生能看到告警

## 九、教学课程编排（建议顺序）

| 课时 | 协议 | 主题 |
|---|---|---|
| 1-3 | udp-basic / udp-reliable / tcp-basic | 传输层基础 + 可靠性 |
| 4-5 | tls-like | 加密信道 |
| 6-7 | http-basic / http2 | 应用层协议演化 |
| 8 | **dns** | 名字解析安全 |
| 9-10 | websocket / mqtt | 实时通信 |
| 11-12 | **oauth2** | 现代鉴权 |
| 13 | **sip** | 实时媒体信令 |
| 14 | **radius** | 接入认证 |
| 15 | quic / kerberos (选修) | 前沿 + 综合 |

## 十、风险评估

| 风险 | 缓解 |
|---|---|
| 协议实现细节差异大, 容易出现 TCP/UDP 边界 bug | 复用 `demo_util.c` 的 `demo_read_all` / `demo_write_all` / TCP 连接辅助 |
| 多场景测试用例膨胀, run_tests.py 变长 | 每个协议 3-4 个核心场景, 拒绝"广撒网" |
| 矩阵 (matrix) 对 transaction / message 协议不适用 | 已通过 `transferView` 字段分流, 无需新代码 |
| WebSocket / OAuth 等需要 HTTP 底层 | 复用 `http_demo_*` 的 HTTP 帧解析函数 |
| 测试机器上没装 TLS 库 (OpenSSL) | DoH 走 HTTP/1.1 over TCP 即可, 用现有的控制信道 mock TLS |
| 课堂时间紧, 6 个协议工作量太大 | 分 Phase 实施; 教师可按需启用 |

## 十一、不在第二阶段范围

- **IoT 短距协议** (BLE / Zigbee / LoRaWAN): 偏硬件, 课堂上难演示真实环境
- **P2P 协议** (BitTorrent / IPFS): 实现复杂, 演示价值不如应用层协议
- **底层路由协议** (BGP / OSPF): 需要虚拟网络环境, 教学复杂
- **后量子密码协议** (NTRU / Kyber): 学术前沿, 不在主流课程范围

## 十二、验收标准

每个新协议:
- [ ] 编译无 warning
- [ ] `run_tests.py` 增加该协议的测试, 至少 3 个场景 PASS
- [ ] `catalog.json` / `schema.json` / `scenarios.json` 三件套完整
- [ ] web 前端下拉框自动出现新协议
- [ ] 前端阶段条 / 摘要 / 矩阵 / 事件日志 全部正确渲染
- [ ] README 补充该协议的教学要点
- [ ] 测试日志中能找到该协议的安全告警事件

## 十三、关键决策记录

1. **不实现真实 TLS**: 复用控制信道的 HTTP/1.1 框架, TLS 协议只演示握手和加密语义, 不引入 OpenSSL 依赖
2. **不实现 IPv6 / SCTP / DCCP**: 课堂演示价值不高, 偏内核态
3. **二进制私有 wire 而非 RFC 字面**: 与现有 7 个协议保持一致, 教学 demo 不需要逐字节符合 RFC
4. **优先级: 教学价值 × 实现可行性**: 不做"看起来酷但讲不清"或"能讲清但太难实现"的协议
