# 下一阶段拓展计划书：多协议安全通信可视化平台

## 1. 项目定位

当前系统已经完成“基于 UDP 的简单安全通信协议”实验要求，并具备 Web 控制台、协议时序、包列表、传输进度、SHA1 校验、日志和测试模拟等能力。下一阶段建议将系统从单一 UDP 实验拓展为一个“多协议安全通信可视化平台”。

拓展目标不是简单堆叠更多客户端和服务端程序，而是把现有能力抽象成可复用平台：不同协议可以接入同一套启动控制、日志采集、协议时序、包字段解析、异常模拟和测试框架。这样系统可以继续用于课程展示、实验扩展、协议对比和安全机制演示。

## 2. 拓展方向建议

### 2.1 可靠 UDP 协议

在当前 UDP 文件传输协议上增加可靠传输机制：

- ACK / NACK 确认包
- 超时重传
- 滑动窗口
- 包去重
- 乱序缓存
- 简单流控

该方向最适合优先做，因为它直接延续当前 UDP 实现，能清晰展示“不可靠 UDP”到“可靠传输层”的演化过程。

可视化重点：

- DATA、ACK、NACK 的双向时序
- 丢包后重传路径
- 滑动窗口移动
- RTT、重传次数、有效吞吐率
- 乱序到达和重排序过程

### 2.2 TCP 对照模式

新增 TCP client/server，用相同文件和相同认证流程实现一版基于 TCP 的传输。

目标不是重做 TCP 协议栈，而是对比应用层在 UDP 和 TCP 上的设计差异：

- TCP 不需要自定义 packet_id 保证顺序
- TCP 是字节流，需要应用层 framing
- TCP 连接建立、断开和异常处理方式不同
- 相同认证逻辑在连接型传输上的实现更简单

可视化重点：

- TCP 连接生命周期
- 应用层消息 framing
- UDP packet 与 TCP stream segment 的概念差异
- 同一文件在 UDP / TCP 两种模式下的日志和指标对比

### 2.3 TLS-like 简化安全握手

在当前密码认证基础上设计一个教学版安全握手，不建议一开始实现完整 TLS。可以先做简化版本：

- ClientHello / ServerHello
- nonce 随机数
- 会话密钥派生
- HMAC 消息认证码
- 重放攻击检测
- 可选对称加密 DATA

如果允许引入依赖，可以考虑 OpenSSL 或 libsodium；如果希望保持实验项目纯 C、低依赖，可以先实现“教学版 HMAC + nonce 校验”，明确说明它不是生产级 TLS。

可视化重点：

- 握手阶段消息
- nonce、session key、MAC 校验状态
- 篡改包、重放包、错误 MAC 的异常流程
- 明文传输与认证/加密传输的对比

### 2.4 HTTP / WebSocket 应用协议演示

当前控制后端已经有 HTTP/WebSocket，可进一步把它纳入可视化体系：

- HTTP 请求/响应解析展示
- WebSocket 握手过程
- WebSocket 帧结构展示
- 同一个文件或消息通过 HTTP、WebSocket、UDP、TCP 的对比

这个方向适合增强系统的“协议博物馆”属性，让用户不仅看自定义 UDP 协议，也能理解常见应用层协议。

### 2.5 QUIC-like 教学模式

不建议直接实现完整 QUIC，复杂度过高。但可以做一个“QUIC-like 简化实验”：

- 基于 UDP
- 带连接 ID
- 多 stream 标识
- ACK 与重传
- 简化握手
- 0-RTT 概念演示

该部分可以作为高级拓展，用于展示现代协议为什么会选择在 UDP 之上重新构造可靠性和安全性。

## 3. 平台架构规划

### 3.1 协议适配器抽象

建议把不同协议接入统一抽象，而不是每新增一个协议就复制一套前端页面和后端控制逻辑。

每个协议模块提供：

- 协议名称和版本
- client/server 启动命令
- 配置字段定义
- 包类型定义
- 日志字段 schema
- 状态机阶段
- 时序图渲染规则
- 测试用例列表
- 异常模拟场景

示例结构：

```text
protocols/
  udp-basic/
    server
    client
    schema.json
    scenarios.json
  udp-reliable/
    server
    client
    schema.json
    scenarios.json
  tcp-basic/
    server
    client
    schema.json
    scenarios.json
```

### 3.2 日志 schema 升级

现有 JSON Lines 日志已经很好，下一步建议升级为通用协议日志 schema：

```json
{
  "time": "2026-06-16T12:00:00.000",
  "protocol": "udp-basic",
  "transport": "udp",
  "role": "client",
  "flow_id": "udp-basic-001",
  "session_id": "session-001",
  "direction": "client_to_server",
  "event": "SEND_DATA",
  "state": "DATA_TRANSFER",
  "packet_type": "DATA",
  "packet_id": 3,
  "seq": 3,
  "ack": 2,
  "stream_id": 0,
  "payload_length": 1000,
  "wire_hex": "0005000003e8...",
  "security": {
    "encrypted": false,
    "mac_valid": true,
    "replay": false
  },
  "message": "packet event"
}
```

这样前端可以稳定支持多协议筛选、flow 联动、时序图、包检查器和测试报告。

### 3.3 控制后端升级

控制后端可以从“固定 server/client 管理器”升级为“实验运行管理器”：

- 支持选择协议
- 支持选择场景
- 支持多组 client/server 运行
- 支持实验 run_id
- 支持读取协议 schema
- 支持统一启动、停止、重置、清空前端状态
- 支持异常模拟参数，例如丢包率、延迟、乱序、篡改、重放

短期仍可保持 C 控制后端，避免重构过大；如果后续功能继续膨胀，可以考虑将控制层迁移到 Python/FastAPI 或 Node.js，但协议核心仍保留 C 实现。

## 4. 前端功能规划

### 4.1 协议选择与场景面板

左侧控制台增加：

- 协议选择：UDP Basic、Reliable UDP、TCP Basic、TLS-like、HTTP/WebSocket、QUIC-like
- 场景选择：正常传输、认证失败、超时、丢包、乱序、篡改、重放、摘要不匹配
- 网络条件：延迟、丢包率、乱序率、重复包率
- 安全配置：明文、HMAC、加密、nonce 校验

### 4.2 多协议 Dashboard

Dashboard 不再只显示一次 UDP 传输，而是显示一次实验 run 的整体状态：

- 当前协议
- 当前场景
- 运行结果
- 传输进度
- 安全校验结果
- 异常数量
- 重传次数
- 平均 RTT
- 有效吞吐率

### 4.3 协议时序增强

协议时序图支持：

- 按 flow/session 显示
- 多角色显示，例如 Client、Server、Attacker、Proxy
- 折叠大量 DATA / ACK 包
- 高亮异常包
- 点击时序包联动 Packet Inspector
- 点击包列表切换对应 flow
- 支持“对比视图”，例如 UDP Basic vs Reliable UDP

### 4.4 Packet Inspector 升级

Packet Inspector 增加协议相关字段：

- transport
- flow_id / session_id
- seq / ack
- stream_id
- flags
- security status
- HMAC / digest 校验结果
- payload preview
- raw hex
- parsed fields

## 5. 测试与异常模拟规划

建议把测试分为三类。

### 5.1 正常功能测试

- UDP Basic 正常认证与传输
- Reliable UDP 丢包后仍能完成传输
- TCP Basic 正常传输
- TLS-like 握手成功
- HTTP/WebSocket 请求响应正常

### 5.2 异常协议测试

- 密码错误
- 超时
- 包类型未知
- payload length 错误
- DATA seq 不连续
- ACK 丢失
- 重复 DATA
- MAC 校验失败
- nonce 重放

### 5.3 可视化联动测试

- 包列表分页稳定
- 包列表点击后时序图切换 flow
- Packet Inspector 字段正确
- 折叠 DATA 展开/收起正常
- 测试输出只显示当前按钮结果
- 重置实验清空前端状态但不删除后端日志文件

## 6. 分阶段实施路线

### 第一阶段：平台化基础

目标：为多协议接入打底，不急着新增复杂协议。

任务：

- 定义通用日志 schema v2
- 给现有 UDP Basic 日志补充 protocol、transport、flow_id、session_id
- 把前端协议时序、包列表、Packet Inspector 改为读取 schema
- 增加协议选择器，但初期只有 UDP Basic
- 整理现有异常模拟为 scenario 配置

验收：

- 当前 UDP 实验功能不退化
- 前端能显示 protocol / flow / session
- 重置、日志、测试、包列表联动稳定

### 第二阶段：Reliable UDP

目标：在当前 UDP 上实现可靠传输机制。

任务：

- 新增 ACK 包和 NACK 包
- 实现超时重传
- 实现简单滑动窗口
- 支持丢包、乱序、重复包模拟
- 前端展示窗口移动、重传和 ACK 时序

验收：

- 在设定丢包率下仍能完成文件传输
- 日志能记录重传次数和 ACK 状态
- 前端能清晰展示丢包和重传过程

### 第三阶段：TCP Basic 对照

目标：加入 TCP 传输模式，形成 UDP/TCP 对比。

任务：

- 实现 TCP server/client
- 设计 TCP 应用层 framing
- 复用认证和 SHA1 校验
- 前端增加 UDP/TCP 对比视图
- 测试相同文件在两种协议下的结果和指标

验收：

- TCP 模式能完成认证、传输、校验
- 前端能解释 TCP stream 与 UDP packet 的差异
- 报告中能展示对比实验数据

### 第四阶段：TLS-like 安全机制

目标：从“密码认证”升级为“安全握手与消息认证”。

任务：

- 设计 ClientHello / ServerHello / Finished
- 加入 nonce
- 加入 session key 概念
- 加入 HMAC 校验
- 加入重放攻击模拟
- 前端展示握手阶段和安全校验状态

验收：

- 正常握手成功
- 篡改包会被检测
- 重放包会被拒绝
- 前端能展示安全失败原因

### 第五阶段：报告与演示完善

目标：将系统整理为可展示、可答辩、可继续开发的完整作品。

任务：

- 完成 README 和开发文档
- 输出协议对比表
- 输出测试覆盖表
- 准备演示场景脚本
- 准备截图和录屏
- 整理已知限制和未来方向

验收：

- 可以 5 到 8 分钟完整演示系统
- 可以解释每个协议模块的设计取舍
- 可以展示正常、异常、安全攻击三类实验

## 7. 优先级建议

建议优先顺序：

1. 日志 schema v2 和 flow/session 标识
2. Reliable UDP
3. TCP Basic
4. 可配置异常模拟
5. TLS-like 简化安全握手
6. HTTP/WebSocket 可视化
7. QUIC-like 教学模式

原因是 Reliable UDP 最贴近当前代码，收益明显，演示效果强；TCP Basic 适合作为对照组；TLS-like 能体现信息安全主题；QUIC-like 最吸引人，但复杂度也最高，应放在后面作为高级拓展。

## 8. 风险与控制

### 8.1 复杂协议不要一次做完整

TLS、QUIC、TCP 拥塞控制都很复杂。项目应明确采用“教学简化版”，重点展示核心机制，而不是宣称实现生产级协议。

### 8.2 保持现有实验功能稳定

当前 UDP Basic 是项目根基。新增协议时应保留现有命令行格式和测试，避免拓展破坏原实验验收。

### 8.3 日志字段必须先统一

多协议系统的难点不只是通信逻辑，而是展示逻辑。如果日志 schema 不统一，前端会变成大量特殊判断，后续很难维护。

### 8.4 异常模拟要可复现

丢包、乱序、延迟等模拟最好由固定 seed 控制，保证演示和测试结果稳定。

## 9. 预期成果

下一阶段完成后，系统可以从“UDP 安全通信实验”升级为：

- 多协议通信实验平台
- 协议时序可视化工具
- 文件传输可靠性对比工具
- 安全握手和攻击模拟演示工具
- 结构化日志与测试报告生成工具

最终展示重点可以从“我完成了一个 UDP 实验”提升为“我基于 UDP 实验构建了一个可扩展的协议可视化实验平台，并在其上实现了可靠传输、TCP 对照和安全握手机制”。

