const appState = {
  status: {},
  logs: [],
  /* allPackets: 所有 flow 中的所有包（包列表原始数据，含双端日志记录） */
  allPackets: [],
  /* realPackets: 基于 packet_uid 去重后的真实包（包列表主视图） */
  realPackets: [],
  /* packets: 当前 flow 的包（旧字段名保留，供 deriveRun 等使用） */
  packets: [],
  selectedPacket: null,
  tests: [],
  testMode: "idle",
  notice: "",
  activeTab: "dashboard",
  theme: "lab",
  language: "zh",
  sidebarCollapsed: false,
  clientRunStartedAt: 0,
  clientRunLogIndex: 0,
  interactiveClientActive: false,
  interactiveLastOutcome: null, // 记录上一次交互式客户端的结局：null / "manual_stop" / "auto_end"
  interactiveWaiting: false, // 仅在真正等待用户输入密码时为 true
  selectedFlowId: null,
  currentFlowId: null,       // 最近一次 flow（最近一次 server/client/sim 启动）
  lastFlowResult: null,      // 最近一次 flow 的结果：OK / ABORT / null
  lastFlowPhase: "INIT",     // 最近一次 flow 的阶段
  flowCounter: 0,            // 全局递增 ID
  sequenceExpandedFlows: new Set(),
  packetFilters: {
    query: "",
    type: "",
    direction: "",
  },
  pagination: {
    packets: 1,
    logs: 1,
  },
};

const PAGE_SIZE = 10;

const packetCodes = {
  JOIN_REQ: 1,
  PASS_REQ: 2,
  PASS_RESP: 3,
  PASS_ACCEPT: 4,
  DATA: 5,
  TERMINATE: 6,
  REJECT: 7,
};

const protocolStages = ["JOIN_REQ", "PASS_REQ", "PASS_RESP", "PASS_ACCEPT", "DATA", "TERMINATE"];

const i18n = {
  zh: {
    documentTitle: "UDP 安全传输实验台",
    appName: "UDP 安全传输实验台",
    console: "控制台",
    server: "服务端",
    client: "客户端",
    listenPort: "监听端口",
    authPassword: "认证密码",
    inputFilePath: "输入文件路径",
    outputFilePath: "输出文件路径",
    startServer: "启动服务端",
    stopServer: "停止服务端",
    passwordModeHint: "兼容三密码或交互式输入",
    serverHost: "服务端地址",
    serverPort: "服务端端口",
    compatPasswords: "兼容三密码",
    interactivePassword: "交互式密码",
    clientPwd1: "客户端密码 1",
    clientPwd2: "客户端密码 2",
    clientPwd3: "客户端密码 3",
    currentPassword: "本次密码",
    sendPassword: "发送密码",
    startClient: "启动客户端",
    stopClient: "停止客户端",
    experimentControl: "实验控制",
    runHint: "运行",
    resetRun: "重置实验",
    appearance: "界面设置",
    appearanceHint: "显示",
    language: "界面语言",
    themeSelect: "风格选择",
    themeGlass: "iOS 玻璃",
    themeMinimal: "极简浅色",
    themeGraphite: "极简深色",
    themeCyber: "赛博实验室",
    themeConsole: "深色控制台",
    themeSignal: "信号看板",
    topTitle: "最小安全通信协议控制台",
    tabDashboard: "仪表盘",
    tabProtocol: "协议",
    tabTransfer: "传输",
    tabLogs: "日志",
    currentRun: "当前运行",
    recentLogs: "最近日志",
    refreshLogs: "刷新日志",
    viewFullLogs: "查看完整日志",
    protocolSequence: "协议时序",
    clientEndpoint: "客户端",
    serverEndpoint: "服务端",
    packetDirectionTitle: "包方向",
    packetInspector: "包检查器",
    packetWireHint: "类型: 2B, 载荷长度: 4B",
    packetList: "包列表",
    allPacketTypes: "全部包类型",
    allDirections: "全部方向",
    clientToServer: "客户端到服务端",
    serverToClient: "服务端到客户端",
    observed: "观察到",
    time: "时间",
    direction: "方向",
    role: "角色",
    packet: "包",
    flowId: "Flow ID",
    payload: "载荷",
    packetId: "分片 ID / 说明",
    state: "状态",
    transferProgress: "传输进度",
    fragmentMatrix: "分片矩阵",
    fragmentHint: "每格代表一个 DATA packet_id",
    logFilters: "日志过滤",
    logFormatHint: "JSON 行日志",
    allRoles: "全部角色",
    serverRole: "服务端",
    clientRole: "客户端",
    controlRole: "控制端",
    allLevels: "全部级别",
    errorsOnly: "只看异常",
    realtimeLogs: "实时日志",
    level: "级别",
    event: "事件",
    message: "消息",
    logSource: "日志来源",
    pairedLogsTitle: "对端日志记录（调试信息）",
    packetFieldsTitle: "字段解析",
    pairedSenderLog: "发送端记录",
    pairedReceiverLog: "接收端记录",
    pairedOtherLog: "对端记录",
    testsAndSim: "测试与异常模拟",
    scriptResults: "自动脚本结果",
    runTests: "运行测试",
    simulateWrong: "模拟认证失败",
    simulateTimeout: "模拟超时",
    running: "运行中",
    stopped: "已停止",
    pending: "等待",
    ok: "成功",
    abort: "中止",
    statusServer: "服务端：{value}",
    statusClient: "客户端：{value}",
    statusPhase: "阶段：{value}",
    statusResult: "结果：{value}",
    railServerStatus: "服务端状态",
    railClientStatus: "客户端状态",
    railStartServer: "启动服务端",
    railStartClient: "启动客户端",
    railReset: "重置实验",
    collapseSidebar: "收起控制边栏",
    expandSidebar: "展开控制边栏",
    showPassword: "显示密码",
    hidePassword: "隐藏密码",
    waitStart: "等待启动",
    doneTitle: "传输完成，摘要匹配",
    abortTitle: "运行中止，请检查异常日志",
    currentPhase: "当前阶段：{phase}",
    passwordAttempt: "第 {current} / 3 次密码尝试",
    passwordAttemptHint: "请先启动交互式客户端",
    passwordAttemptReady: "等待输入密码",
    interactiveClientIdle: "客户端未启动",
    interactiveStartHint: "请先启动交互式客户端",
    authSucceeded: "认证成功，共尝试 {attempts} 次",
    authFailed: "认证失败，共尝试 {attempts} 次",
    authTimedOut: "连接超时，共尝试 {attempts} 次",
    authErrored: "运行异常，共尝试 {attempts} 次",
    clientStopped: "客户端已停止，共尝试 {attempts} 次",
    clientRunningStopped: "客户端已停止，共尝试 {attempts} 次",
    transferCompleted: "传输完成，认证共尝试 {attempts} 次",
    passwordAttemptWaiting: "第 {current} / 3 次密码尝试，等待输入密码",
    clientIdle: "客户端空闲",
    clientRunning: "客户端运行中",
    interactiveLastStopped: "上一轮已停止",
    interactiveLastEnded: "上一轮已结束",
    passwordAttemptComplete: "认证已完成，共尝试 {attempts} 次",
    passwordAttemptFailed: "认证已结束，共尝试 {attempts} 次",
    authSuccessHint: "认证已通过，等待数据开始传输",
    authFailedHint: "本轮认证已结束，请点击“启动客户端”开始新一轮",
    dashboardIntro: "启动服务端和客户端后，这里会展示认证、传输和校验结果。",
    dashboardSummary: "认证尝试 {attempts}/3，已接收 {bytes}。",
    phaseDone: "完成",
    phaseWaiting: "等待",
    phaseError: "异常",
    phaseNotStarted: "未开始",
    transferSummary: "传输摘要",
    received: "已接收",
    total: "总大小",
    dataPackets: "DATA 包",
    attempts: "尝试次数",
    sha1Digest: "SHA1 摘要",
    integrityCheck: "完整性校验",
    digestMatch: "摘要匹配",
    digestMismatch: "摘要不匹配",
    waiting: "等待",
    serverSha1: "服务端 SHA1",
    clientSha1: "客户端 SHA1",
    result: "结果",
    runStatus: "运行状态",
    httpWs: "HTTP/WebSocket",
    serverPid: "服务端 PID",
    clientPid: "客户端 PID",
    phase: "阶段",
    packetsNewest: "{filtered} 个包 · 最新优先",
    packetsFiltered: "{filtered} / {total} 个包 · 最新优先",
    noPackets: "暂无协议包。启动客户端后会出现 JOIN_REQ。",
    dataFolded: "已折叠 × {count}",
    dataFoldedRange: "DATA #{first} ... DATA #{last}",
    dataExpanded: "DATA 分片已展开",
    expandData: "点击展开",
    collapseData: "点击折叠",
    stageControl: "控制阶段",
    stageAuth: "认证阶段",
    stageData: "数据传输",
    stageFinal: "结束阶段",
    stageError: "错误结束",
    statusSent: "发送",
    statusSuccess: "完成",
    statusData: "传输",
    statusPacketError: "异常",
    selectPacket: "选择一个包查看 type、payload length、packet id 和原始十六进制字段。",
    typeCode: "类型码",
    payloadLength: "载荷长度",
    authPayloadLength: "认证载荷 {bytes} B",
    dataFragmentId: "DATA 分片 #{id}",
    noPacketId: "控制包无分片 ID",
    wireHex: "线缆十六进制",
    redactedPacket: "PASS_RESP 载荷已隐藏或原始包不可用",
    progress: "进度",
    sent: "已发送",
    packets: "包数量",
    logEntries: "{count} 条记录 · 最新优先",
    noLogs: "暂无日志。",
    testsEmpty: "尚未运行测试。",
    testsRunning: "测试运行中...",
    simulateAuthRunning: "认证失败模拟中...",
    simulateTimeoutRunning: "超时模拟中...",
    pageStatus: "第 {page} / {totalPages} 页 · 共 {total} 条",
    prevPage: "上一页",
    nextPage: "下一页",
    logSearchPlaceholder: "搜索事件、状态、消息",
    packetSearchPlaceholder: "搜索类型、包 ID、方向或关键字",
    inputPathEmpty: "输入文件路径不能为空。",
    outputPathEmpty: "输出文件路径不能为空。",
    inputPathRelativeOnly: "输入文件路径只支持相对路径。",
    outputPathRelativeOnly: "输出文件路径只支持相对路径。",
    serverStartFailed: "服务端启动失败。",
    clientStartFailed: "客户端启动失败。",
  },
  en: {
    documentTitle: "Secure UDP Transfer Lab",
    appName: "Secure UDP Transfer Lab",
    console: "Console",
    server: "Server",
    client: "Client",
    listenPort: "Listen port",
    authPassword: "Auth password",
    inputFilePath: "Input file path",
    outputFilePath: "Output file path",
    startServer: "Start server",
    stopServer: "Stop server",
    passwordModeHint: "Three-password compatibility or interactive input",
    serverHost: "Server host",
    serverPort: "Server port",
    compatPasswords: "Three-password mode",
    interactivePassword: "Interactive password",
    clientPwd1: "Client password 1",
    clientPwd2: "Client password 2",
    clientPwd3: "Client password 3",
    currentPassword: "Current password",
    sendPassword: "Send password",
    startClient: "Start client",
    stopClient: "Stop client",
    experimentControl: "Experiment control",
    runHint: "Run",
    resetRun: "Reset run",
    appearance: "Appearance",
    appearanceHint: "Display",
    language: "Language",
    themeSelect: "Theme",
    themeGlass: "iOS Glass",
    themeMinimal: "Minimal Light",
    themeGraphite: "Minimal Dark",
    themeCyber: "Cyber Lab",
    themeConsole: "Console Dark",
    themeSignal: "Signal Board",
    topTitle: "Minimal Secure Protocol Console",
    tabDashboard: "Dashboard",
    tabProtocol: "Protocol",
    tabTransfer: "Transfer",
    tabLogs: "Logs",
    currentRun: "Current Run",
    recentLogs: "Recent logs",
    refreshLogs: "Refresh logs",
    viewFullLogs: "View full logs",
    protocolSequence: "Protocol sequence",
    clientEndpoint: "CLIENT",
    serverEndpoint: "SERVER",
    packetDirectionTitle: "Packet direction",
    packetInspector: "Packet Inspector",
    packetWireHint: "Type: 2B, PayloadLen: 4B",
    packetList: "Packet list",
    allPacketTypes: "All packet types",
    allDirections: "All directions",
    clientToServer: "Client to Server",
    serverToClient: "Server to Client",
    observed: "Observed",
    time: "Time",
    direction: "Direction",
    role: "Role",
    packet: "Packet",
    flowId: "Flow ID",
    payload: "Payload",
    packetId: "Fragment ID / Note",
    state: "State",
    transferProgress: "Transfer progress",
    fragmentMatrix: "Fragment matrix",
    fragmentHint: "Each cell represents one DATA packet_id",
    logFilters: "Log filters",
    logFormatHint: "JSON Lines",
    allRoles: "All roles",
    serverRole: "server",
    clientRole: "client",
    controlRole: "control",
    allLevels: "All levels",
    errorsOnly: "Errors only",
    realtimeLogs: "Live logs",
    level: "Level",
    event: "Event",
    message: "Message",
    logSource: "Log source",
    pairedLogsTitle: "Peer-side log records (debug)",
    packetFieldsTitle: "Field parsing",
    pairedSenderLog: "Sender record",
    pairedReceiverLog: "Receiver record",
    pairedOtherLog: "Peer record",
    testsAndSim: "Tests & failure simulation",
    scriptResults: "Automated script results",
    runTests: "Run tests",
    simulateWrong: "Simulate wrong auth",
    simulateTimeout: "Simulate timeout",
    running: "Running",
    stopped: "Stopped",
    pending: "Pending",
    ok: "OK",
    abort: "Abort",
    statusServer: "Server: {value}",
    statusClient: "Client: {value}",
    statusPhase: "Phase: {value}",
    statusResult: "Result: {value}",
    railServerStatus: "Server status",
    railClientStatus: "Client status",
    railStartServer: "Start server",
    railStartClient: "Start client",
    railReset: "Reset run",
    collapseSidebar: "Collapse control sidebar",
    expandSidebar: "Expand control sidebar",
    showPassword: "Show password",
    hidePassword: "Hide password",
    waitStart: "Waiting to start",
    doneTitle: "Transfer complete, digests match",
    abortTitle: "Run aborted. Check the error logs.",
    currentPhase: "Current phase: {phase}",
    passwordAttempt: "Password attempt {current} / 3",
    passwordAttemptHint: "Start the interactive client first",
    passwordAttemptReady: "Waiting for password input",
    interactiveClientIdle: "Client not started",
    interactiveStartHint: "Start the interactive client first",
    authSucceeded: "Authenticated after {attempts} attempt(s)",
    authFailed: "Authentication failed after {attempts} attempt(s)",
    authTimedOut: "Connection timed out after {attempts} attempt(s)",
    authErrored: "Run errored after {attempts} attempt(s)",
    clientStopped: "Client stopped after {attempts} attempt(s)",
    clientRunningStopped: "Client stopped after {attempts} attempt(s)",
    transferCompleted: "Transfer complete, auth used {attempts} attempt(s)",
    passwordAttemptWaiting: "Password attempt {current} / 3, waiting for input",
    clientIdle: "Client idle",
    clientRunning: "Client running",
    interactiveLastStopped: "Last run was stopped",
    interactiveLastEnded: "Last run has ended",
    passwordAttemptComplete: "Authenticated after {attempts} attempt(s)",
    passwordAttemptFailed: "Authentication ended after {attempts} attempt(s)",
    authSuccessHint: "Authenticated, waiting for data transfer",
    authFailedHint: "This authentication round is over. Start a new client to try again.",
    dashboardIntro: "Start the server and client to inspect authentication, transfer, and verification results.",
    dashboardSummary: "Auth attempts {attempts}/3, received {bytes}.",
    phaseDone: "Done",
    phaseWaiting: "Waiting",
    phaseError: "Error",
    phaseNotStarted: "Not started",
    transferSummary: "Transfer summary",
    received: "Received",
    total: "Total",
    dataPackets: "DATA packets",
    attempts: "Attempts",
    sha1Digest: "SHA1 digest",
    integrityCheck: "Integrity check",
    digestMatch: "Digest match",
    digestMismatch: "Digest mismatch",
    waiting: "Waiting",
    serverSha1: "Server SHA1",
    clientSha1: "Client SHA1",
    result: "Result",
    runStatus: "Run status",
    httpWs: "HTTP/WebSocket",
    serverPid: "Server PID",
    clientPid: "Client PID",
    phase: "Phase",
    packetsNewest: "{filtered} packets · newest first",
    packetsFiltered: "{filtered} / {total} packets · newest first",
    noPackets: "No protocol packets yet. Start the client to see JOIN_REQ.",
    dataFolded: "Folded × {count}",
    dataFoldedRange: "DATA #{first} ... DATA #{last}",
    dataExpanded: "DATA fragments expanded",
    expandData: "Click to expand",
    collapseData: "Click to collapse",
    stageControl: "Control phase",
    stageAuth: "Authentication phase",
    stageData: "Data transfer",
    stageFinal: "Final phase",
    stageError: "Error final",
    statusSent: "Sent",
    statusSuccess: "Done",
    statusData: "Transfer",
    statusPacketError: "Error",
    selectPacket: "Select a packet to inspect type, payload length, packet id, and raw hex fields.",
    typeCode: "Type code",
    payloadLength: "Payload length",
    authPayloadLength: "Auth payload {bytes} B",
    dataFragmentId: "DATA fragment #{id}",
    noPacketId: "Control packet, no fragment ID",
    wireHex: "Wire Hex",
    redactedPacket: "PASS_RESP payload redacted or raw packet unavailable",
    progress: "Progress",
    sent: "Sent",
    packets: "Packets",
    logEntries: "{count} entries · newest first",
    noLogs: "No logs yet.",
    testsEmpty: "Tests have not run yet.",
    testsRunning: "Tests running...",
    simulateAuthRunning: "Auth failure simulation running...",
    simulateTimeoutRunning: "Timeout simulation running...",
    pageStatus: "Page {page} / {totalPages} · Total {total}",
    prevPage: "Previous",
    nextPage: "Next",
    logSearchPlaceholder: "Search event, state, message",
    packetSearchPlaceholder: "Search type, Packet ID, direction, or keyword",
    inputPathEmpty: "Input file path is required.",
    outputPathEmpty: "Output file path is required.",
    inputPathRelativeOnly: "Input file path must be relative.",
    outputPathRelativeOnly: "Output file path must be relative.",
    serverStartFailed: "Server start failed.",
    clientStartFailed: "Client start failed.",
  },
};

function byId(id) {
  return document.getElementById(id);
}

function t(key, values = {}) {
  const dictionary = i18n[appState.language] || i18n.zh;
  const fallback = i18n.en[key] || i18n.zh[key] || key;
  return String(dictionary[key] || fallback).replace(/\{(\w+)\}/g, (_, name) => values[name] ?? "");
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function formatBytes(bytes) {
  const value = Number(bytes || 0);
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 / 1024).toFixed(2)} MB`;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function logTimeMs(entry) {
  const value = Date.parse(entry?.time || "");
  return Number.isFinite(value) ? value : 0;
}

function logsSince(startedAt, fallbackIndex = 0) {
  if (!startedAt) return appState.logs;
  if (Number.isFinite(fallbackIndex)) {
    return appState.logs.slice(Math.min(Math.max(fallbackIndex, 0), appState.logs.length));
  }
  return appState.logs.filter((entry) => logTimeMs(entry) >= startedAt);
}

function beginInteractiveAttemptState() {
  appState.interactiveClientActive = true;
  appState.clientRunStartedAt = Date.now();
  appState.clientRunLogIndex = appState.logs.length;
}

function resetInteractiveAttemptState() {
  appState.interactiveClientActive = false;
  appState.clientRunStartedAt = 0;
  appState.clientRunLogIndex = appState.logs.length;
}

function resetFrontendRunState({clearFilters = false} = {}) {
  appState.logs = [];
  appState.packets = [];
  appState.allPackets = [];
  appState.realPackets = [];
  appState.selectedPacket = null;
  appState.interactiveLastOutcome = null;
  appState.selectedFlowId = null;
  appState.currentFlowId = null;
  appState.lastFlowResult = null;
  appState.lastFlowPhase = "INIT";
  appState.tests = [];
  appState.testMode = "idle";
  appState.sequenceExpandedFlows.clear();
  appState.pagination.packets = 1;
  appState.pagination.logs = 1;
  appState.notice = "";
  resetInteractiveAttemptState();
  if (clearFilters) {
    appState.packetFilters.query = "";
    appState.packetFilters.type = "";
    appState.packetFilters.direction = "";
    ["packet-search-filter", "packet-type-filter", "packet-direction-filter"].forEach((id) => {
      const node = byId(id);
      if (node) node.value = "";
    });
  }
}

function setTestRows(rows, mode = "manual") {
  appState.testMode = mode;
  appState.tests = rows.map((row) => ({
    id: row.id || row.name || "case",
    pass: row.pass,
  }));
  renderTests();
}

function timeoutSimulationPort(port) {
  const base = Number(port || 9000);
  const candidate = Number.isFinite(base) ? base + 41 : 9041;
  return String(Math.min(Math.max(candidate, 1024), 65535));
}

function resultLabel(result) {
  if (result === "OK") return t("ok");
  if (result === "ABORT") return t("abort");
  if (result === "Stopped") return t("stopped");
  return t("pending");
}

function phaseLabel(phase) {
  const labels = {
    INIT: appState.language === "zh" ? "初始" : "INIT",
    JOIN: appState.language === "zh" ? "握手" : "JOIN",
    AUTH: appState.language === "zh" ? "认证" : "AUTH",
    DATA_TRANSFER: appState.language === "zh" ? "数据传输" : "DATA_TRANSFER",
    VERIFY: appState.language === "zh" ? "校验" : "VERIFY",
    DONE: appState.language === "zh" ? "完成" : "DONE",
    ABORT: appState.language === "zh" ? "中止" : "ABORT",
  };
  return labels[phase] || phase;
}

function roleLabel(role) {
  if (appState.language !== "zh") return role || "-";
  if (role === "server") return "服务端";
  if (role === "client") return "客户端";
  if (role === "control") return "控制端";
  return role || "-";
}

function isAbsolutePath(path) {
  return path.startsWith("/") || path.startsWith("\\") || /^[A-Za-z]:[\\/]/.test(path);
}

function validateRelativePath(path, emptyKey, absoluteKey) {
  const clean = String(path || "").trim();
  if (!clean) return t(emptyKey);
  if (isAbsolutePath(clean)) return t(absoluteKey);
  return "";
}

function localizeError(message) {
  const text = String(message || "");
  if (appState.language !== "zh") return text;
  const replacements = [
    [/^input path is empty$/, "输入文件路径不能为空。"],
    [/^output path is empty$/, "输出文件路径不能为空。"],
    [/^input path must be relative: (.*)$/s, "输入文件路径只支持相对路径：$1"],
    [/^output path must be relative: (.*)$/s, "输出文件路径只支持相对路径：$1"],
    [/^input path is too long$/, "输入文件路径过长。"],
    [/^output path is too long$/, "输出文件路径过长。"],
    [/^input file not found: (.*)$/s, "输入文件不存在：$1"],
    [/^input path is not a regular file: (.*)$/s, "输入路径不是普通文件：$1"],
    [/^input file is not readable: (.*)$/s, "输入文件不可读：$1"],
    [/^output directory not found: (.*)$/s, "输出目录不存在：$1"],
    [/^output parent is not a directory: (.*)$/s, "输出路径的父级不是目录：$1"],
    [/^output directory is not writable: (.*)$/s, "输出目录不可写：$1"],
    [/^output path is a directory: (.*)$/s, "输出路径不能是目录：$1"],
    [/^output file is not writable: (.*)$/s, "输出文件不可写：$1"],
    [/^server already running or failed$/, "服务端已在运行或启动失败。"],
    [/^client already running or failed$/, "客户端已在运行或启动失败。"],
  ];
  for (const [pattern, replacement] of replacements) {
    if (pattern.test(text)) return text.replace(pattern, replacement);
  }
  return text;
}

function logKey(entry) {
  return [
    entry.time,
    entry.role,
    entry.event,
    entry.packet_type,
    entry.packet_id ?? "",
    entry.message ?? "",
  ].join("|");
}

function peerPort(peer) {
  const match = String(peer || "").match(/:(\d+)$/);
  return match ? match[1] : "";
}

// 生成新的 Flow ID：每次 server/client/test 启动都生成一个独立 flow
// 一次传输尝试 = 一次 flow；成功 / 失败 / 超时 / 认证失败都共享同一个 flow
function generateFlowId(prefix = "flow", entry) {
  appState.flowCounter += 1;
  const port = (entry && (entry.port || peerPort(entry.peer))) || (appState.status.server?.port || appState.status.client?.port) || "udp";
  return `${prefix}-${appState.flowCounter.toString().padStart(4, "0")}-${port}`;
}

// 用户主动启动 server 时调用：
//   不在此处预生成 flow_id，避免与 ensureFlowIds 中的实际 stamp 冲突。
//   真正的 flow_id 由 ensureFlowIds 在收到 SERVER_START 日志时确定（单一来源），
//   并同步到 appState.currentFlowId。
//   同时清空 selectedFlowId，使新 run 默认成为"最近一次流"，不会沿用用户上一次点击的旧流。
function beginServerFlow() {
  appState.currentFlowId = null;
  appState.selectedFlowId = null;
  appState.lastFlowResult = null;
  appState.lastFlowPhase = "INIT";
  return null;
}

// 用户主动启动 client 时调用 -> 等 SERVER_START 的 flow_id 被收到
function beginClientFlow() {
  appState.currentFlowId = null;
  appState.selectedFlowId = null;
  appState.lastFlowResult = null;
  appState.lastFlowPhase = "INIT";
  return null;
}

// 测试/模拟开始时调用 -> 等第一次 SERVER_START / CLIENT_START 决定 flow_id
function beginSimulationFlow() {
  appState.currentFlowId = null;
  appState.selectedFlowId = null;
  appState.lastFlowResult = null;
  appState.lastFlowPhase = "INIT";
  return null;
}

function ensureFlowIds() {
  // 一次传输尝试 = 一次 flow：服务端启动 + 客户端在该端口的尝试 = 同一个 flow
  // 每个 SERVER_START 创建新 server flow；CLIENT_START 复用同端口的 server flow（若存在）
  // 这样 sequence / dashboard 能完整看到双向包；新一次客户端尝试自动开新 flow
  const serverFlowsByPort = new Map();
  let activeServerFlow = null;
  let lastEventFinal = null;

  appState.logs.forEach((entry) => {
    if (entry.flow_id && /^flow-\d{4}-/.test(entry.flow_id)) {
      const port = String(entry.port || peerPort(entry.peer) || "");
      if (entry.role === "server" && entry.event === "SERVER_START" && port) {
        serverFlowsByPort.set(port, entry.flow_id);
        activeServerFlow = entry.flow_id;
      }
      if (entry.event === "FINAL_OK" || entry.event === "FINAL_ABORT") {
        lastEventFinal = entry;
      }
      return;
    }

    let flowId = null;
    const port = String(entry.port || peerPort(entry.peer) || "");

    if (entry.role === "server" && entry.event === "SERVER_START") {
      flowId = generateFlowId("flow", entry);
      if (port) serverFlowsByPort.set(port, flowId);
      activeServerFlow = flowId;
    } else if (entry.role === "client" && entry.event === "CLIENT_START") {
      if (port && serverFlowsByPort.has(port)) {
        flowId = serverFlowsByPort.get(port);
      } else {
        flowId = generateFlowId("flow", entry);
      }
    } else if (entry.role === "server" && activeServerFlow) {
      flowId = activeServerFlow;
    } else if (entry.role === "client") {
      // 客户端后续日志：找最近同端口的 client flow
      const recent = findLatestClientFlowForPort(port);
      if (recent) flowId = recent;
    }

    if (flowId) {
      entry.flow_id = flowId;
      entry.session_id = flowId;
    }
    if (entry.event === "FINAL_OK" || entry.event === "FINAL_ABORT") {
      lastEventFinal = entry;
    }
  });

  // currentFlowId：取最近一个被 stamp 的 flow
  let mostRecent = null;
  for (let i = appState.logs.length - 1; i >= 0; i -= 1) {
    if (appState.logs[i].flow_id) {
      mostRecent = appState.logs[i].flow_id;
      break;
    }
  }
  // 仅有当用户没有显式选中某个 flow 时，才自动跟随最新 flow。
  // 用户在包列表点击某个包后 selectedFlowId 会被设置，协议时序应锁定到该 flow，
  // 不会因为后续日志到达而跳回"最近一次流"。
  if (mostRecent && !appState.selectedFlowId && mostRecent !== appState.currentFlowId) {
    appState.currentFlowId = mostRecent;
  } else if (mostRecent && appState.selectedFlowId && mostRecent !== appState.selectedFlowId) {
    // 用户选中的 flow 仍以 selectedFlowId 为准；仅同步 currentFlowId 给派生计算用
    appState.currentFlowId = appState.selectedFlowId;
  }

  // 同步 lastFlowResult
  if (lastEventFinal && lastEventFinal.flow_id === appState.currentFlowId) {
    appState.lastFlowResult = lastEventFinal.result || (lastEventFinal.event === "FINAL_OK" ? "OK" : "ABORT");
  }
}

function findLatestClientFlowForPort(port) {
  const wantPort = String(port || "");
  if (!wantPort) return null;
  for (let i = appState.logs.length - 1; i >= 0; i -= 1) {
    const e = appState.logs[i];
    if (e.role === "client" && e.event === "CLIENT_START" && e.flow_id) {
      const ePort = String(e.port || peerPort(e.peer) || "");
      if (ePort === wantPort) return e.flow_id;
    }
  }
  return null;
}

function mergeLogs(entries) {
  const seen = new Set(appState.logs.map(logKey));
  for (const entry of entries) {
    if (!entry || !entry.time) continue;
    if (!seen.has(logKey(entry))) {
      appState.logs.push(entry);
      seen.add(logKey(entry));
    }
  }
  appState.logs.sort((a, b) => String(a.time).localeCompare(String(b.time)));
  appState.logs = appState.logs.slice(-1200);
  ensureFlowIds();
  // allPackets: 所有 flow 的包（包列表使用，不过滤 currentFlowId）
  appState.allPackets = appState.logs.filter((entry) => entry.packet_type);
  // realPackets: 基于后端 packet_uid 去重后的真实包；同一 wire 包仅出现一次
  appState.realPackets = buildRealPackets(appState.allPackets);
  // packets: 保留兼容旧引用；按 currentFlowId 过滤
  appState.packets = appState.currentFlowId
    ? appState.allPackets.filter((entry) => entry.flow_id === appState.currentFlowId)
    : appState.allPackets;
  if (appState.selectedFlowId && !appState.packets.some((entry) => entry.flow_id === appState.selectedFlowId)) {
    appState.selectedFlowId = null;
    appState.selectedPacket = null;
  }
}

/**
 * 基于后端 packet_uid 字段对包去重；同 wire 包在 client/server 两端产生相同 uid。
 * - 关键：去重 key 必须包含 flow_id；不同 run 相同输入会得到相同 packet_uid，
 *   若忽略 flow_id 就会把跨 run 的包错合并掉。
 * - 降级（无 packet_uid 的旧日志）：按 (flow_id, packet_type, packet_id, time_window)
 *   - 同一组内保留最早一条（通常是 SEND 端），并把其它端作为 `paired_logs` 备用
 */
function buildRealPackets(allPackets) {
  const groups = new Map();
  for (const entry of allPackets) {
    if (!entry.packet_type) continue;
    const flowId = entry.flow_id || "unknown";
    let key = entry.packet_uid
      ? `${flowId}|${entry.packet_uid}`
      : `${flowId}|${entry.packet_type}|${entry.packet_id ?? ""}|${Math.floor(logTimeMs(entry) / 1500)}`;
    if (!groups.has(key)) {
      groups.set(key, { canonical: entry, paired: [] });
    } else {
      groups.get(key).paired.push(entry);
    }
  }
  return Array.from(groups.values()).map((g) => {
    g.canonical.paired_logs = g.paired;
    return g.canonical;
  });
}

function latest(predicate) {
  for (let i = appState.logs.length - 1; i >= 0; i -= 1) {
    if (predicate(appState.logs[i])) return appState.logs[i];
  }
  return null;
}

function deriveRun() {
  // 只统计最近一次 flow 的日志
  const flowId = appState.currentFlowId;
  const flowLogs = flowId
    ? appState.logs.filter((entry) => entry.flow_id === flowId)
    : appState.logs;
  const flowPackets = flowId
    ? appState.packets.filter((entry) => entry.flow_id === flowId)
    : appState.packets;

  const inFlow = (entry) => !flowId || entry.flow_id === flowId;
  const flowLatest = (predicate) => {
    for (let i = flowLogs.length - 1; i >= 0; i -= 1) {
      if (predicate(flowLogs[i])) return flowLogs[i];
    }
    return null;
  };

  const finalEvent = flowLatest((entry) => entry.event === "FINAL_OK" || entry.event === "FINAL_ABORT");
  let result = finalEvent?.result || "Pending";
  // 当最近一次 flow 已经走到 FINAL_OK/FINAL_ABORT，重置时如果 appState 被清空，应当显示初始态
  if (!flowId) result = "Pending";
  // 同步到 lastFlowResult，供控制台运行状态使用
  if (finalEvent && finalEvent.flow_id === flowId) {
    appState.lastFlowResult = finalEvent.result || (finalEvent.event === "FINAL_OK" ? "OK" : "ABORT");
  }
  const hasAbort = result === "ABORT" || flowLogs.some((entry) => entry.level === "ERROR" || entry.level === "ABORT");
  let phase = "INIT";
  if (hasAbort && result === "ABORT") phase = "ABORT";
  else if (flowLatest((entry) => entry.event === "DIGEST_MATCH")) phase = "DONE";
  else if (flowLatest((entry) => entry.packet_type === "TERMINATE")) phase = "VERIFY";
  else if (flowLatest((entry) => entry.packet_type === "DATA")) phase = "DATA_TRANSFER";
  else if (flowLatest((entry) => ["PASS_REQ", "PASS_RESP", "PASS_ACCEPT", "REJECT"].includes(entry.packet_type))) phase = "AUTH";
  else if (flowLatest((entry) => entry.packet_type === "JOIN_REQ")) phase = "JOIN";
  appState.lastFlowPhase = phase;

  const serverDigest = flowLatest((entry) => entry.event === "SERVER_DIGEST" && entry.sha1);
  const clientDigest = flowLatest((entry) => (entry.event === "DIGEST_MATCH" || entry.event === "DIGEST_MISMATCH") && entry.sha1);
  const dataRecv = flowPackets.filter((entry) => entry.role === "client" && entry.packet_type === "DATA");
  const dataSent = flowPackets.filter((entry) => entry.role === "server" && entry.packet_type === "DATA");
  const inputStart = flowLatest((entry) => entry.event === "SERVER_START");
  const receivedBytes = dataRecv.reduce((sum, entry) => sum + Number(entry.bytes || entry.payload_length || 0), 0);
  const sentBytes = dataSent.reduce((sum, entry) => sum + Number(entry.bytes || entry.payload_length || 0), 0);
  const totalBytes = Number(inputStart?.bytes || Math.max(receivedBytes, sentBytes, 0));
  const attempts = Math.max(0, ...flowLogs.map((entry) => Number(entry.attempt || 0)));
  const progress = totalBytes > 0 ? Math.min(100, Math.round((receivedBytes / totalBytes) * 100)) : result === "OK" ? 100 : 0;
  const firstData = dataRecv[0];
  const lastData = dataRecv[dataRecv.length - 1];
  let throughput = 0;
  if (firstData && lastData) {
    const start = new Date(firstData.time).getTime();
    const end = new Date(lastData.time).getTime();
    const elapsed = Math.max(1, end - start) / 1000;
    throughput = receivedBytes / elapsed;
  }

  return {
    result,
    phase,
    attempts,
    serverDigest: serverDigest?.sha1 || "",
    clientDigest: clientDigest?.sha1 || "",
    digestMatch: Boolean(clientDigest && clientDigest.event === "DIGEST_MATCH"),
    dataRecv,
    dataSent,
    receivedBytes,
    sentBytes,
    totalBytes,
    progress,
    throughput,
    finalEvent,
    flowId,
  };
}

function packetDirection(entry) {
  // 优先用后端直接给出的 direction 字段（权威值）
  const direct = entry && entry.direction;
  if (direct === "Client -> Server" || direct === "Server -> Client" || direct === "Observed") {
    return direct;
  }
  // 回退：基于 role+event 推断（兼容旧日志）
  const event = (entry && entry.event) || "";
  const role = entry && entry.role;
  if (role === "client" && event.startsWith("SEND")) return "Client -> Server";
  if (role === "server" && event.startsWith("RECV")) return "Client -> Server";
  if (role === "server" && event.startsWith("SEND")) return "Server -> Client";
  if (role === "client" && event.startsWith("RECV")) return "Server -> Client";
  return "Observed";
}

function packetDirectionLabel(entry) {
  const direction = packetDirection(entry);
  if (direction === "Client -> Server") return t("clientToServer");
  if (direction === "Server -> Client") return t("serverToClient");
  return t("observed");
}

function packetDirectionText(entry) {
  return packetDirectionLabel(entry);
}

function packetIdentifier(entry) {
  if (entry.packet_type === "DATA" && entry.packet_id !== undefined) {
    return {
      text: t("dataFragmentId", {id: entry.packet_id}),
      title: appState.language === "zh"
        ? "DATA 包头中的 32 位 packet_id，用于校验分片顺序"
        : "32-bit packet_id from the DATA header, used to verify fragment order",
    };
  }
  if (entry.packet_type === "PASS_RESP" && entry.payload_length !== undefined) {
    return {
      text: t("authPayloadLength", {bytes: entry.payload_length}),
      title: appState.language === "zh"
        ? "PASS_RESP 没有 packet_id，这里显示隐藏后的密码载荷长度"
        : "PASS_RESP has no packet_id. This shows the redacted password payload length.",
    };
  }
  return {
    text: "-",
    title: t("noPacketId"),
  };
}

function packetFlowClass(entry) {
  const direction = packetDirection(entry);
  if (direction === "Client -> Server") return "flow-to-server";
  if (direction === "Server -> Client") return "flow-to-client";
  return "flow-observed";
}

function packetTypeClass(type) {
  return `type-${String(type || "unknown").toLowerCase().replaceAll("_", "-")}`;
}

function packetStage(type) {
  if (type === "JOIN_REQ") return "control";
  if (["PASS_REQ", "PASS_RESP", "PASS_ACCEPT"].includes(type)) return "auth";
  if (type === "DATA") return "data";
  if (["TERMINATE", "REJECT"].includes(type)) return "final";
  return "control";
}

function packetStageLabel(type) {
  const stage = packetStage(type);
  if (stage === "control") return t("stageControl");
  if (stage === "auth") return t("stageAuth");
  if (stage === "data") return t("stageData");
  return type === "REJECT" ? t("stageError") : t("stageFinal");
}

function sameProtocolMessage(a, b) {
  if (!a || !b) return false;
  if (a === b) return true;
  if (a.flow_id !== b.flow_id) return false;
  if (a.packet_type !== b.packet_type) return false;
  if (packetDirection(a) !== packetDirection(b)) return false;
  if (a.packet_type === "DATA") {
    return Number(a.packet_id) === Number(b.packet_id);
  }
  if (a.packet_id !== undefined || b.packet_id !== undefined) {
    return Number(a.packet_id) === Number(b.packet_id);
  }
  return true;
}

function sequenceHighlightEntry(flowId) {
  const selected = appState.selectedPacket;
  if (!selected || selected.flow_id !== flowId) return null;
  // 现在时序中包含所有 packet 事件；只要选中包在时序里就直接返回
  const flowPackets = packetsForFlow(flowId);
  if (flowPackets.includes(selected)) return selected;
  // 否则按 message 匹配最近的等价包
  const selectedTime = logTimeMs(selected);
  const candidates = flowPackets
    .filter((entry) => sameProtocolMessage(entry, selected))
    .sort((a, b) => Math.abs(logTimeMs(a) - selectedTime) - Math.abs(logTimeMs(b) - selectedTime));
  return candidates[0] || selected;
}

function packetStatus(entry) {
  if (entry.packet_type === "REJECT" || ["ERROR", "ABORT", "WARN"].includes(entry.level)) {
    return {className: "error", label: t("statusPacketError")};
  }
  if (entry.packet_type === "PASS_ACCEPT" || entry.packet_type === "TERMINATE") {
    return {className: "success", label: t("statusSuccess")};
  }
  if (entry.packet_type === "DATA") {
    return {className: "data", label: t("statusData")};
  }
  return {className: "sent", label: t("statusSent")};
}

function isSendPacket(entry) {
  return Boolean(entry.packet_type && String(entry.event || "").startsWith("SEND"));
}

function latestFlowId() {
  // 优先看 allPackets（跨 flow），保证能拿到最近的 flow
  const source = appState.allPackets.length ? appState.allPackets : appState.packets;
  for (let i = source.length - 1; i >= 0; i -= 1) {
    if (source[i].flow_id) return source[i].flow_id;
  }
  return null;
}

function currentSequenceFlowId() {
  // 1) 显式选中的 flow
  if (appState.selectedFlowId) {
    const source = appState.allPackets.length ? appState.allPackets : appState.packets;
    if (source.some((entry) => entry.flow_id === appState.selectedFlowId)) {
      return appState.selectedFlowId;
    }
  }
  // 2) currentFlowId（最近一次启动的 flow）
  if (appState.currentFlowId) return appState.currentFlowId;
  // 3) 最近一次出现过的 flow
  return latestFlowId();
}

function packetsForFlow(flowId) {
  // 使用 realPackets（去重后的真实包）作为源；按 flowId 过滤
  const source = appState.realPackets.length ? appState.realPackets : appState.packets;
  if (!flowId) return source;
  return source.filter((entry) => entry.flow_id === flowId);
}

function sequencePackets(flowId) {
  // 协议时序与包列表共享同一份数据：realPackets（已按 (flow_id, packet_uid) 去重）。
  // 这样时序与列表的 data-packet-index 索引、selectedPacket 引用都一致，点击高亮同步。
  const flowRealPackets = appState.realPackets.filter(
    (entry) => !flowId || entry.flow_id === flowId
  );
  // realPackets 已经按 (flow_id, packet_uid) 跨端去重，每个 wire 包恰好一条。
  // 这里再做一次按时间排序、把对端 paired 记录挂到 canonical 上即可。
  const sorted = [...flowRealPackets].sort((a, b) => logTimeMs(a) - logTimeMs(b));
  const packets = sorted.map((entry) => {
    // 找同 (flow_id, packet_uid) 但 role 不同的对端记录作为 paired
    if (!entry.packet_uid) {
      return entry;
    }
    const paired = appState.realPackets.filter(
      (e) => e !== entry && e.flow_id === entry.flow_id && e.packet_uid === entry.packet_uid
    );
    if (paired.length) {
      entry.paired_logs = paired;
    }
    return entry;
  });
  const dataPackets = packets.filter((entry) => entry.packet_type === "DATA");
  const expanded = flowId ? appState.sequenceExpandedFlows.has(flowId) : false;
  const shouldFoldData = !expanded && dataPackets.length > 4;
  const firstData = dataPackets.slice(0, 3);
  const lastData = dataPackets.length > 4 ? dataPackets[dataPackets.length - 1] : null;
  const displayedData = shouldFoldData ? new Set([...firstData, lastData].filter(Boolean)) : new Set(dataPackets);
  const result = [];
  let insertedEllipsis = false;
  let insertedToggle = false;

  packets.forEach((entry) => {
    if (entry.packet_type !== "DATA") {
      result.push({kind: "packet", entry});
      return;
    }
    if (expanded && dataPackets.length > 4 && !insertedToggle) {
      result.push({kind: "toggle", expanded: true, count: dataPackets.length});
      insertedToggle = true;
    }
    if (displayedData.has(entry)) {
      result.push({kind: "packet", entry});
      return;
    }
    if (!insertedEllipsis) {
      const folded = dataPackets.filter((packet) => !displayedData.has(packet));
      result.push({
        kind: "ellipsis",
        count: folded.length,
        firstId: folded[0]?.packet_id ?? firstData.at(-1)?.packet_id ?? 0,
        lastId: folded.at(-1)?.packet_id ?? lastData?.packet_id ?? 0,
      });
      insertedEllipsis = true;
    }
  });

  return result;
}

function paginateNewest(items, requestedPage) {
  const total = items.length;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const currentPage = Math.min(Math.max(Number(requestedPage) || 1, 1), totalPages);
  const newestFirst = items.map((item, index) => ({item, index})).reverse();
  const start = (currentPage - 1) * PAGE_SIZE;
  return {
    page: currentPage,
    total,
    totalPages,
    rows: newestFirst.slice(start, start + PAGE_SIZE),
  };
}

function renderPager(container, target, page, totalPages, total) {
  container.innerHTML = `
    <button class="pager-button" data-page-target="${target}" data-page-delta="-1" type="button" ${page <= 1 ? "disabled" : ""}>${t("prevPage")}</button>
    <span class="pager-status">${t("pageStatus", {page, totalPages, total})}</span>
    <button class="pager-button" data-page-target="${target}" data-page-delta="1" type="button" ${page >= totalPages ? "disabled" : ""}>${t("nextPage")}</button>
  `;
}

function setSidebarCollapsed(collapsed) {
  appState.sidebarCollapsed = collapsed;
  byId("app-shell").classList.toggle("sidebar-collapsed", collapsed);
  const toggle = byId("sidebar-toggle");
  toggle.setAttribute("aria-expanded", String(!collapsed));
  toggle.title = collapsed ? t("expandSidebar") : t("collapseSidebar");
  toggle.setAttribute("aria-label", toggle.title);
  try {
    localStorage.setItem("udpLabSidebarCollapsed", collapsed ? "1" : "0");
  } catch (error) {
    console.warn(error);
  }
}

function setTheme(theme) {
  const target = (theme && window.ThemeManager && window.ThemeManager.themes.some((t) => t.id === theme))
    ? theme
    : (window.ThemeManager ? window.ThemeManager.defaultTheme : "neumorph");
  appState.theme = target;
  if (window.ThemeManager) {
    window.ThemeManager.set(target);
  } else {
    document.documentElement.dataset.theme = target;
  }
  try {
    localStorage.setItem("udpLabTheme", target);
  } catch (error) {
    console.warn(error);
  }
}

function syncPasswordToggleText(button) {
  const input = button.closest(".password-field")?.querySelector("input");
  const visible = input?.type === "text";
  const label = visible ? t("hidePassword") : t("showPassword");
  button.setAttribute("aria-label", label);
  button.title = label;
}

function applyLanguage() {
  document.documentElement.lang = appState.language === "zh" ? "zh-CN" : "en";
  document.title = t("documentTitle");
  document.querySelectorAll("[data-i18n]").forEach((node) => {
    node.textContent = t(node.dataset.i18n);
  });
  const languageSelect = byId("language-select");
  if (languageSelect) languageSelect.value = appState.language;
  const searchFilter = byId("search-filter");
  if (searchFilter) searchFilter.placeholder = t("logSearchPlaceholder");
  const packetSearch = byId("packet-search-filter");
  if (packetSearch) packetSearch.placeholder = t("packetSearchPlaceholder");
  [
    ["rail-server-status", "railServerStatus"],
    ["rail-client-status", "railClientStatus"],
    ["rail-start-server-btn", "railStartServer"],
    ["rail-start-client-btn", "railStartClient"],
    ["rail-reset-btn", "railReset"],
  ].forEach(([id, key]) => {
    const node = byId(id);
    if (!node) return;
    node.title = t(key);
    node.setAttribute("aria-label", t(key));
  });
  document.querySelectorAll(".password-toggle").forEach(syncPasswordToggleText);
  setSidebarCollapsed(appState.sidebarCollapsed);
}

function setLanguage(language, rerender = true) {
  appState.language = language === "en" ? "en" : "zh";
  try {
    localStorage.setItem("udpLabLanguage", appState.language);
  } catch (error) {
    console.warn(error);
  }
  applyLanguage();
  // 主题卡片标签随语言刷新
  if (window.ThemeManager && typeof window.ThemeManager.refreshLabels === "function") {
    window.ThemeManager.refreshLabels(appState.language);
  }
  if (rerender) render();
}

function setNotice(message) {
  appState.notice = message || "";
  renderConfig(deriveRun());
}

function syncPasswordMode() {
  const mode = document.querySelector("input[name='mode']:checked")?.value || "compat";
  const compatPanel = byId("compat-passwords");
  const interactivePanel = byId("interactive-password-panel");
  const compat = mode === "compat";
  compatPanel.classList.toggle("is-hidden", !compat);
  interactivePanel.classList.toggle("is-hidden", compat);
  compatPanel.querySelectorAll("input").forEach((input) => {
    input.disabled = !compat;
  });
}

function updateTopbar(run) {
  const serverRunning = appState.status.server?.running;
  const clientRunning = appState.status.client?.running;
  byId("server-pill").textContent = t("statusServer", {value: serverRunning ? t("running") : t("stopped")});
  byId("client-pill").textContent = t("statusClient", {value: clientRunning ? t("running") : t("stopped")});
  // 阶段和结果显示最近一次 flow 的状态
  const displayPhase = appState.currentFlowId ? run.phase : "INIT";
  const displayResult = appState.currentFlowId
    ? (appState.lastFlowResult || run.result)
    : "Pending";
  byId("phase-pill").textContent = t("statusPhase", {value: phaseLabel(displayPhase)});
  byId("result-pill").textContent = t("statusResult", {value: resultLabel(displayResult)});
  byId("server-pill").classList.toggle("is-running", Boolean(serverRunning));
  byId("client-pill").classList.toggle("is-running", Boolean(clientRunning));
  byId("result-pill").classList.toggle("is-running", displayResult === "OK");
  byId("result-pill").classList.toggle("is-abort", displayResult === "ABORT");
  byId("server-dot").classList.toggle("is-running", Boolean(serverRunning));
  byId("client-dot").classList.toggle("is-running", Boolean(clientRunning));
}

function renderPhases(run) {
  const completed = new Set(appState.packets.map((entry) => entry.packet_type));
  const current = protocolStages.find((stage) => !completed.has(stage));
  return protocolStages.map((stage) => {
    const status = run.result === "ABORT" && stage === current ? "fail" : completed.has(stage) ? "done" : stage === current ? "current" : "";
    return `
      <div class="phase-step ${status}">
        <strong>${stage}</strong>
        <div class="bar"><span></span></div>
        <span>${status === "done" ? t("phaseDone") : status === "current" ? t("phaseWaiting") : status === "fail" ? t("phaseError") : t("phaseNotStarted")}</span>
      </div>
    `;
  }).join("");
}

function renderDashboard(run) {
  byId("dashboard-title").textContent =
    run.result === "OK" ? t("doneTitle") :
    run.result === "ABORT" ? t("abortTitle") :
    run.phase === "INIT" ? t("waitStart") : t("currentPhase", {phase: phaseLabel(run.phase)});
  byId("dashboard-summary").textContent =
    run.phase === "INIT" ? t("dashboardIntro") : t("dashboardSummary", {attempts: run.attempts, bytes: formatBytes(run.receivedBytes)});
  byId("dashboard-phases").innerHTML = renderPhases(run);
  byId("metrics-panel").innerHTML = `
    <div class="panel-head"><h2>${t("transferSummary")}</h2><span class="hint">${run.progress}%</span></div>
    <div class="metric-grid">
      <div class="metric"><span>${t("received")}</span><strong>${formatBytes(run.receivedBytes)}</strong></div>
      <div class="metric"><span>${t("total")}</span><strong>${formatBytes(run.totalBytes)}</strong></div>
      <div class="metric"><span>${t("dataPackets")}</span><strong>${run.dataRecv.length}</strong></div>
      <div class="metric"><span>${t("attempts")}</span><strong>${run.attempts}/3</strong></div>
    </div>
  `;
  byId("digest-panel").innerHTML = digestMarkup(run, t("sha1Digest"));
  // 仪表盘"最近日志"也只显示当前 flow
  const flowLogs = appState.currentFlowId
    ? appState.logs.filter((e) => e.flow_id === appState.currentFlowId)
    : [];
  renderLogList(byId("recent-logs"), flowLogs.slice(-8), true);
}

function digestMarkup(run, title) {
  const state = run.clientDigest ? (run.digestMatch ? t("digestMatch") : t("digestMismatch")) : t("waiting");
  const badgeClass = run.digestMatch ? "success" : run.clientDigest ? "danger" : "";
  return `
    <div class="panel-head"><h2>${title}</h2><span class="badge ${badgeClass}">${state}</span></div>
    <div class="digest-lines">
      <div class="digest-line"><span>${t("serverSha1")}</span><code>${escapeHtml(run.serverDigest || t("waiting"))}</code></div>
      <div class="digest-line"><span>${t("clientSha1")}</span><code>${escapeHtml(run.clientDigest || t("waiting"))}</code></div>
      <div class="digest-line"><span>${t("result")}</span><code>${escapeHtml(resultLabel(run.result))}</code></div>
    </div>
  `;
}

function renderConfig(run) {
  // 控制台"运行状态"显示最近一次 flow 的结果，直到点击"重置实验"
  const displayResult = appState.lastFlowResult || (appState.currentFlowId ? run.result : "Pending");
  byId("config-state").innerHTML = `
    <div class="panel-head"><h2>${t("runStatus")}</h2><span class="hint">${t("httpWs")}</span></div>
    ${appState.notice ? `<div class="notice danger">${escapeHtml(appState.notice)}</div>` : ""}
    <div class="metric-grid">
      <div class="metric"><span>${t("serverPid")}</span><strong>${escapeHtml(appState.status.server?.pid || "-")}</strong></div>
      <div class="metric"><span>${t("clientPid")}</span><strong>${escapeHtml(appState.status.client?.pid || "-")}</strong></div>
      <div class="metric"><span>${t("phase")}</span><strong>${phaseLabel(appState.currentFlowId ? run.phase : "INIT")}</strong></div>
      <div class="metric"><span>${t("result")}</span><strong>${resultLabel(displayResult)}</strong></div>
    </div>
  `;
}

function renderInteractiveAttempt(run) {
  const attemptNode = byId("interactive-attempt");
  if (!attemptNode) return;

  // 0) 空闲：未启动交互式客户端（或已被停止 / 完成）
  if (!appState.interactiveClientActive) {
    attemptNode.classList.remove("is-waiting", "is-success", "is-danger", "is-stopped", "is-timeout", "is-error");
    attemptNode.classList.add("is-idle");
    const lastOutcome = appState.interactiveLastOutcome;
    let hint = t("interactiveStartHint");
    if (lastOutcome === "manual_stop") {
      hint = t("interactiveLastStopped");
    } else if (lastOutcome === "auto_end") {
      hint = t("interactiveLastEnded");
    }
    attemptNode.innerHTML = `
      <span>${escapeHtml(t("clientIdle"))}</span>
      <small>${escapeHtml(hint)}</small>
    `;
    return;
  }

  // 1) 仅统计本次启动之后的日志，限定到 current flow
  const scopedLogs = appState.clientRunStartedAt
    ? logsSince(appState.clientRunStartedAt, appState.clientRunLogIndex)
    : appState.logs;
  const flowScoped = scopedLogs.filter(
    (entry) => !appState.currentFlowId || entry.flow_id === appState.currentFlowId
  );
  // 已尝试次数 = 当前 flow 中最大的 attempt 值（取最小 3）
  const attempts = Math.min(
    Math.max(0, ...flowScoped.map((entry) => Number(entry.attempt || 0))),
    3
  );
  const hasSuccess = flowScoped.some(
    (entry) => entry.event === "AUTH_SUCCESS" || entry.packet_type === "PASS_ACCEPT"
  );
  const hasFail = flowScoped.some((entry) => entry.event === "AUTH_FAIL");
  const hasReject = flowScoped.some((entry) => entry.packet_type === "REJECT");
  const hasFinalOk = flowScoped.some((entry) => entry.event === "FINAL_OK");
  const hasFinalAbort = flowScoped.some(
    (entry) => entry.event === "FINAL_ABORT" || entry.result === "ABORT"
  );
  const hasTimeout = flowScoped.some((entry) => entry.event === "TIMEOUT");
  const hasError = flowScoped.some(
    (entry) =>
      entry.level === "ERROR" &&
      entry.event !== "AUTH_FAIL" &&
      !hasFinalAbort &&
      !hasTimeout
  );
  const clientStillRunning = Boolean(appState.status.client?.running);
  // 用户主动停止（按钮点击）：当 interactiveClientActive 为 true 但 client 不再运行，且没有 FINAL 事件
  const manuallyStopped = appState.interactiveClientActive && !clientStillRunning &&
    !hasFinalOk && !hasFinalAbort && !hasSuccess && !hasFail && attempts < 3;
  // 等待输入中：客户端运行中 & 没有终态
  const waiting = clientStillRunning && !hasSuccess && !hasReject && !hasFinalOk && !hasFinalAbort && !hasTimeout;

  let title = "";
  let hint = "";
  let stateClass = "is-waiting";
  // attempts 的合理显示：若已 success/done，至少 1；其他情况按实际
  const displayAttempts = Math.max(attempts, hasSuccess || hasFinalOk ? 1 : 0);
  if (hasFinalOk) {
    // 4) 一次传输正常结束
    title = t("transferCompleted", {attempts: displayAttempts});
    stateClass = "is-success";
    hint = "";
  } else if (hasSuccess) {
    // 3) 认证成功
    title = t("authSucceeded", {attempts: displayAttempts});
    stateClass = "is-success";
    hint = "";
  } else if (hasReject) {
    // 4) 三次认证失败（服务端发 REJECT）
    title = t("authFailed", {attempts: 3});
    stateClass = "is-danger";
    hint = "";
  } else if (hasTimeout) {
    // 7) 连接超时
    title = t("authTimedOut", {attempts: displayAttempts});
    stateClass = "is-timeout";
    hint = "";
  } else if (hasFinalAbort && hasError) {
    // 8) 运行异常
    title = t("authErrored", {attempts: displayAttempts});
    stateClass = "is-error";
    hint = "";
  } else if (hasFinalAbort) {
    title = t("authFailed", {attempts: displayAttempts});
    stateClass = "is-danger";
    hint = "";
  } else if (manuallyStopped) {
    // 5) 手动停止客户端：保留"上一轮已停止"上下文
    appState.interactiveLastOutcome = "manual_stop";
    title = t("clientRunningStopped", {attempts: displayAttempts});
    stateClass = "is-stopped";
    hint = "";
  } else if (waiting) {
    // 1) 等待输入密码
    const nextAttempt = Math.min(Math.max(attempts + 1, 1), 3);
    title = t("passwordAttemptWaiting", {current: nextAttempt});
    hint = "";
    stateClass = "is-waiting";
  } else {
    // 兜底（运行中但尚未等待输入）
    title = t("clientRunning");
    hint = "";
    stateClass = "is-waiting";
  }

  attemptNode.classList.remove(
    "is-waiting", "is-success", "is-danger", "is-stopped",
    "is-timeout", "is-error", "is-idle"
  );
  attemptNode.classList.add(stateClass);
  attemptNode.innerHTML = hint
    ? `<span>${escapeHtml(title)}</span><small>${escapeHtml(hint)}</small>`
    : `<span>${escapeHtml(title)}</span>`;

  // 终态事件触发后，更新 idle 上下文，便于下次进入 idle 时展示
  if (manuallyStopped) {
    appState.interactiveLastOutcome = "manual_stop";
  } else if (hasFinalOk || hasReject || hasTimeout || hasError || hasFinalAbort) {
    appState.interactiveLastOutcome = "auto_end";
  }
}

function filteredPackets() {
  // 包列表展示所有 flow 的真实包（去重后）
  const source = appState.realPackets.length ? appState.realPackets : appState.packets;
  const query = appState.packetFilters.query.trim().toLowerCase();
  const type = appState.packetFilters.type;
  const direction = appState.packetFilters.direction;
  return source.filter((entry) => {
    const rawDirection = packetDirection(entry);
    const haystack = [
      entry.time,
      entry.event,
      entry.state,
      entry.message,
      entry.packet_type,
      entry.packet_id,
      entry.flow_id,
      entry.packet_uid,
      entry.session_id,
      rawDirection,
      packetDirectionText(entry),
      entry.payload_length,
    ].join(" ").toLowerCase();
    if (type && entry.packet_type !== type) return false;
    if (direction && rawDirection !== direction) return false;
    if (query && !haystack.includes(query)) return false;
    return true;
  });
}

function renderProtocol() {
  const packets = filteredPackets();
  const packetPage = paginateNewest(packets, appState.pagination.packets);
  const sequenceFlowId = currentSequenceFlowId();
  const sequenceItems = sequencePackets(sequenceFlowId);
  const highlightedPacket = sequenceHighlightEntry(sequenceFlowId);
  appState.pagination.packets = packetPage.page;
  // 包列表显示所有 flow 的真实包（去重后）；"X / Y" 中的 Y 用 realPackets 总数
  const allCount = appState.realPackets.length;
  byId("packet-count").textContent = packets.length === allCount
    ? t("packetsNewest", {filtered: packets.length})
    : t("packetsFiltered", {filtered: packets.length, total: allCount});
  byId("sequence-view").innerHTML = sequenceItems.map((item) => {
    if (item.kind === "toggle") {
      return `
        <div class="sequence-row sequence-gap flow-to-client">
          <span class="endpoint client is-target">${t("clientEndpoint")}</span>
          <button class="sequence-line flow-to-client stage-data is-ellipsis sequence-toggle" data-sequence-toggle="${escapeHtml(sequenceFlowId || "")}" type="button">
            <span class="status-icon data" aria-hidden="true"></span>
            <strong>${escapeHtml(t("dataExpanded"))}</strong>
            <span class="flow-meta">${escapeHtml(t("collapseData"))}</span>
          </button>
          <span class="endpoint server is-source">${t("serverEndpoint")}</span>
        </div>
      `;
    }
    if (item.kind === "ellipsis") {
      return `
        <div class="sequence-row sequence-gap flow-to-client">
          <span class="endpoint client is-target">${t("clientEndpoint")}</span>
          <button class="sequence-line flow-to-client stage-data is-ellipsis sequence-toggle" data-sequence-toggle="${escapeHtml(sequenceFlowId || "")}" type="button">
            <span class="status-icon data" aria-hidden="true"></span>
            <strong>${escapeHtml(t("dataFoldedRange", {first: item.firstId, last: item.lastId}))}</strong>
            <span class="flow-meta">${escapeHtml(t("dataFolded", {count: item.count}))} · ${escapeHtml(t("expandData"))}</span>
          </button>
          <span class="endpoint server is-source">${t("serverEndpoint")}</span>
        </div>
      `;
    }
    const entry = item.entry;
    const direction = packetDirection(entry);
    const flowClass = packetFlowClass(entry);
    const toServer = direction === "Client -> Server";
    const toClient = direction === "Server -> Client";
    // 共享数据源：realPackets（已去重），点击时序列与列表都用同一索引
    const packetIndex = appState.realPackets.indexOf(entry);
    const selected = entry === highlightedPacket ? "is-selected" : "";
    const status = packetStatus(entry);
    const messageName = `${entry.packet_type}${entry.packet_id !== undefined ? ` #${entry.packet_id}` : ""}`;
    return `
      <div class="sequence-row ${flowClass} ${selected}">
        <span class="endpoint client ${toServer ? "is-source" : toClient ? "is-target" : ""}">${t("clientEndpoint")}</span>
        <button class="sequence-line ${flowClass} stage-${packetStage(entry.packet_type)} ${packetTypeClass(entry.packet_type)}" data-packet-index="${packetIndex}" type="button" aria-label="${escapeHtml(messageName)} ${escapeHtml(packetDirectionLabel(entry))}">
          <span class="status-icon ${status.className}" title="${status.label}" aria-hidden="true"></span>
          <strong>${escapeHtml(messageName)}</strong>
          <span class="flow-meta">${escapeHtml(packetStageLabel(entry.packet_type))}</span>
        </button>
        <span class="endpoint server ${toClient ? "is-source" : toServer ? "is-target" : ""}">${t("serverEndpoint")}</span>
      </div>
    `;
  }).join("") || `<p class="inspector-empty">${t("noPackets")}</p>`;

  byId("packet-table-body").innerHTML = packetPage.rows.map(({item: entry}) => {
    const sourceIndex = appState.realPackets.indexOf(entry);
    const identifier = packetIdentifier(entry);
    const directionText = packetDirectionText(entry);
    const packetCode = packetCodes[entry.packet_type] || entry.packet_code || 0;
    const packetTitle = `${entry.packet_type || "-"} · UID ${entry.packet_uid || "-"}`.trim();
    return `
    <tr data-packet-index="${sourceIndex}" class="${appState.selectedPacket === entry ? "is-selected" : ""}">
      <td class="num-cell" title="${sourceIndex + 1}">${sourceIndex + 1}</td>
      <td class="mono" title="${escapeHtml(entry.time)}">${escapeHtml(entry.time)}</td>
      <td class="mono col-flow-cell" title="${escapeHtml(entry.flow_id || "-")}">${escapeHtml(entry.flow_id || "-")}</td>
      <td class="packet-cell" title="${escapeHtml(packetTitle)}">${escapeHtml(entry.packet_type)}</td>
      <td title="${escapeHtml(directionText)}">${escapeHtml(directionText)}</td>
      <td class="num-cell" title="${packetCode}">${packetCode}</td>
      <td class="num-cell" title="${escapeHtml(entry.payload_length ?? "-")}">${escapeHtml(entry.payload_length ?? "-")}</td>
      <td title="${escapeHtml(identifier.title)}">${escapeHtml(identifier.text)}</td>
      <td title="${escapeHtml(entry.state || "-")}">${escapeHtml(entry.state || "-")}</td>
    </tr>
  `;
  }).join("");
  renderPager(byId("packet-pager"), "packets", packetPage.page, packetPage.totalPages, packetPage.total);
  renderInspector();
}

function renderInspector() {
  const source = appState.realPackets.length ? appState.realPackets : appState.packets;
  const packet = appState.selectedPacket || source[source.length - 1];
  if (!packet) {
    byId("packet-inspector").innerHTML = `<p class="inspector-empty">${t("selectPacket")}</p>`;
    return;
  }
  const wireHex = packet.wire_hex || t("redactedPacket");
  // 解析出的协议字段合并到主 field-list（不再单独区块）
  const parsed = parsePacketFields(packet);
  const mainRows = [
    {label: t("packet"), value: escapeHtml(packet.packet_type)},
    {label: t("flowId"), value: escapeHtml(packet.flow_id || "-"), mono: true},
    {label: t("direction"), value: escapeHtml(packetDirectionText(packet))},
    {label: t("typeCode"), value: String(packetCodes[packet.packet_type] || packet.packet_code || "?")},
    {label: t("payloadLength"), value: `${escapeHtml(packet.payload_length ?? 0)} B`},
    {label: t("packetId"), value: escapeHtml(packetIdentifier(packet).text), title: escapeHtml(packetIdentifier(packet).title)},
    {label: t("state"), value: escapeHtml(packet.state || "-")},
    {label: t("time"), value: escapeHtml(packet.time), mono: true},
  ];
  // 追加 wire-level 协议字段（如 DATA 的 packet_id / payload hex，TERMINATE 的 SHA1）
  parsed.forEach((row) => {
    mainRows.push({label: row.label, value: row.value, mono: true});
  });
  byId("packet-inspector").innerHTML = `
    <div class="field-list">
      ${mainRows.map((r) => `
        <div><span>${r.label}</span><strong${r.mono ? ' class="mono"' : ""}${r.title ? ` title="${r.title}"` : ""}>${r.value}</strong></div>
      `).join("")}
    </div>
    <h3 class="inspector-subhead">${t("wireHex")}</h3>
    <code class="packet-hex">${escapeHtml(wireHex)}</code>
  `;
}

/**
 * 按 packet_type 解析 wire_hex，得到该包的结构化字段
 * 不依赖运行时模糊字符串匹配；优先用后端给的 wire_hex（如果可用）
 */
function parsePacketFields(packet) {
  const hex = String(packet.wire_hex || "").replace(/\s+/g, "");
  const fields = [];
  if (!hex) return fields;
  // 通用：packet_uid
  if (packet.packet_uid) {
    fields.push({label: "packet_uid", value: packet.packet_uid});
  }
  // 通用：direction
  fields.push({label: "direction", value: packetDirectionText(packet)});
  // 按包类型解析
  const type = packet.packet_type;
  if (type === "DATA") {
    // DATA: type(2) + payload_len(4) + packet_id(4) + payload
    if (hex.length >= 20) {
      const typeHex = hex.slice(0, 4);
      const lenHex = hex.slice(4, 12);
      const idHex = hex.slice(12, 20);
      const payloadHex = hex.slice(20);
      fields.push({label: "wire.type", value: `${typeHex} (${parseInt(typeHex, 16)})`});
      fields.push({label: "wire.payload_length", value: `${parseInt(lenHex, 16)} B`});
      fields.push({label: "wire.packet_id", value: `${parseInt(idHex, 16)}`});
      fields.push({label: "wire.payload", value: payloadHex ? `${payloadHex.slice(0, 64)}${payloadHex.length > 64 ? "…" : ""}` : "(empty)"});
    }
  } else if (type === "TERMINATE") {
    // TERMINATE: type(2) + payload_len(4) + SHA1(20 bytes)
    if (hex.length >= 12) {
      const typeHex = hex.slice(0, 4);
      const lenHex = hex.slice(4, 12);
      const digestHex = hex.slice(12, 52);
      fields.push({label: "wire.type", value: `${typeHex} (${parseInt(typeHex, 16)})`});
      fields.push({label: "wire.payload_length", value: `${parseInt(lenHex, 16)} B`});
      fields.push({label: "wire.sha1", value: digestHex || "(missing)"});
    }
  } else if (type === "PASS_RESP") {
    if (hex.length >= 12) {
      const typeHex = hex.slice(0, 4);
      const lenHex = hex.slice(4, 12);
      fields.push({label: "wire.type", value: `${typeHex} (${parseInt(typeHex, 16)})`});
      fields.push({label: "wire.payload_length", value: `${parseInt(lenHex, 16)} B`});
      fields.push({label: "wire.payload", value: "(redacted: password)"});
    }
  } else {
    // JOIN_REQ / PASS_REQ / PASS_ACCEPT / REJECT: type(2) + payload_len(4) [+ payload]
    if (hex.length >= 12) {
      const typeHex = hex.slice(0, 4);
      const lenHex = hex.slice(4, 12);
      const payloadLen = parseInt(lenHex, 16);
      fields.push({label: "wire.type", value: `${typeHex} (${parseInt(typeHex, 16)})`});
      fields.push({label: "wire.payload_length", value: `${payloadLen} B`});
      const rest = hex.slice(12);
      if (rest && payloadLen > 0) {
        fields.push({label: "wire.payload", value: `${rest.slice(0, 64)}${rest.length > 64 ? "…" : ""}`});
      }
    }
  }
  return fields;
}

function renderTransfer(run) {
  byId("transfer-progress").style.width = `${run.progress}%`;
  byId("throughput-label").textContent = `${formatBytes(Math.round(run.throughput))}/s`;
  byId("transfer-stats").innerHTML = `
    <div class="metric"><span>${t("progress")}</span><strong>${run.progress}%</strong></div>
    <div class="metric"><span>${t("received")}</span><strong>${formatBytes(run.receivedBytes)}</strong></div>
    <div class="metric"><span>${t("sent")}</span><strong>${formatBytes(run.sentBytes)}</strong></div>
    <div class="metric"><span>${t("packets")}</span><strong>${run.dataRecv.length}</strong></div>
  `;
  const ids = run.dataRecv.map((entry) => Number(entry.packet_id || 0));
  const maxId = ids.length ? Math.max(...ids) : 0;
  const cells = Math.max(maxId + 1, run.result === "Pending" ? 24 : ids.length);
  const received = new Set(ids);
  byId("fragment-matrix").innerHTML = Array.from({length: Math.min(Math.max(cells, 1), 400)}, (_, id) => {
    const cls = received.has(id) ? "received" : "";
    return `<button class="fragment ${cls}" title="DATA #${id}" data-fragment-id="${id}" type="button"></button>`;
  }).join("");
  byId("transfer-digest").innerHTML = digestMarkup(run, t("integrityCheck"));
}

function filteredLogs() {
  const role = byId("role-filter")?.value || "";
  const level = byId("level-filter")?.value || "";
  const search = (byId("search-filter")?.value || "").toLowerCase();
  const errorOnly = byId("error-only")?.checked;
  return appState.logs.filter((entry) => {
    const haystack = `${entry.event || ""} ${entry.state || ""} ${entry.message || ""} ${entry.packet_type || ""} ${roleLabel(entry.role)}`.toLowerCase();
    if (role && entry.role !== role) return false;
    if (level && entry.level !== level) return false;
    if (errorOnly && !["ERROR", "ABORT", "WARN"].includes(entry.level)) return false;
    if (search && !haystack.includes(search)) return false;
    return true;
  });
}

function renderLogList(container, logs, compact = false) {
  container.innerHTML = logs.map((entry) => {
    const isError = ["ERROR", "ABORT", "WARN"].includes(entry.level);
    const roleEvent = `${roleLabel(entry.role)} · ${entry.event || "-"}`;
    const message = compact ? (entry.message || entry.packet_type || "") : `${entry.state || ""} ${entry.packet_type || ""} ${entry.message || ""}`.trim();
    return `
      <div class="log-entry ${isError ? "error" : ""}">
        <span class="mono" title="${escapeHtml(entry.time)}">${escapeHtml(entry.time)}</span>
        <strong title="${escapeHtml(entry.level)}">${escapeHtml(entry.level)}</strong>
        <span title="${escapeHtml(roleEvent)}">${escapeHtml(roleEvent)}</span>
        <span class="log-message" title="${escapeHtml(message)}">${escapeHtml(message)}</span>
      </div>
    `;
  }).join("") || `<p class="inspector-empty">${t("noLogs")}</p>`;
}

// 实时日志：标准表格 + 表头，5 列（时间 / 级别 / 角色 / 事件 / 消息）
function renderLogTable(tbody, logs) {
  if (!tbody) return;
  tbody.innerHTML = logs.map((entry) => {
    const isError = ["ERROR", "ABORT", "WARN"].includes(entry.level);
    const message = `${entry.state || ""} ${entry.packet_type || ""} ${entry.message || ""}`.trim() || "-";
    return `
      <tr class="log-row ${isError ? "is-error" : ""}">
        <td class="mono col-time" title="${escapeHtml(entry.time)}">${escapeHtml(entry.time)}</td>
        <td class="col-level"><span class="log-level log-level-${escapeHtml(String(entry.level || "INFO").toLowerCase())}">${escapeHtml(entry.level || "-")}</span></td>
        <td class="col-role" title="${escapeHtml(entry.role || "-")}">${escapeHtml(roleLabel(entry.role))}</td>
        <td class="col-event" title="${escapeHtml(entry.event || "-")}">${escapeHtml(entry.event || "-")}</td>
        <td class="col-message" title="${escapeHtml(message)}">${escapeHtml(message)}</td>
      </tr>
    `;
  }).join("") || `<tr><td colspan="5" class="inspector-empty">${t("noLogs")}</td></tr>`;
}

function renderLogs() {
  const logs = filteredLogs();
  const logPage = paginateNewest(logs, appState.pagination.logs);
  appState.pagination.logs = logPage.page;
  byId("log-count").textContent = t("logEntries", {count: logs.length});
  renderLogTable(byId("full-log-tbody"), logPage.rows.map((row) => row.item));
  renderPager(byId("log-pager"), "logs", logPage.page, logPage.totalPages, logPage.total);
}

function renderTests() {
  byId("test-results").innerHTML = appState.tests.map((test) => `
    <div class="test-row">
      <strong>${escapeHtml(test.id || "case")}</strong>
      <span class="badge ${test.pass ? "success" : test.pass === false ? "danger" : ""}">${test.pass ? "PASS" : test.pass === false ? "FAIL" : "RUNNING"}</span>
    </div>
  `).join("") || `<p class="inspector-empty">${t("testsEmpty")}</p>`;
}

function render() {
  const run = deriveRun();
  updateTopbar(run);
  renderDashboard(run);
  renderConfig(run);
  renderInteractiveAttempt(run);
  renderProtocol();
  renderTransfer(run);
  renderLogs();
  renderTests();
  // 暴露给 theme-manager.js
  window.render = render;
}

async function refreshStatus() {
  appState.status = await window.Api.status();
  render();
}

async function refreshLogs() {
  const data = await window.Api.logs();
  mergeLogs([...(data.server || []), ...(data.client || []), ...(data.control || [])]);
  await refreshPackets();
  render();
}

/**
 * 从后端 /api/packets 拉取结构化包数据。
 * 这是包列表和协议时序的权威数据源——独立于普通 log，方便隔离日志噪声。
 * 失败时（例如后端尚未建立 packets.jsonl）静默回退到从 logs 推断。
 */
async function refreshPackets() {
  try {
    const data = await window.Api.packets();
    if (data && Array.isArray(data.packets)) {
      // 把后端 packets 写回 appState.logs（去重），触发 ensureFlowIds
      const existingKeys = new Set(appState.logs.map(logKey));
      let added = 0;
      for (const p of data.packets) {
        if (!existingKeys.has(logKey(p))) {
          appState.logs.push(p);
          existingKeys.add(logKey(p));
          added += 1;
        }
      }
      if (added > 0) {
        appState.logs.sort((a, b) => String(a.time).localeCompare(String(b.time)));
        appState.logs = appState.logs.slice(-1200);
        ensureFlowIds();
        appState.allPackets = appState.logs.filter((entry) => entry.packet_type);
        appState.realPackets = buildRealPackets(appState.allPackets);
        appState.packets = appState.currentFlowId
          ? appState.allPackets.filter((entry) => entry.flow_id === appState.currentFlowId)
          : appState.allPackets;
      }
    }
  } catch (err) {
    // 静默：仍由 /api/logs 路径兜底
  }
}

async function waitForSimulationResult(startedAt, fallbackIndex, predicate, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    await refreshStatus();
    await refreshLogs();
    const recent = logsSince(startedAt, fallbackIndex);
    if (predicate(recent)) return true;
    await sleep(350);
  }
  await refreshStatus();
  await refreshLogs();
  return predicate(logsSince(startedAt, fallbackIndex));
}

function connectWebSocket() {
  const protocol = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${protocol}://${location.host}/ws`);
  ws.addEventListener("message", (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.type === "log" && data.entry) {
        mergeLogs([data.entry]);
      }
      if (data.type === "status") {
        appState.status.server = {...(appState.status.server || {}), ...(data.server || {})};
        appState.status.client = {...(appState.status.client || {}), ...(data.client || {})};
      }
      render();
    } catch (error) {
      console.warn(error);
    }
  });
  ws.addEventListener("close", () => {
    setTimeout(connectWebSocket, 1500);
  });
}

function formObject(form) {
  return Object.fromEntries(new FormData(form).entries());
}

function wireEvents() {
  document.querySelectorAll(".tab").forEach((button) => {
    button.addEventListener("click", () => {
      appState.activeTab = button.dataset.tab;
      document.querySelectorAll(".tab").forEach((tab) => tab.classList.toggle("is-active", tab === button));
      document.querySelectorAll(".tab-panel").forEach((panel) => {
        panel.classList.toggle("is-active", panel.id === `tab-${appState.activeTab}`);
      });
    });
  });

  byId("server-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = formObject(event.currentTarget);
    data.inputFile = String(data.inputFile || "").trim();
    byId("server-input-path").value = data.inputFile;
    const pathError = validateRelativePath(data.inputFile, "inputPathEmpty", "inputPathRelativeOnly");
    if (pathError) {
      setNotice(pathError);
      return;
    }
    // 启动一次新的 server 流程
    beginServerFlow();
    const result = await window.Api.startServer(data);
    setNotice(result.ok === false ? localizeError(result.error || t("serverStartFailed")) : "");
    setTimeout(refreshStatus, 250);
  });

  byId("client-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = formObject(event.currentTarget);
    data.outputFile = String(data.outputFile || "").trim();
    byId("client-output-path").value = data.outputFile;
    const pathError = validateRelativePath(data.outputFile, "outputPathEmpty", "outputPathRelativeOnly");
    if (pathError) {
      setNotice(pathError);
      return;
    }
    if (data.mode === "interactive") {
      beginInteractiveAttemptState();
    } else {
      resetInteractiveAttemptState();
    }
    // 启动一次新的 client 流程
    beginClientFlow();
    renderInteractiveAttempt(deriveRun());
    const result = await window.Api.startClient(data);
    if (result.ok === false) {
      resetInteractiveAttemptState();
    }
    setNotice(result.ok === false ? localizeError(result.error || t("clientStartFailed")) : "");
    setTimeout(refreshStatus, 250);
  });

  byId("sidebar-toggle").addEventListener("click", () => {
    setSidebarCollapsed(!appState.sidebarCollapsed);
  });

  byId("theme-select").addEventListener("change", (event) => {
    setTheme(event.currentTarget.value);
  });

  byId("language-select").addEventListener("change", (event) => {
    setLanguage(event.currentTarget.value);
  });

  byId("rail-start-server-btn").addEventListener("click", () => {
    byId("server-form").requestSubmit();
  });

  byId("rail-start-client-btn").addEventListener("click", () => {
    byId("client-form").requestSubmit();
  });

  document.querySelectorAll("input[name='mode']").forEach((input) => {
    input.addEventListener("change", syncPasswordMode);
  });

  byId("stop-server-btn").addEventListener("click", async () => {
    await window.Api.stopServer();
    resetInteractiveAttemptState();
    await refreshStatus();
  });
  byId("stop-client-btn").addEventListener("click", async () => {
    await window.Api.stopClient();
    resetInteractiveAttemptState();
    await refreshStatus();
  });
  byId("send-password-btn").addEventListener("click", async () => {
    await window.Api.sendPassword(byId("interactive-password").value);
    setTimeout(refreshLogs, 250);
  });
  [byId("reset-btn"), byId("rail-reset-btn")].forEach((button) => {
    button.addEventListener("click", async () => {
      // 后端：停止所有子进程并清空日志文件（保留日志目录）
      await window.Api.reset();
      // 前端：清空所有状态、日志、包、协议时序、测试、密码态、当前 flow
      resetFrontendRunState({clearFilters: true});
      // 立即重新拉取后端状态（C 端日志已被清空，UI 立即显示初始态）
      await refreshStatus();
      await refreshLogs();
      // 主动 render 一次确保所有面板回到初始干净状态
      render();
    });
  });
  byId("refresh-logs-btn").addEventListener("click", refreshLogs);
  byId("view-full-logs-btn").addEventListener("click", () => {
    document.querySelector("[data-tab='logs']").click();
    byId("full-log-list").scrollIntoView({behavior: "smooth", block: "start"});
  });
  ["role-filter", "level-filter", "search-filter", "error-only"].forEach((id) => {
    byId(id).addEventListener("input", () => {
      appState.pagination.logs = 1;
      render();
    });
  });
  ["packet-search-filter", "packet-type-filter", "packet-direction-filter"].forEach((id) => {
    const syncPacketFilters = () => {
      appState.packetFilters.query = byId("packet-search-filter").value || "";
      appState.packetFilters.type = byId("packet-type-filter").value || "";
      appState.packetFilters.direction = byId("packet-direction-filter").value || "";
      appState.pagination.packets = 1;
      renderProtocol();
    };
    byId(id).addEventListener("input", syncPacketFilters);
    byId(id).addEventListener("change", syncPacketFilters);
  });

  document.addEventListener("click", (event) => {
    const passwordToggle = event.target.closest(".password-toggle");
    if (passwordToggle) {
      const field = passwordToggle.closest(".password-field");
      const input = field?.querySelector("input");
      if (input) {
        const visible = input.type === "text";
        input.type = visible ? "password" : "text";
        passwordToggle.classList.toggle("is-visible", !visible);
        const icon = passwordToggle.querySelector(".shape-icon");
        icon?.classList.toggle("icon-eye", visible);
        icon?.classList.toggle("icon-eye-off", !visible);
        syncPasswordToggleText(passwordToggle);
      }
      return;
    }

    const pageButton = event.target.closest("[data-page-target]");
    if (pageButton && !pageButton.disabled) {
      const target = pageButton.dataset.pageTarget;
      const delta = Number(pageButton.dataset.pageDelta || 0);
      appState.pagination[target] += delta;
      render();
      return;
    }

    const sequenceToggle = event.target.closest("[data-sequence-toggle]");
    if (sequenceToggle) {
      const flowId = sequenceToggle.dataset.sequenceToggle;
      if (flowId) {
        if (appState.sequenceExpandedFlows.has(flowId)) {
          appState.sequenceExpandedFlows.delete(flowId);
        } else {
          appState.sequenceExpandedFlows.add(flowId);
        }
        renderProtocol();
      }
      return;
    }

    const packetTarget = event.target.closest("[data-packet-index]");
    if (packetTarget) {
      const index = Number(packetTarget.dataset.packetIndex);
      // 共享数据源：realPackets（与表格 / 时序 render 同一份），确保 selectedPacket 与高亮一致
      const entry = appState.realPackets[index];
      if (entry) {
        appState.selectedPacket = entry;
        appState.selectedFlowId = entry.flow_id || null;
        // 点击包：协议时序切换到该包所属 flow
        if (entry.flow_id) {
          appState.currentFlowId = entry.flow_id;
          appState.packets = appState.realPackets.filter((e) => e.flow_id === entry.flow_id);
        }
      }
      render();
      return;
    }
    const fragment = event.target.closest("[data-fragment-id]");
    if (fragment) {
      const id = Number(fragment.dataset.fragmentId);
      const found = appState.realPackets.find((entry) => entry.packet_type === "DATA" && Number(entry.packet_id) === id) || null;
      if (found) {
        appState.selectedPacket = found;
        appState.selectedFlowId = found.flow_id || null;
        if (found.flow_id) {
          appState.currentFlowId = found.flow_id;
          appState.packets = appState.realPackets.filter((e) => e.flow_id === found.flow_id);
        }
      }
      appState.activeTab = "protocol";
      document.querySelector("[data-tab='protocol']").click();
    }
  });

  byId("run-tests-btn").addEventListener("click", async () => {
    setNotice("");
    setTestRows([{id: "test_suite", pass: null}], "suite");
    beginSimulationFlow();
    const result = await window.Api.runTests();
    if (result.ok === false) {
      setTestRows([{id: "test_suite", pass: false}], "suite");
      setNotice(localizeError(result.error || "cannot run tests"));
    } else {
      setTestRows(result.tests || [], "suite");
    }
    await refreshLogs();
  });

  byId("simulate-wrong-btn").addEventListener("click", async () => {
    const serverForm = formObject(byId("server-form"));
    const clientForm = formObject(byId("client-form"));
    setNotice("");
    setTestRows([{id: "auth_failed", pass: null}], "auth_failed");
    // 不调用 /api/reset：保留已有日志；只停止可能在跑的子进程
    await window.Api.stopServer();
    await window.Api.stopClient();
    setTestRows([{id: "auth_failed", pass: null}], "auth_failed");
    beginSimulationFlow();
    await refreshStatus();
    const startedAt = Date.now();
    const fallbackIndex = null;
    resetInteractiveAttemptState();
    const serverResult = await window.Api.startServer(serverForm);
    if (serverResult.ok === false) {
      setTestRows([{id: "auth_failed", pass: false}], "auth_failed");
      setNotice(localizeError(serverResult.error || t("serverStartFailed")));
      return;
    }
    await sleep(350);
    const clientResult = await window.Api.startClient({
      host: clientForm.host,
      port: serverForm.port,
      outputFile: "output/wrong-auth.bin",
      mode: "compat",
      pwd1: "wrong-one",
      pwd2: "wrong-two",
      pwd3: "wrong-three",
    });
    if (clientResult.ok === false) {
      setTestRows([{id: "auth_failed", pass: false}], "auth_failed");
      setNotice(localizeError(clientResult.error || t("clientStartFailed")));
      return;
    }
    const passed = await waitForSimulationResult(startedAt, fallbackIndex, (recent) => {
      const hasThirdFailure = recent.some((entry) => entry.event === "AUTH_FAIL" && Number(entry.attempt || 0) >= 3);
      const hasRejectOrAbort = recent.some((entry) =>
        entry.packet_type === "REJECT" ||
        entry.event === "FINAL_ABORT" ||
        /three password|authentication failure|password rejected/i.test(`${entry.message || ""} ${entry.error_code || ""}`)
      );
      return hasThirdFailure || hasRejectOrAbort;
    });
    setTestRows([{id: "auth_failed", pass: passed}], "auth_failed");
    if (passed) setNotice("");
  });

  byId("simulate-timeout-btn").addEventListener("click", async () => {
    const clientForm = formObject(byId("client-form"));
    setNotice("");
    setTestRows([{id: "timeout", pass: null}], "timeout");
    // 不调用 /api/reset：保留已有日志；只停止可能在跑的子进程
    await window.Api.stopServer();
    await window.Api.stopClient();
    setTestRows([{id: "timeout", pass: null}], "timeout");
    beginSimulationFlow();
    await refreshStatus();
    const startedAt = Date.now();
    const fallbackIndex = null;
    resetInteractiveAttemptState();
    const clientResult = await window.Api.startClient({
      host: clientForm.host,
      port: timeoutSimulationPort(clientForm.port),
      outputFile: "output/timeout.bin",
      mode: "compat",
      pwd1: "secret",
      pwd2: "secret",
      pwd3: "secret",
    });
    if (clientResult.ok === false) {
      setTestRows([{id: "timeout", pass: false}], "timeout");
      setNotice(localizeError(clientResult.error || t("clientStartFailed")));
      return;
    }
    const passed = await waitForSimulationResult(startedAt, fallbackIndex, (recent) => {
      return recent.some((entry) =>
        entry.event === "TIMEOUT" ||
        /timeout/i.test(`${entry.error_code || ""} ${entry.message || ""}`)
      );
    }, 15000);
    setTestRows([{id: "timeout", pass: passed}], "timeout");
    if (passed) setNotice("");
  });
}

async function boot() {
  try {
    setLanguage(localStorage.getItem("udpLabLanguage") || "zh", false);
    setSidebarCollapsed(localStorage.getItem("udpLabSidebarCollapsed") === "1");
  } catch (error) {
    console.warn(error);
    setLanguage("zh", false);
  }
  // 主题：先读新版存储，再回退到旧版 lab/minimal/graphite 等映射
  let savedTheme = null;
  try { savedTheme = localStorage.getItem("udpLabThemeV2"); } catch (e) { /* noop */ }
  if (!savedTheme) {
    try { savedTheme = localStorage.getItem("udpLabTheme"); } catch (e) { /* noop */ }
  }
  // 旧主题 id 映射
  const legacyMap = {
    lab: "liquid",
    minimal: "nordic",
    graphite: "nordic",
    cyber: "cyber",
    console: "metal",
    signal: "matcha",
  };
  if (savedTheme && legacyMap[savedTheme]) savedTheme = legacyMap[savedTheme];
  if (window.ThemeManager) {
    window.ThemeManager.init();
  }
  setTheme(savedTheme || (window.ThemeManager ? window.ThemeManager.defaultTheme : "neumorph"));
  applyLanguage();
  wireEvents();
  syncPasswordMode();
  await refreshStatus();
  await refreshLogs();
  connectWebSocket();
  setInterval(refreshStatus, 2500);
  setInterval(refreshLogs, 6000);
}

boot();
