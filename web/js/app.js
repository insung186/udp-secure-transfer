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
  catalog: {protocols: []},
  protocolSchemas: {},
  scenarioCatalog: {},
  selectedProtocol: "udp-basic",
  selectedScenario: "normal",
  compareProtocol: "",
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
    type: "",
    direction: "",
    flow: "",
    state: "",
    sort: "newest",
  },
  logFilters: {
    role: "",
    level: "",
    event: "",
    /* timeRange: 时间区间预设。可选值：
         "all"    — 全部（默认，不应用时间过滤）
         "1m"     — 最近 1 分钟
         "5m"     — 最近 5 分钟
         "30m"    — 最近 30 分钟
         "custom" — 自定义（用 timeFrom + timeTo 输入框的值）
       用预设的好处是 "1 分钟前 / 5 分钟前" 这种相对概念是动态的，
       不会"5 分钟后用户的过滤区间还停留在点击那一刻的 5 分钟前"。 */
    timeRange: "all",
    timeFrom: "",
    timeTo: "",
    sort: "newest",
    errorOnly: false,
  },
  pagination: {
    packets: 1,
    logs: 1,
  },
  /* throughputSamples: 每秒采一次，{t, bytes}。
     sparkline 用 samples 推算每秒速率；30 个点保留约 30 秒历史。 */
  throughputSamples: [],
  /* transferFlowId: 传输 tab 的 flow 选择器；独立于 currentFlowId，让用户
     在不影响主视图的情况下翻看历史 flow。null 表示跟随 currentFlowId。 */
  transferFlowId: null,
  /* matrixView: 分片矩阵显示选项 */
  matrixView: {
    showDup: true,
    showGaps: true,
    showTime: false,
  },
  hoverFragmentId: null,
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
  ACK: 8,
  NACK: 9,
};

const protocolStages = ["JOIN_REQ", "PASS_REQ", "PASS_RESP", "PASS_ACCEPT", "DATA", "TERMINATE"];

const i18n = {
  zh: {
    documentTitle: "多协议教学演示平台",
    appName: "多协议教学演示平台",
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
    protocolLab: "协议与场景",
    platformHint: "平台化配置",
    protocolSelect: "协议",
    scenarioSelect: "场景",
    scenarioDescription: "当前场景说明会显示在这里。",
    runScenario: "运行场景",
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
    topTitle: "统一多协议实验控制台",
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
    allPacketTypes: "类型",
    allDirections: "方向",
    allFlows: "流",
    allStates: "状态",
    allEvents: "事件",
    sortNewest: "最新优先",
    sortOldest: "最旧优先",
    clearAll: "清空",
    clearTime: "清空时段",
    firstPage: "首页",
    lastPage: "末页",
    timeRange: "时间",
    rangeAll: "全部",
    range1m: "1 分钟",
    range5m: "5 分钟",
    range30m: "30 分钟",
    rangeCustom: "自定义",
    customRange: "自定义时段",
    clientToServer: "客户端到服务端",
    serverToClient: "服务端到客户端",
    observed: "观察到",
    time: "时间",
    direction: "方向",
    role: "角色",
    protocolLabel: "协议",
    transportLabel: "传输层",
    scenarioLabel: "场景",
    ackLabel: "ACK",
    seqLabel: "SEQ",
    windowLabel: "窗口",
    retransmitLabel: "重传",
    packet: "包",
    flowId: "Flow ID",
    sessionId: "Session ID",
    payload: "载荷",
    packetId: "分片 ID / 说明",
    state: "状态",
    transferProgress: "传输进度",
    fragmentMatrix: "分片矩阵",
    fragmentHint: "每格代表一个 DATA packet_id",
    transferContext: "当前传输",
    flowSelector: "Flow",
    autoFlow: "自动（最近）",
    transferHeroIdle: "等待启动服务端和客户端",
    transferHeroNoFlow: "尚未产生传输 flow",
    transferHeroFiles: "{server} → {client}",
    transferHeroMeta: "开始 {start} · 持续 {duration} · 期望 {total}",
    transferHeroPhaseOk: "摘要匹配 ✓",
    transferHeroPhaseFail: "摘要不匹配 ✗",
    transferHeroPhaseRunning: "传输中…",
    transferHeroPhaseAuth: "认证中…",
    transferHeroPhaseIdle: "空闲",
    transferHeroScenario: "场景: {scenario}",
    lifecycleTitle: "传输阶段",
    stageIdle: "空闲",
    stageAuth: "认证",
    stageTransfer: "传输",
    stageVerify: "校验",
    stageDone: "完成",
    stageAbort: "中止",
    transferThroughput: "吞吐率时间线",
    throughputNow: "当前",
    throughputAvg: "平均",
    throughputPeak: "峰值",
    throughputWindow: "近 {seconds}s 窗口",
    throughputIdle: "等待数据流…",
    matrixSummary: "已收 {received} / 期望 {expected} · 丢失 {lost} · 重复 {dup} · 乱序 {oof}",
    matrixShowDup: "显示重复",
    matrixShowGaps: "标出缺口",
    matrixShowTime: "显示时间带",
    legendReceived: "已收",
    legendLost: "丢失",
    legendDup: "重复",
    legendOof: "乱序",
    legendPending: "未到",
    matrixIdle: "传输尚未开始。启动客户端后这里会显示 DATA 分片矩阵。",
    matrixAuthOnly: "认证阶段，尚未传输 DATA。",
    fragmentTooltip: "DATA #{id} · {bytes} · {time} · 距 {prev} {delta}",
    fragmentTooltipFirst: "DATA #{id} · {bytes} · {time}",
    etaSuffix: "剩余约 {seconds}",
    etaLabel: "ETA",
    etaDone: "传输完成",
    etaPending: "等待数据开始",
    integrityCheck: "完整性校验",
    transferHistory: "传输历史",
    historyEmpty: "暂无传输历史",
    historyCount: "{count} 次传输",
    historyResultOk: "成功",
    historyResultAbort: "中止",
    historyResultPending: "进行中",
    historyDurationMs: "{ms} ms",
    historyDurationS: "{s} s",
    noResultYet: "—",
    latestFlow: "跟随最新",
    logFilters: "日志过滤",
    logFormatHint: "JSON 行日志",
    allRoles: "角色",
    serverRole: "server",
    clientRole: "client",
    controlRole: "control",
    allLevels: "级别",
    errorsOnly: "仅异常",
    errorStateAll: "全部",
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
    testsAndSim: "自动测试套件",
    testsAndSimHint: "「认证失败」「超时」等场景请通过上方「协议与场景」运行；本面板只运行自动化测试脚本。",
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
    dataFoldedRange: "DATA #{first} — DATA #{last}",
    dataExpanded: "DATA 分片已展开",
    foldStartMarker: "DATA #{id} 之前被折叠 · 共 {count} 个",
    foldEndMarker: "DATA #{id} 之前被折叠",
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
    packetUid: "包 UID",
    wireDetails: "线缆层细节",
    wirePayload: "载荷字节",
    wireSha1: "SHA1 摘要",
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
    inputPathEmpty: "输入文件路径不能为空。",
    outputPathEmpty: "输出文件路径不能为空。",
    inputPathRelativeOnly: "输入文件路径只支持相对路径。",
    outputPathRelativeOnly: "输出文件路径只支持相对路径。",
    serverStartFailed: "服务端启动失败。",
    clientStartFailed: "客户端启动失败。",
  },
  en: {
    documentTitle: "Multi-Protocol Teaching Lab",
    appName: "Multi-Protocol Teaching Lab",
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
    protocolLab: "Protocol & scenario",
    platformHint: "Platform config",
    protocolSelect: "Protocol",
    scenarioSelect: "Scenario",
    scenarioDescription: "The selected scenario description appears here.",
    runScenario: "Run scenario",
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
    topTitle: "Unified Multi-Protocol Console",
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
    allPacketTypes: "Type",
    allDirections: "Dir",
    allFlows: "Flow",
    allStates: "State",
    allEvents: "Event",
    sortNewest: "Newest",
    sortOldest: "Oldest",
    clearAll: "Clear",
    clearTime: "Clear range",
    firstPage: "First",
    lastPage: "Last",
    timeRange: "Time",
    rangeAll: "All",
    range1m: "1 min",
    range5m: "5 min",
    range30m: "30 min",
    rangeCustom: "Custom",
    customRange: "Custom range",
    clientToServer: "Client to Server",
    serverToClient: "Server to Client",
    observed: "Observed",
    time: "Time",
    direction: "Direction",
    role: "Role",
    protocolLabel: "Protocol",
    transportLabel: "Transport",
    scenarioLabel: "Scenario",
    ackLabel: "ACK",
    seqLabel: "SEQ",
    windowLabel: "Window",
    retransmitLabel: "Retransmit",
    packet: "Packet",
    flowId: "Flow ID",
    sessionId: "Session ID",
    payload: "Payload",
    packetId: "Fragment ID / Note",
    state: "State",
    transferProgress: "Transfer progress",
    fragmentMatrix: "Fragment matrix",
    fragmentHint: "Each cell represents one DATA packet_id",
    transferContext: "Current Transfer",
    flowSelector: "Flow",
    autoFlow: "Auto (latest)",
    transferHeroIdle: "Start the server and client to begin a transfer.",
    transferHeroNoFlow: "No transfer flow yet",
    transferHeroFiles: "{server} → {client}",
    transferHeroMeta: "Start {start} · Duration {duration} · Expected {total}",
    transferHeroPhaseOk: "Digest match ✓",
    transferHeroPhaseFail: "Digest mismatch ✗",
    transferHeroPhaseRunning: "Transferring…",
    transferHeroPhaseAuth: "Authenticating…",
    transferHeroPhaseIdle: "Idle",
    transferHeroScenario: "Scenario: {scenario}",
    lifecycleTitle: "Transfer phases",
    stageIdle: "Idle",
    stageAuth: "Auth",
    stageTransfer: "Transfer",
    stageVerify: "Verify",
    stageDone: "Done",
    stageAbort: "Abort",
    transferThroughput: "Throughput timeline",
    throughputNow: "now",
    throughputAvg: "avg",
    throughputPeak: "peak",
    throughputWindow: "last {seconds}s window",
    throughputIdle: "Waiting for data…",
    matrixSummary: "Received {received} / Expected {expected} · Lost {lost} · Dup {dup} · OoO {oof}",
    matrixShowDup: "Show duplicates",
    matrixShowGaps: "Mark gaps",
    matrixShowTime: "Show time band",
    legendReceived: "received",
    legendLost: "lost",
    legendDup: "dup",
    legendOof: "OoO",
    legendPending: "pending",
    matrixIdle: "Transfer not started. Cells will appear once the client sends DATA.",
    matrixAuthOnly: "Authentication phase, no DATA yet.",
    fragmentTooltip: "DATA #{id} · {bytes} · {time} · Δ {delta} from {prev}",
    fragmentTooltipFirst: "DATA #{id} · {bytes} · {time}",
    etaSuffix: "~{seconds} left",
    etaLabel: "ETA",
    etaDone: "Transfer complete",
    etaPending: "Waiting for data",
    integrityCheck: "Integrity check",
    transferHistory: "Transfer history",
    historyEmpty: "No transfer history",
    historyCount: "{count} runs",
    historyResultOk: "OK",
    historyResultAbort: "Abort",
    historyResultPending: "Running",
    historyDurationMs: "{ms} ms",
    historyDurationS: "{s} s",
    noResultYet: "—",
    latestFlow: "Follow latest",
    logFilters: "Log filters",
    logFormatHint: "JSON Lines",
    allRoles: "All roles",
    serverRole: "server",
    clientRole: "client",
    controlRole: "control",
    allLevels: "All levels",
    errorsOnly: "Errors only",
    errorStateAll: "All",
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
    testsAndSim: "Automated test suite",
    testsAndSimHint: "Scenarios like \"auth failure\" or \"timeout\" are run from the \"Protocol & scenarios\" panel above. This panel only runs the automated test scripts.",
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
    dataFoldedRange: "DATA #{first} — DATA #{last}",
    dataExpanded: "DATA fragments expanded",
    foldStartMarker: "DATA #{id} was folded · {count} total",
    foldEndMarker: "DATA #{id} was folded",
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
    packetUid: "Packet UID",
    wireDetails: "Wire-level details",
    wirePayload: "Payload bytes",
    wireSha1: "SHA1 digest",
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

/* YYYY-MM-DD HH:MM:SS — 给 sparkline 的"now 标记"用 */
function formatTimeOfDay(d) {
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
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
  appState.throughputSamples = [];
  appState.transferFlowId = null;
  appState.hoverFragmentId = null;
  appState.matrixView = {showDup: true, showGaps: true, showTime: false};
  // 同步 DOM 上的 checkbox 状态（防止重置后开关与 state 不一致）
  const dup = byId("matrix-show-dup");
  const gaps = byId("matrix-show-gaps");
  const time = byId("matrix-show-time");
  if (dup) dup.checked = true;
  if (gaps) gaps.checked = true;
  if (time) time.checked = false;
  resetInteractiveAttemptState();
  if (clearFilters) {
    // 包过滤
    appState.packetFilters.type = "";
    appState.packetFilters.direction = "";
    appState.packetFilters.flow = "";
    appState.packetFilters.state = "";
    appState.packetFilters.sort = "newest";
    // 日志过滤
    appState.logFilters.role = "";
    appState.logFilters.level = "";
    appState.logFilters.event = "";
    appState.logFilters.timeRange = "all";
    appState.logFilters.timeFrom = "";
    appState.logFilters.timeTo = "";
    appState.logFilters.sort = "newest";
    appState.logFilters.errorOnly = false;
    // 同步 DOM
    ["packet-type-filter", "packet-direction-filter", "packet-flow-filter",
     "packet-state-filter", "packet-sort", "role-filter", "level-filter",
     "log-event-filter", "log-time-from", "log-time-to", "log-sort"].forEach((id) => {
      const node = byId(id);
      if (node) node.value = "";
    });
    // sort / timeRange 各自有固定默认值（不是空字符串）
    const sortNode = byId("packet-sort");
    if (sortNode) sortNode.value = "newest";
    const logSortNode = byId("log-sort");
    if (logSortNode) logSortNode.value = "newest";
    // 错误过滤分段控件：把"全部"段标为 active
    const errToggle = byId("log-error-only-toggle");
    if (errToggle) {
      errToggle.querySelectorAll(".seg-btn").forEach((btn) => {
        btn.classList.toggle("is-active", btn.dataset.state === "all");
      });
    }
    // 时间分段控件：把"全部"段标为 active
    const segGroup = byId("log-time-range");
    if (segGroup) {
      segGroup.querySelectorAll(".seg-btn").forEach((btn) => {
        btn.classList.toggle("is-active", btn.dataset.range === "all");
      });
    }
    // 隐藏自定义时段行
    const customRow = byId("log-custom-time-row");
    if (customRow) customRow.classList.add("is-hidden");
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

function protocolOptions() {
  return Array.isArray(appState.catalog?.protocols) ? appState.catalog.protocols : [];
}

function currentProtocolDef() {
  const protocols = protocolOptions();
  return protocols.find((item) => item.id === appState.selectedProtocol) || protocols[0] || null;
}

function protocolDisplayName(protocolId) {
  const found = protocolOptions().find((item) => item.id === protocolId);
  return found?.name || protocolId || "-";
}

function currentScenarioList() {
  return appState.scenarioCatalog[appState.selectedProtocol]?.scenarios || [];
}

function currentScenarioDef() {
  const scenarios = currentScenarioList();
  return scenarios.find((item) => item.id === appState.selectedScenario) || scenarios[0] || null;
}

function scenarioDisplayName(scenarioId, protocolId = appState.selectedProtocol) {
  const scenarios = appState.scenarioCatalog[protocolId]?.scenarios || [];
  const found = scenarios.find((item) => item.id === scenarioId);
  return found?.name || scenarioId || "-";
}

function protocolPacketTypes() {
  return appState.protocolSchemas[appState.selectedProtocol]?.packetTypes || [];
}

function protocolSequenceStages() {
  return appState.protocolSchemas[appState.selectedProtocol]?.sequenceStages || protocolStages;
}

function protocolSchema(protocolId = appState.selectedProtocol) {
  return appState.protocolSchemas[protocolId] || {};
}

function protocolTransferView(protocolId = appState.selectedProtocol) {
  return protocolSchema(protocolId)?.transferView || "file";
}

function protocolSummary(protocolId = appState.selectedProtocol) {
  return protocolSchema(protocolId)?.summary || "";
}

function primaryPacketNamesForProtocol(protocolId = appState.selectedProtocol) {
  const view = protocolTransferView(protocolId);
  if (view === "transaction") return ["STATUS_RESPONSE", "AUTH_RESPONSE", "UPLOAD_RESPONSE"];
  if (view === "message") return ["TEXT"];
  return ["DATA", "APP_DATA", "STREAM"];
}

function flowTransferEntries(flowPackets, protocolId, role) {
  const names = new Set(primaryPacketNamesForProtocol(protocolId));
  return flowPackets.filter((entry) => entry.role === role && names.has(entry.packet_type));
}

function flowTimelineEntries(flowPackets, protocolId) {
  const view = protocolTransferView(protocolId);
  if (view === "transaction") {
    return flowPackets.filter((entry) => /REQUEST|RESPONSE/.test(entry.packet_type || ""));
  }
  if (view === "message") {
    return flowPackets.filter((entry) =>
      ["UPGRADE_REQUEST", "UPGRADE_RESPONSE", "TEXT", "PING", "PONG", "CLOSE"].includes(entry.packet_type)
    );
  }
  return flowPackets.filter((entry) =>
    ["DATA", "APP_DATA", "STREAM", "ACK", "NACK", "TERMINATE", "CLOSE"].includes(entry.packet_type)
  );
}

function uniqueTransferEntries(entries) {
  const seen = new Set();
  const unique = [];
  for (const entry of entries) {
    const key = entry.packet_uid || `${entry.packet_type}:${entry.packet_id ?? entry.seq ?? entry.time ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(entry);
  }
  return unique;
}

function deriveFlowPhase(flowLogs, flowPackets, protocolId, result) {
  const primaryRecv = flowTransferEntries(flowPackets, protocolId, "client");
  const packetNames = new Set(flowLogs.map((entry) => entry.packet_type).filter(Boolean));
  if (result === "ABORT") return "ABORT";
  if (flowLogs.some((entry) => entry.event === "DIGEST_MATCH") || result === "OK") return "DONE";
  if (packetNames.has("TERMINATE") || packetNames.has("CLOSE")) return "VERIFY";
  if (primaryRecv.length > 0) return "DATA_TRANSFER";
  if (["PASS_REQ", "PASS_RESP", "PASS_ACCEPT", "REJECT", "CLIENT_HELLO", "SERVER_HELLO", "FINISHED",
       "AUTH_REQUEST", "AUTH_RESPONSE", "HANDSHAKE", "HANDSHAKE_ACK", "UPGRADE_REQUEST", "UPGRADE_RESPONSE"].some((name) => packetNames.has(name))) {
    return "AUTH";
  }
  if (["JOIN_REQ", "INITIAL", "STATUS_REQUEST"].some((name) => packetNames.has(name))) {
    return "JOIN";
  }
  return "INIT";
}

function syncProtocolSelectors() {
  const protocolSelect = byId("protocol-select");
  const scenarioSelect = byId("scenario-select");
  const scenarioDescription = byId("scenario-description");
  const protocols = protocolOptions();
  const currentProtocol = currentProtocolDef();
  if (protocolSelect) {
    protocolSelect.innerHTML = protocols.map((item) =>
      `<option value="${escapeHtml(item.id)}">${escapeHtml(item.name || item.id)}</option>`
    ).join("");
    protocolSelect.value = currentProtocol?.id || "";
  }
  const scenarios = currentScenarioList();
  const currentScenario = currentScenarioDef();
  if (scenarioSelect) {
    scenarioSelect.innerHTML = scenarios.map((item) =>
      `<option value="${escapeHtml(item.id)}">${escapeHtml(item.name || item.id)}</option>`
    ).join("");
    scenarioSelect.value = currentScenario?.id || "";
  }
  if (scenarioDescription) {
    scenarioDescription.textContent = currentScenario?.description || t("scenarioDescription");
  }
}

async function loadProtocolCatalog() {
  try {
    const catalog = await window.Api.catalog();
    if (!catalog || !Array.isArray(catalog.protocols)) return;
    appState.catalog = catalog;
    if (!protocolOptions().some((item) => item.id === appState.selectedProtocol)) {
      appState.selectedProtocol = protocolOptions()[0]?.id || "udp-basic";
    }
    for (const item of protocolOptions()) {
      if (item.schema && !appState.protocolSchemas[item.id]) {
        appState.protocolSchemas[item.id] = await window.Api.protocolResource(item.schema);
      }
      if (item.scenarios && !appState.scenarioCatalog[item.id]) {
        appState.scenarioCatalog[item.id] = await window.Api.protocolResource(item.scenarios);
      }
    }
    const protocol = currentProtocolDef();
    const scenarios = appState.scenarioCatalog[protocol?.id || ""]?.scenarios || [];
    if (!scenarios.some((item) => item.id === appState.selectedScenario)) {
      appState.selectedScenario = protocol?.defaultScenario || scenarios[0]?.id || "normal";
    }
    if (!appState.compareProtocol || appState.compareProtocol === appState.selectedProtocol) {
      appState.compareProtocol = protocolOptions().find((item) => item.id !== appState.selectedProtocol)?.id || appState.selectedProtocol;
    }
    syncProtocolSelectors();
  } catch (error) {
    console.warn(error);
  }
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
//
// Prefix includes the current backend session_id so that reloading the page
// (which resets appState.flowCounter to 0) cannot collide with flow IDs
// already present in logs/server.jsonl from earlier sessions.
function generateFlowId(prefix = "flow", entry) {
  appState.flowCounter += 1;
  const port = (entry && (entry.port || peerPort(entry.peer))) || (appState.status.server?.port || appState.status.client?.port) || "udp";
  const session = (appState.status.experiment && appState.status.experiment.session_id) || "pre";
  return `${prefix}-${session}-${appState.flowCounter.toString().padStart(4, "0")}-${port}`;
}

/* After loading logs from the backend, scan for any pre-existing flow IDs of
   the shape we generate so the next counter increment doesn't reuse a number.
   Returns the highest existing counter value (0 if none). */
function maxExistingFlowCounter(logs) {
  let maxN = 0;
  const re = /-(\d{4,})-[a-z]+$/i;
  for (const entry of logs || []) {
    const fid = entry && entry.flow_id;
    if (typeof fid !== "string") continue;
    const m = fid.match(re);
    if (m) {
      const n = parseInt(m[1], 10);
      if (Number.isFinite(n) && n > maxN) maxN = n;
    }
  }
  return maxN;
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
    if (entry.flow_id) {
      const port = String(entry.port || peerPort(entry.peer) || "");
      if (entry.role === "server" && entry.event === "SERVER_START" && port) {
        serverFlowsByPort.set(port, entry.flow_id);
        activeServerFlow = entry.flow_id;
      }
      if (!entry.session_id) {
        entry.session_id = entry.flow_id;
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

  // lastFlowResult is now derived by deriveRun() and applied by render()
  // (single source of truth — no double writes here).
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
  rebuildRealPacketsIndex();
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

/* O(1) lookup table mapping realPackets entry -> index. Populated alongside
   `appState.realPackets` whenever buildRealPackets() runs. Replaces two
   `realPackets.indexOf(entry)` calls inside the render hot path that
   contributed O(n²) per render. */
function rebuildRealPacketsIndex() {
  appState.realPacketsIndex = new Map();
  for (let i = 0; i < appState.realPackets.length; i += 1) {
    appState.realPacketsIndex.set(appState.realPackets[i], i);
  }
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
  const lastFlowResult = (finalEvent && finalEvent.flow_id === flowId)
    ? (finalEvent.result || (finalEvent.event === "FINAL_OK" ? "OK" : "ABORT"))
    : null;
  const serverDigest = flowLatest((entry) => entry.event === "SERVER_DIGEST" && entry.sha1);
  const clientDigest = flowLatest((entry) => (entry.event === "DIGEST_MATCH" || entry.event === "DIGEST_MISMATCH") && entry.sha1);
  const protocolId = flowLatest((entry) => entry.protocol)?.protocol
    || appState.status.experiment?.protocol
    || appState.selectedProtocol;
  const dataRecv = flowTransferEntries(flowPackets, protocolId, "client");
  const dataSent = flowTransferEntries(flowPackets, protocolId, "server");
  const dataRecvUnique = uniqueTransferEntries(dataRecv);
  const dataSentUnique = uniqueTransferEntries(dataSent);
  const inputStart = flowLatest((entry) => entry.event === "SERVER_START");
  const flowMeta = flowLatest((entry) => entry.protocol || entry.transport || entry.session_id || entry.scenario);
  const phase = deriveFlowPhase(flowLogs, flowPackets, protocolId, result);
  const ackCount = flowLogs.filter((entry) => entry.packet_type === "ACK").length;
  const nackCount = flowLogs.filter((entry) => entry.packet_type === "NACK").length;
  const retransmits = flowLogs.filter((entry) =>
    String(entry.event || "").includes("RETRANSMIT") || Number(entry.retransmit_count || 0) > 0
  ).length;
  const receivedBytes = dataRecvUnique.reduce((sum, entry) => sum + Number(entry.bytes || entry.payload_length || 0), 0);
  const sentBytes = dataSentUnique.reduce((sum, entry) => sum + Number(entry.bytes || entry.payload_length || 0), 0);
  const totalBytes = protocolTransferView(protocolId) === "file"
    ? Number(inputStart?.bytes || Math.max(receivedBytes, sentBytes, 0))
    : Math.max(receivedBytes, sentBytes, 0);
  const attempts = Math.max(0, ...flowLogs.map((entry) => Number(entry.attempt || 0)));
  const progress = totalBytes > 0 ? Math.min(100, Math.round((receivedBytes / totalBytes) * 100)) : result === "OK" ? 100 : 0;
  const firstData = dataRecvUnique[0];
  const lastData = dataRecvUnique[dataRecvUnique.length - 1];
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
    lastFlowResult,
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
    ackCount,
    nackCount,
    retransmits,
    protocol: protocolId,
    transport: flowMeta?.transport || appState.status.experiment?.transport || currentProtocolDef()?.transport || "udp",
    scenario: flowMeta?.scenario || appState.status.experiment?.scenario || currentScenarioDef()?.name || appState.selectedScenario,
    sessionId: flowMeta?.session_id || appState.status.experiment?.session_id || "",
    transferView: protocolTransferView(protocolId),
    timelineEntries: flowTimelineEntries(flowPackets, protocolId),
    finalEvent,
    flowId,
  };
}

/**
 * 解析传输矩阵状态：基于一个 flow 的所有 DATA 日志计算每个 packet_id 的最终态。
 * 语义：
 *   - expectedCount = max(server SEND DATA packet_id) + 1（server 序号从 0 开始）
 *   - receivedSet  = client RECV DATA 的 packet_id 集合
 *   - lostIds      = expected 但未到达（server 发了但 client 没收到）
 *   - dupIds       = 同一 packet_id 收到多次（用 packet_uid 计数）
 *   - oofIds       = 到达时间晚于其后编号（视为乱序）
 *   - pendingIds   = 在 [0, expected) 中、server 还没发的（多用于传输中）
 * 入参是 deriveRun() 返回值（含 dataRecv / dataSent）。
 */
function computeTransferStats(run) {
  if ((run.transferView || protocolTransferView(run.protocol)) !== "file") {
    return {
      expectedCount: run.timelineEntries?.length || run.dataSent.length || 0,
      receivedCount: run.dataRecv.length,
      sentCount: run.dataSent.length,
      lostCount: 0,
      dupCount: 0,
      oofCount: 0,
      lostIds: new Set(),
      dupIds: new Set(),
      oofIds: new Set(),
      pendingIds: new Set(),
      recvIds: new Set(),
      sentIds: new Set(),
    };
  }
  const sentIds = new Set();
  let maxSentId = -1;
  for (const e of (run.dataSent || [])) {
    const id = Number(e.packet_id || 0);
    sentIds.add(id);
    if (id > maxSentId) maxSentId = id;
  }

  const recvIds = new Set();
  const recvCount = new Map();
  let maxRecvId = -1;
  for (const e of (run.dataRecv || [])) {
    const id = Number(e.packet_id || 0);
    recvIds.add(id);
    recvCount.set(id, (recvCount.get(id) || 0) + 1);
    if (id > maxRecvId) maxRecvId = id;
  }

  const expectedCount = sentIds.size > 0 ? Math.max(maxSentId + 1, 0) : 0;

  const lostIds = new Set();
  if (expectedCount > 0) {
    for (let id = 0; id < expectedCount; id += 1) {
      if (sentIds.has(id) && !recvIds.has(id)) lostIds.add(id);
    }
  }

  const dupIds = new Set();
  let dupCount = 0;
  for (const [id, count] of recvCount) {
    if (count > 1) {
      dupIds.add(id);
      dupCount += count - 1;
    }
  }

  /* 乱序判定：按到达时间遍历，如果当前 packet_id 小于已见最大值，
     视为该包"迟到"——计为一次乱序。O(n) 一次扫描。 */
  const oofIds = new Set();
  const sortedRecv = [...(run.dataRecv || [])].sort(
    (a, b) => logTimeMs(a) - logTimeMs(b)
  );
  let oofCount = 0;
  let maxSoFar = -1;
  for (const e of sortedRecv) {
    const id = Number(e.packet_id || 0);
    if (id < maxSoFar) {
      oofCount += 1;
      oofIds.add(id);
    } else {
      maxSoFar = id;
    }
  }

  /* pending：server 还没发的（expectedCount 内、sentIds 没有的）。 */
  const pendingIds = new Set();
  if (expectedCount > 0) {
    for (let id = 0; id < expectedCount; id += 1) {
      if (!sentIds.has(id)) pendingIds.add(id);
    }
  }

  return {
    expectedCount,
    receivedCount: recvIds.size,
    sentCount: sentIds.size,
    lostCount: lostIds.size,
    dupCount,
    oofCount,
    lostIds,
    dupIds,
    oofIds,
    pendingIds,
    recvIds,
    sentIds,
  };
}

/**
 * 传输 tab 实际使用的 flow id：
 * 1) 用户在 transfer-flow-select 里显式选了某个 flow → 用它
 * 2) 否则跟随 currentFlowId
 * 3) 都没有 → null
 */
function effectiveTransferFlowId() {
  if (appState.transferFlowId) return appState.transferFlowId;
  return appState.currentFlowId;
}

/**
 * 收集历史 flow：按 flow_id 汇总每条 flow 的 result / phase / 时长 / 字节。
 * 给传输历史面板用。最多返回 10 条最近的。
 */
function collectFlowHistory() {
  const flows = new Map();
  for (const entry of appState.logs) {
    if (!entry.flow_id) continue;
    if (!flows.has(entry.flow_id)) {
      flows.set(entry.flow_id, {
        flowId: entry.flow_id,
        firstTime: entry.time,
        lastTime: entry.time,
        role: entry.role,
        events: [],
        packetsSent: 0,
        packetsRecv: 0,
        bytes: 0,
        result: null,
        scenario: null,
      });
    }
    const f = flows.get(entry.flow_id);
    if (entry.time && entry.time < f.firstTime) f.firstTime = entry.time;
    if (entry.time && entry.time > f.lastTime) f.lastTime = entry.time;
    if (entry.event) f.events.push(entry.event);
    if (entry.packet_type === "DATA" && entry.role === "server") {
      f.packetsSent += 1;
      f.bytes = Math.max(f.bytes, Number(entry.payload_length || entry.bytes || 0));
    }
    if (entry.packet_type === "DATA" && entry.role === "client") {
      f.packetsRecv += 1;
    }
    if (entry.event === "FINAL_OK") f.result = "OK";
    else if (entry.event === "FINAL_ABORT") f.result = "ABORT";
    else if (entry.event === "AUTH_FAIL") f.result = f.result || "AUTH_FAIL";
    else if (entry.event === "TIMEOUT") f.result = f.result || "TIMEOUT";
    if (entry.scenario) f.scenario = entry.scenario;
    else if (entry.event === "AUTH_SUCCESS") f.scenario = "normal";
  }
  const arr = Array.from(flows.values()).sort(
    (a, b) => String(b.firstTime).localeCompare(String(a.firstTime))
  );
  return arr.slice(0, 10);
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
  if ((entry.packet_type === "ACK" || entry.packet_type === "NACK") && entry.ack !== undefined) {
    return {
      text: `ack ${entry.ack}`,
      title: appState.language === "zh"
        ? "反馈包中的累计确认序号 / 缺失分片序号"
        : "Cumulative ACK or missing fragment sequence in the feedback packet.",
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
  if (type === "DATA" || type === "ACK" || type === "NACK") return "data";
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
  const FOLD_THRESHOLD = 4;
  const shouldFold = dataPackets.length > FOLD_THRESHOLD;
  /* 被折叠的"中段"：dataPackets[3] 到 dataPackets[length-2]（即首 3 + 末 1 之外）。
     折叠时只显示首 3 + 末 1；展开时全显示，但用 full-width bar 在 [3] 之前和 [length-2] 之后
     各打一个标记（"DATA #3 · 之前被折叠" / "DATA #64 · 之前被折叠"），让用户一眼看出
     "这段原来是折叠的，现在展开了"。 */
  const FOLD_HEAD = 3;
  const FOLD_TAIL = 1;
  const foldStartIdx = FOLD_HEAD;
  const foldEndIdx = dataPackets.length - FOLD_TAIL - 1;
  const foldCount = dataPackets.length - FOLD_HEAD - FOLD_TAIL;

  const result = [];

  if (shouldFold && expanded) {
    /* 展开态：所有 DATA 包都显示；在 [foldStartIdx] 之前插入 start-bar，在 [foldEndIdx] 之后插入 end-bar。*/
    packets.forEach((entry) => {
      if (entry.packet_type !== "DATA") {
        result.push({kind: "packet", entry});
        return;
      }
      const dataIdx = dataPackets.indexOf(entry);
      if (dataIdx === foldStartIdx) {
        result.push({
          kind: "foldStart",
          packetId: entry.packet_id,
          count: foldCount,
        });
      }
      result.push({kind: "packet", entry});
      if (dataIdx === foldEndIdx) {
        result.push({
          kind: "foldEnd",
          packetId: entry.packet_id,
        });
      }
    });
  } else if (shouldFold) {
    /* 折叠态：只显示首 3 + 末 1，中间一个 full-width bar 代替整段被折叠数据。 */
    const firstData = dataPackets.slice(0, FOLD_HEAD);
    const lastData = dataPackets[dataPackets.length - 1];
    const displayed = new Set([...firstData, lastData]);
    let insertedBar = false;
    packets.forEach((entry) => {
      if (entry.packet_type !== "DATA") {
        result.push({kind: "packet", entry});
        return;
      }
      if (displayed.has(entry)) {
        result.push({kind: "packet", entry});
        return;
      }
      if (!insertedBar) {
        result.push({
          kind: "ellipsis",
          firstId: dataPackets[foldStartIdx]?.packet_id ?? 0,
          lastId: dataPackets[foldEndIdx]?.packet_id ?? 0,
          count: foldCount,
        });
        insertedBar = true;
      }
    });
  } else {
    /* DATA 包 <= FOLD_THRESHOLD，不需要折叠/展开逻辑 */
    packets.forEach((entry) => result.push({kind: "packet", entry}));
  }

  return result;
}

function paginate(items, requestedPage, sortOrder) {
  /* 通用分页：
     - sortOrder="newest"（默认）：把 items 倒序，让最新的在前
     - sortOrder="oldest"：保持原顺序（最旧的在前）
     返回的 rows 已按排序结果切片好；调用方直接渲染即可。 */
  const total = items.length;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const currentPage = Math.min(Math.max(Number(requestedPage) || 1, 1), totalPages);
  const indexed = items.map((item, index) => ({item, index}));
  const ordered = sortOrder === "oldest" ? indexed : indexed.slice().reverse();
  const start = (currentPage - 1) * PAGE_SIZE;
  return {
    page: currentPage,
    total,
    totalPages,
    rows: ordered.slice(start, start + PAGE_SIZE),
  };
}

function renderPager(container, target, page, totalPages, total) {
  /* 4 按钮：首页 / 上一页 / 下一页 / 末页。
     data-page-delta 用 Infinity / -Infinity 表达"跳到首/末"；
     现有的 click handler 会用 Number() 转换，得到 +/-Infinity。
     注意：第一/最后一页时分别禁用首页/末页的按钮。*/
  const isFirst = page <= 1;
  const isLast = page >= totalPages;
  container.innerHTML = `
    <button class="pager-button" data-page-target="${target}" data-page-delta="-Infinity" type="button" ${isFirst ? "disabled" : ""} title="${escapeHtml(t("firstPage"))}">«</button>
    <button class="pager-button" data-page-target="${target}" data-page-delta="-1" type="button" ${isFirst ? "disabled" : ""}>${t("prevPage")}</button>
    <span class="pager-status">${t("pageStatus", {page, totalPages, total})}</span>
    <button class="pager-button" data-page-target="${target}" data-page-delta="1" type="button" ${isLast ? "disabled" : ""}>${t("nextPage")}</button>
    <button class="pager-button" data-page-target="${target}" data-page-delta="Infinity" type="button" ${isLast ? "disabled" : ""} title="${escapeHtml(t("lastPage"))}">»</button>
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
  syncProtocolSelectors();
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
  const stages = protocolSequenceStages();
  const current = stages.find((stage) => !completed.has(stage));
  return stages.map((stage) => {
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
      <div class="metric"><span>${t("protocolLabel")}</span><strong>${escapeHtml(protocolDisplayName(run.protocol || appState.selectedProtocol))}</strong></div>
      <div class="metric"><span>${t("scenarioLabel")}</span><strong>${escapeHtml(scenarioDisplayName(run.scenario || appState.selectedScenario, run.protocol || appState.selectedProtocol))}</strong></div>
      <div class="metric"><span>${t("received")}</span><strong>${formatBytes(run.receivedBytes)}</strong></div>
      <div class="metric"><span>${t("total")}</span><strong>${formatBytes(run.totalBytes)}</strong></div>
      <div class="metric"><span>${t("dataPackets")}</span><strong>${run.dataRecv.length}</strong></div>
      <div class="metric"><span>${t("attempts")}</span><strong>${run.attempts}/3</strong></div>
      <div class="metric"><span>${t("ackLabel")}</span><strong>${run.ackCount}</strong></div>
      <div class="metric"><span>${t("retransmitLabel")}</span><strong>${run.retransmits}</strong></div>
    </div>
  `;
  byId("digest-panel").innerHTML = digestMarkup(run, t("sha1Digest"));
  // 仪表盘"最近日志"也只显示当前 flow
  const flowLogs = appState.currentFlowId
    ? appState.logs.filter((e) => e.flow_id === appState.currentFlowId)
    : [];
  renderLogList(byId("recent-logs"), flowLogs.slice(-8), true);
}

function renderProtocolSummaryCard(run) {
  const node = byId("protocol-summary-panel");
  if (!node) return;
  const currentId = run.protocol || appState.selectedProtocol;
  const current = protocolOptions().find((item) => item.id === currentId) || currentProtocolDef();
  const compareOptions = protocolOptions().filter((item) => item.id !== currentId);
  if (!compareOptions.some((item) => item.id === appState.compareProtocol)) {
    appState.compareProtocol = compareOptions[0]?.id || currentId;
  }
  const compare = protocolOptions().find((item) => item.id === appState.compareProtocol) || null;
  const currentStages = (protocolSchema(currentId).sequenceStages || []).join(" -> ");
  const compareStages = compare ? (protocolSchema(compare.id).sequenceStages || []).join(" -> ") : "";
  node.innerHTML = `
    <div class="panel-head">
      <h2>${escapeHtml(appState.language === "zh" ? "当前协议摘要" : "Protocol summary")}</h2>
      <span class="hint">${escapeHtml(appState.language === "zh" ? "协议画像" : "Profile")}</span>
    </div>
    <div class="metric-grid protocol-summary-grid">
      <div class="metric"><span>${t("protocolLabel")}</span><strong>${escapeHtml(current?.name || currentId)}</strong></div>
      <div class="metric"><span>${t("scenarioLabel")}</span><strong>${escapeHtml(scenarioDisplayName(run.scenario || appState.selectedScenario, currentId))}</strong></div>
    </div>
    <div class="protocol-stage-line"><span>${escapeHtml(appState.language === "zh" ? "时序阶段" : "Sequence")}</span><code>${escapeHtml(currentStages || "-")}</code></div>
    <div class="protocol-compare-row">
      <label>
        <span class="label-text">${escapeHtml(appState.language === "zh" ? "对比协议" : "Compare protocol")}</span>
        <select id="compare-protocol-select">
          ${compareOptions.map((item) => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.name || item.id)}</option>`).join("")}
        </select>
      </label>
      ${compare ? `<div class="protocol-compare-card">
        <strong>${escapeHtml(compare.name || compare.id)}</strong>
        <code>${escapeHtml(compareStages || "-")}</code>
      </div>` : ""}
    </div>
  `;
  const select = byId("compare-protocol-select");
  if (select) {
    select.value = appState.compareProtocol;
    select.onchange = (event) => {
      appState.compareProtocol = event.currentTarget.value || currentId;
      renderProtocolSummaryCard(run);
    };
  }
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
      <div class="metric"><span>${t("protocolLabel")}</span><strong>${escapeHtml(protocolDisplayName(run.protocol || appState.selectedProtocol))}</strong></div>
      <div class="metric"><span>${t("scenarioLabel")}</span><strong>${escapeHtml(scenarioDisplayName(run.scenario || appState.selectedScenario, run.protocol || appState.selectedProtocol))}</strong></div>
      <div class="metric"><span>${t("serverPid")}</span><strong>${escapeHtml(appState.status.server?.pid || "-")}</strong></div>
      <div class="metric"><span>${t("clientPid")}</span><strong>${escapeHtml(appState.status.client?.pid || "-")}</strong></div>
      <div class="metric"><span>${t("sessionId")}</span><strong class="mono">${escapeHtml(run.sessionId || appState.status.experiment?.session_id || "-")}</strong></div>
      <div class="metric"><span>${t("transportLabel")}</span><strong>${escapeHtml(run.transport || "udp")}</strong></div>
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
  const type = appState.packetFilters.type;
  const direction = appState.packetFilters.direction;
  const flow = appState.packetFilters.flow;
  const state = appState.packetFilters.state;
  return source.filter((entry) => {
    const rawDirection = packetDirection(entry);
    if (type && entry.packet_type !== type) return false;
    if (direction && rawDirection !== direction) return false;
    if (flow && entry.flow_id !== flow) return false;
    if (state && entry.state !== state) return false;
    return true;
  });
}

function renderProtocol() {
  const packets = filteredPackets();
  // 同步下拉选项：flow_id / state 需要根据当前 realPackets 动态生成
  syncPacketFilterOptions();
  // 同步协议时序的 flow 选择器
  syncSequenceFlowOptions();
  const packetPage = paginate(packets, appState.pagination.packets, appState.packetFilters.sort);
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
    /* 全宽折叠条：3 种 kind
       - "ellipsis"（折叠态）：一个 bar，跨越整行，提示"DATA #first — #last · 省略 N 个 · 点击展开"
       - "foldStart"（展开态左端）：bar 标记"DATA #first · 之前被折叠 · 点击折叠"
       - "foldEnd"（展开态右端）：bar 标记"DATA #last · 之前被折叠 · 点击折叠"
       视觉上 bar 与 packet row 不同（不是 sequence-row，没有 client/server endpoint），整宽
       占据 sequence-view 的全部宽度。点击任何一个 bar 都触发同一个 toggle 逻辑。*/
    if (item.kind === "ellipsis") {
      return `
        <button class="fold-bar sequence-toggle" data-sequence-toggle="${escapeHtml(sequenceFlowId || "")}" type="button" aria-label="${escapeHtml(t("expandData"))}">
          <span class="fold-bar-line" aria-hidden="true"></span>
          <span class="fold-bar-text">
            <span class="fold-bar-dots" aria-hidden="true">⋯⋯⋯</span>
            <span class="fold-bar-range">${escapeHtml(t("dataFoldedRange", {first: item.firstId, last: item.lastId}))}</span>
            <span class="fold-bar-count">${escapeHtml(t("dataFolded", {count: item.count}))}</span>
            <span class="fold-bar-action">${escapeHtml(t("expandData"))}</span>
            <span class="fold-bar-dots" aria-hidden="true">⋯⋯⋯</span>
          </span>
          <span class="fold-bar-line" aria-hidden="true"></span>
        </button>
      `;
    }
    if (item.kind === "foldStart") {
      return `
        <button class="fold-bar sequence-toggle" data-sequence-toggle="${escapeHtml(sequenceFlowId || "")}" type="button" aria-label="${escapeHtml(t("collapseData"))}">
          <span class="fold-bar-line" aria-hidden="true"></span>
          <span class="fold-bar-text">
            <span class="fold-bar-dots" aria-hidden="true">⋯⋯⋯</span>
            <span class="fold-bar-marker">${escapeHtml(t("foldStartMarker", {id: item.packetId, count: item.count}))}</span>
            <span class="fold-bar-action">${escapeHtml(t("collapseData"))}</span>
          </span>
          <span class="fold-bar-line" aria-hidden="true"></span>
        </button>
      `;
    }
    if (item.kind === "foldEnd") {
      return `
        <button class="fold-bar sequence-toggle" data-sequence-toggle="${escapeHtml(sequenceFlowId || "")}" type="button" aria-label="${escapeHtml(t("collapseData"))}">
          <span class="fold-bar-line" aria-hidden="true"></span>
          <span class="fold-bar-text">
            <span class="fold-bar-dots" aria-hidden="true">⋯⋯⋯</span>
            <span class="fold-bar-marker">${escapeHtml(t("foldEndMarker", {id: item.packetId}))}</span>
            <span class="fold-bar-action">${escapeHtml(t("collapseData"))}</span>
          </span>
          <span class="fold-bar-line" aria-hidden="true"></span>
        </button>
      `;
    }
    const entry = item.entry;
    const direction = packetDirection(entry);
    const flowClass = packetFlowClass(entry);
    const toServer = direction === "Client -> Server";
    const toClient = direction === "Server -> Client";
    // 共享数据源：realPackets（已去重），点击时序列与列表都用同一索引
    const packetIndex = (appState.realPacketsIndex && appState.realPacketsIndex.get(entry)) ?? -1;
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
    const sourceIndex = (appState.realPacketsIndex && appState.realPacketsIndex.get(entry)) ?? -1;
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
  // 主字段清单：摘要级（friendly）。已与 parsePacketFields 严格去重——
  // 类型码 / 载荷长度 / packet_id / 方向都只在这里出现一次；
  // parsePacketFields 只补充"摘要里没有"的 wire-level 新信息（DATA 的载荷 hex、
  // TERMINATE 的 SHA1、PASS_RESP 的脱敏提示）。
  const mainRows = [
    {label: t("packet"), value: escapeHtml(packet.packet_type)},
    {label: t("protocolLabel"), value: escapeHtml(protocolDisplayName(packet.protocol || appState.status.experiment?.protocol || appState.selectedProtocol))},
    {label: t("flowId"), value: escapeHtml(packet.flow_id || "-"), mono: true},
    {label: t("sessionId"), value: escapeHtml(packet.session_id || appState.status.experiment?.session_id || "-"), mono: true},
    {label: t("packetUid"), value: escapeHtml(packet.packet_uid || "-"), mono: true},
    {label: t("scenarioLabel"), value: escapeHtml(scenarioDisplayName(packet.scenario || appState.status.experiment?.scenario || appState.selectedScenario, packet.protocol || appState.status.experiment?.protocol || appState.selectedProtocol))},
    {label: t("direction"), value: escapeHtml(packetDirectionText(packet))},
    {label: t("typeCode"), value: String(packetCodes[packet.packet_type] || packet.packet_code || "?")},
    {label: t("payloadLength"), value: `${escapeHtml(packet.payload_length ?? 0)} B`},
    {label: t("packetId"), value: escapeHtml(packetIdentifier(packet).text), title: escapeHtml(packetIdentifier(packet).title)},
    {label: t("state"), value: escapeHtml(packet.state || "-")},
    {label: t("time"), value: escapeHtml(packet.time), mono: true},
  ].concat(
    packet.seq !== undefined && packet.seq !== null ? [{label: t("seqLabel"), value: escapeHtml(packet.seq), mono: true}] : [],
    packet.ack !== undefined && packet.ack !== null ? [{label: t("ackLabel"), value: escapeHtml(packet.ack), mono: true}] : [],
    packet.window_size !== undefined && packet.window_size !== null ? [{label: t("windowLabel"), value: escapeHtml(packet.window_size), mono: true}] : [],
    packet.retransmit_count !== undefined && packet.retransmit_count !== null ? [{label: t("retransmitLabel"), value: escapeHtml(packet.retransmit_count), mono: true}] : [],
    packet.stream_offset !== undefined && packet.stream_offset !== null ? [{label: "stream_offset", value: escapeHtml(packet.stream_offset), mono: true}] : [],
    packet.connection_id ? [{label: "connection_id", value: escapeHtml(packet.connection_id), mono: true}] : [],
    packet.stream_id !== undefined && packet.stream_id !== null ? [{label: "stream_id", value: escapeHtml(packet.stream_id), mono: true}] : [],
    packet.method ? [{label: "method", value: escapeHtml(packet.method)}] : [],
    packet.path ? [{label: "path", value: escapeHtml(packet.path), mono: true}] : [],
    packet.status_code !== undefined && packet.status_code !== null ? [{label: "status", value: escapeHtml(packet.status_code), mono: true}] : [],
    packet.header_summary ? [{label: "headers", value: escapeHtml(packet.header_summary), mono: true}] : [],
    packet.frame_type ? [{label: "frame_type", value: escapeHtml(packet.frame_type)}] : [],
    packet.security ? [{label: "security", value: escapeHtml(JSON.stringify(packet.security)), mono: true}] : []
  );
  const wireExtras = parsePacketFields(packet);
  byId("packet-inspector").innerHTML = `
    <div class="field-list">
      ${mainRows.map((r) => `
        <div><span>${r.label}</span><strong${r.mono ? ' class="mono"' : ""}${r.title ? ` title="${r.title}"` : ""}>${r.value}</strong></div>
      `).join("")}
    </div>
    ${wireExtras.length ? `<h3 class="inspector-subhead">${t("wireDetails")}</h3>
    <div class="field-list">
      ${wireExtras.map((r) => `
        <div><span>${r.label}</span><strong class="mono">${r.value}</strong></div>
      `).join("")}
    </div>` : ""}
    <h3 class="inspector-subhead">${t("wireHex")}</h3>
    <code class="packet-hex">${escapeHtml(wireHex)}</code>
  `;
}

/**
 * 从 wire_hex 解析"摘要里没有的"额外字段。
 * 严格不与主字段清单重复——不输出 type / payload_length / direction / packet_id
 * 这些已经在 mainRows 里。仅当 wire 携带"摘要里看不到"的信息时才补充：
 *   - DATA: payload 字节预览
 *   - TERMINATE: SHA1 摘要
 *   - PASS_RESP: 脱敏说明
 *   - 其他: 无
 */
function parsePacketFields(packet) {
  const hex = String(packet.wire_hex || "").replace(/\s+/g, "");
  if (!hex) return [];
  const fields = [];
  const type = packet.packet_type;
  if (type === "DATA") {
    if (hex.length >= 20) {
      const payloadHex = hex.slice(20);
      fields.push({label: t("wirePayload"), value: payloadHex
        ? `${payloadHex.slice(0, 64)}${payloadHex.length > 64 ? "…" : ""}`
        : "(empty)"});
    }
  } else if (type === "TERMINATE") {
    if (hex.length >= 52) {
      fields.push({label: t("wireSha1"), value: hex.slice(12, 52) || "(missing)"});
    }
  } else if (type === "PASS_RESP") {
    if (hex.length >= 12) {
      fields.push({label: t("wirePayload"), value: t("redactedPacket")});
    }
  }
  return fields;
}

/* 传输 tab 总入口：依次渲染子面板。
   注意：这里的 run 仍然是 deriveRun() 结果（基于 currentFlowId），
   但所有"显示用的 run"都基于 effectiveTransferFlowId()，让用户能切换历史。 */
function renderTransfer(run) {
  const flowId = effectiveTransferFlowId();
  const scopedRun = scopeRunToFlow(run, flowId);
  const stats = computeTransferStats(scopedRun);

  renderTransferFlowOptions();
  renderTransferHero(scopedRun, flowId);
  renderLifecycle(scopedRun);
  renderProgress(scopedRun, stats);
  renderThroughput(scopedRun);
  renderFragmentMatrix(scopedRun, stats);
  renderIntegrity(scopedRun);
  renderTransferHistory();
}

/**
 * 复制一份 deriveRun 输出，但把 dataRecv/dataSent/sentBytes 等都按指定 flowId 过滤。
   如果当前 run 已经是该 flow 直接复用；否则按 flow 重新聚合。
   注意：必须用 allPackets（未去重），不能用 realPackets（按 packet_uid 跨端去重后，
   canonical 几乎总是 server 端的 SEND_DATA，导致 dataRecv 永远是空，
   进而 progress = 0、lostCount = expectedCount）。*/
function scopeRunToFlow(run, flowId) {
  if (!flowId || run.flowId === flowId) return run;
  const flowLogs = appState.logs.filter((e) => e.flow_id === flowId);
  /* 关键：用 allPackets，保留 client / server 两端记录。*/
  const flowPackets = appState.allPackets.filter((e) => e.flow_id === flowId);
  const protocolId = [...flowLogs].reverse().find((e) => e.protocol)?.protocol || run.protocol || appState.selectedProtocol;
  const dataRecv = flowTransferEntries(flowPackets, protocolId, "client");
  const dataSent = flowTransferEntries(flowPackets, protocolId, "server");
  const receivedBytes = uniqueTransferEntries(dataRecv).reduce((s, e) => s + Number(e.bytes || e.payload_length || 0), 0);
  const sentBytes = uniqueTransferEntries(dataSent).reduce((s, e) => s + Number(e.bytes || e.payload_length || 0), 0);
  const finalEvent = [...flowLogs].reverse().find(
    (e) => e.event === "FINAL_OK" || e.event === "FINAL_ABORT"
  );
  let result = finalEvent
    ? (finalEvent.result || (finalEvent.event === "FINAL_OK" ? "OK" : "ABORT"))
    : "Pending";
  const inputStart = [...flowLogs].reverse().find((e) => e.event === "SERVER_START");
  const totalBytes = protocolTransferView(protocolId) === "file"
    ? Number(inputStart?.bytes || Math.max(receivedBytes, sentBytes, 0))
    : Math.max(receivedBytes, sentBytes, 0);
  const progress = totalBytes > 0
    ? Math.min(100, Math.round((receivedBytes / totalBytes) * 100))
    : (result === "OK" ? 100 : 0);
  const firstData = dataRecv[0];
  const lastData = dataRecv[dataRecv.length - 1];
  let throughput = 0;
  if (firstData && lastData) {
    const start = new Date(firstData.time).getTime();
    const end = new Date(lastData.time).getTime();
    throughput = receivedBytes / Math.max(1, end - start) * 1000;
  }
  const phase = deriveFlowPhase(flowLogs, flowPackets, protocolId, result);
  const attempts = Math.max(0, ...flowLogs.map((e) => Number(e.attempt || 0)));
  const serverDigest = [...flowLogs].reverse().find((e) => e.event === "SERVER_DIGEST" && e.sha1);
  const clientDigest = [...flowLogs].reverse().find(
    (e) => (e.event === "DIGEST_MATCH" || e.event === "DIGEST_MISMATCH") && e.sha1
  );
  return {
    ...run,
    flowId,
    result,
    phase,
    attempts,
    progress,
    totalBytes,
    receivedBytes,
    sentBytes,
    dataRecv,
    dataSent,
    throughput,
    serverDigest: serverDigest?.sha1 || "",
    clientDigest: clientDigest?.sha1 || "",
    digestMatch: Boolean(clientDigest && clientDigest.event === "DIGEST_MATCH"),
    protocol: protocolId,
    transferView: protocolTransferView(protocolId),
    timelineEntries: flowTimelineEntries(flowPackets, protocolId),
  };
}

/* 1. Hero: 上下文 + Flow 选择器 */
function renderTransferFlowOptions() {
  const sel = byId("transfer-flow-select");
  if (!sel) return;
  const flows = collectFlowHistory();
  const current = effectiveTransferFlowId() || "";
  sel.innerHTML = `<option value="" data-i18n="latestFlow">${escapeHtml(t("latestFlow") || "Latest")}</option>` +
    flows.map((f) =>
      `<option value="${escapeHtml(f.flowId)}">${escapeHtml(f.flowId)}</option>`
    ).join("");
  sel.value = current;
}

function renderTransferHero(run, flowId) {
  const titleNode = byId("transfer-hero-title");
  const filesNode = byId("transfer-hero-files");
  const metaNode = byId("transfer-hero-meta");
  if (!titleNode) return;

  if (!flowId) {
    titleNode.textContent = t("transferHeroIdle");
    if (filesNode) filesNode.textContent = "";
    if (metaNode) metaNode.textContent = "";
    return;
  }

  /* 标题随结果/阶段变化 */
  let title = "";
  if (run.result === "OK") title = t("transferHeroPhaseOk");
  else if (run.result === "ABORT") title = t("transferHeroPhaseFail");
  else if (run.phase === "DATA_TRANSFER" || run.phase === "VERIFY") title = t("transferHeroPhaseRunning");
  else if (run.phase === "AUTH" || run.phase === "JOIN") title = t("transferHeroPhaseAuth");
  else title = t("transferHeroPhaseIdle");
  titleNode.textContent = title;

  /* 文件路径：server input + client output。Sidebar 表单里保存的最新值。 */
  const serverInput = byId("server-input-path")?.value || "—";
  const clientOutput = byId("client-output-path")?.value || "—";
  if (filesNode) {
    if ((run.transferView || protocolTransferView(run.protocol)) === "file") {
      filesNode.textContent = t("transferHeroFiles", {server: serverInput, client: clientOutput});
    } else if ((run.transferView || protocolTransferView(run.protocol)) === "transaction") {
      filesNode.textContent = appState.language === "zh"
        ? `请求 / 响应事务 · 输出 ${clientOutput}`
        : `Request/response transactions · output ${clientOutput}`;
    } else {
      filesNode.textContent = appState.language === "zh"
        ? `消息 / 帧演示 · 输出 ${clientOutput}`
        : `Message/frame demo · output ${clientOutput}`;
    }
  }

  /* 时长 + 总大小 */
  const flowLogs = appState.logs.filter((e) => e.flow_id === flowId);
  const firstTime = flowLogs[0]?.time;
  const lastTime = flowLogs[flowLogs.length - 1]?.time;
  let duration = "—";
  if (firstTime && lastTime) {
    const ms = new Date(lastTime).getTime() - new Date(firstTime).getTime();
    duration = ms > 1000 ? `${(ms / 1000).toFixed(2)} s` : `${ms} ms`;
  }
  if (metaNode) {
    metaNode.textContent = t("transferHeroMeta", {
      start: firstTime ? firstTime.split("T")[1]?.split(".")[0] || firstTime : "—",
      duration,
      total: formatBytes(run.totalBytes),
    });
  }

  /* 右侧 stats：去掉 Flow 一项（与上方 flow 选择器重复），剩下 8 项按 4 列 × 2 行 */
  const heroStats = byId("transfer-hero-stats");
  if (heroStats) {
    heroStats.innerHTML = `
      <div class="metric"><span>${t("protocolLabel")}</span><strong>${escapeHtml(protocolDisplayName(run.protocol || appState.selectedProtocol))}</strong></div>
      <div class="metric"><span>${t("scenarioLabel")}</span><strong>${escapeHtml(scenarioDisplayName(run.scenario || appState.selectedScenario, run.protocol || appState.selectedProtocol))}</strong></div>
      <div class="metric"><span>${t("sessionId")}</span><strong class="mono">${escapeHtml(run.sessionId || appState.status.experiment?.session_id || "-")}</strong></div>
      <div class="metric"><span>${t("attempts")}</span><strong>${run.attempts || 0}${run.attempts ? "/3" : ""}</strong></div>
      <div class="metric"><span>${t("dataPackets")}</span><strong>${run.dataRecv.length}</strong></div>
      <div class="metric"><span>${t("ackLabel")}</span><strong>${run.ackCount}</strong></div>
      <div class="metric"><span>${t("retransmitLabel")}</span><strong>${run.retransmits}</strong></div>
      <div class="metric"><span>${t("result")}</span><strong>${resultLabel(run.result)}</strong></div>
    `;
  }
}

/* 2. 生命周期阶段条：IDLE → AUTH → TRANSFER → VERIFY → OK/ABORT */
function renderLifecycle(run) {
  const strip = byId("lifecycle-strip");
  if (!strip) return;
  const stages = [
    {key: "IDLE",     label: t("stageIdle"),     match: () => true},
    {key: "AUTH",     label: t("stageAuth"),     match: (r) => ["JOIN","AUTH"].includes(r.phase)},
    {key: "TRANSFER", label: t("stageTransfer"), match: (r) => r.phase === "DATA_TRANSFER"},
    {key: "VERIFY",   label: t("stageVerify"),   match: (r) => r.phase === "VERIFY" || r.phase === "DONE"},
    {key: "DONE",     label: r => r.result === "ABORT" ? t("stageAbort") : t("stageDone"),
      match: (r) => r.result === "OK" || r.result === "ABORT"},
  ];
  const aborted = run.result === "ABORT";
  const isFinalDone = run.result === "OK";
  /* currentIdx = 最高已通过的阶段。"通过"指的是 match() 为 true。
     例如 DATA_TRANSFER 阶段时，IDLE/AUTH/TRANSFER 都 match，最高 = 2。*/
  let currentIdx = 0;
  for (let i = stages.length - 1; i >= 0; i -= 1) {
    if (stages[i].match(run)) { currentIdx = i; break; }
  }
  strip.innerHTML = stages.map((s, i) => {
    let cls;
    if (aborted && i === stages.length - 1) {
      cls = "is-abort";
    } else if (i < currentIdx) {
      cls = "is-done";
    } else if (i === currentIdx) {
      /* 最后阶段且 result=OK → 应该是"完成"视觉，不是"进行中" */
      cls = (i === stages.length - 1 && isFinalDone) ? "is-done" : "is-current";
    } else {
      cls = "is-pending";
    }
    const label = typeof s.label === "function" ? s.label(run) : s.label;
    return `<div class="lifecycle-step ${cls}">
      <span class="lifecycle-dot"></span>
      <span class="lifecycle-label">${escapeHtml(label)}</span>
    </div>${i < stages.length - 1 ? '<span class="lifecycle-bar"></span>' : ''}`;
  }).join("");
}

/* 3. 进度面板 */
function renderProgress(run, stats) {
  const fill = byId("transfer-progress");
  const label = byId("transfer-percent-label");
  if (fill) fill.style.width = `${run.progress}%`;
  if (label) label.textContent = `${run.progress}%`;

  /* ETA */
  let eta = t("etaPending");
  if (run.result === "OK") eta = t("etaDone");
  else if (stats.receivedCount > 0 && run.totalBytes > 0 && run.throughput > 0) {
    const remainingBytes = Math.max(0, run.totalBytes - run.receivedBytes);
    const sec = Math.round(remainingBytes / run.throughput);
    if (sec > 0 && sec < 9999) eta = t("etaSuffix", {seconds: `${sec}s`});
  }

  const statsNode = byId("transfer-stats");
  if (!statsNode) return;
  if ((run.transferView || protocolTransferView(run.protocol)) !== "file") {
    statsNode.innerHTML = `
      <div class="metric"><span>${t("progress")}</span><strong>${run.progress}%</strong></div>
      <div class="metric"><span>${t("received")}</span><strong>${formatBytes(run.receivedBytes)}</strong></div>
      <div class="metric"><span>${t("sent")}</span><strong>${formatBytes(run.sentBytes)}</strong></div>
      <div class="metric"><span>${appState.language === "zh" ? "步骤数" : "Steps"}</span><strong>${run.timelineEntries?.length || 0}</strong></div>
      <div class="metric"><span>${t("ackLabel")}</span><strong>${run.ackCount}</strong></div>
      <div class="metric"><span>${t("retransmitLabel")}</span><strong>${run.retransmits}</strong></div>
    `;
    return;
  }
  statsNode.innerHTML = `
    <div class="metric"><span>${t("progress")}</span><strong>${run.progress}%</strong></div>
    <div class="metric"><span>${t("received")}</span><strong>${formatBytes(run.receivedBytes)} / ${formatBytes(run.totalBytes)}</strong></div>
    <div class="metric"><span>${t("sent")}</span><strong>${formatBytes(run.sentBytes)}</strong></div>
    <div class="metric"><span>${t("dataPackets")}</span><strong>${run.dataRecv.length}${run.dataSent.length ? ` / ${run.dataSent.length}` : ""}</strong></div>
    <div class="metric eta-metric"><span>${t("etaLabel")}</span><strong>${escapeHtml(eta)}</strong></div>
    <div class="metric loss-metric"><span>${t("legendLost")}</span><strong>${stats.lostCount}</strong></div>
    <div class="metric dup-metric"><span>${t("legendDup")}</span><strong>${stats.dupCount}</strong></div>
    <div class="metric oof-metric"><span>${t("legendOof")}</span><strong>${stats.oofCount}</strong></div>
  `;
}

/* 4. 吞吐率时间线（sparkline）
   **系统级实时仪表**，不跟 flow 绑定：
   - 数据源固定为 appState.throughputSamples（每秒采样一次）
   - bytes 是当前 allPackets 里所有 client 端 DATA 包的总字节数（跨所有 flow 累加）
   - 切 flow / 切 tab / 跑测试都不影响——曲线持续演化
   - reset 才清空 samples（重新开始 30s 窗口）*/
function renderThroughput(run) {
  const svg = byId("throughput-svg");
  const label = byId("throughput-label");
  const clockNode = byId("throughput-clock");
  const statsNode = byId("throughput-stats");
  if (!svg) return;

  const samples = appState.throughputSamples;
  const rates = ratesFromSamples(samples);
  const max = rates.length ? Math.max(...rates, 1) : 1;
  const avg = rates.length ? rates.reduce((s, v) => s + v, 0) / rates.length : 0;
  const peak = max;
  const now = rates.length ? rates[rates.length - 1] || 0 : 0;
  /* 窗口内总字节：最新 sample 的累计 - 最早 sample 的累计 */
  const windowBytes = samples.length >= 2
    ? Math.max(0, samples[samples.length - 1].bytes - samples[0].bytes)
    : 0;

  if (label) label.textContent = `${formatBytes(Math.round(now))}/s`;
  if (clockNode) clockNode.textContent = formatTimeOfDay(new Date());
  if (statsNode) {
    statsNode.innerHTML = `
      <div class="metric"><span>${t("throughputNow")}</span><strong>${formatBytes(Math.round(now))}/s</strong></div>
      <div class="metric"><span>${t("throughputAvg")}</span><strong>${formatBytes(Math.round(avg))}/s</strong></div>
      <div class="metric"><span>${t("throughputPeak")}</span><strong>${formatBytes(Math.round(peak))}/s</strong></div>
      <div class="metric"><span>${t("throughputWindow", {seconds: 30})}</span><strong>${formatBytes(windowBytes)}</strong></div>
    `;
  }

  /* SVG 折线：X = sample index，Y = rate/max 归一化后反向（SVG Y 向下） */
  const W = 240;
  const H = 60;
  if (rates.length < 2) {
    svg.innerHTML = `<text x="${W/2}" y="${H/2 + 4}" text-anchor="middle" class="spark-empty">${escapeHtml(t("throughputIdle"))}</text>`;
    return;
  }
  const N = rates.length;
  const stepX = W / (N - 1);
  const points = rates.map((r, i) => {
    const x = (i * stepX).toFixed(2);
    const y = (H - (r / max) * (H - 4) - 2).toFixed(2);
    return `${x},${y}`;
  });
  const polyline = points.join(" ");
  const areaPoints = `0,${H} ${polyline} ${W},${H}`;
  const lastX = ((N - 1) * stepX).toFixed(2);
  const lastY = (H - (rates[N - 1] / max) * (H - 4) - 2).toFixed(2);
  /* 当前时间显示在 panel-head 的 #throughput-clock（YYYY-MM-DD HH:MM:SS），SVG 内不再重复 */
  svg.innerHTML = `
    <defs>
      <linearGradient id="spark-grad" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="currentColor" stop-opacity="0.45"/>
        <stop offset="100%" stop-color="currentColor" stop-opacity="0.05"/>
      </linearGradient>
    </defs>
    <polygon points="${areaPoints}" fill="url(#spark-grad)"/>
    <polyline points="${polyline}" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round" stroke-linecap="round"/>
    <!-- "现在" 标记：右端虚线 + 数据点（时间由 panel-head 时钟承载） -->
    <line x1="${W}" y1="2" x2="${W}" y2="${H - 4}" stroke="currentColor" stroke-width="0.6" stroke-dasharray="2,2" opacity="0.55"/>
    <circle cx="${lastX}" cy="${lastY}" r="2" fill="currentColor"/>
  `;
}

/* 滑动窗口：每个采样点 = (bytes_i - bytes_{i-1}) / dt。第一个点为 0（无参考）。*/
function ratesFromSamples(samples) {
  const rates = [];
  for (let i = 0; i < samples.length; i += 1) {
    if (i === 0) {
      rates.push(0);
    } else {
      const dt = Math.max(1, samples[i].t - samples[i - 1].t) / 1000;
      const db = Math.max(0, samples[i].bytes - samples[i - 1].bytes);
      rates.push(db / dt);
    }
  }
  return rates;
}

/* 5. 分片矩阵 */
function renderFragmentMatrix(run, stats) {
  const matrix = byId("fragment-matrix");
  const summary = byId("matrix-summary");
  const legend = byId("matrix-legend");
  if (!matrix) return;
  if ((run.transferView || protocolTransferView(run.protocol)) !== "file") {
    const entries = run.timelineEntries || [];
    if (summary) {
      summary.innerHTML = `<span class="matrix-summary-text">${
        escapeHtml(appState.language === "zh" ? `记录 ${entries.length} 个事务 / 消息步骤` : `${entries.length} transaction/message steps`)
      }</span>`;
    }
    if (legend) {
      legend.innerHTML = "";
    }
    matrix.classList.remove("show-time");
    matrix.classList.add("protocol-event-list");
    matrix.innerHTML = entries.length
      ? entries.map((entry) => `
          <div class="protocol-event-row">
            <div><strong>${escapeHtml(entry.packet_type || "-")}</strong><span class="hint">${escapeHtml(packetDirectionText(entry))}</span></div>
            <div class="mono">${escapeHtml(entry.method || entry.frame_type || entry.path || entry.connection_id || "-")}</div>
            <div class="mono">${escapeHtml(entry.path || (entry.status_code ?? entry.stream_id ?? "-"))}</div>
          </div>
        `).join("")
      : `<p class="inspector-empty matrix-empty">${escapeHtml(appState.language === "zh" ? "当前协议还没有事务 / 消息记录。" : "No transaction/message records yet.")}</p>`;
    return;
  }
  matrix.classList.remove("protocol-event-list");

  /* 摘要 + 图例 */
  if (summary) {
    summary.innerHTML = `<span class="matrix-summary-text">${escapeHtml(t("matrixSummary", {
      received: stats.receivedCount,
      expected: stats.expectedCount || stats.receivedCount,
      lost: stats.lostCount,
      dup: stats.dupCount,
      oof: stats.oofCount,
    }))}</span>`;
  }
  if (legend) {
    legend.innerHTML = `
      <span class="legend-chip legend-received">${escapeHtml(t("legendReceived"))}</span>
      ${appState.matrixView.showGaps ? `<span class="legend-chip legend-lost">${escapeHtml(t("legendLost"))}</span>` : ""}
      ${appState.matrixView.showDup ? `<span class="legend-chip legend-dup">${escapeHtml(t("legendDup"))}</span>` : ""}
      <span class="legend-chip legend-oof">${escapeHtml(t("legendOof"))}</span>
      <span class="legend-chip legend-pending">${escapeHtml(t("legendPending"))}</span>
    `;
  }

  /* 空态：没有任何 DATA 包。
     必须用 is-empty class 把 grid 切到 block，否则 <p> 被 grid item 约束成 22px 宽，
     中英文都按 1 字 1 行换行。*/
  if (stats.expectedCount === 0 && stats.receivedCount === 0) {
    const idle = run.phase === "AUTH" || run.phase === "JOIN"
      ? t("matrixAuthOnly")
      : t("matrixIdle");
    matrix.classList.add("is-empty");
    matrix.classList.remove("show-time");
    matrix.innerHTML = `<p class="inspector-empty matrix-empty">${escapeHtml(idle)}</p>`;
    return;
  }

  /* 非空态：恢复 grid 布局 */
  matrix.classList.remove("is-empty");
  matrix.classList.toggle("show-time", appState.matrixView.showTime);

  /* 决定要画多少格：优先用 expectedCount，否则用 max(expectedCount, receivedCount)
     兜底。最大 400 防爆。 */
  const total = Math.min(Math.max(stats.expectedCount, stats.receivedCount, 1), 400);
  const view = appState.matrixView;

  /* 时间带：在每个分片格的顶部叠加一条细线表示"到达相对时间"。
     我们只在该 flow 内的 RECV 上画。 */
  const recvByTime = [...run.dataRecv].sort((a, b) => logTimeMs(a) - logTimeMs(b));
  const firstRecvTime = recvByTime.length ? logTimeMs(recvByTime[0]) : 0;
  const lastRecvTime = recvByTime.length ? logTimeMs(recvByTime[recvByTime.length - 1]) : 0;
  const span = Math.max(1, lastRecvTime - firstRecvTime);
  const recvTimeById = new Map();
  for (const e of recvByTime) {
    recvTimeById.set(Number(e.packet_id), logTimeMs(e));
  }

  let cells = "";
  for (let id = 0; id < total; id += 1) {
    const classes = ["fragment"];
    const isReceived = stats.recvIds.has(id);
    const isLost = stats.lostIds.has(id);
    const isDup = stats.dupIds.has(id);
    const isOof = stats.oofIds.has(id);
    const isPending = stats.pendingIds.has(id) && !isReceived && !isLost;
    if (isReceived) classes.push("received");
    if (isDup && view.showDup) classes.push("dup");
    if (isLost && view.showGaps) classes.push("lost");
    if (isOof) classes.push("oof");
    if (isPending) classes.push("pending");
    if (id === appState.hoverFragmentId) classes.push("hovering");
    cells += `<button class="${classes.join(" ")}" data-fragment-id="${id}" type="button" aria-label="DATA #${id}"></button>`;
  }
  matrix.innerHTML = cells;
}

/* 6. 完整性面板：直接写字段，不复用 digestMarkup（避免 h2 重复）。
   digestMarkup 会自己生成 panel-head 的 h2，但我们这块面板已经有自己的 panel-head。 */
function renderIntegrity(run) {
  const node = byId("transfer-digest");
  if (!node) return;
  const state = run.clientDigest
    ? (run.digestMatch ? t("digestMatch") : t("digestMismatch"))
    : t("waiting");
  const badgeClass = run.digestMatch ? "success" : run.clientDigest ? "danger" : "";
  const clientOutput = byId("client-output-path")?.value || "";
  const pathLabel = appState.language === "zh" ? "客户端路径" : "Client path";
  const sizeLabel = appState.language === "zh" ? "期望大小" : "Expected size";
  node.innerHTML = `
    <div class="digest-status"><span class="badge ${badgeClass}">${escapeHtml(state)}</span></div>
    <div class="digest-line"><span>${t("serverSha1")}</span><code>${escapeHtml(run.serverDigest || t("waiting"))}</code></div>
    <div class="digest-line"><span>${t("clientSha1")}</span><code>${escapeHtml(run.clientDigest || t("waiting"))}</code></div>
    ${clientOutput ? `<div class="digest-line"><span>${escapeHtml(pathLabel)}</span><code class="mono">${escapeHtml(clientOutput)}</code></div>` : ""}
    <div class="digest-line"><span>${escapeHtml(sizeLabel)}</span><code>${escapeHtml(formatBytes(run.totalBytes))}</code></div>
    <div class="digest-line"><span>${t("result")}</span><code>${escapeHtml(resultLabel(run.result))}</code></div>
  `;
}

/* 7. 传输历史 */
function renderTransferHistory() {
  const list = byId("transfer-history-list");
  const hint = byId("transfer-history-hint");
  if (!list) return;
  const flows = collectFlowHistory();
  if (!flows.length) {
    list.innerHTML = `<p class="inspector-empty">${escapeHtml(t("historyEmpty"))}</p>`;
    if (hint) hint.textContent = "";
    return;
  }
  if (hint) hint.textContent = t("historyCount", {count: flows.length});

  const currentFlow = effectiveTransferFlowId();
  list.innerHTML = flows.map((f) => {
    const isCurrent = f.flowId === currentFlow;
    const resultClass = f.result === "OK" ? "success" : f.result === "ABORT" ? "danger" : "";
    const resultLabelText = f.result === "OK"
      ? t("historyResultOk")
      : f.result === "ABORT"
        ? t("historyResultAbort")
        : t("historyResultPending");
    /* 持续时长 */
    let duration = "—";
    if (f.firstTime && f.lastTime) {
      const ms = new Date(f.lastTime).getTime() - new Date(f.firstTime).getTime();
      duration = ms > 1000 ? t("historyDurationS", {s: (ms / 1000).toFixed(2)}) : t("historyDurationMs", {ms});
    }
    return `<button class="history-row ${isCurrent ? "is-current" : ""}" data-history-flow="${escapeHtml(f.flowId)}" type="button">
      <span class="history-flow-id mono">${escapeHtml(f.flowId)}</span>
      <span class="history-meta">${f.packetsRecv}/${f.packetsSent} DATA · ${duration}</span>
      <span class="badge ${resultClass}">${escapeHtml(resultLabelText)}</span>
    </button>`;
  }).join("");
}

function showFragmentTooltip(anchor, id, recv, sortedRecvs) {
  const tip = byId("fragment-tooltip");
  if (!tip) return;
  const bytes = Number(recv.bytes || recv.payload_length || 0);
  const time = recv.time ? recv.time.split("T")[1] || recv.time : "—";
  /* 找前一个到达的包 */
  const idx = sortedRecvs.indexOf(recv);
  let content;
  if (idx > 0) {
    const prev = sortedRecvs[idx - 1];
    const delta = logTimeMs(recv) - logTimeMs(prev);
    content = t("fragmentTooltip", {
      id,
      bytes: formatBytes(bytes),
      time,
      prev: `#${prev.packet_id}`,
      delta: delta < 1 ? "<1ms" : `${delta}ms`,
    });
  } else {
    content = t("fragmentTooltipFirst", {id, bytes: formatBytes(bytes), time});
  }
  tip.textContent = content;
  tip.hidden = false;
  /* 用 fixed 定位（viewport 坐标），绕开 tooltip 跟 matrix 的相对关系问题。
     CSS 已经配了 transform: translate(-50%, -100%) 让它居中悬浮在 cell 上方。*/
  const cellRect = anchor.getBoundingClientRect();
  tip.style.left = `${cellRect.left + cellRect.width / 2}px`;
  tip.style.top = `${cellRect.top}px`;
}

function hideFragmentTooltip() {
  const tip = byId("fragment-tooltip");
  if (tip) tip.hidden = true;
}

/* 每秒采样一次系统级吞吐率，给 sparkline 用。
   **不跟 flow 绑定**：bytes 是当前 allPackets 里所有 client-received DATA 的总字节数。
   这样 sparkline 反映的是"系统此刻的实时吞吐率"，无论用户在看哪个 flow、是否在跑 transfer。*/
function sampleThroughput() {
  const totalBytes = appState.allPackets
    .filter((e) => e.role === "client" && ["DATA", "APP_DATA", "STREAM"].includes(e.packet_type))
    .reduce((s, e) => s + Number(e.bytes || e.payload_length || 0), 0);
  appState.throughputSamples.push({t: Date.now(), bytes: totalBytes});
  if (appState.throughputSamples.length > 30) appState.throughputSamples.shift();
}

function filteredLogs() {
  const role = byId("role-filter")?.value || "";
  const level = byId("level-filter")?.value || "";
  const event = byId("log-event-filter")?.value || "";
  const errorOnly = appState.logFilters.errorOnly === true;
  /* 时间区间：先看预设（timeRange 状态），预设里说"all" 则不过滤；说"1m/5m/30m"
     就动态算"now - N 分钟"；说"custom" 才用两个输入框的绝对值。预设每次过滤都重算，
     所以"1 分钟前"始终是相对于当前时刻的 1 分钟。 */
  const preset = appState.logFilters.timeRange || "all";
  let fromMs = null;
  let toMs = null;
  if (preset === "1m" || preset === "5m" || preset === "30m") {
    const minutes = preset === "1m" ? 1 : preset === "5m" ? 5 : 30;
    fromMs = Date.now() - minutes * 60 * 1000;
    toMs = Date.now();
  } else if (preset === "custom") {
    const timeFrom = byId("log-time-from")?.value || "";
    const timeTo = byId("log-time-to")?.value || "";
    fromMs = timeFrom ? Date.parse(timeFrom) : null;
    toMs = timeTo ? Date.parse(timeTo) : null;
  }
  return appState.logs.filter((entry) => {
    if (role && entry.role !== role) return false;
    if (level && entry.level !== level) return false;
    if (event && entry.event !== event) return false;
    if (errorOnly && !["ERROR", "ABORT", "WARN"].includes(entry.level)) return false;
    if (fromMs !== null || toMs !== null) {
      const t = logTimeMs(entry);
      if (fromMs !== null && t < fromMs) return false;
      if (toMs !== null && t > toMs) return false;
    }
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
  // 同步 log 事件下拉（按当前 logs 动态生成所有出现的事件名）
  syncLogEventOptions();
  const logPage = paginate(logs, appState.pagination.logs, appState.logFilters.sort);
  appState.pagination.logs = logPage.page;
  byId("log-count").textContent = t("logEntries", {count: logs.length});
  renderLogTable(byId("full-log-tbody"), logPage.rows.map((row) => row.item));
  renderPager(byId("log-pager"), "logs", logPage.page, logPage.totalPages, logPage.total);
}

/* 维护 flow_id 下拉：根据 appState.realPackets 收集所有出现过的 flow_id。
   保留用户已选值（即使新数据里没有）；不存在时回退到 "全部流"。 */
function syncPacketFilterOptions() {
  const typeSel = byId("packet-type-filter");
  const flowSel = byId("packet-flow-filter");
  const stateSel = byId("packet-state-filter");
  if (!typeSel || !flowSel || !stateSel) return;
  const flows = new Set();
  const states = new Set();
  for (const p of appState.realPackets) {
    if (p.flow_id) flows.add(p.flow_id);
    if (p.state) states.add(p.state);
  }
  const currentType = appState.packetFilters.type;
  const sortedFlows = Array.from(flows).sort();
  const sortedStates = Array.from(states).sort();
  const curFlow = appState.packetFilters.flow;
  const curState = appState.packetFilters.state;
  const packetTypes = protocolPacketTypes();
  typeSel.innerHTML = `<option value="">${escapeHtml(t("allPacketTypes"))}</option>` +
    packetTypes.map((item) => `<option value="${escapeHtml(item.name)}">${escapeHtml(item.name)}</option>`).join("");
  typeSel.value = (currentType && packetTypes.some((item) => item.name === currentType)) ? currentType : "";
  appState.packetFilters.type = typeSel.value;
  flowSel.innerHTML = `<option value="">${escapeHtml(t("allFlows"))}</option>` +
    sortedFlows.map((f) => `<option value="${escapeHtml(f)}">${escapeHtml(f)}</option>`).join("");
  flowSel.value = (curFlow && sortedFlows.includes(curFlow)) ? curFlow : "";
  appState.packetFilters.flow = flowSel.value;
  stateSel.innerHTML = `<option value="">${escapeHtml(t("allStates"))}</option>` +
    sortedStates.map((s) => `<option value="${escapeHtml(s)}">${escapeHtml(s)}</option>`).join("");
  stateSel.value = (curState && sortedStates.includes(curState)) ? curState : "";
  appState.packetFilters.state = stateSel.value;
}

/* 协议时序 flow 选择器：根据 appState.realPackets 收集 flow_id，加上"自动（最近）"一项。 */
function syncSequenceFlowOptions() {
  const sel = byId("sequence-flow-select");
  if (!sel) return;
  const flows = new Set();
  for (const p of appState.realPackets) {
    if (p.flow_id) flows.add(p.flow_id);
  }
  // 按时间倒序：最后出现的 flow 排第一
  const seen = new Set();
  const ordered = [];
  for (let i = appState.realPackets.length - 1; i >= 0; i -= 1) {
    const id = appState.realPackets[i].flow_id;
    if (id && !seen.has(id)) {
      seen.add(id);
      ordered.push(id);
    }
  }
  const current = appState.selectedFlowId || "";
  sel.innerHTML = `<option value="" data-i18n="autoFlow">${escapeHtml(t("autoFlow") || "Auto (latest)")}</option>` +
    ordered.map((f) => `<option value="${escapeHtml(f)}">${escapeHtml(f)}</option>`).join("");
  // 只在用户已显式选择 flow 时把 select 锁住；否则保持"Auto"
  sel.value = (current && ordered.includes(current)) ? current : "";
}

/* 维护 log 事件下拉：根据 appState.logs 收集所有出现过的 event 名。 */
function syncLogEventOptions() {
  const sel = byId("log-event-filter");
  if (!sel) return;
  const events = new Set();
  for (const e of appState.logs) {
    if (e.event) events.add(e.event);
  }
  const sorted = Array.from(events).sort();
  const cur = byId("log-event-filter")?.value || "";
  sel.innerHTML = `<option value="">${escapeHtml(t("allEvents"))}</option>` +
    sorted.map((ev) => `<option value="${escapeHtml(ev)}">${escapeHtml(ev)}</option>`).join("");
  sel.value = (cur && sorted.includes(cur)) ? cur : "";
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
  /* Lift derived values from the run into appState here (single owner) so
     deriveRun() itself stays pure — no hidden side effects on read. */
  if (run.lastFlowResult) {
    appState.lastFlowResult = run.lastFlowResult;
  }
  appState.lastFlowPhase = run.phase || "INIT";
  updateTopbar(run);
  renderDashboard(run);
  renderProtocolSummaryCard(run);
  renderConfig(run);
  renderInteractiveAttempt(run);
  renderProtocol();
  renderTransfer(run);
  renderLogs();
  renderTests();
  /* 主动隐藏 tooltip（render 整体刷新后位置会失效） */
  hideFragmentTooltip();
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
        rebuildRealPacketsIndex();
        appState.packets = appState.currentFlowId
          ? appState.allPackets.filter((entry) => entry.flow_id === appState.currentFlowId)
          : appState.allPackets;
      }
    }
  } catch (err) {
    console.warn("refreshPackets failed:", err);
    appState.notice = "无法获取包列表：后端 /api/packets 返回异常";
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
        appState.status.experiment = {...(appState.status.experiment || {}), ...(data.experiment || {})};
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

async function runScenarioById(scenarioId) {
  if (scenarioId === "auth-failure") {
    await simulateAuthFailure();
    return;
  }
  if (scenarioId === "timeout") {
    await simulateTimeout();
    return;
  }
  await window.Api.stopServer();
  await window.Api.stopClient();
  await refreshStatus();
  byId("server-form").requestSubmit();
  setTimeout(() => {
    byId("client-form").requestSubmit();
  }, 350);
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
    data.protocol = appState.selectedProtocol;
    data.scenario = appState.selectedScenario;
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
    data.protocol = appState.selectedProtocol;
    data.scenario = appState.selectedScenario;
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

  byId("protocol-select")?.addEventListener("change", (event) => {
    appState.selectedProtocol = event.currentTarget.value || "udp-basic";
    const protocol = currentProtocolDef();
    const scenarios = appState.scenarioCatalog[appState.selectedProtocol]?.scenarios || [];
    appState.selectedScenario = protocol?.defaultScenario || scenarios[0]?.id || "normal";
    syncProtocolSelectors();
    render();
  });

  byId("scenario-select")?.addEventListener("change", (event) => {
    appState.selectedScenario = event.currentTarget.value || "normal";
    syncProtocolSelectors();
    render();
  });

  byId("run-scenario-btn")?.addEventListener("click", async () => {
    await runScenarioById(appState.selectedScenario);
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
  byId("view-full-logs-btn").addEventListener("click", (event) => {
    event.preventDefault();
    document.querySelector("[data-tab='logs']").click();
    /* Scroll to the logs panel header instead of the (nonexistent) anchor. */
    byId("full-log-tbody").scrollIntoView({behavior: "smooth", block: "start"});
  });
  // 日志过滤：role / level / event / 时间段 / 排序 / error-only
  ["role-filter", "level-filter", "log-event-filter", "log-sort"].forEach((id) => {
    byId(id).addEventListener("input", () => {
      appState.pagination.logs = 1;
      render();
    });
    byId(id).addEventListener("change", () => {
      appState.pagination.logs = 1;
      render();
    });
  });
  // 时间段用 change 触发（input 在 datetime-local 上是逐位变化，干扰太大）
  ["log-time-from", "log-time-to"].forEach((id) => {
    byId(id).addEventListener("change", () => {
      appState.pagination.logs = 1;
      render();
    });
  });
  // 包过滤：type / direction / flow / state / 排序
  ["packet-type-filter", "packet-direction-filter", "packet-flow-filter",
   "packet-state-filter", "packet-sort"].forEach((id) => {
    byId(id).addEventListener("change", () => {
      appState.packetFilters.type = byId("packet-type-filter").value || "";
      appState.packetFilters.direction = byId("packet-direction-filter").value || "";
      appState.packetFilters.flow = byId("packet-flow-filter").value || "";
      appState.packetFilters.state = byId("packet-state-filter").value || "";
      appState.packetFilters.sort = byId("packet-sort").value || "newest";
      appState.pagination.packets = 1;
      renderProtocol();
    });
  });
  // 协议时序：flow 选择器
  byId("sequence-flow-select")?.addEventListener("change", (event) => {
    const value = event.currentTarget.value || "";
    // 空串代表"自动（最近一次）"——清掉显式选择，让 currentSequenceFlowId() 回退到 currentFlowId
    appState.selectedFlowId = value || null;
    appState.currentFlowId = value || appState.currentFlowId;
    renderProtocol();
  });
  // 清空包过滤：把 5 个 select 复位、重置 appState、回第一页、重渲染
  const packetClear = byId("packet-filter-clear");
  if (packetClear) {
    packetClear.addEventListener("click", () => {
      appState.packetFilters.type = "";
      appState.packetFilters.direction = "";
      appState.packetFilters.flow = "";
      appState.packetFilters.state = "";
      appState.packetFilters.sort = "newest";
      appState.pagination.packets = 1;
      ["packet-type-filter", "packet-direction-filter", "packet-flow-filter",
       "packet-state-filter", "packet-sort"].forEach((id) => {
        const node = byId(id);
        if (node) node.value = "";
      });
      // sort 复位为 "newest"（不是空）
      byId("packet-sort").value = "newest";
      renderProtocol();
    });
  }
  // 清空日志过滤：6 个 select 复位、error-only 取消勾选、时间段留空、sort=newest、回第一页
  const logClear = byId("log-filter-clear");
  if (logClear) {
    logClear.addEventListener("click", () => {
      appState.logFilters.role = "";
      appState.logFilters.level = "";
      appState.logFilters.event = "";
      appState.logFilters.timeRange = "all";
      appState.logFilters.timeFrom = "";
      appState.logFilters.timeTo = "";
      appState.logFilters.sort = "newest";
      appState.logFilters.errorOnly = false;
      appState.pagination.logs = 1;
      ["role-filter", "level-filter", "log-event-filter",
       "log-time-from", "log-time-to", "log-sort"].forEach((id) => {
        const node = byId(id);
        if (node) node.value = "";
      });
      byId("log-sort").value = "newest";
      // 分段控件回到"全部"
      const segGroup = byId("log-time-range");
      if (segGroup) {
        segGroup.querySelectorAll(".seg-btn").forEach((btn) => {
          btn.classList.toggle("is-active", btn.dataset.range === "all");
        });
      }
      // 错误过滤分段控件回到"全部"
      const errToggle = byId("log-error-only-toggle");
      if (errToggle) {
        errToggle.querySelectorAll(".seg-btn").forEach((btn) => {
          btn.classList.toggle("is-active", btn.dataset.state === "all");
        });
      }
      // 隐藏自定义时段行
      const customRow = byId("log-custom-time-row");
      if (customRow) customRow.classList.add("is-hidden");
      render();
    });
  }
  // 传输 tab：flow 选择器
  byId("transfer-flow-select")?.addEventListener("change", (event) => {
    appState.transferFlowId = event.currentTarget.value || null;
    renderTransfer(deriveRun());
  });
  // 传输 tab：矩阵显示开关
  ["matrix-show-dup", "matrix-show-gaps", "matrix-show-time"].forEach((id) => {
    const node = byId(id);
    if (!node) return;
    node.addEventListener("change", () => {
      appState.matrixView = {
        showDup: byId("matrix-show-dup")?.checked ?? true,
        showGaps: byId("matrix-show-gaps")?.checked ?? true,
        showTime: byId("matrix-show-time")?.checked ?? false,
      };
      renderTransfer(deriveRun());
    });
  });
  // 矩阵 hover：tooltip
  const matrixNode = byId("fragment-matrix");
  if (matrixNode) {
    matrixNode.addEventListener("mouseover", (event) => {
      const cell = event.target.closest("[data-fragment-id]");
      if (!cell) return;
      const id = Number(cell.dataset.fragmentId);
      const flowId = effectiveTransferFlowId();
      if (!flowId) return;
      /* 用 allPackets（未去重），才能找到 client 端 RECV_DATA 记录 */
      const recvs = appState.allPackets
        .filter((e) => e.flow_id === flowId && e.role === "client" && e.packet_type === "DATA")
        .sort((a, b) => logTimeMs(a) - logTimeMs(b));
      const recv = recvs.find((e) => Number(e.packet_id) === id);
      if (!recv) return;
      appState.hoverFragmentId = id;
      showFragmentTooltip(cell, id, recv, recvs);
    });
    matrixNode.addEventListener("mouseout", (event) => {
      const cell = event.target.closest("[data-fragment-id]");
      if (!cell) return;
      appState.hoverFragmentId = null;
      hideFragmentTooltip();
    });
  }

  // 时间分段控件：5 段单选（全部 / 1m / 5m / 30m / 自定义）
  // 选 "custom" 才显示 datetime 输入行；其他段隐藏输入并用预设规则
  const segGroup = byId("log-time-range");
  if (segGroup) {
    segGroup.addEventListener("click", (event) => {
      const btn = event.target.closest(".seg-btn");
      if (!btn) return;
      const range = btn.dataset.range;
      if (!range) return;
      // 切换 is-active
      segGroup.querySelectorAll(".seg-btn").forEach((b) => {
        b.classList.toggle("is-active", b === btn);
      });
      // 更新 state
      appState.logFilters.timeRange = range;
      // 显示 / 隐藏自定义行
      const customRow = byId("log-custom-time-row");
      if (customRow) {
        customRow.classList.toggle("is-hidden", range !== "custom");
      }
      // 选"自定义"段时，若两个输入框都为空，自动填上 from=now-1h, to=now——
      // 用户不需要先看空框再手动填"现在"
      if (range === "custom") {
        const fromEl = byId("log-time-from");
        const toEl = byId("log-time-to");
        const now = new Date();
        const hourAgo = new Date(now.getTime() - 60 * 60 * 1000);
        const pad = (n) => String(n).padStart(2, "0");
        const fmt = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
        if (fromEl && !fromEl.value) fromEl.value = fmt(hourAgo);
        if (toEl && !toEl.value) toEl.value = fmt(now);
      }
      appState.pagination.logs = 1;
      render();
    });
  }
  // 自定义时段行的 datetime 输入：change 即触发过滤
  ["log-time-from", "log-time-to"].forEach((id) => {
    byId(id).addEventListener("change", () => {
      appState.pagination.logs = 1;
      render();
    });
  });
  // 错误过滤分段控件（全部 / 仅异常）
  // 替代原来的 check-pill 设计：和 time-range 同样的胶囊组，视觉一致
  const errToggle = byId("log-error-only-toggle");
  if (errToggle) {
    errToggle.addEventListener("click", (event) => {
      const btn = event.target.closest(".seg-btn");
      if (!btn) return;
      const state = btn.dataset.state;
      if (!state) return;
      errToggle.querySelectorAll(".seg-btn").forEach((b) => {
        b.classList.toggle("is-active", b === btn);
      });
      appState.logFilters.errorOnly = state === "errors";
      appState.pagination.logs = 1;
      render();
    });
  }

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
      const rawDelta = String(pageButton.dataset.pageDelta || "0");
      if (rawDelta === "Infinity") {
        /* 末页：跳到当前已知的最大页（由 renderPager 计算） */
        const source = target === "packets" ? filteredPackets() : filteredLogs();
        const totalPages = Math.max(1, Math.ceil(source.length / PAGE_SIZE));
        appState.pagination[target] = totalPages;
      } else if (rawDelta === "-Infinity") {
        /* 首页 */
        appState.pagination[target] = 1;
      } else {
        const delta = Number(rawDelta);
        appState.pagination[target] += delta;
      }
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
      return;
    }
    const historyRow = event.target.closest("[data-history-flow]");
    if (historyRow) {
      const flowId = historyRow.dataset.historyFlow;
      if (flowId) {
        appState.transferFlowId = flowId;
        renderTransfer(deriveRun());
      }
      return;
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
}

/* 原"模拟认证失败"按钮逻辑：从协议与场景下拉选择 auth-failure 时也会复用 */
async function simulateAuthFailure() {
  appState.selectedScenario = "auth-failure";
  syncProtocolSelectors();
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
  const serverResult = await window.Api.startServer({
    ...serverForm,
    protocol: appState.selectedProtocol,
    scenario: appState.selectedScenario,
  });
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
    protocol: appState.selectedProtocol,
    scenario: appState.selectedScenario,
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
}

/* 原"模拟超时"按钮逻辑：从协议与场景下拉选择 timeout 时也会复用 */
async function simulateTimeout() {
  appState.selectedScenario = "timeout";
  syncProtocolSelectors();
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
    protocol: appState.selectedProtocol,
    scenario: appState.selectedScenario,
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
}

async function boot() {
  try {
    setLanguage(localStorage.getItem("udpLabLanguage") || "zh", false);
    setSidebarCollapsed(localStorage.getItem("udpLabSidebarCollapsed") === "1");
  } catch (error) {
    console.warn(error);
    setLanguage("zh", false);
  }
  // 日志时间区间：默认"全部"（不过滤）。重置时也是"全部"。
  // 自定义输入框留空，隐藏自定义行；只有用户主动选"自定义"段才显示。
  // 注意：datetime-local 输入框不再预填 2000-01-01 之类的"魔法日期"——
  //   那是反直觉的"我看不出我选了 2000 年"的视觉陷阱。
  const segGroup = byId("log-time-range");
  if (segGroup && !segGroup.querySelector(".seg-btn.is-active")) {
    segGroup.querySelectorAll(".seg-btn").forEach((btn) => {
      btn.classList.toggle("is-active", btn.dataset.range === "all");
    });
  }
  // 自定义时段行默认隐藏
  const customRow = byId("log-custom-time-row");
  if (customRow) customRow.classList.add("is-hidden");
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
  await loadProtocolCatalog();
  wireEvents();
  syncProtocolSelectors();
  syncPasswordMode();
  await refreshStatus();
  await refreshLogs();
  /* After the first log load, advance the flow counter past anything already
     present so refreshes don't regenerate the same flow IDs. */
  appState.flowCounter = Math.max(appState.flowCounter, maxExistingFlowCounter(appState.logs));
  connectWebSocket();
  setInterval(refreshStatus, 2500);
  setInterval(refreshLogs, 6000);
  /* 吞吐率采样：每秒一次。sparkline 渲染也走同一周期。 */
  setInterval(() => {
    sampleThroughput();
    if (appState.activeTab === "transfer") {
      renderThroughput(deriveRun());
    }
  }, 1000);
}

boot();
