const appState = {
  status: {},
  logs: [],
  packets: [],
  selectedPacket: null,
  tests: [],
  activeTab: "dashboard",
};

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

function byId(id) {
  return document.getElementById(id);
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
  appState.packets = appState.logs.filter((entry) => entry.packet_type);
}

function latest(predicate) {
  for (let i = appState.logs.length - 1; i >= 0; i -= 1) {
    if (predicate(appState.logs[i])) return appState.logs[i];
  }
  return null;
}

function deriveRun() {
  const finalEvent = latest((entry) => entry.event === "FINAL_OK" || entry.event === "FINAL_ABORT");
  const result = finalEvent?.result || "Pending";
  const hasAbort = result === "ABORT" || appState.logs.some((entry) => entry.level === "ERROR" || entry.level === "ABORT");
  let phase = "INIT";
  if (hasAbort && result === "ABORT") phase = "ABORT";
  else if (latest((entry) => entry.event === "DIGEST_MATCH")) phase = "DONE";
  else if (latest((entry) => entry.packet_type === "TERMINATE")) phase = "VERIFY";
  else if (latest((entry) => entry.packet_type === "DATA")) phase = "DATA_TRANSFER";
  else if (latest((entry) => ["PASS_REQ", "PASS_RESP", "PASS_ACCEPT", "REJECT"].includes(entry.packet_type))) phase = "AUTH";
  else if (latest((entry) => entry.packet_type === "JOIN_REQ")) phase = "JOIN";

  const serverDigest = latest((entry) => entry.event === "SERVER_DIGEST" && entry.sha1);
  const clientDigest = latest((entry) => (entry.event === "DIGEST_MATCH" || entry.event === "DIGEST_MISMATCH") && entry.sha1);
  const dataRecv = appState.logs.filter((entry) => entry.role === "client" && entry.packet_type === "DATA");
  const dataSent = appState.logs.filter((entry) => entry.role === "server" && entry.packet_type === "DATA");
  const inputStart = latest((entry) => entry.event === "SERVER_START");
  const receivedBytes = dataRecv.reduce((sum, entry) => sum + Number(entry.bytes || entry.payload_length || 0), 0);
  const sentBytes = dataSent.reduce((sum, entry) => sum + Number(entry.bytes || entry.payload_length || 0), 0);
  const totalBytes = Number(inputStart?.bytes || Math.max(receivedBytes, sentBytes, 0));
  const attempts = Math.max(0, ...appState.logs.map((entry) => Number(entry.attempt || 0)));
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
  };
}

function packetDirection(entry) {
  const event = entry.event || "";
  if (entry.role === "client" && event.startsWith("SEND")) return "Client -> Server";
  if (entry.role === "server" && event.startsWith("RECV")) return "Client -> Server";
  if (entry.role === "server" && event.startsWith("SEND")) return "Server -> Client";
  if (entry.role === "client" && event.startsWith("RECV")) return "Server -> Client";
  return "Observed";
}

function updateTopbar(run) {
  const serverRunning = appState.status.server?.running;
  const clientRunning = appState.status.client?.running;
  byId("server-pill").textContent = `Server: ${serverRunning ? "Running" : "Stopped"}`;
  byId("client-pill").textContent = `Client: ${clientRunning ? "Running" : "Stopped"}`;
  byId("phase-pill").textContent = `Phase: ${run.phase}`;
  byId("result-pill").textContent = `Result: ${run.result}`;
  byId("server-pill").classList.toggle("is-running", Boolean(serverRunning));
  byId("client-pill").classList.toggle("is-running", Boolean(clientRunning));
  byId("result-pill").classList.toggle("is-running", run.result === "OK");
  byId("result-pill").classList.toggle("is-abort", run.result === "ABORT");
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
        <span>${status === "done" ? "完成" : status === "current" ? "等待" : status === "fail" ? "异常" : "未开始"}</span>
      </div>
    `;
  }).join("");
}

function renderDashboard(run) {
  byId("dashboard-title").textContent =
    run.result === "OK" ? "传输完成，摘要匹配" :
    run.result === "ABORT" ? "运行中止，请检查异常日志" :
    run.phase === "INIT" ? "等待启动" : `当前阶段：${run.phase}`;
  byId("dashboard-summary").textContent =
    run.finalEvent?.message || `认证尝试 ${run.attempts}/3，已接收 ${formatBytes(run.receivedBytes)}。`;
  byId("dashboard-phases").innerHTML = renderPhases(run);
  byId("metrics-panel").innerHTML = `
    <div class="panel-head"><h2>传输摘要</h2><span class="hint">${run.progress}%</span></div>
    <div class="metric-grid">
      <div class="metric"><span>Received</span><strong>${formatBytes(run.receivedBytes)}</strong></div>
      <div class="metric"><span>Total</span><strong>${formatBytes(run.totalBytes)}</strong></div>
      <div class="metric"><span>DATA packets</span><strong>${run.dataRecv.length}</strong></div>
      <div class="metric"><span>Attempts</span><strong>${run.attempts}/3</strong></div>
    </div>
  `;
  byId("digest-panel").innerHTML = digestMarkup(run, "SHA1 摘要");
  renderLogList(byId("recent-logs"), appState.logs.slice(-8), true);
}

function digestMarkup(run, title) {
  const state = run.clientDigest ? (run.digestMatch ? "Digest Match" : "Digest Mismatch") : "Waiting";
  const badgeClass = run.digestMatch ? "success" : run.clientDigest ? "danger" : "";
  return `
    <div class="panel-head"><h2>${title}</h2><span class="badge ${badgeClass}">${state}</span></div>
    <div class="digest-lines">
      <div class="digest-line"><span>Server SHA1</span><code>${escapeHtml(run.serverDigest || "waiting")}</code></div>
      <div class="digest-line"><span>Client SHA1</span><code>${escapeHtml(run.clientDigest || "waiting")}</code></div>
      <div class="digest-line"><span>Result</span><code>${escapeHtml(run.result)}</code></div>
    </div>
  `;
}

function renderConfig(run) {
  byId("config-state").innerHTML = `
    <div class="panel-head"><h2>运行状态</h2><span class="hint">HTTP/WebSocket</span></div>
    <div class="metric-grid">
      <div class="metric"><span>Server PID</span><strong>${escapeHtml(appState.status.server?.pid || "-")}</strong></div>
      <div class="metric"><span>Client PID</span><strong>${escapeHtml(appState.status.client?.pid || "-")}</strong></div>
      <div class="metric"><span>Phase</span><strong>${run.phase}</strong></div>
      <div class="metric"><span>Result</span><strong>${run.result}</strong></div>
    </div>
  `;
}

function renderProtocol() {
  const packets = appState.packets;
  byId("packet-count").textContent = `${packets.length} packets`;
  byId("sequence-view").innerHTML = packets.slice(-28).map((entry, index) => {
    const direction = packetDirection(entry);
    const toServer = direction === "Client -> Server";
    return `
      <div class="sequence-row">
        <span>${toServer ? "Client" : "Server"}</span>
        <button class="sequence-line ${toServer ? "to-server" : "to-client"}" data-packet-index="${appState.packets.indexOf(entry)}" type="button">
          ${escapeHtml(entry.packet_type)}${entry.packet_id !== undefined ? ` #${entry.packet_id}` : ""}
        </button>
        <span>${toServer ? "Server" : "Client"}</span>
      </div>
    `;
  }).join("") || `<p class="inspector-empty">暂无协议包。启动客户端后会出现 JOIN_REQ。</p>`;

  byId("packet-table-body").innerHTML = packets.map((entry, index) => `
    <tr data-packet-index="${index}">
      <td>${index + 1}</td>
      <td>${escapeHtml(entry.time)}</td>
      <td>${packetDirection(entry)}</td>
      <td>${escapeHtml(entry.role)}</td>
      <td>${escapeHtml(entry.packet_type)} (${packetCodes[entry.packet_type] || "?"})</td>
      <td>${escapeHtml(entry.payload_length ?? "-")}</td>
      <td>${escapeHtml(entry.packet_id ?? "-")}</td>
      <td>${escapeHtml(entry.state || "-")}</td>
    </tr>
  `).join("");
  renderInspector();
}

function renderInspector() {
  const packet = appState.selectedPacket || appState.packets[appState.packets.length - 1];
  if (!packet) {
    byId("packet-inspector").innerHTML = `<p class="inspector-empty">选择一个包查看 type、payload length、packet id 和原始十六进制字段。</p>`;
    return;
  }
  byId("packet-inspector").innerHTML = `
    <div class="field-list">
      <div><span>Packet</span><strong>${escapeHtml(packet.packet_type)}</strong></div>
      <div><span>Type Code</span><strong>${packetCodes[packet.packet_type] || "?"}</strong></div>
      <div><span>Payload Length</span><strong>${escapeHtml(packet.payload_length ?? 0)}</strong></div>
      <div><span>Packet ID</span><strong>${escapeHtml(packet.packet_id ?? "N/A")}</strong></div>
      <div><span>Direction</span><strong>${packetDirection(packet)}</strong></div>
      <div><span>Role</span><strong>${escapeHtml(packet.role)}</strong></div>
      <div><span>State</span><strong>${escapeHtml(packet.state || "-")}</strong></div>
      <div><span>Time</span><strong>${escapeHtml(packet.time)}</strong></div>
    </div>
    <h3 style="margin-top:14px">Wire Hex</h3>
    <code class="packet-hex">${escapeHtml(packet.wire_hex || "PASS_RESP payload redacted or raw packet unavailable")}</code>
  `;
}

function renderTransfer(run) {
  byId("transfer-progress").style.width = `${run.progress}%`;
  byId("throughput-label").textContent = `${formatBytes(Math.round(run.throughput))}/s`;
  byId("transfer-stats").innerHTML = `
    <div class="metric"><span>Progress</span><strong>${run.progress}%</strong></div>
    <div class="metric"><span>Received</span><strong>${formatBytes(run.receivedBytes)}</strong></div>
    <div class="metric"><span>Sent</span><strong>${formatBytes(run.sentBytes)}</strong></div>
    <div class="metric"><span>Packets</span><strong>${run.dataRecv.length}</strong></div>
  `;
  const ids = run.dataRecv.map((entry) => Number(entry.packet_id || 0));
  const maxId = ids.length ? Math.max(...ids) : 0;
  const cells = Math.max(maxId + 1, run.result === "Pending" ? 24 : ids.length);
  const received = new Set(ids);
  byId("fragment-matrix").innerHTML = Array.from({length: Math.min(Math.max(cells, 1), 400)}, (_, id) => {
    const cls = received.has(id) ? "received" : "";
    return `<button class="fragment ${cls}" title="DATA #${id}" data-fragment-id="${id}" type="button"></button>`;
  }).join("");
  byId("transfer-digest").innerHTML = digestMarkup(run, "完整性校验");
}

function filteredLogs() {
  const role = byId("role-filter")?.value || "";
  const level = byId("level-filter")?.value || "";
  const search = (byId("search-filter")?.value || "").toLowerCase();
  const errorOnly = byId("error-only")?.checked;
  return appState.logs.filter((entry) => {
    const haystack = `${entry.event || ""} ${entry.state || ""} ${entry.message || ""} ${entry.packet_type || ""}`.toLowerCase();
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
    return `
      <div class="log-entry ${isError ? "error" : ""}">
        <span class="mono">${escapeHtml(entry.time)}</span>
        <strong>${escapeHtml(entry.level)}</strong>
        <span>${escapeHtml(entry.role)} · ${escapeHtml(entry.event)}</span>
        <span class="log-message">${escapeHtml(compact ? (entry.message || entry.packet_type || "") : `${entry.state || ""} ${entry.packet_type || ""} ${entry.message || ""}`)}</span>
      </div>
    `;
  }).join("") || `<p class="inspector-empty">暂无日志。</p>`;
}

function renderLogs() {
  const logs = filteredLogs();
  byId("log-count").textContent = `${logs.length} entries`;
  renderLogList(byId("full-log-list"), logs.slice(-300));
}

function renderTests() {
  byId("test-results").innerHTML = appState.tests.map((test) => `
    <div class="test-row">
      <strong>${escapeHtml(test.id || test.name || "case")}</strong>
      <span>${escapeHtml(test.name || test.message || "")}</span>
      <span class="badge ${test.pass ? "success" : "danger"}">${test.pass ? "PASS" : "FAIL"}</span>
    </div>
  `).join("") || `<p class="inspector-empty">尚未运行测试。</p>`;
}

function render() {
  const run = deriveRun();
  updateTopbar(run);
  renderDashboard(run);
  renderConfig(run);
  renderProtocol();
  renderTransfer(run);
  renderLogs();
  renderTests();
}

async function refreshStatus() {
  appState.status = await window.Api.status();
  render();
}

async function refreshLogs() {
  const data = await window.Api.logs();
  mergeLogs([...(data.server || []), ...(data.client || []), ...(data.control || [])]);
  render();
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
    await window.Api.startServer(formObject(event.currentTarget));
    setTimeout(refreshStatus, 250);
  });

  byId("client-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    await window.Api.startClient(formObject(event.currentTarget));
    setTimeout(refreshStatus, 250);
  });

  document.querySelectorAll("input[name='mode']").forEach((input) => {
    input.addEventListener("change", () => {
      byId("compat-passwords").style.display = input.value === "interactive" && input.checked ? "none" : "grid";
    });
  });

  byId("stop-server-btn").addEventListener("click", async () => {
    await window.Api.stopServer();
    await refreshStatus();
  });
  byId("stop-client-btn").addEventListener("click", async () => {
    await window.Api.stopClient();
    await refreshStatus();
  });
  byId("send-password-btn").addEventListener("click", async () => {
    await window.Api.sendPassword(byId("interactive-password").value);
  });
  byId("reset-btn").addEventListener("click", async () => {
    await window.Api.reset();
    await refreshStatus();
  });
  byId("clear-logs-btn").addEventListener("click", async () => {
    await window.Api.clearLogs();
    appState.logs = [];
    appState.packets = [];
    render();
  });
  byId("refresh-logs-btn").addEventListener("click", refreshLogs);
  ["role-filter", "level-filter", "search-filter", "error-only"].forEach((id) => {
    byId(id).addEventListener("input", render);
  });

  document.addEventListener("click", (event) => {
    const packetTarget = event.target.closest("[data-packet-index]");
    if (packetTarget) {
      const index = Number(packetTarget.dataset.packetIndex);
      appState.selectedPacket = appState.packets[index];
      renderInspector();
    }
    const fragment = event.target.closest("[data-fragment-id]");
    if (fragment) {
      const id = Number(fragment.dataset.fragmentId);
      appState.selectedPacket = appState.packets.find((entry) => entry.packet_type === "DATA" && Number(entry.packet_id) === id) || null;
      appState.activeTab = "protocol";
      document.querySelector("[data-tab='protocol']").click();
    }
  });

  byId("run-tests-btn").addEventListener("click", async () => {
    byId("test-results").innerHTML = `<p class="inspector-empty">测试运行中...</p>`;
    const result = await window.Api.runTests();
    appState.tests = result.tests || [];
    renderTests();
    await refreshLogs();
  });

  byId("simulate-wrong-btn").addEventListener("click", async () => {
    const serverForm = formObject(byId("server-form"));
    const clientForm = formObject(byId("client-form"));
    await window.Api.reset();
    await window.Api.startServer(serverForm);
    setTimeout(async () => {
      await window.Api.startClient({
        host: clientForm.host,
        port: serverForm.port,
        outputFile: "output/wrong-auth.bin",
        mode: "compat",
        pwd1: "wrong-one",
        pwd2: "wrong-two",
        pwd3: "wrong-three",
      });
    }, 350);
  });

  byId("simulate-timeout-btn").addEventListener("click", async () => {
    const clientForm = formObject(byId("client-form"));
    await window.Api.reset();
    await window.Api.startClient({
      host: clientForm.host,
      port: String(Number(clientForm.port || 9000) + 41),
      outputFile: "output/timeout.bin",
      mode: "compat",
      pwd1: "secret",
      pwd2: "secret",
      pwd3: "secret",
    });
  });
}

async function boot() {
  wireEvents();
  await refreshStatus();
  await refreshLogs();
  connectWebSocket();
  setInterval(refreshStatus, 2500);
  setInterval(refreshLogs, 6000);
}

boot();
