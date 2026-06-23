/* =============================================================================
   dock.js — 状态信息条
   注入位置：顶部栏第 2 行 #topbar-info-strip（在 app 名 / 状态条下方）。
   显示：当前协议、运行态（服务端/客户端 PID + 状态）、运行时长、
         吞吐累计、Flow 计数、状态药丸。
   通过 window.Lab.state 读 app state；每 1s 刷新一次，不抢主循环。
   旧版本是底部固定 36px 横条；本版本已并入 topbar，不再占视口高度。
   ============================================================================= */
(function () {
  'use strict';

  function ensureInfoStrip() {
    let strip = document.getElementById('topbar-info-strip');
    if (!strip) return null;
    if (strip.dataset.dockReady === '1') return strip;
    strip.dataset.dockReady = '1';
    /* 与 status-strip 拆分职责：
       - status-strip 负责"操作态"（服务端 / 客户端 / 阶段 / 结果）—— app.js 维护
       - info-strip 负责"度量"（协议 / 运行时长 / 吞吐 / Flow）—— dock.js 维护
       两边不再重复显示同一信息。 */
    strip.innerHTML = [
      '<span class="topbar-info-segment">',
        '<span class="topbar-info-label">协议</span>',
        '<strong class="topbar-info-value" id="topbar-info-protocol">—</strong>',
      '</span>',
      '<span class="topbar-info-divider" aria-hidden="true">·</span>',
      '<span class="topbar-info-segment">',
        '<span class="topbar-info-label">运行时长</span>',
        '<strong class="topbar-info-value" id="topbar-info-runtime">00:00</strong>',
      '</span>',
      '<span class="topbar-info-divider" aria-hidden="true">·</span>',
      '<span class="topbar-info-segment">',
        '<span class="topbar-info-label">吞吐</span>',
        '<strong class="topbar-info-value" id="topbar-info-bytes">0 B</strong>',
      '</span>',
      '<span class="topbar-info-divider" aria-hidden="true">·</span>',
      '<span class="topbar-info-segment">',
        '<span class="topbar-info-label">Flow</span>',
        '<strong class="topbar-info-value" id="topbar-info-flow">0</strong>',
      '</span>',
    ].join('');
    return strip;
  }

  function formatRuntime(ms) {
    if (!ms || ms < 0) return '00:00';
    const total = Math.floor(ms / 1000);
    const h = Math.floor(total / 3600);
    const m = Math.floor((total % 3600) / 60);
    const s = total % 60;
    if (h > 0) return `${h}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
    return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
  }

  function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  }

  function refresh() {
    const Lab = window.Lab;
    if (!Lab || !Lab.state) return;
    const state = Lab.state;
    const status = state.status || {};

    /* 协议 */
    const protocolId = state.selectedProtocol || '—';
    const protocolName = (Lab.helpers.protocolDisplayName && Lab.helpers.protocolDisplayName(protocolId)) || protocolId;
    setText('topbar-info-protocol', protocolName);

    /* 运行时长：取 server/client 较晚启动的那个，到现在 */
    const serverStartedAt = (status.server && status.server.started_at) || 0;
    const clientStartedAt = state.clientRunStartedAt || 0;
    const baseTs = Math.max(serverStartedAt, clientStartedAt);
    const runtimeMs = baseTs ? Date.now() - baseTs : 0;
    setText('topbar-info-runtime', formatRuntime(runtimeMs));

    /* 吞吐：累计 throughputSamples 的 bytes */
    const samples = state.throughputSamples || [];
    let totalBytes = 0;
    for (let i = 0; i < samples.length; i++) {
      totalBytes += samples[i].bytes || 0;
    }
    setText('topbar-info-bytes', Lab.helpers.formatBytes(totalBytes));

    /* Flow 计数：按 flow_id 去重 */
    const flowIds = new Set();
    (state.logs || []).forEach((entry) => { if (entry.flow_id) flowIds.add(entry.flow_id); });
    setText('topbar-info-flow', String(flowIds.size || state.flowCounter || 0));
  }

  function init() {
    const strip = ensureInfoStrip();
    if (!strip) return;
    refresh();
    setInterval(refresh, 1000);

    /* 命令面板命令：原"切换底部状态栏"改为"切换顶部信息条" */
    if (window.Lab && window.Lab.commands) {
      const old = window.Lab.commands['dock.toggle'];
      window.Lab.commands['dock.toggle'] = {
        title: '切换顶部状态信息条',
        group: '视图',
        run: () => {
          const el = document.getElementById('topbar-info-strip');
          if (el) el.classList.toggle('is-hidden');
        },
      };
      if (old) window.Lab.commands['dock.toggle']._legacy = old;
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
