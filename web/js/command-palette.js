/* =============================================================================
   command-palette.js — Cmd/Ctrl+K 命令面板
   模糊搜索注册到 window.Lab.commands 的所有命令 + 主题切换 + Tab 跳转。
   键盘：↑/↓ 选择、Enter 执行、Esc 关闭、Cmd/Ctrl+K 唤出。
   命令分类：
     - 系统: theme.*, language.*, notifications.*, dock.toggle
     - 视图: tab.*, search.*, dock.toggle
     - 控制: server.start/stop, client.start/stop, experiment.reset
     - 协议: theme.* (9 套主题)
     - 导出: export.* (3 种格式)
     - 帮助: help.show
   ============================================================================= */
(function () {
  'use strict';

  const STORAGE_KEY_RECENTS = 'udpLabCommandRecents';

  /* 内置命令：theme.*, tab.*, language.*, experiment.reset, server.*, client.*, help.show */
  const BUILTIN_COMMANDS = [
    /* 主题 */
    {id: 'theme.neumorph', title: '主题：Neumorphism 新拟态', group: '主题', run: () => setTheme('neumorph')},
    {id: 'theme.aurora', title: '主题：Aurora 极光辉光', group: '主题', run: () => setTheme('aurora')},
    {id: 'theme.cartoon', title: '主题：Cartoon 卡通', group: '主题', run: () => setTheme('cartoon')},
    {id: 'theme.cyber', title: '主题：Cyberpunk 赛博朋克', group: '主题', run: () => setTheme('cyber')},
    {id: 'theme.sticker', title: '主题：Sticker 贴纸', group: '主题', run: () => setTheme('sticker')},
    {id: 'theme.nordic', title: '主题：Nordic 北欧冷雾', group: '主题', run: () => setTheme('nordic')},
    {id: 'theme.liquid', title: '主题：Liquid Glass 流体光感', group: '主题', run: () => setTheme('liquid')},
    {id: 'theme.metal', title: '主题：Embossed Metal 金属', group: '主题', run: () => setTheme('metal')},
    {id: 'theme.matcha', title: '主题：Matcha 抹茶', group: '主题', run: () => setTheme('matcha')},
    /* Tab 跳转 */
    {id: 'tab.dashboard', title: '跳到：仪表盘 Dashboard', group: '视图', run: () => switchTab('dashboard')},
    {id: 'tab.protocol', title: '跳到：协议时序 Protocol', group: '视图', run: () => switchTab('protocol')},
    {id: 'tab.transfer', title: '跳到：传输视图 Transfer', group: '视图', run: () => switchTab('transfer')},
    {id: 'tab.logs', title: '跳到：完整日志 Logs', group: '视图', run: () => switchTab('logs')},
    /* 语言 */
    {id: 'language.zh', title: '切换语言：中文', group: '系统', run: () => setLanguage('zh')},
    {id: 'language.en', title: 'Switch language: English', group: '系统', run: () => setLanguage('en')},
    /* 控制 */
    {id: 'experiment.reset', title: '重置实验（停止所有子进程 + 清空日志）', group: '控制', run: () => triggerReset()},
    {id: 'server.start', title: '启动服务端', group: '控制', run: () => submitForm('server-form')},
    {id: 'server.stop', title: '停止服务端', group: '控制', run: () => clickButton('stop-server-btn')},
    {id: 'client.start', title: '启动客户端', group: '控制', run: () => submitForm('client-form')},
    {id: 'client.stop', title: '停止客户端', group: '控制', run: () => clickButton('stop-client-btn')},
    {id: 'test.run', title: '运行自动化测试', group: '控制', run: () => clickButton('run-tests-btn')},
    /* 帮助 */
    {id: 'help.show', title: '显示欢迎面板', group: '帮助', hint: '?help=1', run: () => window.openWelcomeOverlay && window.openWelcomeOverlay()},
  ];

  function setTheme(id) {
    const Lab = window.Lab;
    if (Lab && Lab.theme && Lab.theme.set) {
      Lab.theme.set(id);
    } else {
      const select = document.getElementById('theme-select');
      if (select) {
        select.value = id;
        select.dispatchEvent(new Event('change', {bubbles: true}));
      }
    }
  }

  function setLanguage(lang) {
    const select = document.getElementById('language-select');
    if (select) {
      select.value = lang;
      select.dispatchEvent(new Event('change', {bubbles: true}));
    }
  }

  function switchTab(tab) {
    const tabBtn = document.querySelector(`[data-tab="${tab}"]`);
    if (tabBtn) tabBtn.click();
  }

  function submitForm(id) {
    const form = document.getElementById(id);
    if (form) form.requestSubmit();
  }

  function clickButton(id) {
    const btn = document.getElementById(id);
    if (btn) btn.click();
  }

  function triggerReset() {
    clickButton('reset-btn') || clickButton('rail-reset-btn');
  }

  function fuzzyMatch(query, text) {
    if (!query) return 1;
    const q = query.toLowerCase();
    const t = String(text || '').toLowerCase();
    if (t.includes(q)) return 2;
    /* 字符顺序匹配：query 的每个字符按顺序出现在 t 中 */
    let qi = 0;
    for (let i = 0; i < t.length && qi < q.length; i++) {
      if (t[i] === q[qi]) qi++;
    }
    return qi === q.length ? 1 : 0;
  }

  function getAllCommands() {
    const Lab = window.Lab;
    const registered = Lab && Lab.commands ? Object.values(Lab.commands) : [];
    return [...BUILTIN_COMMANDS, ...registered];
  }

  function getRecents() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY_RECENTS);
      return raw ? JSON.parse(raw) : [];
    } catch (e) { return []; }
  }

  function pushRecent(id) {
    try {
      const recents = getRecents().filter((x) => x !== id);
      recents.unshift(id);
      localStorage.setItem(STORAGE_KEY_RECENTS, JSON.stringify(recents.slice(0, 8)));
    } catch (e) { /* noop */ }
  }

  function buildOverlay() {
    const overlay = document.createElement('div');
    overlay.id = 'lab-palette';
    overlay.className = 'lab-palette';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-label', '命令面板');
    overlay.hidden = true;
    overlay.innerHTML = [
      '<div class="lab-palette-backdrop"></div>',
      '<div class="lab-palette-panel">',
        '<div class="lab-palette-input-wrap">',
          '<span class="lab-palette-icon" aria-hidden="true">⌘</span>',
          '<input type="text" class="lab-palette-input" id="lab-palette-input" ',
            'placeholder="输入命令、主题名或 Tab 名…" aria-label="搜索命令" ',
            'autocomplete="off" spellcheck="false" />',
          '<kbd class="lab-palette-kbd">ESC</kbd>',
        '</div>',
        '<div class="lab-palette-results" id="lab-palette-results" role="listbox"></div>',
        '<div class="lab-palette-foot">',
          '<span><kbd>↑</kbd><kbd>↓</kbd> 选择</span>',
          '<span><kbd>↵</kbd> 执行</span>',
          '<span><kbd>ESC</kbd> 关闭</span>',
        '</div>',
      '</div>',
    ].join('');
    document.body.appendChild(overlay);
    return overlay;
  }

  let overlay = null;
  let input = null;
  let resultsEl = null;
  let activeIndex = 0;
  let currentResults = [];

  function renderResults(query) {
    const all = getAllCommands();
    const recents = getRecents();
    const recentSet = new Set(recents);
    let filtered;
    if (!query) {
      /* 无 query：最近用过优先，其余按 group 排序 */
      const recentsList = all.filter((c) => recentSet.has(c.id));
      const rest = all.filter((c) => !recentSet.has(c.id));
      filtered = [...recentsList, ...rest];
    } else {
      filtered = all
        .map((c) => {
          const score = Math.max(
            fuzzyMatch(query, c.title),
            fuzzyMatch(query, c.id),
            fuzzyMatch(query, c.group || ''),
          );
          return {cmd: c, score};
        })
        .filter((x) => x.score > 0)
        .sort((a, b) => b.score - a.score)
        .map((x) => x.cmd);
    }
    currentResults = filtered.slice(0, 30);
    activeIndex = 0;
    if (!currentResults.length) {
      resultsEl.innerHTML = '<div class="lab-palette-empty">没有匹配的命令</div>';
      return;
    }
    let lastGroup = null;
    const html = currentResults.map((c, i) => {
      const groupHeader = c.group && c.group !== lastGroup
        ? `<div class="lab-palette-group">${escapeHtml(c.group)}</div>` : '';
      lastGroup = c.group || lastGroup;
      const hint = c.hint ? `<span class="lab-palette-hint">${escapeHtml(c.hint)}</span>` : '';
      return `${groupHeader}<button type="button" class="lab-palette-item ${i === 0 ? 'is-active' : ''}" data-index="${i}" role="option">`
        + `<span class="lab-palette-item-title">${highlightHtml(c.title, query)}</span>`
        + hint
        + `</button>`;
    }).join('');
    resultsEl.innerHTML = html;
    Array.from(resultsEl.querySelectorAll('.lab-palette-item')).forEach((node) => {
      node.addEventListener('click', () => {
        const idx = Number(node.dataset.index);
        executeCommand(currentResults[idx]);
      });
      node.addEventListener('mouseenter', () => {
        activeIndex = Number(node.dataset.index);
        updateActive();
      });
    });
  }

  function highlightHtml(text, query) {
    const t = String(text);
    if (!query) return escapeHtml(t);
    const idx = t.toLowerCase().indexOf(query.toLowerCase());
    if (idx < 0) return escapeHtml(t);
    return escapeHtml(t.slice(0, idx)) + '<mark>' + escapeHtml(t.slice(idx, idx + query.length)) + '</mark>' + escapeHtml(t.slice(idx + query.length));
  }

  function escapeHtml(s) {
    return String(s).replace(/[<>&"']/g, (c) => ({'<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;'}[c]));
  }

  function updateActive() {
    Array.from(resultsEl.querySelectorAll('.lab-palette-item')).forEach((node, i) => {
      node.classList.toggle('is-active', i === activeIndex);
    });
    const active = resultsEl.querySelector('.lab-palette-item.is-active');
    if (active) active.scrollIntoView({block: 'nearest'});
  }

  function executeCommand(cmd) {
    if (!cmd) return;
    try { cmd.run(); } catch (e) { console.error('command failed', e); }
    pushRecent(cmd.id);
    closePalette();
  }

  function openPalette() {
    if (!overlay) overlay = buildOverlay();
    if (!input) input = document.getElementById('lab-palette-input');
    if (!resultsEl) resultsEl = document.getElementById('lab-palette-results');
    overlay.hidden = false;
    input.value = '';
    renderResults('');
    requestAnimationFrame(() => input.focus());
  }

  function closePalette() {
    if (overlay) overlay.hidden = true;
  }

  function isOpen() {
    return overlay && !overlay.hidden;
  }

  function wireGlobalKeys() {
    document.addEventListener('keydown', (event) => {
      const isMac = navigator.platform.toLowerCase().includes('mac');
      const meta = isMac ? event.metaKey : event.ctrlKey;
      /* Cmd/Ctrl+K 唤出 */
      if (meta && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        if (isOpen()) closePalette(); else openPalette();
        return;
      }
      if (!isOpen()) return;
      /* 面板内按键 */
      if (event.key === 'Escape') {
        event.preventDefault();
        closePalette();
      } else if (event.key === 'ArrowDown') {
        event.preventDefault();
        activeIndex = Math.min(activeIndex + 1, currentResults.length - 1);
        updateActive();
      } else if (event.key === 'ArrowUp') {
        event.preventDefault();
        activeIndex = Math.max(activeIndex - 1, 0);
        updateActive();
      } else if (event.key === 'Enter') {
        event.preventDefault();
        executeCommand(currentResults[activeIndex]);
      }
    });
  }

  function init() {
    overlay = buildOverlay();
    input = document.getElementById('lab-palette-input');
    resultsEl = document.getElementById('lab-palette-results');
    input.addEventListener('input', () => renderResults(input.value));
    overlay.querySelector('.lab-palette-backdrop').addEventListener('click', closePalette);
    wireGlobalKeys();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
