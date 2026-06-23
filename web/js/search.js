/* =============================================================================
   search.js — 实时日志/包列表的全文搜索框
   在已有的 filters-panel 和 packet-table 工具栏里各注入一个
   <input type="search">，与现有 select 过滤器并列（AND）。
   写入 appState.logFilters.search / appState.packetFilters.search，
   由 app.js 的 filteredLogs() / filteredPackets() 读取（已扩展）。
   250ms debounce + Cmd/Ctrl+F 聚焦到当前 tab 的搜索框。
   ============================================================================= */
(function () {
  'use strict';

  const DEBOUNCE_MS = 200;
  const STORAGE_KEY = 'udpLabSearchHistory';

  function debounce(fn, ms) {
    let timer = null;
    return function (...args) {
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => fn.apply(this, args), ms);
    };
  }

  function makeSearchInput({placeholder, ariaLabel, onInput}) {
    const wrap = document.createElement('div');
    wrap.className = 'lab-search';
    const input = document.createElement('input');
    input.type = 'search';
    input.className = 'lab-search-input';
    input.placeholder = placeholder;
    input.setAttribute('aria-label', ariaLabel);
    input.spellcheck = false;
    input.autocomplete = 'off';
    const clear = document.createElement('button');
    clear.type = 'button';
    clear.className = 'lab-search-clear';
    clear.setAttribute('aria-label', '清空搜索');
    clear.title = '清空搜索';
    clear.textContent = '×';
    clear.hidden = true;
    wrap.appendChild(input);
    wrap.appendChild(clear);
    const apply = debounce((value) => {
      onInput(value);
      clear.hidden = !value;
    }, DEBOUNCE_MS);
    input.addEventListener('input', (event) => apply(event.currentTarget.value));
    clear.addEventListener('click', () => {
      input.value = '';
      onInput('');
      clear.hidden = true;
      input.focus();
    });
    /* ESC 清空 */
    input.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && input.value) {
        event.stopPropagation();
        input.value = '';
        onInput('');
        clear.hidden = true;
      }
    });
    return {wrap, input, clear};
  }

  function attachLogSearch() {
    /* 日志过滤的 panel-head 紧邻 role/level/event select；
       在 .log-filter-bar 之后插入搜索框。 */
    const bar = document.getElementById('log-filters') || document.querySelector('[data-role="log-filters"]');
    if (!bar) return null;
    const {wrap, input, clear} = makeSearchInput({
      placeholder: '搜索日志（消息 / 事件 / 协议类型）',
      ariaLabel: '日志全文搜索',
      onInput: (value) => {
        const Lab = window.Lab;
        if (!Lab || !Lab.state) return;
        Lab.state.logFilters.search = value;
        Lab.state.pagination.logs = 1;
        if (Lab.render) Lab.render();
      },
    });
    bar.appendChild(wrap);
    return {wrap, input, clear};
  }

  function attachPacketSearch() {
    /* 包过滤的工具栏：放在 5 个 select 同行尾部 */
    const bar = document.getElementById('packet-filters') || document.querySelector('[data-role="packet-filters"]');
    if (!bar) return null;
    const {wrap, input, clear} = makeSearchInput({
      placeholder: '搜索包（类型 / UID / hex）',
      ariaLabel: '包全文搜索',
      onInput: (value) => {
        const Lab = window.Lab;
        if (!Lab || !Lab.state) return;
        Lab.state.packetFilters.search = value;
        Lab.state.pagination.packets = 1;
        if (Lab.renderProtocol) Lab.renderProtocol();
      },
    });
    bar.appendChild(wrap);
    return {wrap, input, clear};
  }

  function wireGlobalShortcut(logSearch, packetSearch) {
    document.addEventListener('keydown', (event) => {
      const isMac = navigator.platform.toLowerCase().includes('mac');
      const meta = isMac ? event.metaKey : event.ctrlKey;
      if (!meta || event.key.toLowerCase() !== 'f') return;
      /* 防止浏览器原生查找 */
      event.preventDefault();
      const Lab = window.Lab;
      if (!Lab || !Lab.state) return;
      const tab = Lab.state.activeTab;
      if (tab === 'protocol' && packetSearch && packetSearch.input) {
        packetSearch.input.focus();
        packetSearch.input.select();
      } else if (logSearch && logSearch.input) {
        logSearch.input.focus();
        logSearch.input.select();
      }
    });
  }

  function init() {
    const logSearch = attachLogSearch();
    const packetSearch = attachPacketSearch();
    wireGlobalShortcut(logSearch, packetSearch);

    if (window.Lab && window.Lab.commands) {
      window.Lab.commands['search.logs'] = {
        title: '聚焦日志搜索',
        group: '搜索',
        hint: 'Cmd/Ctrl + F',
        run: () => logSearch && logSearch.input && logSearch.input.focus(),
      };
      window.Lab.commands['search.packets'] = {
        title: '聚焦包搜索',
        group: '搜索',
        hint: 'Cmd/Ctrl + F',
        run: () => packetSearch && packetSearch.input && packetSearch.input.focus(),
      };
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
