/* =============================================================================
   notifications.js — Web Notifications 桌面通知
   在以下事件触发时弹系统通知（即使切到别的标签页也能看到）：
     1. 传输完成（client 跑完 → OK）
     2. 握手失败（REJECT / 多次 PASS_RESP 错）
     3. 密码错误（interactive 模式 + interactiveWaiting=true + 收到 REJECT）
   首次使用弹"启用通知"提示；用户拒绝则不再询问。
   通过对比 prev 快照检测"刚刚发生"的事件，避免每 250ms 刷状态时重复弹。
   依赖：window.Lab.state（appState 引用）
   ============================================================================= */
(function () {
  'use strict';

  const STORAGE_KEY_ENABLED = 'udpLabNotificationsEnabled';
  const STORAGE_KEY_ASKED = 'udpLabNotificationsAsked';

  let prev = null;
  let pollTimer = null;
  let lastNotifiedKey = null;

  function isSupported() {
    return typeof window !== 'undefined' && 'Notification' in window;
  }

  function isEnabled() {
    try { return localStorage.getItem(STORAGE_KEY_ENABLED) === '1'; } catch (e) { return false; }
  }

  function setEnabled(value) {
    try { localStorage.setItem(STORAGE_KEY_ENABLED, value ? '1' : '0'); } catch (e) { /* noop */ }
  }

  function setAsked() {
    try { localStorage.setItem(STORAGE_KEY_ASKED, '1'); } catch (e) { /* noop */ }
  }

  function wasAsked() {
    try { return localStorage.getItem(STORAGE_KEY_ASKED) === '1'; } catch (e) { return false; }
  }

  async function requestPermission() {
    if (!isSupported()) return 'unsupported';
    if (Notification.permission === 'granted') {
      setEnabled(true);
      return 'granted';
    }
    if (Notification.permission === 'denied') {
      setEnabled(false);
      return 'denied';
    }
    setAsked();
    try {
      const result = await Notification.requestPermission();
      const ok = result === 'granted';
      setEnabled(ok);
      return result;
    } catch (e) {
      return 'denied';
    }
  }

  function fire(title, body, opts = {}) {
    if (!isSupported()) return;
    if (Notification.permission !== 'granted') return;
    if (!isEnabled()) return;
    try {
      const n = new Notification(title, {
        body: String(body || '').slice(0, 240),
        tag: opts.tag || 'lab',
        renotify: !!opts.renotify,
        icon: opts.icon || '/favicon.ico',
      });
      if (opts.timeout) {
        setTimeout(() => { try { n.close(); } catch (e) { /* noop */ } }, opts.timeout);
      }
      n.onclick = () => {
        try { window.focus(); } catch (e) { /* noop */ }
        if (opts.onClick) opts.onClick();
        n.close();
      };
    } catch (e) {
      console.warn('notifications: fire failed', e);
    }
  }

  function buildSnapshot(state) {
    const logs = state.logs || [];
    const lastErrorIdx = (() => {
      for (let i = logs.length - 1; i >= 0; i--) {
        const level = logs[i].level;
        if (level === 'ERROR' || level === 'ABORT') return i;
      }
      return -1;
    })();
    const lastErr = lastErrorIdx >= 0 ? logs[lastErrorIdx] : null;
    const status = state.status || {};
    const serverRunning = !!(status.server && status.server.running);
    const clientRunning = !!(status.client && status.client.running);
    return {
      lastLogCount: logs.length,
      lastErrorIdx,
      lastErrorKey: lastErr ? `${logs[lastErrorIdx].time}-${logs[lastErrorIdx].level}-${logs[lastErrorIdx].message || ''}` : null,
      clientRunning,
      serverRunning,
      lastFlowResult: state.lastFlowResult,
      lastFlowPhase: state.lastFlowPhase,
      interactiveOutcome: state.interactiveLastOutcome,
    };
  }

  function detectEvents(prevSnap, currSnap) {
    if (!prevSnap) return [];
    const events = [];
    /* 1. 错误日志首次出现：每条 ERROR/ABORT 弹一次（按 key 去重） */
    if (currSnap.lastErrorKey &&
        currSnap.lastErrorKey !== prevSnap.lastErrorKey &&
        currSnap.lastErrorIdx > prevSnap.lastErrorIdx) {
      events.push({
        type: 'error',
        title: '⚠ 实验出现错误',
        body: '点击查看实时日志',
        tag: `lab-err-${currSnap.lastErrorKey}`,
        renotify: true,
        onClick: () => {
          const Lab = window.Lab;
          if (Lab && Lab.state) Lab.state.activeTab = 'logs';
          document.querySelector('[data-tab="logs"]')?.click();
        },
      });
    }
    /* 2. 客户端由 running → not running（传输完成） */
    if (prevSnap.clientRunning && !currSnap.clientRunning) {
      const ok = currSnap.lastFlowResult === 'OK';
      events.push({
        type: 'complete',
        title: ok ? '✓ 传输完成' : '× 传输中断',
        body: ok ? '所有分片已成功接收' : '传输流程中断，可查看错误日志',
        tag: 'lab-run-end',
        renotify: true,
      });
    }
    /* 3. 交互式客户端进入等待态后又错误（密码错误提示） */
    const Lab = window.Lab;
    if (Lab && Lab.state) {
      const interactiveWaiting = Lab.state.interactiveWaiting;
      const lastLog = (Lab.state.logs || []).slice(-1)[0];
      if (interactiveWaiting && lastLog && lastLog.level === 'ERROR' && /password|pwd|密码/i.test(lastLog.message || '')) {
        const key = `pwd-${lastLog.time}`;
        if (key !== lastNotifiedKey) {
          lastNotifiedKey = key;
          events.push({
            type: 'password',
            title: '🔑 密码错误',
            body: '请在交互式密码框中重试',
            tag: key,
            renotify: true,
          });
        }
      }
    }
    return events;
  }

  function tick() {
    const Lab = window.Lab;
    if (!Lab || !Lab.state) return;
    const curr = buildSnapshot(Lab.state);
    const events = detectEvents(prev, curr);
    events.forEach((evt) => fire(evt.title, evt.body, evt));
    prev = curr;
  }

  function init() {
    if (!isSupported()) return;
    /* 默认询问一次（如果用户没表态） */
    if (!wasAsked() && !isEnabled()) {
      /* 给个小提示 UI；点击后请求权限 */
      showPermissionHint();
    }
    /* 启动轮询：每 1.5s 比对一次快照 */
    prev = buildSnapshot((window.Lab && window.Lab.state) || {logs: [], status: {}, lastFlowResult: null, lastFlowPhase: 'INIT', interactiveLastOutcome: null});
    pollTimer = setInterval(tick, 1500);

    if (window.Lab && window.Lab.commands) {
      window.Lab.commands['notifications.enable'] = {
        title: '启用桌面通知',
        group: '系统',
        run: async () => {
          const result = await requestPermission();
          if (result === 'granted') {
            fire('✓ 通知已启用', '传输完成、握手失败时会弹出系统通知');
            removePermissionHint();
          } else if (result === 'denied') {
            fire('通知被拒绝', '可在浏览器设置中重新允许');
          }
        },
      };
      window.Lab.commands['notifications.disable'] = {
        title: '关闭桌面通知',
        group: '系统',
        run: () => {
          setEnabled(false);
          fire('通知已关闭', '不会弹出系统通知');
        },
      };
    }
  }

  function showPermissionHint() {
    if (document.getElementById('lab-notif-hint')) return;
    const hint = document.createElement('div');
    hint.id = 'lab-notif-hint';
    hint.className = 'lab-notif-hint';
    hint.setAttribute('role', 'status');
    hint.innerHTML = [
      '<span class="lab-notif-hint-text">启用桌面通知？传输完成 / 错误时会弹出</span>',
      '<button type="button" class="lab-notif-hint-btn lab-notif-hint-allow">允许</button>',
      '<button type="button" class="lab-notif-hint-btn lab-notif-hint-dismiss">稍后</button>',
    ].join('');
    document.body.appendChild(hint);
    hint.querySelector('.lab-notif-hint-allow').addEventListener('click', async () => {
      const result = await requestPermission();
      if (result === 'granted') fire('✓ 通知已启用', '已开启');
      removePermissionHint();
    });
    hint.querySelector('.lab-notif-hint-dismiss').addEventListener('click', () => {
      setAsked();
      removePermissionHint();
    });
  }

  function removePermissionHint() {
    const hint = document.getElementById('lab-notif-hint');
    if (hint) hint.remove();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
