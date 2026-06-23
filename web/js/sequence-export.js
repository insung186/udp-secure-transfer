/* =============================================================================
   sequence-export.js — 协议时序导出
   3 种格式：
     1. JSON —— 完整包数据（含 flow_id / time / packet_type / direction / hex）
     2. Mermaid sequenceDiagram —— 可粘贴到文档/笔记
     3. PNG —— 通过把序列渲染成 inline SVG，再用 canvas 序列化下载
   入口：在 sequence-panel 的 panel-tools 注入一组 "导出 ▼" 按钮。
   依赖：window.Lab.state（读 realPackets / selectedFlowId / currentFlowId）
   ============================================================================= */
(function () {
  'use strict';

  function getFlowPackets() {
    const Lab = window.Lab;
    if (!Lab || !Lab.state) return [];
    const state = Lab.state;
    const flowId = state.selectedFlowId || state.currentFlowId;
    if (!flowId) return [];
    return (state.realPackets || []).filter((p) => p.flow_id === flowId);
  }

  function getFlowId() {
    const Lab = window.Lab;
    if (!Lab || !Lab.state) return 'flow';
    const state = Lab.state;
    return state.selectedFlowId || state.currentFlowId || 'flow';
  }

  function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      a.remove();
      URL.revokeObjectURL(url);
    }, 200);
  }

  function exportJson() {
    const Lab = window.Lab;
    if (!Lab) return;
    const packets = getFlowPackets();
    const flowId = getFlowId();
    const payload = {
      flow_id: flowId,
      protocol: Lab.state.selectedProtocol,
      scenario: Lab.state.selectedScenario,
      exported_at: new Date().toISOString(),
      packet_count: packets.length,
      packets: packets.map((p) => ({
        time: p.time,
        flow_id: p.flow_id,
        role: p.role,
        packet_type: p.packet_type,
        state: p.state,
        direction: p.direction,
        uid: p.packet_uid || null,
        size: p.size || null,
        hex_preview: p.hex_preview || null,
        message: p.message || null,
      })),
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {type: 'application/json'});
    downloadBlob(blob, `sequence-${flowId}.json`);
  }

  function exportMermaid() {
    const Lab = window.Lab;
    if (!Lab) return;
    const packets = getFlowPackets();
    const flowId = getFlowId();
    const lines = ['sequenceDiagram', `    autonumber`];
    const seenParticipant = new Set();
    const roleToAlias = (role) => {
      const r = String(role || 'unknown');
      return `p${r.replace(/[^a-z0-9]/gi, '_')}`;
    };
    packets.forEach((p) => {
      const fromAlias = roleToAlias(p.role);
      const toAlias = roleToAlias(p.role === 'client' ? 'server' : 'client');
      if (!seenParticipant.has(fromAlias)) {
        lines.push(`    participant ${fromAlias} as ${p.role || 'unknown'}`);
        seenParticipant.add(fromAlias);
      }
      if (!seenParticipant.has(toAlias)) {
        lines.push(`    participant ${toAlias} as ${p.role === 'client' ? 'server' : 'client'}`);
        seenParticipant.add(toAlias);
      }
      const label = `${p.packet_type || '?'}${p.state ? ` (${p.state})` : ''}`;
      const suffix = p.size ? ` [${p.size}B]` : '';
      lines.push(`    ${fromAlias}->>+${toAlias}: ${label}${suffix}`);
      lines.push(`    ${toAlias}-->>-${fromAlias}: ack`);
    });
    const blob = new Blob([lines.join('\n')], {type: 'text/plain'});
    downloadBlob(blob, `sequence-${flowId}.mmd`);
  }

  function exportPng() {
    const Lab = window.Lab;
    if (!Lab) return;
    const packets = getFlowPackets();
    if (!packets.length) {
      flashHint('当前 flow 无包数据');
      return;
    }
    /* 把 packets 渲染成一张 inline SVG（最简图：左右两列 client/server + 中间连线） */
    const flowId = getFlowId();
    const padding = 30;
    const colWidth = 110;
    const colGap = 200;
    const rowHeight = 36;
    const width = padding * 2 + colWidth * 2 + colGap;
    const height = padding * 2 + rowHeight * packets.length + 50;
    const cx1 = padding + colWidth / 2;
    const cx2 = width - padding - colWidth / 2;

    const theme = readThemeColors();
    const bg = theme.bg || '#FFFFFF';
    const ink = theme.ink || '#1F2A33';
    const muted = theme.muted || '#5A6E7A';
    const primary = theme.primary || '#3E5C76';
    const line = theme.line || '#D5DCE0';

    let svg = `<?xml version="1.0" encoding="UTF-8"?>`;
    svg += `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">`;
    svg += `<rect x="0" y="0" width="${width}" height="${height}" fill="${bg}"/>`;
    /* 两条 lifeline */
    svg += `<line x1="${cx1}" y1="${padding + 24}" x2="${cx1}" y2="${height - padding}" stroke="${line}" stroke-width="1.5"/>`;
    svg += `<line x1="${cx2}" y1="${padding + 24}" x2="${cx2}" y2="${height - padding}" stroke="${line}" stroke-width="1.5"/>`;
    /* 头部 label */
    svg += `<rect x="${cx1 - 50}" y="${padding}" width="100" height="24" rx="6" fill="${primary}"/>`;
    svg += `<text x="${cx1}" y="${padding + 16}" text-anchor="middle" font-family="-apple-system, sans-serif" font-size="12" font-weight="600" fill="#FFFFFF">client</text>`;
    svg += `<rect x="${cx2 - 50}" y="${padding}" width="100" height="24" rx="6" fill="${primary}"/>`;
    svg += `<text x="${cx2}" y="${padding + 16}" text-anchor="middle" font-family="-apple-system, sans-serif" font-size="12" font-weight="600" fill="#FFFFFF">server</text>`;
    /* 每条 packet 一行 */
    packets.forEach((p, i) => {
      const y = padding + 50 + i * rowHeight;
      const isClient = p.role === 'client';
      const fromX = isClient ? cx1 : cx2;
      const toX = isClient ? cx2 : cx1;
      const dash = p.packet_type === 'ACK' ? '4 4' : 'none';
      const color = p.state === 'ERROR' || p.level === 'ERROR' ? '#E84A1F' : primary;
      svg += `<line x1="${fromX}" y1="${y}" x2="${toX}" y2="${y}" stroke="${color}" stroke-width="1.5" ${dash ? `stroke-dasharray="${dash}"` : ''}/>`;
      svg += `<polygon points="${toX - 5},${y - 4} ${toX},${y} ${toX - 5},${y + 4}" fill="${color}"/>`;
      const labelX = (fromX + toX) / 2;
      const label = `${p.packet_type || '?'}${p.state ? ` (${p.state})` : ''}`;
      const labelWidth = Math.max(label.length * 7, 60);
      svg += `<rect x="${labelX - labelWidth / 2}" y="${y - 9}" width="${labelWidth}" height="18" rx="9" fill="${bg}" stroke="${line}"/>`;
      svg += `<text x="${labelX}" y="${y + 4}" text-anchor="middle" font-family="ui-monospace, monospace" font-size="11" fill="${ink}">${escapeXml(label)}</text>`;
      /* 时间戳 */
      const timeText = p.time || '';
      svg += `<text x="${padding}" y="${y + 4}" font-family="ui-monospace, monospace" font-size="10" fill="${muted}">${escapeXml(timeText)}</text>`;
    });
    /* 底部 caption */
    svg += `<text x="${width / 2}" y="${height - 8}" text-anchor="middle" font-family="-apple-system, sans-serif" font-size="10" fill="${muted}">flow: ${escapeXml(flowId)} · ${packets.length} packets</text>`;
    svg += `</svg>`;

    /* SVG -> PNG via canvas */
    const img = new Image();
    const svgBlob = new Blob([svg], {type: 'image/svg+xml'});
    const svgUrl = URL.createObjectURL(svgBlob);
    img.onload = () => {
      const scale = 2; /* 2x 高清 */
      const canvas = document.createElement('canvas');
      canvas.width = width * scale;
      canvas.height = height * scale;
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = bg;
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      canvas.toBlob((blob) => {
        if (blob) downloadBlob(blob, `sequence-${flowId}.png`);
        URL.revokeObjectURL(svgUrl);
      }, 'image/png');
    };
    img.onerror = () => {
      URL.revokeObjectURL(svgUrl);
      flashHint('PNG 导出失败');
    };
    img.src = svgUrl;
  }

  function readThemeColors() {
    const style = getComputedStyle(document.documentElement);
    return {
      bg: style.getPropertyValue('--bg').trim() || '#FFFFFF',
      ink: style.getPropertyValue('--ink').trim() || '#1F2A33',
      muted: style.getPropertyValue('--muted').trim() || '#5A6E7A',
      primary: style.getPropertyValue('--primary').trim() || '#3E5C76',
      line: style.getPropertyValue('--line').trim() || '#D5DCE0',
    };
  }

  function escapeXml(s) {
    return String(s).replace(/[<>&'"]/g, (c) => ({
      '<': '&lt;', '>': '&gt;', '&': '&amp;', "'": '&apos;', '"': '&quot;',
    })[c]);
  }

  function flashHint(text) {
    const el = document.createElement('div');
    el.className = 'lab-flash-hint';
    el.textContent = text;
    document.body.appendChild(el);
    setTimeout(() => el.classList.add('is-shown'), 30);
    setTimeout(() => { el.classList.remove('is-shown'); setTimeout(() => el.remove(), 300); }, 1800);
  }

  function makeExportMenu() {
    const wrap = document.createElement('div');
    wrap.className = 'lab-export';
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'ghost-button lab-export-btn';
    btn.innerHTML = '<span>导出</span><span class="lab-export-caret" aria-hidden="true">▾</span>';
    const menu = document.createElement('div');
    menu.className = 'lab-export-menu';
    menu.setAttribute('role', 'menu');
    menu.hidden = true;
    const items = [
      {label: '导出为 JSON', hint: '完整包数据', action: exportJson},
      {label: '导出为 Mermaid', hint: '可粘贴到文档', action: exportMermaid},
      {label: '导出为 PNG', hint: '序列时序图', action: exportPng},
    ];
    items.forEach((item) => {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'lab-export-item';
      b.setAttribute('role', 'menuitem');
      b.innerHTML = `<span>${item.label}</span><span class="lab-export-item-hint">${item.hint}</span>`;
      b.addEventListener('click', () => {
        menu.hidden = true;
        item.action();
      });
      menu.appendChild(b);
    });
    btn.addEventListener('click', (event) => {
      event.stopPropagation();
      menu.hidden = !menu.hidden;
    });
    document.addEventListener('click', () => { menu.hidden = true; });
    wrap.appendChild(btn);
    wrap.appendChild(menu);
    return wrap;
  }

  function init() {
    /* 注入到 sequence-panel 的 panel-tools（与 flow 选择器同区） */
    const tools = document.querySelector('.sequence-panel .panel-tools');
    if (!tools) return;
    if (tools.querySelector('.lab-export')) return;
    const exportMenu = makeExportMenu();
    tools.appendChild(exportMenu);

    if (window.Lab && window.Lab.commands) {
      window.Lab.commands['export.sequence.json'] = {title: '导出时序为 JSON', group: '导出', run: exportJson};
      window.Lab.commands['export.sequence.mermaid'] = {title: '导出时序为 Mermaid', group: '导出', run: exportMermaid};
      window.Lab.commands['export.sequence.png'] = {title: '导出时序为 PNG', group: '导出', run: exportPng};
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
