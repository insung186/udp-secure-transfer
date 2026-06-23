/* =============================================================================
   dragdrop.js — 拖放上传
   把现有的 <input id="server-input-path"> / <input id="client-output-path">
   包装成可拖放：用户拖文件到输入框/整张 sidebar 都可触发，自动写入路径。
   注意：本平台是 C/S 实验，路径需要在工作目录中已存在；前端只填路径名，
   不真正上传文件二进制（避免误把桌面文件塞进 udp-secure-transfer/uploads/）。
   ============================================================================= */
(function () {
  'use strict';

  /* "选择文件"的小标签：从 input 旁的 label 借用。
     用 File API 拿文件名（仅 basename），写回到 input value。 */
  function basename(path) {
    if (!path) return '';
    const norm = String(path).replace(/\\/g, '/');
    const idx = norm.lastIndexOf('/');
    return idx >= 0 ? norm.slice(idx + 1) : norm;
  }

  function attachDropZone(input) {
    if (!input || input.dataset.dragdropReady === '1') return;
    input.dataset.dragdropReady = '1';
    const field = input.closest('.field, .form-field, .control-section, .run-test-cell, .panel');
    const target = field || input.parentElement || input;
    target.classList.add('lab-dropzone');

    const hint = document.createElement('span');
    hint.className = 'lab-dropzone-hint';
    hint.textContent = '拖入文件';
    target.appendChild(hint);

    let dragDepth = 0;

    target.addEventListener('dragenter', (event) => {
      if (!event.dataTransfer) return;
      event.preventDefault();
      dragDepth++;
      target.classList.add('is-dragover');
      event.dataTransfer.dropEffect = 'copy';
    });
    target.addEventListener('dragover', (event) => {
      if (!event.dataTransfer) return;
      event.preventDefault();
      event.dataTransfer.dropEffect = 'copy';
    });
    target.addEventListener('dragleave', () => {
      dragDepth = Math.max(0, dragDepth - 1);
      if (dragDepth === 0) target.classList.remove('is-dragover');
    });
    target.addEventListener('drop', (event) => {
      event.preventDefault();
      dragDepth = 0;
      target.classList.remove('is-dragover');
      const file = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
      if (!file) return;
      /* 只取文件名（实验环境要求路径在 CWD 内），不取 path（File API 不暴露） */
      const name = basename(file.name);
      if (!name) return;
      input.value = name;
      input.dispatchEvent(new Event('input', {bubbles: true}));
      input.dispatchEvent(new Event('change', {bubbles: true}));
      /* 视觉反馈：短暂高亮 */
      target.classList.add('is-dropped');
      setTimeout(() => target.classList.remove('is-dropped'), 600);
    });
  }

  function init() {
    const inputs = [
      document.getElementById('server-input-path'),
      document.getElementById('client-output-path'),
    ].filter(Boolean);
    inputs.forEach(attachDropZone);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
