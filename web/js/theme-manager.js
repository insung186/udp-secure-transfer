/* =============================================================================
   theme-manager.js — 9 套主题切换 + 持久化
   主题通过 [data-theme="..."] 切换；状态保存在 localStorage。
   设计参考：chroma-atlas/src/detail/styles/* 与 src/data/palettes.jsx
   ============================================================================= */
(function () {
  'use strict';

  // 9 套主题：id -> 名称 / 描述 / 色板
  const THEMES = [
    {
      id: 'neumorph',
      name: 'Neumorphism',
      nameZh: '新拟态',
      desc: '柔和凹凸阴影、米灰底、单一强调色',
      swatches: ['#E0E5EC', '#5A6A85', '#7A8AB5', '#B8BEC7', '#FFFFFF', '#2C3E50'],
    },
    {
      id: 'aurora',
      name: 'Aurora',
      nameZh: '极光辉光',
      desc: '深蓝紫 + 极光绿 + 紫色流光 + 渐变光晕',
      swatches: ['#0A1A2E', '#5BFFB5', '#9B5BFF', '#5BB5FF', '#FF6B9D', '#E5F5F0'],
    },
    {
      id: 'cartoon',
      name: 'Cartoon',
      nameZh: '卡通',
      desc: '黄色背景 + 黑色粗描边 + 硬阴影偏移',
      swatches: ['#FFE066', '#FF4FA8', '#4ECDC4', '#FF6B6B', '#0F0F0F', '#FFFFFF'],
    },
    {
      id: 'cyber',
      name: 'Cyberpunk',
      nameZh: '赛博朋克',
      desc: '深紫底 + 霓虹粉青 + 等宽 + 扫描线 + 荧光',
      swatches: ['#0A0118', '#FF2E97', '#00F0FF', '#A100FF', '#FFD600', '#E5D9FF'],
    },
    {
      id: 'sticker',
      name: 'Sticker',
      nameZh: '贴纸',
      desc: '浅蓝底 + 错位硬阴影 + 卡通字体 + 多色装饰',
      swatches: ['#A8D8FF', '#FF6B6B', '#FFD93D', '#4ECDC4', '#5BC8FF', '#0F2848'],
    },
    {
      id: 'nordic',
      name: 'Nordic',
      nameZh: '北欧冷雾',
      desc: '冷灰蓝调、安静克制、微阴影',
      swatches: ['#ECEFF1', '#3E5C76', '#7A99B5', '#1F2A33', '#5A6E7A', '#D5DCE0'],
    },
    {
      id: 'liquid',
      name: 'Liquid Glass',
      nameZh: '流体光感',
      desc: '渐变彩色底 + 玻璃半透 + 高光反射 + 柔光',
      swatches: ['#D1C5FF', '#5C3D99', '#FF6B9D', '#5BC8FF', '#FFD93D', '#FFFFFF'],
    },
    {
      id: 'metal',
      name: 'Embossed Metal',
      nameZh: '金属',
      desc: '暗灰底 + 金色强调 + 内嵌 LCD 屏 + 拉丝',
      swatches: ['#1A1A1A', '#D4B25F', '#F5B83A', '#C9B57A', '#6B6B6B', '#0F0F0F'],
    },
    {
      id: 'matcha',
      name: 'Matcha',
      nameZh: '抹茶',
      desc: '日式抹茶绿 + 米色 + 圆角 + 陶瓷感',
      swatches: ['#EDEDDF', '#7A9059', '#A8B57A', '#5C7340', '#B84418', '#2E3A24'],
    },
  ];

  const STORAGE_KEY = 'udpLabThemeV2';
  const DEFAULT_THEME = 'neumorph';
  const FALLBACK_THEMES = new Set(THEMES.map((t) => t.id));

  function ensureDecorLayer() {
    let decor = document.querySelector('.theme-decor');
    if (decor) return decor;
    decor = document.createElement('div');
    decor.className = 'theme-decor';
    decor.setAttribute('aria-hidden', 'true');
    decor.innerHTML = [
      '<div class="theme-decor-grid"></div>',
      '<div class="theme-decor-blob theme-decor-blob-1"></div>',
      '<div class="theme-decor-blob theme-decor-blob-2"></div>',
      '<div class="theme-decor-blob theme-decor-blob-3"></div>',
      '<div class="theme-decor-scanlines"></div>',
    ].join('');
    document.body.insertBefore(decor, document.body.firstChild);
    return decor;
  }

  function applyDecorBackgrounds(themeId) {
    const decor = document.querySelector('.theme-decor');
    if (!decor) return;
    const grid = decor.querySelector('.theme-decor-grid');
    const scan = decor.querySelector('.theme-decor-scanlines');
    if (grid) {
      grid.style.background = 'var(--grid-bg)';
      grid.style.backgroundSize = 'var(--grid-size, 40px 40px)';
    }
    if (scan) {
      scan.style.background = 'var(--scanlines-bg)';
    }
  }

  function readSavedTheme() {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved && FALLBACK_THEMES.has(saved)) return saved;
    } catch (error) {
      console.warn('theme-manager: read saved failed', error);
    }
    return DEFAULT_THEME;
  }

  function persist(themeId) {
    try {
      localStorage.setItem(STORAGE_KEY, themeId);
    } catch (error) {
      console.warn('theme-manager: persist failed', error);
    }
  }

  // 在 i18n 模块尚未就绪时，也能给出名称/描述
  function pickLabel(theme, language) {
    if (language === 'en') return theme.name + ' · ' + theme.desc;
    return theme.nameZh + ' · ' + theme.desc;
  }

  function setTheme(themeId, options) {
    const target = FALLBACK_THEMES.has(themeId) ? themeId : DEFAULT_THEME;
    document.documentElement.dataset.theme = target;
    ensureDecorLayer();
    applyDecorBackgrounds(target);
    // 同步原生 select
    const select = document.getElementById('theme-select');
    if (select && select.value !== target) select.value = target;
    if (!options || options.persist !== false) persist(target);
    return target;
  }

  // 填充主题下拉框：仅保留短名称（中文显示 nameZh，英文显示 name）
  //
  // 增量更新而非 innerHTML 重写：保留用户的键盘焦点 / 滚动位置 / 打开状态，
  // 否则 setTheme / refreshLabels 在 dropdown 打开时强制 select.value = target
  // 会让用户失去当前选择。
  function fillThemeSelect() {
    const select = document.getElementById('theme-select');
    if (!select) return;
    const current = document.documentElement.dataset.theme || DEFAULT_THEME;
    const isEn = document.documentElement.lang === 'en';
    const wanted = THEMES.map((theme) => ({
      id: theme.id,
      label: isEn ? theme.name : theme.nameZh,
    }));
    // Add or update each option in place.
    const seen = new Set();
    wanted.forEach((entry) => {
      seen.add(entry.id);
      let opt = select.querySelector(`option[value="${entry.id}"]`);
      if (!opt) {
        opt = document.createElement('option');
        opt.value = entry.id;
        select.appendChild(opt);
      }
      opt.textContent = entry.label;
      opt.selected = entry.id === current;
    });
    // Remove options for themes that no longer exist (e.g. legacy).
    Array.from(select.options).forEach((opt) => {
      if (!seen.has(opt.value)) opt.remove();
    });
  }

  // 刷新下拉框文字（语言切换时）
  function refreshThemeSelectLabels() {
    fillThemeSelect();
  }

  // 暴露到全局
  window.ThemeManager = {
    themes: THEMES,
    defaultTheme: DEFAULT_THEME,
    set: setTheme,
    get: () => document.documentElement.dataset.theme || DEFAULT_THEME,
    init: function () {
      const saved = readSavedTheme();
      setTheme(saved, { persist: false });
      ensureDecorLayer();
      applyDecorBackgrounds(saved);
      fillThemeSelect();
    },
    refreshLabels: refreshThemeSelectLabels,
  };
})();
