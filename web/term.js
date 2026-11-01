'use strict';

/* ============================================================
   极简 VT 屏幕：把字节流解析成字符网格，再渲染成 span。
   只实现 shell 日常会用到的序列（定位、擦除、SGR、滚屏），
   不做完整终端仿真——引 xterm.js 会多 300KB，不划算。
   ============================================================ */

const VT_COLORS = [
  '#1c2226', '#e05c5c', '#5fce8a', '#e2c05a', '#6aa9ff', '#c98bf0', '#4fc9d4', '#cfd8dd',
  '#5d6b73', '#ff7b72', '#7ee7a5', '#f0d582', '#8fc0ff', '#e0a8ff', '#7fe6ee', '#ffffff',
];

function xterm256(n) {
  if (n == null) return '';
  if (n < 16) return VT_COLORS[n];
  if (n < 232) {
    const i = n - 16;
    const lv = [0, 95, 135, 175, 215, 255];
    return `rgb(${lv[Math.floor(i / 36)]},${lv[Math.floor(i / 6) % 6]},${lv[i % 6]})`;
  }
  const g = 8 + (n - 232) * 10;
  return `rgb(${g},${g},${g})`;
}

class VTScreen {
  constructor(el) {
    this.el = el;
    this.cols = 80;
    this.rows = 24;
    this.styles = [''];
    this.styleMap = { '': 0 };
    this.focused = false;
    this.resetState();
  }

  resetState() {
    this.chars = new Array(this.rows * this.cols).fill(' ');
    this.attrs = new Array(this.rows * this.cols).fill(0);
    this.x = 0;
    this.y = 0;
    this.top = 0;
    this.bottom = this.rows - 1;
    this.savedX = 0;
    this.savedY = 0;
    this.showCursor = true;
    this.fg = '';
    this.bg = '';
    this.bold = false;
    this.underline = false;
    this.reverse = false;
    this.curIdx = 0;
    this.dirty = true;
  }

  reset() {
    this.resetState();
    this.schedule();
  }

  buildStyle() {
    let fg = this.fg;
    let bg = this.bg;
    if (this.reverse) {
      const t = fg || '#d8e0e6';
      fg = bg || '#12161a';
      bg = t;
    }
    let s = '';
    if (fg) s += 'color:' + fg + ';';
    if (bg) s += 'background:' + bg + ';';
    if (this.bold) s += 'font-weight:600;';
    if (this.underline) s += 'text-decoration:underline;';
    return s;
  }

  recalcStyle() {
    const s = this.buildStyle();
    let i = this.styleMap[s];
    if (i === undefined) {
      i = this.styles.length;
      this.styles.push(s);
      this.styleMap[s] = i;
    }
    this.curIdx = i;
  }

  /* ---------- 缓冲操作 ---------- */

  put(ch) {
    if (this.x >= this.cols) {
      this.x = 0;
      this.lineFeed();
    }
    const i = this.y * this.cols + this.x;
    this.chars[i] = ch;
    this.attrs[i] = this.curIdx;
    this.x++;
  }

  lineFeed() {
    if (this.y === this.bottom) this.scrollUp(1);
    else if (this.y < this.rows - 1) this.y++;
  }

  reverseIndex() {
    if (this.y === this.top) this.scrollDown(1);
    else if (this.y > 0) this.y--;
  }

  scrollUp(n) {
    const w = this.cols;
    const span = (this.bottom - this.top + 1 - n) * w;
    this.chars.copyWithin(this.top * w, (this.top + n) * w, (this.top + n) * w + span);
    this.attrs.copyWithin(this.top * w, (this.top + n) * w, (this.top + n) * w + span);
    for (let y = this.bottom - n + 1; y <= this.bottom; y++) {
      const base = y * w;
      for (let x = 0; x < w; x++) {
        this.chars[base + x] = ' ';
        this.attrs[base + x] = 0;
      }
    }
  }

  scrollDown(n) {
    const w = this.cols;
    const span = (this.bottom - this.top + 1 - n) * w;
    this.chars.copyWithin((this.top + n) * w, this.top * w, this.top * w + span);
    this.attrs.copyWithin((this.top + n) * w, this.top * w, this.top * w + span);
    for (let y = this.top; y < this.top + n; y++) {
      const base = y * w;
      for (let x = 0; x < w; x++) {
        this.chars[base + x] = ' ';
        this.attrs[base + x] = 0;
      }
    }
  }

  eraseLine(mode) {
    const base = this.y * this.cols;
    let from = 0;
    let to = this.cols - 1;
    if (mode === 0) from = this.x;
    else if (mode === 1) to = this.x;
    for (let x = from; x <= to; x++) {
      this.chars[base + x] = ' ';
      this.attrs[base + x] = 0;
    }
  }

  eraseDisplay(mode) {
    if (mode === 2 || mode === 3) {
      this.chars.fill(' ');
      this.attrs.fill(0);
      return;
    }
    if (mode === 1) {
      for (let y = 0; y < this.y; y++) this.eraseRow(y);
      this.eraseLine(1);
      return;
    }
    this.eraseLine(0);
    for (let y = this.y + 1; y < this.rows; y++) this.eraseRow(y);
  }

  eraseRow(y) {
    const base = y * this.cols;
    for (let x = 0; x < this.cols; x++) {
      this.chars[base + x] = ' ';
      this.attrs[base + x] = 0;
    }
  }

  insertLines(n) {
    if (this.y < this.top || this.y > this.bottom) return;
    const w = this.cols;
    const span = (this.bottom - this.y + 1 - n) * w;
    this.chars.copyWithin((this.y + n) * w, this.y * w, this.y * w + span);
    this.attrs.copyWithin((this.y + n) * w, this.y * w, this.y * w + span);
    for (let y = this.y; y < this.y + n; y++) this.eraseRow(y);
  }

  deleteLines(n) {
    if (this.y < this.top || this.y > this.bottom) return;
    const w = this.cols;
    const span = (this.bottom - this.y + 1 - n) * w;
    this.chars.copyWithin(this.y * w, (this.y + n) * w, (this.y + n) * w + span);
    this.attrs.copyWithin(this.y * w, (this.y + n) * w, (this.y + n) * w + span);
    for (let y = this.bottom - n + 1; y <= this.bottom; y++) this.eraseRow(y);
  }

  insertChars(n) {
    const base = this.y * this.cols;
    const span = this.cols - this.x - n;
    if (span <= 0) return;
    this.chars.copyWithin(base + this.x + n, base + this.x, base + this.x + span);
    this.attrs.copyWithin(base + this.x + n, base + this.x, base + this.x + span);
    for (let x = this.x; x < this.x + n; x++) {
      this.chars[base + x] = ' ';
      this.attrs[base + x] = 0;
    }
  }

  deleteChars(n) {
    const base = this.y * this.cols;
    const span = this.cols - this.x - n;
    if (span <= 0) return;
    this.chars.copyWithin(base + this.x, base + this.x + n, base + this.x + n + span);
    this.attrs.copyWithin(base + this.x, base + this.x + n, base + this.x + n + span);
    for (let x = this.cols - n; x < this.cols; x++) {
      this.chars[base + x] = ' ';
      this.attrs[base + x] = 0;
    }
  }

  /* ---------- 解析 ---------- */

  write(data) {
    for (let i = 0; i < data.length; i++) {
      const ch = data[i];
      if (ch === '\x1b') {
        i = this.escape(data, i);
        continue;
      }
      if (ch === '\r') { this.x = 0; continue; }
      if (ch === '\n') { this.lineFeed(); continue; }
      if (ch === '\b') { if (this.x > 0) this.x--; continue; }
      if (ch === '\t') {
        this.x = Math.min(this.cols - 1, (Math.floor(this.x / 8) + 1) * 8);
        continue;
      }
      if (ch === '\x07') continue;
      const code = ch.charCodeAt(0);
      if (code < 32 || code === 127) continue;
      // 代理对合成一个字符，避免把 emoji 拆成两个乱码
      if (code >= 0xd800 && code <= 0xdbff && i + 1 < data.length) {
        const next = data.charCodeAt(i + 1);
        if (next >= 0xdc00 && next <= 0xdfff) {
          this.put(ch + data[++i]);
          continue;
        }
      }
      this.put(ch);
    }
    this.dirty = true;
    this.schedule();
  }

  escape(s, i) {
    const n = s[i + 1];
    if (n === '[') {
      let j = i + 2;
      let params = '';
      while (j < s.length && /[0-9;?><!]/.test(s[j])) {
        params += s[j++];
      }
      while (j < s.length && s.charCodeAt(j) >= 0x20 && s.charCodeAt(j) <= 0x2f) j++;
      if (j >= s.length) return j;
      this.csi(params, s[j]);
      return j;
    }
    if (n === ']') {
      let j = i + 2;
      while (j < s.length) {
        if (s[j] === '\x07') return j;
        if (s[j] === '\x1b' && s[j + 1] === '\\') return j + 1;
        j++;
      }
      return s.length;
    }
    if (n === '(' || n === ')' || n === '#' || n === '=' || n === '>') return i + 2;
    if (n === '7') { this.savedX = this.x; this.savedY = this.y; return i + 1; }
    if (n === '8') { this.x = this.savedX; this.y = this.savedY; return i + 1; }
    if (n === 'M') { this.reverseIndex(); return i + 1; }
    if (n === 'D') { this.lineFeed(); return i + 1; }
    if (n === 'E') { this.x = 0; this.lineFeed(); return i + 1; }
    if (n === 'c') { this.resetState(); return i + 1; }
    return i + 1;
  }

  csi(params, final) {
    let priv = false;
    if (params.length && '?><!'.indexOf(params[0]) >= 0) {
      priv = true;
      params = params.slice(1);
    }
    const p = params === '' ? [] : params.split(';').map(v => parseInt(v, 10) || 0);
    const arg = (i, d) => (p[i] === undefined || p[i] === 0 ? d : p[i]);
    const clampY = v => Math.max(0, Math.min(this.rows - 1, v));
    const clampX = v => Math.max(0, Math.min(this.cols - 1, v));

    switch (final) {
      case 'H': case 'f':
        this.y = clampY(arg(0, 1) - 1);
        this.x = clampX(arg(1, 1) - 1);
        break;
      case 'A': this.y = Math.max(this.top, this.y - arg(0, 1)); break;
      case 'B': this.y = Math.min(this.bottom, this.y + arg(0, 1)); break;
      case 'C': this.x = clampX(this.x + arg(0, 1)); break;
      case 'D': this.x = clampX(this.x - arg(0, 1)); break;
      case 'E': this.y = Math.min(this.bottom, this.y + arg(0, 1)); this.x = 0; break;
      case 'F': this.y = Math.max(this.top, this.y - arg(0, 1)); this.x = 0; break;
      case 'G': this.x = clampX(arg(0, 1) - 1); break;
      case 'd': this.y = clampY(arg(0, 1) - 1); break;
      case 'J': this.eraseDisplay(p[0] || 0); break;
      case 'K': this.eraseLine(p[0] || 0); break;
      case 'm': this.sgr(p); break;
      case 'L': this.insertLines(arg(0, 1)); break;
      case 'M': this.deleteLines(arg(0, 1)); break;
      case 'P': this.deleteChars(arg(0, 1)); break;
      case '@': this.insertChars(arg(0, 1)); break;
      case 'S': this.scrollUp(arg(0, 1)); break;
      case 'T': this.scrollDown(arg(0, 1)); break;
      case 'r':
        this.top = Math.max(0, arg(0, 1) - 1);
        this.bottom = Math.min(this.rows - 1, arg(1, this.rows) - 1);
        if (this.top >= this.bottom) { this.top = 0; this.bottom = this.rows - 1; }
        this.x = 0;
        this.y = this.top;
        break;
      case 'h': case 'l':
        if (priv && p.indexOf(25) >= 0) this.showCursor = final === 'h';
        break;
      default:
        break;
    }
  }

  sgr(p) {
    if (!p.length) p = [0];
    for (let i = 0; i < p.length; i++) {
      const v = p[i];
      if (v === 0) {
        this.fg = ''; this.bg = ''; this.bold = false; this.underline = false; this.reverse = false;
      } else if (v === 1) this.bold = true;
      else if (v === 4) this.underline = true;
      else if (v === 7) this.reverse = true;
      else if (v === 22) this.bold = false;
      else if (v === 24) this.underline = false;
      else if (v === 27) this.reverse = false;
      else if (v >= 30 && v <= 37) this.fg = VT_COLORS[v - 30];
      else if (v === 39) this.fg = '';
      else if (v >= 40 && v <= 47) this.bg = VT_COLORS[v - 40];
      else if (v === 49) this.bg = '';
      else if (v >= 90 && v <= 97) this.fg = VT_COLORS[v - 90 + 8];
      else if (v >= 100 && v <= 107) this.bg = VT_COLORS[v - 100 + 8];
      else if (v === 38 || v === 48) {
        const isFg = v === 38;
        if (p[i + 1] === 5) {
          const c = xterm256(p[i + 2]);
          if (isFg) this.fg = c; else this.bg = c;
          i += 2;
        } else if (p[i + 1] === 2) {
          const c = `rgb(${p[i + 2] || 0},${p[i + 3] || 0},${p[i + 4] || 0})`;
          if (isFg) this.fg = c; else this.bg = c;
          i += 4;
        }
      }
    }
    this.recalcStyle();
  }

  /* ---------- 渲染 ---------- */

  schedule() {
    if (this._raf) return;
    this._raf = requestAnimationFrame(() => {
      this._raf = 0;
      this.render();
    });
  }

  render() {
    if (!this.dirty) return;
    this.dirty = false;
    const out = [];
    for (let y = 0; y < this.rows; y++) {
      let line = '';
      let run = '';
      let last = 0;
      for (let x = 0; x < this.cols; x++) {
        const i = y * this.cols + x;
        const ch = this.chars[i];
        if (this.focused && this.showCursor && x === this.x && y === this.y) {
          if (run) { line += this.span(last, run); run = ''; }
          line += '<span class="cur">' + (ch === ' ' ? '\u00a0' : esc(ch)) + '</span>';
          last = this.attrs[i];
          continue;
        }
        if (this.attrs[i] !== last) {
          if (run) { line += this.span(last, run); run = ''; }
          last = this.attrs[i];
        }
        run += ch;
      }
      if (run) line += this.span(last, run);
      out.push(line);
    }
    this.el.innerHTML = out.join('\n');
  }

  span(idx, text) {
    const s = this.styles[idx];
    return s ? '<span style="' + s + '">' + esc(text) + '</span>' : esc(text);
  }

  resize(rows, cols) {
    if (rows === this.rows && cols === this.cols) return;
    const oldChars = this.chars;
    const oldAttrs = this.attrs;
    const oldRows = this.rows;
    const oldCols = this.cols;
    this.rows = rows;
    this.cols = cols;
    this.chars = new Array(rows * cols).fill(' ');
    this.attrs = new Array(rows * cols).fill(0);
    const h = Math.min(rows, oldRows);
    const w = Math.min(cols, oldCols);
    for (let y = 0; y < h; y++) {
      for (let x = 0; x < w; x++) {
        this.chars[y * cols + x] = oldChars[y * oldCols + x];
        this.attrs[y * cols + x] = oldAttrs[y * oldCols + x];
      }
    }
    this.top = 0;
    this.bottom = rows - 1;
    this.y = Math.min(this.y, rows - 1);
    this.x = Math.min(this.x, cols - 1);
    this.dirty = true;
    this.schedule();
  }
}

/* ============================================================
   终端界面：会话列表、WebSocket 接入、键盘与自适应尺寸
   ============================================================ */

const TermUI = (() => {
  let screen = null;
  let sock = null;
  let sid = '';
  let current = null; // 当前会话的元信息
  let info = null;
  let retries = 0;
  let retryTimer = null;
  let closing = false;
  let lastSize = { rows: 0, cols: 0 };

  const enc = new TextEncoder();
  const dec = new TextDecoder();

  function mounted() {
    return !!screen;
  }

  function mount() {
    if (mounted()) return;
    screen = new VTScreen($('#termScreen'));
    screen.focused = false;
    bindKeys();
    bindResize();
  }

  /* ---------- 尺寸 ---------- */

  function measure() {
    const probe = document.createElement('span');
    probe.className = 'term-probe';
    probe.textContent = 'M'.repeat(64);
    document.body.appendChild(probe);
    const rect = probe.getBoundingClientRect();
    probe.remove();
    return { w: rect.width / 64 || 7.2, h: rect.height || 15 };
  }

  function fit() {
    const host = $('#termHost');
    if (!host || !screen) return { rows: 24, cols: 80 };
    const { w, h } = measure();
    const cs = getComputedStyle(host);
    const padX = parseFloat(cs.paddingLeft) + parseFloat(cs.paddingRight);
    const padY = parseFloat(cs.paddingTop) + parseFloat(cs.paddingBottom);
    const cols = Math.max(20, Math.min(400, Math.floor((host.clientWidth - padX) / w)));
    const rows = Math.max(8, Math.min(200, Math.floor((host.clientHeight - padY) / h)));
    return { rows, cols };
  }

  function applyFit(send) {
    if (!screen) return;
    const { rows, cols } = fit();
    if (rows === lastSize.rows && cols === lastSize.cols) return;
    lastSize = { rows, cols };
    screen.resize(rows, cols);
    if (send && sock && sock.readyState === 1) {
      sock.send(JSON.stringify({ type: 'resize', rows, cols }));
    }
  }

  function bindResize() {
    let timer = null;
    const onResize = () => {
      clearTimeout(timer);
      timer = setTimeout(() => applyFit(true), 120);
    };
    window.addEventListener('resize', onResize);
    if (window.ResizeObserver) {
      new ResizeObserver(onResize).observe($('#termHost'));
    }
  }

  /* ---------- 键盘 ---------- */

  const FKEYS = {
    F1: '\x1bOP', F2: '\x1bOQ', F3: '\x1bOR', F4: '\x1bOS',
    F5: '\x1b[15~', F6: '\x1b[17~', F7: '\x1b[18~', F8: '\x1b[19~',
    F9: '\x1b[20~', F10: '\x1b[21~', F11: '\x1b[23~', F12: '\x1b[24~',
  };

  function keySeq(e) {
    const k = e.key;
    if (k === 'Enter') return '\r';
    if (k === 'Backspace') return '\x7f';
    if (k === 'Tab') return e.shiftKey ? '\x1b[Z' : '\t';
    if (k === 'Escape') return '\x1b';
    if (k === 'ArrowUp') return '\x1b[A';
    if (k === 'ArrowDown') return '\x1b[B';
    if (k === 'ArrowRight') return '\x1b[C';
    if (k === 'ArrowLeft') return '\x1b[D';
    if (k === 'Home') return '\x1b[H';
    if (k === 'End') return '\x1b[F';
    if (k === 'Insert') return '\x1b[2~';
    if (k === 'Delete') return '\x1b[3~';
    if (k === 'PageUp') return '\x1b[5~';
    if (k === 'PageDown') return '\x1b[6~';
    if (FKEYS[k]) return FKEYS[k];
    if (e.ctrlKey && !e.altKey && !e.metaKey && k.length === 1) {
      const c = k.toUpperCase().charCodeAt(0);
      if (c >= 64 && c <= 95) return String.fromCharCode(c - 64);
    }
    return '';
  }

  function sendText(text) {
    if (!sock || sock.readyState !== 1) return;
    sock.send(enc.encode(text));
  }

  function bindKeys() {
    const input = $('#termInput');
    const host = $('#termHost');

    host.addEventListener('mousedown', e => {
      if (e.target.closest('button')) return;
      setTimeout(() => input.focus(), 0);
    });

    input.addEventListener('focus', () => {
      if (screen) { screen.focused = true; screen.dirty = true; screen.schedule(); }
    });
    input.addEventListener('blur', () => {
      if (screen) { screen.focused = false; screen.dirty = true; screen.schedule(); }
    });

    input.addEventListener('keydown', e => {
      if (e.isComposing) return;
      // Ctrl/Cmd+C 在有选中文字时留给浏览器复制
      if ((e.ctrlKey || e.metaKey) && e.key === 'c' && String(window.getSelection())) {
        return;
      }
      if ((e.ctrlKey || e.metaKey) && e.key === 'v') return; // 交给 paste 事件
      const seq = keySeq(e);
      if (!seq) return;
      e.preventDefault();
      sendText(seq);
    });

    input.addEventListener('input', () => {
      const v = input.value;
      if (v) {
        sendText(v);
        input.value = '';
      }
    });

    input.addEventListener('paste', e => {
      e.preventDefault();
      const text = (e.clipboardData || window.clipboardData).getData('text');
      if (text) sendText(text.replace(/\r\n/g, '\r').replace(/\n/g, '\r'));
    });
  }

  /* ---------- 会话 ---------- */

  async function loadInfo() {
    try {
      info = await api('/api/term/info');
    } catch (e) {
      info = { enable: false, shells: [], ssh: [], error: e.message };
    }
    $('#term-keep').textContent = info.keepMin || 0;
    $('#termHint').textContent = info.enable
      ? (info.lanOnly ? '仅内网可用' : '允许公网访问') + ' · 会话保活 ' + (info.keepMin || 0) + ' 分钟'
      : '已在设置里关闭';
    const sh = $('#term-shell');
    sh.innerHTML = (info.shells || []).map(s => `<option value="${esc(s)}">${esc(s)}</option>`).join('')
      || '<option value="">无可用 shell</option>';
    if (info.defaultShell && (info.shells || []).includes(info.defaultShell)) sh.value = info.defaultShell;

    const ssh = $('#term-ssh');
    ssh.innerHTML = (info.ssh || []).length
      ? info.ssh.map(c => `<option value="${esc(c.name)}">${esc(c.name)} · ${esc(c.user)}@${esc(c.host)}</option>`).join('')
      : '<option value="">未配置（在设置里加）</option>';
    if (!info.enable) {
      showErr($('#termErr'), '终端功能已关闭，到「设置」里打开后再用');
    }
    loadSessions();
    return info;
  }

  function fmtAge(iso) {
    const t = new Date(iso).getTime();
    if (!t) return '—';
    const s = Math.max(0, Math.floor((Date.now() - t) / 1000));
    if (s < 60) return s + ' 秒前';
    if (s < 3600) return Math.floor(s / 60) + ' 分钟前';
    return Math.floor(s / 3600) + ' 小时前';
  }

  async function loadSessions() {
    let d;
    try {
      d = await api('/api/term/sessions');
    } catch (e) {
      return [];
    }
    const list = d.sessions || [];
    const box = $('#termSessions');
    box.innerHTML = list.length ? list.map(s => `
      <div class="mini-row">
        <span class="dot ${s.attached ? 'ok' : 'warn'}"></span>
        <div class="grow">
          <div>${esc(s.kind === 'ssh' ? 'SSH' : '本机')} · ${esc(s.title)}</div>
          <div class="mono">${s.attached ? '已连接' : '等待接回'} · ${fmtAge(s.lastUsed)}活动 · ${s.cols}×${s.rows}</div>
        </div>
        <button class="ghost sm" data-attach="${esc(s.id)}">接入</button>
        <button class="ghost sm danger-text" data-kill="${esc(s.id)}">结束</button>
      </div>`).join('') : '<p class="empty">还没有会话，选上面的 shell 或 SSH 开一个</p>';
    return list;
  }

  async function open(kind, payload) {
    hide($('#termErr'));
    if (!info || !info.enable) {
      showErr($('#termErr'), '终端功能已关闭');
      return;
    }
    const { rows, cols } = fit();
    try {
      const d = await api('/api/term/sessions', {
        method: 'POST',
        body: JSON.stringify(Object.assign({ kind, rows, cols }, payload)),
      });
      mount();
      attach(d.id, d.title);
    } catch (e) {
      showErr($('#termErr'), e.message);
    }
  }

  function attach(id, title) {
    mount();
    if (sock) {
      closing = true;
      try { sock.close(); } catch (e) { /* 忽略 */ }
      sock = null;
    }
    clearTimeout(retryTimer);
    retries = 0;
    closing = false;
    sid = id;
    current = { id: id, title: title || '终端' };
    $('#termCard').classList.remove('hidden');
    $('#termTitle').textContent = current.title;
    $('#termState').textContent = '连接中…';

    const size = (function () {
      applyFit(false);
      return lastSize.rows ? lastSize : fit();
    })();
    lastSize = size;
    screen.resize(size.rows, size.cols);
    screen.reset();
    screen.el.innerHTML = '<span class="term-boot">正在接入会话 ' + esc(id) + ' …</span>';

    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = `${proto}//${location.host}/api/term/ws?id=${encodeURIComponent(id)}&rows=${size.rows}&cols=${size.cols}`;
    let ws;
    try {
      ws = new WebSocket(url);
    } catch (e) {
      showErr($('#termErr'), '建立 WebSocket 失败: ' + e.message);
      return;
    }
    ws.binaryType = 'arraybuffer';
    sock = ws;

    ws.onopen = () => {
      retries = 0;
      $('#termState').textContent = '已连接';
      applyFit(true);
      $('#termInput').focus();
    };

    ws.onmessage = ev => {
      if (typeof ev.data === 'string') {
        let m;
        try { m = JSON.parse(ev.data); } catch (e) { return; }
        if (m.type === 'exit') {
          $('#termState').textContent = '已结束';
          screen.focused = false;
          screen.write('\r\n\x1b[90m[会话已结束：' + (m.msg || '') + ']\x1b[0m\r\n');
          closing = true;
          loadSessions();
        }
        return;
      }
      screen.write(dec.decode(new Uint8Array(ev.data), { stream: true }));
    };

    ws.onclose = () => {
      if (closing || sock !== ws) return;
      sock = null;
      $('#termState').textContent = '已断开';
      if (retries++ < 2) {
        $('#termState').textContent = '断线，重连中…';
        retryTimer = setTimeout(() => attach(sid, current && current.title), 1500);
      } else {
        screen.write('\r\n\x1b[90m[连接已断开，点「接入」可再试；shell 仍在服务端运行]\x1b[0m\r\n');
        loadSessions();
      }
    };

    ws.onerror = () => { /* onclose 会跟着来，这里不重复处理 */ };
  }

  function detachView() {
    closing = true;
    if (sock) {
      try { sock.close(); } catch (e) { /* 忽略 */ }
      sock = null;
    }
    sid = '';
    $('#termCard').classList.add('hidden');
    loadSessions();
    toast('已断开显示，shell 继续在后台运行');
  }

  async function closeSession() {
    if (!sid) return;
    const id = sid;
    closing = true;
    if (sock) {
      try { sock.close(); } catch (e) { /* 忽略 */ }
      sock = null;
    }
    try {
      await api('/api/term/sessions?id=' + encodeURIComponent(id), { method: 'DELETE' });
      toast('会话已结束');
    } catch (e) {
      toast(e.message, true);
    }
    sid = '';
    $('#termCard').classList.add('hidden');
    loadSessions();
  }

  /* ---------- 事件绑定 ---------- */

  function init() {
    $('#btnTermLocal').addEventListener('click', () => {
      open('local', { shell: $('#term-shell').value });
    });
    $('#btnTermSSH').addEventListener('click', () => {
      const name = $('#term-ssh').value;
      if (!name) {
        showErr($('#termErr'), '还没有配置 SSH 连接，先在「设置 → 终端」里加一条');
        return;
      }
      open('ssh', { name });
    });
    $('#btnTermRefresh').addEventListener('click', () => loadSessions());
    $('#btnTermDetach').addEventListener('click', detachView);
    $('#btnTermClose').addEventListener('click', closeSession);

    $('#termSessions').addEventListener('click', e => {
      const a = e.target.closest('[data-attach]');
      if (a) {
        const row = a.closest('.mini-row');
        attach(a.dataset.attach, row ? row.querySelector('.grow div').textContent.trim() : '终端');
        return;
      }
      const k = e.target.closest('[data-kill]');
      if (k) {
        api('/api/term/sessions?id=' + encodeURIComponent(k.dataset.kill), { method: 'DELETE' })
          .then(() => { if (sid === k.dataset.kill) { sid = ''; $('#termCard').classList.add('hidden'); } loadSessions(); })
          .catch(err => toast(err.message, true));
      }
    });
  }

  // 切到终端页：刷新会话，并在没有连接时自动接回最近一个空闲会话
  async function show() {
    mount();
    await loadInfo();
    const list = await loadSessions();
    if (sock || sid) return;
    const free = list.filter(s => !s.attached && !s.exited);
    if (free.length) {
      const last = free[free.length - 1];
      attach(last.id, last.title);
    }
  }

  return { init, show, mount, attach, loadSessions, loadInfo };
})();

TermUI.init();
