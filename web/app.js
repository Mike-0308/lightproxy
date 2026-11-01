'use strict';

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

const state = {
  config: null,
  status: null,
  editIndex: -1,
  tab: 'overview',
};

/* ---------- 小工具 ---------- */

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

let toastTimer = null;
function toast(msg, bad) {
  const el = $('#toast');
  el.textContent = msg;
  el.classList.toggle('bad', !!bad);
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 2600);
}

async function api(path, opts) {
  const r = await fetch(path, Object.assign({ headers: { 'Content-Type': 'application/json' } }, opts || {}));
  if (r.status === 401) {
    location.reload();
    throw new Error('未登录');
  }
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
  return d;
}

function fmtUptime(sec) {
  if (!sec) return '—';
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  if (d) return d + ' 天 ' + h + ' 小时';
  if (h) return h + ' 小时 ' + m + ' 分';
  if (m) return m + ' 分';
  return sec + ' 秒';
}

function fmtTime(t) {
  if (!t || String(t).startsWith('0001')) return '—';
  const d = new Date(t);
  if (isNaN(d.getTime())) return '—';
  const p = n => String(n).padStart(2, '0');
  return p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
}

function showErr(el, msg) {
  if (!el) return;
  el.textContent = msg;
  el.classList.remove('hidden');
}
function hide(el) { if (el) el.classList.add('hidden'); }

/* ---------- 加载 ---------- */

async function loadAll() {
  const [c, s] = await Promise.all([api('/api/config'), api('/api/status')]);
  state.config = c.config;
  state.status = s;
  $('#ver').textContent = 'v' + s.version;
  fillForms();
  renderOverview();
  renderRules();
  renderForwardRules();
  renderForward();
  renderACME();
  renderRecords();
  renderDDNS();
  renderWOL();
  renderWOLEdit();
  if (state.tab === 'logs') loadLogs();
}

function fillForms() {
  const c = state.config, d = c.ddns || {};
  $('#d-enable').checked = !!d.enable;
  $('#d-ak').value = d.accessKeyId || '';
  $('#d-sk').value = d.accessKeySecret || '';
  $('#d-mode').value = d.ipMode || 'api';
  $('#d-iface').value = d.interface || '';
  $('#d-interval').value = d.interval || 300;
  $('#d-ttl').value = d.ttl || 600;
  $('#d-sources').value = (d.ipSources || []).join('\n');

  const t = c.tls || {}, a = c.admin || {}, rt = c.runtime || {};
  $('#s-listen').value = c.listen || '';
  $('#s-admin').value = a.listen || '';
  $('#s-user').value = a.user || '';
  $('#s-pass').value = a.pass || '';
  $('#s-mem').value = rt.memLimitMB || 32;
  $('#s-access').checked = rt.accessLog !== false;
  $('#s-tls').checked = !!t.enable;
  // 证书路径由后端自动推导，只有手填过、且和自动目录不同才回显
  const autoDir = (state.status && state.status.certsDirAuto) || '';
  $('#s-certdir').value = (t.certDir && t.certDir !== autoDir) ? t.certDir : '';
  const dirText = (state.status && state.status.certsDir) || autoDir || '安装目录/certs';
  $('#s-certsdir').textContent = dirText;
  if ($('#a-certsdir')) $('#a-certsdir').textContent = dirText;
  $('#s-httplisten').value = t.httpListen || '';
  $('#s-redirect').checked = !!t.redirect;
  $('#s-pubport').value = t.publicPort || 443;

  const sec = c.security || {};
  $('#s-reqdomain').checked = !!sec.requireDomain;
  $('#s-extrahosts').value = (sec.extraHosts || []).join(', ');
  $('#s-entry').value = sec.entryPath || '';
  $('#f-knock').checked = !!sec.knockForward;
  renderEntryHint();

  const f = c.forward || {}, ac = c.acme || {};
  $('#f-enable').checked = !!f.enable;
  $('#f-backend').value = f.backend || 'auto';
  $('#f-hairpin').checked = !!f.hairpin;
  $('#f-v6forward').checked = f.v6Forward !== false;
  $('#a-enable').checked = !!ac.enable;
  $('#a-email').value = ac.email || '';
  $('#a-ca').value = ac.ca || 'letsencrypt';
  $('#a-domains').value = (ac.domains || []).join('\n');
  $('#a-keytype').value = ac.keyType || 'ec256';
  $('#a-renewdays').value = ac.renewDays || 30;
  $('#a-ak').value = ac.accessKeyId || '';
  $('#a-sk').value = ac.accessKeySecret || '';

  const tm = c.term || {};
  $('#t-enable').checked = tm.enable !== false;
  $('#t-lanonly').checked = tm.lanOnly !== false;
  $('#t-keep').value = tm.keepMin == null ? 60 : tm.keepMin;
  $('#t-max').value = tm.maxSessions || 4;
  $('#t-shell').value = tm.shell || '';
  renderSSH();
}

/* ---------- 安全入口提示 ---------- */

// 用第一条规则的域名拼一个完整的外网入口地址，省得用户自己拼端口拼错。
function renderEntryHint() {
  const el = $('#s-entry-url');
  if (!el) return;
  const raw = ($('#s-entry').value || '').trim();
  if (!raw) {
    el.textContent = '未启用';
    return;
  }
  const path = '/' + raw.replace(/^\/+/, '').replace(/\/+$/, '');
  const rules = (state.config && state.config.proxy) || [];
  let host = '';
  for (const r of rules) {
    if (r.disable) continue;
    host = (r.hosts || []).find(h => h && !h.startsWith('*.')) || '';
    if (host) break;
  }
  if (!host) {
    el.textContent = '外网入口：https://你的域名:端口' + path;
    return;
  }
  const port = +$('#s-pubport').value || (state.config && state.config.tls && state.config.tls.publicPort) || 443;
  el.textContent = '外网入口：https://' + host + (port === 443 ? '' : ':' + port) + path;
}

function randomEntry() {
  const chars = 'abcdefghijkmnpqrstuvwxyz23456789';
  let s = '';
  const buf = new Uint32Array(6);
  (window.crypto || window.msCrypto).getRandomValues(buf);
  for (let i = 0; i < 6; i++) s += chars[buf[i] % chars.length];
  $('#s-entry').value = '/' + s;
  renderEntryHint();
}

/* ---------- 概览 ---------- */
function renderOverview() {
  const s = state.status;
  if (!s) return;
  $('#ov-uptime').textContent = fmtUptime(s.uptimeSec);
  $('#ov-mem').textContent = (s.mem.rssMB ? s.mem.rssMB + ' MB' : s.mem.heapMB + ' MB');
  $('#ov-req').textContent = (s.stats.requests || 0).toLocaleString();
  $('#ov-live').textContent = s.stats.live || 0;
  $('#ov-listen').textContent = s.listen + (s.tls ? '（HTTPS）' : '（HTTP）');
  $('#ov-admin').textContent = 'http://' + s.adminListen + (s.tls ? '（明文，建议只在内网）' : '');
  $('#ov-tls').textContent = s.tls
    ? '已启用 · ' + (s.tlsInfo.count || 0) + ' 张证书' + (s.tlsInfo.notAfter ? ' · 到期 ' + s.tlsInfo.notAfter : '')
    : '未启用';
  $('#ov-ver').textContent = 'v' + s.version + ' · ' + s.hostname;
  $('#ov-restart').textContent = s.needRestart ? '有改动待重启生效' : '';

  const entry = (s.security && s.security.entryPath) || '';
  $('#ov-entry').textContent = entry
    ? entry + '（外网只认这个路径，内网不受限）'
    : '未启用';

  const rules = s.rules || [];
  $('#ov-rules').innerHTML = rules.length
    ? rules.map(r => `
      <div class="mini-row">
        <span class="dot ok"></span>
        <div class="grow">
          <div>${esc(r.name)}</div>
          <div class="mono">${esc((r.hosts || []).join(', '))}${r.path && r.path !== '/' ? esc(r.path) : ''} → ${esc(r.target)}</div>
        </div>
      </div>`).join('')
    : '<p class="empty">还没有转发规则</p>';

  const d = s.ddns || {};
  if (!d.enabled) {
    $('#ov-ddns').innerHTML = '<p class="empty">未启用</p>';
  } else {
    const rows = [`<div class="mini-row"><span class="dot ${d.lastError ? 'err' : 'ok'}"></span><div class="grow"><div>${d.lastError ? '同步异常' : '同步正常'}</div><div class="mono">${d.lastError ? esc(d.lastError) : '公网 IP ' + esc(d.publicIpv4 || d.publicIpv6 || '—')}</div></div></div>`];
    $('#ov-ddns').innerHTML = rows.join('');
  }

  const fw = s.forward || {};
  if (fw.error) {
    $('#ov-fwd').innerHTML = `<div class="mini-row"><span class="dot err"></span><div class="grow"><div>下发失败</div><div class="mono">${esc(fw.error)}</div></div></div>`;
  } else if (fw.ready) {
    $('#ov-fwd').innerHTML = `<div class="mini-row"><span class="dot ok"></span><div class="grow"><div>${fw.applied} 条规则生效中</div><div class="mono">${esc(fw.backend)} · ${esc(fw.persist || '')}</div></div></div>`;
  } else {
    $('#ov-fwd').innerHTML = '<p class="empty">未启用</p>';
  }

  const ac = s.acme || {};
  if (ac.issuing) {
    $('#ov-acme').innerHTML = `<div class="mini-row"><span class="dot warn"></span><div class="grow"><div>正在签发</div><div class="mono">${esc(ac.stage || '准备中')}</div></div></div>`;
  } else if (ac.notAfter) {
    $('#ov-acme').innerHTML = `<div class="mini-row"><span class="dot ok"></span><div class="grow"><div>证书有效${ac.subject ? ' · ' + esc(ac.subject) : ''}</div><div class="mono">到期 ${esc(ac.notAfter)}</div></div></div>`;
  } else if (ac.enabled) {
    $('#ov-acme').innerHTML = '<p class="empty">已启用，尚未签发</p>';
  } else {
    $('#ov-acme').innerHTML = '<p class="empty">未启用</p>';
  }
}

/* ---------- 反代规则 ---------- */

function renderRules() {
  const rules = (state.config && state.config.proxy) || [];
  const wrap = $('#ruleList');
  if (!rules.length) {
    wrap.innerHTML = '<p class="empty">还没有规则。点右上角「新增规则」，把域名指向内网设备。</p>';
    return;
  }
  wrap.innerHTML = rules.map((r, i) => `
    <div class="rule ${r.disable ? 'off' : ''}">
      <div class="rule-main">
        <div class="rule-name">${esc(r.name)}${r.disable ? '<span class="badge">已停用</span>' : ''}</div>
        <div class="rule-line"><code>${esc((r.hosts || []).join(', '))}</code>${r.path && r.path !== '/' ? '<code>' + esc(r.path) + '</code>' : ''}<span class="arrow">→</span><code>${esc(r.target)}</code></div>
      </div>
      <div class="rule-actions">
        <button class="ghost sm" data-edit="${i}">编辑</button>
        <button class="ghost sm danger-text" data-del="${i}">删除</button>
      </div>
    </div>`).join('');
}

function openEditor(i) {
  state.editIndex = i;
  const r = i >= 0 ? state.config.proxy[i] : {
    name: '', hosts: [], path: '/', target: '', headers: {}, delHeaders: [],
  };
  $('#editorTitle').textContent = i >= 0 ? '编辑规则' : '新增规则';
  $('#r-name').value = r.name || '';
  $('#r-hosts').value = (r.hosts || []).join(', ');
  $('#r-path').value = r.path || '/';
  $('#r-target').value = r.target || '';
  $('#r-headers').value = Object.entries(r.headers || {}).map(([k, v]) => k + ': ' + v).join('\n');
  $('#r-delHeaders').value = (r.delHeaders || []).join(', ');
  $('#r-preserveHost').checked = !!r.preserveHost;
  $('#r-insecure').checked = !!r.insecure;
  $('#r-disable').checked = !!r.disable;
  hide($('#ruleErr'));
  $('#editor').classList.remove('hidden');
  $('#editor').scrollIntoView({ behavior: 'smooth', block: 'center' });
}

function ruleFromForm() {
  const headers = {};
  $('#r-headers').value.split('\n').forEach(line => {
    const i = line.indexOf(':');
    if (i > 0) headers[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  });
  return {
    name: $('#r-name').value.trim(),
    hosts: $('#r-hosts').value.split(/[\s,，]+/).map(s => s.trim()).filter(Boolean),
    path: $('#r-path').value.trim() || '/',
    target: $('#r-target').value.trim(),
    preserveHost: $('#r-preserveHost').checked,
    insecure: $('#r-insecure').checked,
    disable: $('#r-disable').checked,
    headers,
    delHeaders: $('#r-delHeaders').value.split(/[,，\s]+/).map(s => s.trim()).filter(Boolean),
  };
}

/* ---------- 端口转发 ---------- */

function renderForwardRules() {
  const rules = (state.config && state.config.forward && state.config.forward.rules) || [];
  const wrap = $('#fwdList');
  if (!rules.length) {
    wrap.innerHTML = '<p class="empty">还没有规则。点下面「添加规则」，把外网端口指到内网设备。</p>';
    return;
  }
  wrap.innerHTML = rules.map((r, i) => `
    <div class="fw-row ${r.disable ? 'off' : ''}" data-i="${i}">
      <input class="fw-name" value="${esc(r.name)}" placeholder="名称">
      <select class="fw-proto">
        <option value="tcp"${(r.proto || 'tcp') === 'tcp' ? ' selected' : ''}>TCP</option>
        <option value="udp"${r.proto === 'udp' ? ' selected' : ''}>UDP</option>
        <option value="both"${r.proto === 'both' ? ' selected' : ''}>TCP+UDP</option>
      </select>
      <input class="fw-port" type="number" min="1" max="65535" value="${r.port || ''}" placeholder="8080">
      <input class="fw-host" value="${esc(r.toHost)}" placeholder="192.168.10.10">
      <input class="fw-toport" type="number" min="1" max="65535" value="${r.toPort || ''}" placeholder="80">
      <div class="mid"><input type="checkbox" class="fw-disable"${r.disable ? ' checked' : ''}></div>
      <button class="del" data-delfwd="${i}" title="删除">×</button>
    </div>`).join('');
}

function syncForwardRules(c) {
  const old = (state.config.forward && state.config.forward.rules) || [];
  c.forward = c.forward || {};
  c.forward.rules = $$('#fwdList .fw-row').map(row => {
    const base = Object.assign({}, old[+row.dataset.i] || {});
    base.name = row.querySelector('.fw-name').value.trim();
    base.proto = row.querySelector('.fw-proto').value;
    base.port = +row.querySelector('.fw-port').value || 0;
    base.toHost = row.querySelector('.fw-host').value.trim();
    base.toPort = +row.querySelector('.fw-toport').value || 0;
    base.disable = row.querySelector('.fw-disable').checked;
    return base;
  });
}

function renderForward() {
  const st = (state.status && state.status.forward) || {};
  const cfg = (state.config && state.config.forward) || {};
  const meta = [];
  if (st.backend && st.backend !== 'none') meta.push('后端 ' + st.backend);
  if (st.ready) meta.push(st.applied + ' 条已生效');
  if (st.relayPorts && st.relayPorts.length) meta.push('IPv6 裸转发 ' + st.relayPorts.join('、'));
  if (st.knocks && st.knocks.length) meta.push('敲门放行 ' + st.knocks.length + ' 个来源');
  if (st.hairpin) meta.push('内网回环');
  if (st.updated && !String(st.updated).startsWith('0001')) meta.push('更新于 ' + fmtTime(st.updated));
  $('#fwdMeta').textContent = meta.join(' · ');

  if (!cfg.enable) {
    $('#fwdStatus').innerHTML = '<p class="empty">未启用。规则不会写进内核，也不会开机恢复。</p>';
    return;
  }
  const rows = [];
  if (st.error) {
    rows.push(`<div class="mini-row"><span class="dot err"></span><div class="grow">
      <div>下发失败，已自动回滚</div><div class="mono">${esc(st.error)}</div></div></div>`);
  } else if (st.ready) {
    rows.push(`<div class="mini-row"><span class="dot ok"></span><div class="grow">
      <div>${st.applied} 条转发规则已写入 ${esc(st.backend)}</div>
      <div class="mono">${esc(st.persist || '未做开机持久化')}</div></div></div>`);
    if (st.relayPorts && st.relayPorts.length) {
      rows.push(`<div class="mini-row"><span class="dot ok"></span><div class="grow">
        <div>IPv6 用户态转发监听中：${st.relayPorts.join('、')}</div>
        <div class="mono">外网 IPv6 打这些端口会原样转给规则里的内网目标（RDP/SSH 等任意 TCP/UDP）</div></div></div>`);
      if (st.knocks && st.knocks.length) {
        rows.push(`<div class="mini-row"><span class="dot ok"></span><div class="grow">
          <div>已敲门放行：${esc(st.knocks.join('、'))}</div>
          <div class="mono">只有这些来源网络能连转发的端口（重新访问安全入口可续期）</div></div></div>`);
      }
    }
    if (st.openPorts && st.openPorts.length) {
      rows.push(`<div class="mini-row"><span class="dot ok"></span><div class="grow">
        <div>反代端口已对外放行：${st.openPorts.join('、')}</div>
        <div class="mono">管理面板端口不在其中，只能经反代域名访问</div></div></div>`);
    }
  } else {
    rows.push('<div class="mini-row"><span class="dot warn"></span><div class="grow"><div>尚未下发</div><div class="mono">点「保存并下发」让规则生效</div></div></div>');
  }
  $('#fwdStatus').innerHTML = rows.join('');
}

/* ---------- 自动证书 ---------- */

function renderACME() {
  const st = (state.status && state.status.acme) || {};
  const meta = [];
  if (st.notAfter) meta.push('到期 ' + st.notAfter);
  if (st.lastOk) meta.push('上次签发 ' + st.lastOk);
  $('#acmeMeta').textContent = meta.join(' · ');

  const rows = [];
  if (st.issuing) {
    rows.push(`<div class="mini-row"><span class="dot warn"></span><div class="grow">
      <div>正在签发…</div><div class="mono">${esc(st.stage || '准备中')}</div></div></div>`);
  } else if (st.lastError) {
    rows.push(`<div class="mini-row"><span class="dot err"></span><div class="grow">
      <div>签发失败</div><div class="mono">${esc(st.lastError)}</div></div></div>`);
  } else if (st.notAfter) {
    rows.push(`<div class="mini-row"><span class="dot ok"></span><div class="grow">
      <div>证书有效${st.subject ? ' · ' + esc(st.subject) : ''}</div>
      <div class="mono">到期时间 ${esc(st.notAfter)}</div></div></div>`);
  } else if (st.enabled) {
    rows.push('<div class="mini-row"><span class="dot warn"></span><div class="grow"><div>还没有证书</div><div class="mono">点「立即签发」开始申请</div></div></div>');
  } else {
    rows.push('<p class="empty">未启用</p>');
  }
  $('#acmeStatus').innerHTML = rows.join('');
}

/* ---------- DDNS 记录 ---------- */

function renderRecords() {
  const recs = (state.config.ddns && state.config.ddns.records) || [];
  const wrap = $('#recList');
  if (!recs.length) {
    wrap.innerHTML = '<p class="empty">还没有记录。域名需已托管在阿里云解析。</p>';
    return;
  }
  wrap.innerHTML = recs.map((r, i) => `
    <div class="rec" data-i="${i}">
      <input class="rec-domain" value="${esc(r.domain)}" placeholder="example.com">
      <input class="rec-rr" value="${esc(r.rr || '@')}" placeholder="@ 或 * 或 home">
      <select class="rec-type">
        <option value="A"${(r.type || 'A') === 'A' ? ' selected' : ''}>A</option>
        <option value="AAAA"${r.type === 'AAAA' ? ' selected' : ''}>AAAA</option>
      </select>
      <button class="ghost sm danger-text" data-delrec="${i}">删除</button>
    </div>`).join('');
}

function syncRecords(c) {
  const old = (state.config.ddns && state.config.ddns.records) || [];
  c.ddns.records = $$('#recList .rec').map(row => {
    const base = Object.assign({}, old[+row.dataset.i] || {});
    base.domain = row.querySelector('.rec-domain').value.trim().toLowerCase();
    base.rr = row.querySelector('.rec-rr').value.trim() || '@';
    base.type = row.querySelector('.rec-type').value;
    return base;
  }).filter(r => r.domain);
}

function renderDDNS() {
  const d = (state.status && state.status.ddns) || {};
  const meta = [];
  if (d.enabled) {
    if (d.publicIpv4) meta.push('公网 IPv4 ' + d.publicIpv4);
    if (d.publicIpv6) meta.push('公网 IPv6 ' + d.publicIpv6);
    if (d.lastRun && !String(d.lastRun).startsWith('0001')) meta.push('上次 ' + fmtTime(d.lastRun));
  } else {
    meta.push('未启用');
  }
  $('#ddnsMeta').textContent = meta.join(' · ');

  const recs = d.records || [];
  $('#ddnsStatus').innerHTML = recs.length ? recs.map(r => {
    const cls = r.state === 'error' ? 'err'
      : (r.state === 'ok' || r.state === 'updated' || r.state === 'added') ? 'ok' : 'warn';
    return `<div class="mini-row">
      <span class="dot ${cls}"></span>
      <div class="grow">
        <div>${esc(r.rr)}.${esc(r.domain)} <span class="mono">${esc(r.type)}</span></div>
        <div class="mono">${esc(r.message || '')}${r.current ? ' · 当前 ' + esc(r.current) : ''}${r.desired && r.desired !== r.current ? ' · 目标 ' + esc(r.desired) : ''}</div>
      </div>
      <span class="mono">${fmtTime(r.updatedAt)}</span>
    </div>`;
  }).join('') : '<p class="empty">暂无同步记录</p>';
}

/* ---------- 网络唤醒 ---------- */

function wolDevices() {
  state.config.wol = state.config.wol || { devices: [] };
  if (!Array.isArray(state.config.wol.devices)) state.config.wol.devices = [];
  return state.config.wol.devices;
}

function renderWOL() {
  const devs = wolDevices();
  $('#wolList').innerHTML = devs.length ? devs.map((d, i) => `
    <div class="mini-row">
      <span class="dot"></span>
      <div class="grow">
        <div>${esc(d.name || '未命名设备')}</div>
        <div class="mono">${esc((d.macs || []).join(' · ') || '未填 MAC')}${d.broadcast ? ' → ' + esc(d.broadcast) : ''}</div>
      </div>
      <button class="primary sm" data-wake="${i}">唤醒</button>
    </div>`).join('') : '<p class="empty">还没有设备，在下面添加</p>';
}

function renderWOLEdit() {
  const devs = wolDevices();
  $('#wolEdit').innerHTML = devs.map((d, i) => `
    <div class="wol-row">
      <input data-wf="name" data-i="${i}" value="${esc(d.name || '')}" placeholder="群晖">
      <input data-wf="macs" data-i="${i}" value="${esc((d.macs || []).join(', '))}" placeholder="00:11:32:AA:BB:CC">
      <input data-wf="broadcast" data-i="${i}" value="${esc(d.broadcast || '')}" placeholder="留空 = 255.255.255.255">
      <button class="del" data-delwol="${i}" title="删除">×</button>
    </div>`).join('');
}

$('#btnAddWol').addEventListener('click', () => {
  wolDevices().push({ name: '', macs: [], broadcast: '' });
  renderWOLEdit();
  renderWOL();
  const names = $$('#wolEdit input[data-wf="name"]');
  if (names.length) names[names.length - 1].focus();
});

$('#wolEdit').addEventListener('input', e => {
  const el = e.target.closest('[data-wf]');
  if (!el) return;
  const dev = wolDevices()[+el.dataset.i];
  if (!dev) return;
  if (el.dataset.wf === 'macs') {
    dev.macs = el.value.split(/[,，\s]+/).map(s => s.trim()).filter(Boolean);
  } else {
    dev[el.dataset.wf] = el.value.trim();
  }
});

$('#wolEdit').addEventListener('click', e => {
  const b = e.target.closest('[data-delwol]');
  if (!b) return;
  wolDevices().splice(+b.dataset.delwol, 1);
  renderWOLEdit();
  renderWOL();
});

$('#btnSaveWol').addEventListener('click', () => saveConfig(null, $('#wolErr')));

$('#wolList').addEventListener('click', async e => {
  const b = e.target.closest('[data-wake]');
  if (!b) return;
  const dev = wolDevices()[+b.dataset.wake];
  if (!dev) return;
  b.disabled = true;
  try {
    const d = await api('/api/wol/wake', { method: 'POST', body: JSON.stringify({ name: dev.name }) });
    toast('已发出 ' + d.sent + ' 个魔术包');
  } catch (err) {
    toast(err.message, true);
  }
  setTimeout(() => { b.disabled = false; }, 800);
});

/* ---------- SSH 连接表（设置页） ---------- */

function sshConns() {
  state.config.term = state.config.term || {};
  if (!Array.isArray(state.config.term.ssh)) state.config.term.ssh = [];
  return state.config.term.ssh;
}

function renderSSH() {
  const list = sshConns();
  $('#sshList').innerHTML = list.map((c, i) => {
    const isKey = c.auth === 'key';
    return `
    <div class="ssh-row">
      <input data-sf="name" data-i="${i}" value="${esc(c.name || '')}" placeholder="群晖">
      <input data-sf="host" data-i="${i}" value="${esc(c.host || '')}" placeholder="192.168.31.10">
      <input data-sf="port" data-i="${i}" type="number" min="1" max="65535" value="${c.port || 22}">
      <input data-sf="user" data-i="${i}" value="${esc(c.user || '')}" placeholder="root">
      <select data-sf="auth" data-i="${i}">
        <option value="password"${isKey ? '' : ' selected'}>密码</option>
        <option value="key"${isKey ? ' selected' : ''}>私钥</option>
      </select>
      <input data-sf="secret" data-i="${i}" value="${esc(isKey ? (c.keyPath || '') : (c.password || ''))}"
        placeholder="${isKey ? '/root/.ssh/id_ed25519' : '登录密码'}">
      <button class="del" data-delssh="${i}" title="删除">×</button>
    </div>`;
  }).join('');
}

$('#btnAddSSH').addEventListener('click', () => {
  sshConns().push({ name: '', host: '', port: 22, user: 'root', auth: 'password', password: '' });
  renderSSH();
  const names = $$('#sshList input[data-sf="name"]');
  if (names.length) names[names.length - 1].focus();
});

$('#sshList').addEventListener('input', e => {
  const el = e.target.closest('[data-sf]');
  if (!el || el.tagName === 'SELECT') return;
  const c = sshConns()[+el.dataset.i];
  if (!c) return;
  const f = el.dataset.sf;
  if (f === 'secret') {
    if (c.auth === 'key') c.keyPath = el.value.trim();
    else c.password = el.value;
    return;
  }
  if (f === 'port') c.port = +el.value || 22;
  else c[f] = el.value.trim();
});

$('#sshList').addEventListener('change', e => {
  const el = e.target.closest('select[data-sf]');
  if (!el) return;
  const c = sshConns()[+el.dataset.i];
  if (!c) return;
  c.auth = el.value;
  renderSSH();
});

$('#sshList').addEventListener('click', e => {
  const b = e.target.closest('[data-delssh]');
  if (!b) return;
  sshConns().splice(+b.dataset.delssh, 1);
  renderSSH();
});

/* ---------- 配置收集与保存 ---------- */

function collectConfig() {
  const c = JSON.parse(JSON.stringify(state.config));
  // DDNS
  c.ddns = c.ddns || {};
  c.ddns.enable = $('#d-enable').checked;
  c.ddns.accessKeyId = $('#d-ak').value.trim();
  c.ddns.accessKeySecret = $('#d-sk').value.trim();
  c.ddns.ipMode = $('#d-mode').value;
  c.ddns.interface = $('#d-iface').value.trim();
  c.ddns.interval = +$('#d-interval').value || 300;
  c.ddns.ttl = +$('#d-ttl').value || 600;
  c.ddns.ipSources = $('#d-sources').value.split(/[\n,，\s]+/).map(s => s.trim()).filter(Boolean);
  c.ddns.provider = 'aliyun';
  syncRecords(c);

  // 监听 / 面板 / 运行时
  c.listen = $('#s-listen').value.trim() || ':16666';
  c.admin = c.admin || {};
  c.admin.listen = $('#s-admin').value.trim() || '0.0.0.0:18080';
  c.admin.user = $('#s-user').value.trim() || 'admin';
  c.admin.pass = $('#s-pass').value;
  c.runtime = c.runtime || {};
  c.runtime.memLimitMB = +$('#s-mem').value || 32;
  c.runtime.accessLog = $('#s-access').checked;

  // TLS：证书路径由后端自动推导，不再由界面填写
  c.tls = c.tls || {};
  c.tls.enable = $('#s-tls').checked;
  c.tls.certDir = $('#s-certdir').value.trim();
  c.tls.httpListen = $('#s-httplisten').value.trim();
  c.tls.redirect = $('#s-redirect').checked;
  c.tls.publicPort = Number($('#s-pubport').value) || 443;

  // 访问控制
  c.security = c.security || {};
  c.security.requireDomain = $('#s-reqdomain').checked;
  c.security.extraHosts = $('#s-extrahosts').value
    .split(/[,\s]+/).map(x => x.trim()).filter(Boolean);
  c.security.entryPath = $('#s-entry').value.trim();
  c.security.knockForward = $('#f-knock').checked;

  // 端口转发
  c.forward = c.forward || {};
  c.forward.enable = $('#f-enable').checked;
  c.forward.backend = $('#f-backend').value;
  c.forward.hairpin = $('#f-hairpin').checked;
  c.forward.v6Forward = $('#f-v6forward').checked;
  syncForwardRules(c);

  // 自动证书
  c.acme = c.acme || {};
  c.acme.enable = $('#a-enable').checked;
  c.acme.email = $('#a-email').value.trim();
  c.acme.ca = $('#a-ca').value;
  c.acme.domains = $('#a-domains').value.split(/[\n,，\s]+/).map(s => s.trim()).filter(Boolean);
  c.acme.keyType = $('#a-keytype').value;
  c.acme.renewDays = +$('#a-renewdays').value || 30;
  c.acme.accessKeyId = $('#a-ak').value.trim();
  c.acme.accessKeySecret = $('#a-sk').value.trim();

  // 终端（SSH 列表在编辑时已经写回 state.config.term.ssh）
  c.term = c.term || {};
  c.term.enable = $('#t-enable').checked;
  c.term.lanOnly = $('#t-lanonly').checked;
  c.term.keepMin = Math.max(0, +$('#t-keep').value || 0);
  c.term.maxSessions = +$('#t-max').value || 4;
  c.term.shell = $('#t-shell').value.trim();
  return c;
}

async function saveConfig(cfg, errEl) {
  hide(errEl);
  try {
    await api('/api/config', { method: 'POST', body: JSON.stringify(cfg || collectConfig()) });
  } catch (e) {
    showErr(errEl, e.message);
    toast(e.message, true);
    return false;
  }
  toast('已保存并生效');
  // 刚改了安全入口时，后面的请求会因为旧票据失效被拦，交给页面跳转处理，不当作保存失败
  try { await loadAll(); } catch (e) { /* 忽略 */ }
  return true;
}

// 改了安全入口就跳到新地址，否则当前页面继续请求 /api 会一直 404。
// 直接开面板端口（18080）进来的不跳——面板端口上本来就没有入口路径。
function maybeJumpToEntry(before, after) {
  const norm = s => ('/' + String(s || '').replace(/^\/+/, '').replace(/\/+$/, '')).replace(/\/$/, '');
  const a = norm(before), b = norm(after);
  if (a === b || !b) return false;
  const adminPort = String((state.status && state.status.adminListen) || '').split(':').pop();
  if (location.port === adminPort) return false;
  toast('入口已修改，正在跳转到新入口…');
  setTimeout(() => { location.href = location.protocol + '//' + location.host + b; }, 900);
  return true;
}

/* ---------- 日志 ---------- */

async function loadLogs() {
  try {
    const d = await api('/api/logs?n=300');
    const box = $('#logBox');
    const atBottom = box.scrollTop + box.clientHeight >= box.scrollHeight - 40;
    box.innerHTML = (d.lines || []).map(l => {
      const cls = l.level === 'ERROR' ? 'l-error' : l.level === 'WARN' ? 'l-warn' : '';
      const t = String(l.time || '').replace('T', ' ').slice(5, 19);
      return `<span class="${cls}"><span class="l-time">${esc(t)}</span> ${esc(l.msg)}</span>`;
    }).join('\n') || '暂无日志';
    if (atBottom) box.scrollTop = box.scrollHeight;
  } catch (e) { /* 忽略轮询错误 */ }
}

/* ---------- 交互绑定 ---------- */

function switchTab(name) {
  state.tab = name;
  $$('.tabs button').forEach(b => b.classList.toggle('on', b.dataset.tab === name));
  $$('.tab').forEach(s => s.classList.toggle('hidden', s.id !== 'tab-' + name));
  if (location.hash.slice(1) !== name) history.replaceState(null, '', '#' + name);
  if (name === 'logs') loadLogs();
  if (name === 'forward') renderForward();
  if (name === 'acme') renderACME();
  if (name === 'wol') { renderWOL(); renderWOLEdit(); }
  if (name === 'term') TermUI.show();
}

$('#tabs').addEventListener('click', e => {
  const b = e.target.closest('button[data-tab]');
  if (b) switchTab(b.dataset.tab);
});
$$('[data-goto]').forEach(a => a.addEventListener('click', () => switchTab(a.dataset.goto)));

$('#btnLogout').addEventListener('click', async () => {
  try { await api('/api/logout', { method: 'POST' }); } catch (e) {}
  location.reload();
});

/* 规则 */
$('#btnAddRule').addEventListener('click', () => openEditor(-1));
$('#btnCancelRule').addEventListener('click', () => { $('#editor').classList.add('hidden'); });

$('#ruleList').addEventListener('click', e => {
  const ed = e.target.closest('[data-edit]');
  if (ed) return openEditor(+ed.dataset.edit);
  const del = e.target.closest('[data-del]');
  if (del) {
    const i = +del.dataset.del;
    const name = state.config.proxy[i].name;
    if (!confirm('删除规则「' + name + '」？')) return;
    state.config.proxy.splice(i, 1);
    renderRules();
    saveConfig(state.config, $('#ruleErr'));
  }
});

$('#btnSaveRule').addEventListener('click', async () => {
  const r = ruleFromForm();
  const err = $('#ruleErr');
  hide(err);
  if (!r.name) return showErr(err, '请填写名称');
  if (!r.hosts.length) return showErr(err, '请至少填写一个域名');
  if (!r.target) return showErr(err, '请填写上游地址');

  const cfg = collectConfig();
  if (state.editIndex >= 0) cfg.proxy[state.editIndex] = r;
  else cfg.proxy.push(r);

  if (await saveConfig(cfg, err)) $('#editor').classList.add('hidden');
});

/* DDNS */
$('#btnAddRec').addEventListener('click', () => {
  state.config.ddns.records = state.config.ddns.records || [];
  state.config.ddns.records.push({ domain: '', rr: '@', type: 'A' });
  renderRecords();
});

$('#recList').addEventListener('click', e => {
  const b = e.target.closest('[data-delrec]');
  if (!b) return;
  state.config.ddns.records.splice(+b.dataset.delrec, 1);
  renderRecords();
});

$('#btnSaveDDNS').addEventListener('click', () => saveConfig(null, $('#ddnsErr')));

$('#btnTestAK').addEventListener('click', async () => {
  const ok = $('#ddnsOk'), err = $('#ddnsErr');
  hide(ok); hide(err);
  try {
    const d = await api('/api/ddns/test', {
      method: 'POST',
      body: JSON.stringify({
        accessKeyId: $('#d-ak').value.trim(),
        accessKeySecret: $('#d-sk').value.trim(),
      }),
    });
    if (!d.ok) throw new Error(d.error || '验证失败');
    ok.textContent = 'AccessKey 有效，账号下共 ' + d.domains + ' 个域名';
    ok.classList.remove('hidden');
  } catch (e) { showErr(err, e.message); }
});

$('#btnDetectIP').addEventListener('click', async () => {
  const ok = $('#ddnsOk'), err = $('#ddnsErr');
  hide(ok); hide(err);
  try {
    const d = await api('/api/ddns/ip', {
      method: 'POST',
      body: JSON.stringify({
        ipMode: $('#d-mode').value,
        interface: $('#d-iface').value.trim(),
        ipSources: $('#d-sources').value.split(/[\n,，\s]+/).map(s => s.trim()).filter(Boolean),
      }),
    });
    const parts = [];
    if (d.ipv4) parts.push('IPv4: ' + d.ipv4);
    if (d.ipv6) parts.push('IPv6: ' + d.ipv6);
    if (!parts.length) throw new Error(d.error4 || d.error6 || '未检测到公网地址');
    ok.textContent = parts.join('　');
    ok.classList.remove('hidden');
  } catch (e) { showErr(err, e.message); }
});

$('#btnRunDDNS').addEventListener('click', async () => {
  const ok = $('#ddnsOk'), err = $('#ddnsErr');
  hide(ok); hide(err);
  try {
    const d = await api('/api/ddns/run', { method: 'POST' });
    state.status.ddns = d.status;
    renderDDNS();
    if (!d.ok) throw new Error(d.error || '同步失败');
    ok.textContent = '同步完成';
    ok.classList.remove('hidden');
  } catch (e) {
    showErr(err, e.message);
    try {
      const s = await api('/api/status');
      state.status = s;
      renderDDNS();
    } catch (_) {}
  }
});

/* 端口转发 */
$('#btnAddFwd').addEventListener('click', () => {
  state.config.forward = state.config.forward || {};
  state.config.forward.rules = state.config.forward.rules || [];
  state.config.forward.rules.push({ name: '', proto: 'tcp', port: '', toHost: '', toPort: '' });
  renderForwardRules();
});

$('#fwdList').addEventListener('click', e => {
  const b = e.target.closest('[data-delfwd]');
  if (!b) return;
  state.config.forward.rules.splice(+b.dataset.delfwd, 1);
  renderForwardRules();
});

$('#btnSaveFwd').addEventListener('click', async () => {
  const ok = $('#fwdOk'), err = $('#fwdErr');
  hide(ok); hide(err);
  const bad = $$('#fwdList .fw-row').find(r =>
    !r.querySelector('.fw-port').value || !r.querySelector('.fw-host').value || !r.querySelector('.fw-toport').value);
  if (bad) return showErr(err, '有规则没填完整：外网端口、目标地址、目标端口都是必填');
  try {
    await api('/api/config', { method: 'POST', body: JSON.stringify(collectConfig()) });
    const d = await api('/api/forward/apply', { method: 'POST' });
    if (!d.ok) throw new Error(d.error || '下发失败');
    ok.textContent = '已保存并下发：' + d.state.applied + ' 条规则（' + d.state.backend + '）· ' + (d.state.persist || '');
    ok.classList.remove('hidden');
    await loadAll();
  } catch (e) { showErr(err, e.message); toast(e.message, true); }
});

$('#btnApplyFwd').addEventListener('click', async () => {
  const ok = $('#fwdOk'), err = $('#fwdErr');
  hide(ok); hide(err);
  try {
    const d = await api('/api/forward/apply', { method: 'POST' });
    if (!d.ok) throw new Error(d.error || '下发失败');
    ok.textContent = '已重新下发 ' + d.state.applied + ' 条规则（' + d.state.backend + '）';
    ok.classList.remove('hidden');
    await loadAll();
  } catch (e) { showErr(err, e.message); }
});

$('#btnClearFwd').addEventListener('click', async () => {
  if (!confirm('清空内核里的转发规则？面板上的配置会保留，随时可以重新下发。')) return;
  const ok = $('#fwdOk'), err = $('#fwdErr');
  hide(ok); hide(err);
  try {
    const d = await api('/api/forward/clear', { method: 'POST' });
    if (!d.ok) throw new Error(d.error || '清理失败');
    ok.textContent = '内核规则已清空';
    ok.classList.remove('hidden');
    await loadAll();
  } catch (e) { showErr(err, e.message); }
});

/* 自动证书 */
$('#btnSaveACME').addEventListener('click', () => saveConfig(null, $('#acmeErr')));

$('#btnTestACME').addEventListener('click', async () => {
  const ok = $('#acmeOk'), err = $('#acmeErr');
  hide(ok); hide(err);
  try {
    const d = await api('/api/acme/test', {
      method: 'POST',
      body: JSON.stringify({
        accessKeyId: $('#a-ak').value.trim(),
        accessKeySecret: $('#a-sk').value.trim(),
        domains: $('#a-domains').value.split(/[\n,，\s]+/).map(s => s.trim()).filter(Boolean),
      }),
    });
    if (d.rows) {
      const bad = d.rows.filter(r => !r.ok).map(r => r.domain);
      if (bad.length) throw new Error('这些域名在阿里云账号下找不到对应解析：' + bad.join('、'));
      ok.textContent = '检查通过：' + d.rows.map(r => r.domain + ' → ' + r.zone + '（记录名 ' + r.rr + '）').join('；');
      ok.classList.remove('hidden');
      return;
    }
    if (!d.ok) throw new Error(d.error || '检查未通过');
    ok.textContent = '检查通过';
    ok.classList.remove('hidden');
  } catch (e) { showErr(err, e.message); }
});

$('#btnIssueACME').addEventListener('click', async () => {
  if (!confirm('开始签发证书？约需 1~2 分钟，期间可以离开这个页面。')) return;
  const ok = $('#acmeOk'), err = $('#acmeErr');
  hide(ok); hide(err);
  try {
    const d = await api('/api/acme/issue', { method: 'POST' });
    ok.textContent = d.message || '已开始签发';
    ok.classList.remove('hidden');
    setTimeout(refreshStatus, 1500);
  } catch (e) { showErr(err, e.message); }
});

/* 设置 */
$('#btnSaveSettings').addEventListener('click', async () => {
  const before = (state.config.security || {}).entryPath || '';
  const next = $('#s-entry').value.trim();
  if (await saveConfig(null, $('#setErr'))) maybeJumpToEntry(before, next);
});

$('#s-entry').addEventListener('input', renderEntryHint);
$('#s-pubport').addEventListener('input', renderEntryHint);
$('#btnGenEntry').addEventListener('click', randomEntry);

$('#btnReloadCert').addEventListener('click', async () => {
  const ok = $('#setOk'), err = $('#setErr');
  hide(ok); hide(err);
  try {
    await api('/api/config', { method: 'POST', body: JSON.stringify(collectConfig()) });
    const d = await api('/api/reload', { method: 'POST' });
    ok.textContent = '证书已重载：' + (d.names || []).join(', ');
    ok.classList.remove('hidden');
  } catch (e) { showErr(err, e.message); }
});

$('#btnRestart').addEventListener('click', async () => {
  if (!confirm('重启服务？当前正在处理的代理连接会短暂中断。')) return;
  const err = $('#setErr'), ok = $('#setOk');
  hide(err); hide(ok);
  try {
    await api('/api/restart', { method: 'POST' });
    ok.textContent = '正在重启，稍后自动刷新…';
    ok.classList.remove('hidden');
    setTimeout(waitBack, 1500);
  } catch (e) { showErr(err, e.message); }
});

async function waitBack(tries) {
  tries = tries || 0;
  try {
    await api('/api/status');
    location.reload();
  } catch (e) {
    if (tries > 20) {
      showErr($('#setErr'), '服务没有回来，请检查日志或用 SSH 重启');
      return;
    }
    setTimeout(() => waitBack(tries + 1), 800);
  }
}

/* 配置导出 / 导入（zip 备份包，含证书） */
$('#btnExportCfg').addEventListener('click', async () => {
  const err = $('#setErr'), ok = $('#setOk');
  hide(err); hide(ok);
  try {
    const r = await fetch('/api/config/export');
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const blob = await r.blob();
    const cd = r.headers.get('Content-Disposition') || '';
    const m = cd.match(/filename="?([^";]+)"?/);
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = (m && m[1]) || 'lightproxy-backup.zip';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
    ok.textContent = '备份已导出（含配置、证书与私钥，请妥善保管）';
    ok.classList.remove('hidden');
  } catch (e) { showErr(err, '导出失败: ' + e.message); }
});

$('#btnImportCfg').addEventListener('click', () => $('#importFile').click());

$('#importFile').addEventListener('change', async (ev) => {
  const file = ev.target.files && ev.target.files[0];
  ev.target.value = '';
  if (!file) return;
  const err = $('#setErr'), ok = $('#setOk');
  hide(err); hide(ok);
  let buf;
  try { buf = await file.arrayBuffer(); } catch (e) { showErr(err, '读取文件失败: ' + e.message); return; }
  const bytes = new Uint8Array(buf);
  const isZip = bytes.length > 4 && bytes[0] === 0x50 && bytes[1] === 0x4b;

  if (!isZip) {
    // 兼容旧版导出的纯 JSON
    let parsed;
    try { parsed = JSON.parse(new TextDecoder().decode(bytes)); }
    catch (e) { showErr(err, '既不是 zip 备份包，也不是合法的 JSON 文件'); return; }
    if (!confirm('导入将覆盖当前全部配置（面板密码、规则、密钥都会被替换），且立即生效。确定继续？')) return;
    try {
      await api('/api/config/import', { method: 'POST', body: JSON.stringify(parsed) });
      ok.textContent = '配置已导入并生效，正在刷新页面…';
      ok.classList.remove('hidden');
      setTimeout(() => location.reload(), 1200);
    } catch (e) { showErr(err, '导入失败: ' + e.message); }
    return;
  }

  if (!confirm('导入备份包将覆盖当前全部配置与证书，且立即生效。确定继续？')) return;
  try {
    const r = await fetch('/api/config/import', {
      method: 'POST',
      headers: { 'Content-Type': 'application/zip' },
      body: buf,
    });
    if (r.status === 401) { location.reload(); return; }
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
    const n = (d.certs || []).length;
    ok.textContent = '备份已恢复' + (n ? '（含 ' + n + ' 个证书文件）' : '') + '，正在刷新页面…';
    ok.classList.remove('hidden');
    setTimeout(() => location.reload(), 1400);
  } catch (e) { showErr(err, '导入失败: ' + e.message); }
});

$('#btnRefreshLogs').addEventListener('click', loadLogs);

/* ---------- 轮询 ---------- */

async function refreshStatus() {
  try {
    const s = await api('/api/status');
    state.status = s;
    if (state.tab === 'overview') renderOverview();
    if (state.tab === 'ddns') renderDDNS();
    if (state.tab === 'forward') renderForward();
    if (state.tab === 'acme') renderACME();
    return s;
  } catch (e) { return null; }
}

setInterval(() => {
  if (!document.hidden) refreshStatus();
}, 5000);

setInterval(() => {
  if (document.hidden || state.tab !== 'logs') return;
  if ($('#autoLog').checked) loadLogs();
}, 3000);

/* ---------- 启动 ---------- */

const TABS = ['overview', 'proxy', 'forward', 'ddns', 'acme', 'wol', 'term', 'logs', 'settings'];

// 等 term.js 加载完再切初始页：hash 直接指到「终端」时 switchTab 会用到 TermUI
document.addEventListener('DOMContentLoaded', () => {
  const initial = location.hash.slice(1);
  if (TABS.includes(initial)) switchTab(initial);
  loadAll().catch(e => toast('加载失败：' + e.message, true));
});
