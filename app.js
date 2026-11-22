// GeoCheck dashboard. Talks only to the local daemon (docs/API.md); no external services from the browser.
(() => {
'use strict';

const SS_TOKEN = 'geocheck.token';   // sessionStorage only, and only when the user ticks "запомнить на вкладке"
const LS_PREFS = 'geocheck.prefs';    // non-secret settings: urls, sources, repeats, apiBase
const TERMINAL = new Set(['done', 'cancelled', 'failed']);

// Cell statuses from docs/API.md. `tone` drives colour; FAILS are counted as failures (README table).
const STATUS = {
  'ok':             { label: 'ок', tone: 'ok' },
  'slow':           { label: 'медленно', tone: 'warn' },
  'challenge':      { label: 'CF-челлендж', tone: 'block' },
  'blocked':        { label: 'отказ 4xx', tone: 'block' },
  'server-error':   { label: '5xx', tone: 'err' },
  'network-error':  { label: 'обрыв', tone: 'grey' },
  'nginx-503':      { label: 'nginx 503 (антибот)', tone: 'block' },
  'antibot-passed': { label: 'антибот: Send ок', tone: 'ok' },
  'antibot-failed': { label: 'антибот: Send не прошёл', tone: 'err' },
  'domain-down':    { label: 'домен не грузится', tone: 'grey' },
  'exit-down':      { label: 'выход не работает', tone: 'dead' },
  'pending':        { label: '…', tone: 'pending' },
};
const FAILS = new Set(['slow', 'challenge', 'blocked', 'server-error', 'network-error', 'antibot-failed', 'domain-down']);

// Symptom text per dominant failure, taken from the README symptom table.
const SYMPTOMS = {
  'challenge':     '403 с cf-mitigated: CloudFlare-челлендж (бот-блок по гео, ASN или репутации IP)',
  'server-error':  '5xx с CF-RAY: origin не отвечает или CF обрывает сессию',
  'network-error': 'обрыв на TCP/TLS: режется сеть или выход, до CF не дошли',
  'blocked':       '4xx-отказ: гео-политика CF или блок по ASN',
  'slow':          'страница грузится дольше порога: медленный путь или перегруженный origin',
  'antibot-failed':'заглушка антибота: после Send страница не открылась',
  'domain-down':   'корень домена не открылся, страницы не проверялись',
};
const SOURCE_LABEL = { local: 'демон', 'check-host': 'check-host', globalping: 'GlobalPing', browser: 'браузер' };

const st = {
  token: '', base: '', jobId: null, job: null, timer: null, pollFails: 0,
  connected: false, view: 'results',
};

const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtMs = ms => (ms == null ? '' : ms >= 1000 ? (ms / 1000).toFixed(1) + ' с' : Math.round(ms) + ' мс');
const shortUrl = u => { try { const x = new URL(u); return x.host + (x.pathname === '/' ? '' : x.pathname); } catch { return u; } };
const clampInt = (v, lo, hi, d) => { const n = parseInt(v, 10); return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : d; };

class ApiError extends Error {
  constructor(kind, msg) { super(msg); this.kind = kind; }
}

async function api(path, opts = {}) {
  const headers = { Accept: 'application/json' };
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
  if (path !== '/api/health') headers['X-RG-Token'] = st.token;
  let r;
  try {
    r = await fetch(st.base + path, {
      method: opts.method || 'GET', body: opts.body, headers, cache: 'no-store',
      signal: AbortSignal.timeout(opts.timeout || 15000),
    });
  } catch {
    throw new ApiError('network', 'демон не отвечает');
  }
  if (r.status === 401) throw new ApiError('auth', 'токен не принят демоном');
  if (!r.ok) {
    let msg = 'HTTP ' + r.status;
    try { msg = (await r.json()).error || msg; } catch { /* keep HTTP status */ }
    throw new ApiError('http', msg);
  }
  return r.json();
}

/* ---------- connection ---------- */

function setConn(tone, text) {
  const el = $('daemonState');
  el.className = 'conn conn-' + tone;
  el.textContent = text;
}

function setNotice(text, tone = '') {
  const el = $('notice');
  el.className = 'notice ' + (tone ? 'n-' + tone : '');
  el.textContent = text;
}

function setButtons() {
  const running = !!st.jobId;
  $('btnStart').disabled = !st.connected || running;
  $('btnCancel').disabled = !running;
  const hasJob = !!st.job;
  $('btnCsv').disabled = !hasJob;
  $('btnJson').disabled = !hasJob;
}

async function connect() {
  st.token = $('token').value.trim();
  st.base = $('apiBase').value.trim().replace(/\/+$/, '');
  if (st.token && $('rememberToken').checked) sessionStorage.setItem(SS_TOKEN, st.token);
  else sessionStorage.removeItem(SS_TOKEN);
  savePrefs();
  st.connected = false; setButtons();
  if (!st.token) { setConn('grey', 'нужен токен'); return; }
  setConn('grey', 'проверяю…');
  try {
    await api('/api/health');
    const { exits } = await api('/api/exits');
    st.connected = true;
    const up = exits.filter(e => e.status === 'up').length;
    const down = exits.filter(e => e.status === 'down').length;
    setConn('ok', `демон на связи · выходов: ${up} работают${down ? ', ' + down + ' не работают' : ''}`);
    if (!st.job) renderDeadExits(exits);
  } catch (e) {
    setConn('err', e.kind === 'auth' ? 'токен не принят' : e.message);
  }
  setButtons();
}

/* ---------- start, poll, cancel ---------- */

function parseUrls(text) {
  const out = [];
  for (const raw of text.split(/\r?\n/)) {
    const u = raw.trim();
    if (u && !out.includes(u)) out.push(u);
  }
  return out;
}

async function startJob() {
  const urls = parseUrls($('urls').value);
  if (!urls.length) return setNotice('введите хотя бы один адрес', 'err');
  for (const u of urls) {
    let ok = false;
    try { const x = new URL(u); ok = x.protocol === 'http:' || x.protocol === 'https:'; } catch { /* not a URL */ }
    if (!ok) return setNotice('не похоже на адрес http(s): ' + u, 'err');
  }
  if (urls.length > 50) return setNotice('не больше 50 адресов за один прогон', 'err');
  const sources = {
    localExits: $('srcLocal').checked, checkHost: $('srcCheckHost').checked,
    globalPing: $('srcGlobalPing').checked, browser: $('srcBrowser').checked,
  };
  if (!Object.values(sources).some(Boolean)) return setNotice('выберите хотя бы один источник', 'err');
  const body = {
    urls, sources,
    repeats: clampInt($('repeats').value, 1, 3, 3),
    domainFirst: $('domainFirst').checked,
    maxNodes: clampInt($('maxNodes').value, 5, 40, 20),
  };
  savePrefs();
  setNotice('');
  try {
    const r = await api('/api/jobs', { method: 'POST', body: JSON.stringify(body) });
    st.job = null;
    st.jobId = r.id;
    st.pollFails = 0;
    setButtons();
    setNotice('проверка поставлена в очередь', 'ok');
    tick();
  } catch (e) {
    setNotice('не запустилось: ' + e.message, 'err');
  }
}

async function cancelJob() {
  if (!st.jobId) return;
  $('btnCancel').disabled = true;
  try {
    await api(`/api/jobs/${encodeURIComponent(st.jobId)}/cancel`, { method: 'POST' });
    setNotice('отмена отправлена, частичные результаты сохранятся');
  } catch (e) {
    setNotice('отмена не прошла: ' + e.message, 'err');
    $('btnCancel').disabled = false;
  }
}

async function tick() {
  clearTimeout(st.timer);
  const id = st.jobId;
  if (!id) return;
  try {
    const job = await api(`/api/jobs/${encodeURIComponent(id)}`);
    if (id !== st.jobId) return;            // another job was started meanwhile
    st.pollFails = 0;
    st.job = job;
    render();
    if (TERMINAL.has(job.state)) return finish(job);
  } catch (e) {
    if (id !== st.jobId) return;
    st.pollFails++;
    setNotice(`опрос не удался (${st.pollFails}/5): ${e.message}`, 'err');
    if (st.pollFails >= 5 || e.kind === 'auth') {
      st.jobId = null; setButtons();
      return;
    }
  }
  st.timer = setTimeout(tick, 1500);
}

function finish(job) {
  st.jobId = null;
  setButtons();
  const map = {
    done: ['готово: прогон завершён', 'ok'],
    cancelled: ['отменено: сохранены частичные результаты', 'warn'],
    failed: ['ошибка: ' + (job.error || 'причина не указана'), 'err'],
  };
  const [text, tone] = map[job.state] || ['завершено', ''];
  setNotice(text, tone);
  renderProgress(job);
}

/* ---------- derived data ---------- */

function buildRows(job) {
  const map = new Map();
  for (const e of job.exits || []) {
    map.set(`${e.source}|${e.id}`, { key: `${e.source}|${e.id}`, label: e.label || e.id, country: e.country, source: e.source, exitIp: e.exitIp, status: e.status || 'unknown' });
  }
  for (const c of job.results || []) {
    const key = `${c.source}|${c.exitId}`;
    if (!map.has(key)) map.set(key, { key, label: c.exitLabel || c.exitId, country: c.country, source: c.source, exitIp: c.exitIp, status: 'unknown' });
  }
  const rows = [...map.values()];
  rows.sort((a, b) => (a.status === 'down') - (b.status === 'down') || a.source.localeCompare(b.source) || a.label.localeCompare(b.label));
  return rows;
}

function cellIndex(job) {
  const idx = new Map();
  for (const c of job.results || []) idx.set(c.url + '\n' + c.source + '|' + c.exitId, c);
  return idx;
}

function verdictFor(job, url, rows, idx) {
  const liveRows = rows.filter(r => r.status !== 'down');
  const cells = liveRows.map(r => idx.get(url + '\n' + r.key)).filter(Boolean);
  const live = cells.filter(c => c.status !== 'pending' && c.status !== 'exit-down');
  const dead = rows.filter(r => r.status === 'down').length;
  const running = !!st.jobId;
  if (!live.length) {
    return { tone: 'muted', head: running ? 'считается…' : 'нет измерений', detail: dead ? `${dead} выходов не работают — в вердикт не входят` : '', counts: {} };
  }
  const counts = {};
  for (const c of live) counts[c.status] = (counts[c.status] || 0) + 1;
  const fails = live.filter(c => FAILS.has(c.status));
  const extra = [];
  if (dead) extra.push(`${dead} выход(ов) не работают — вне вердикта`);
  if (counts['nginx-503']) extra.push(`nginx 503 у ${counts['nginx-503']}: жёсткий антибот, сбоем не считается`);
  if (!fails.length) {
    return { tone: 'ok', head: `доступен: ${live.length} замеров без сбоя`, detail: extra.join('; '), counts };
  }
  const dominant = Object.keys(counts).filter(s => FAILS.has(s)).sort((a, b) => counts[b] - counts[a])[0];
  let detail = SYMPTOMS[dominant] || '';
  const failC = [...new Set(fails.map(c => c.country).filter(Boolean))];
  const okC = [...new Set(live.filter(c => !FAILS.has(c.status)).map(c => c.country).filter(Boolean))];
  const geoLike = dominant === 'challenge' || dominant === 'blocked';
  if (geoLike && failC.length && okC.length && !failC.some(c => okC.includes(c))) {
    detail += `. Проходит в ${okC.join(', ')}, не проходит в ${failC.join(', ')}: похоже на гео-политику`;
  }
  if (extra.length) detail += '. ' + extra.join('; ');
  const share = fails.length / live.length;
  return {
    tone: share >= 0.5 ? 'err' : 'warn',
    head: `сбои: ${fails.length} из ${live.length} замеров`,
    detail, counts,
  };
}

/* ---------- rendering ---------- */

function renderProgress(job) {
  const p = job.progress || { done: 0, total: 0 };
  const pct = p.total ? Math.min(100, Math.round(p.done * 100 / p.total)) : (TERMINAL.has(job.state) ? 100 : 0);
  $('progBar').style.width = pct + '%';
  const stateTxt = { queued: 'в очереди', running: 'идёт', done: 'готово', cancelled: 'отменено', failed: 'ошибка' }[job.state] || job.state;
  $('progText').textContent = `${stateTxt}: ${p.done ?? 0} из ${p.total ?? 0}${p.stage ? ' · ' + p.stage : ''}`;
}

function renderDeadExits(exits) {
  const box = $('deadExits');
  const down = (exits || []).filter(e => e.status === 'down');
  if (!down.length) { box.classList.add('hidden'); box.innerHTML = ''; return; }
  box.classList.remove('hidden');
  box.innerHTML = `<h3>Выходы не работают: ${down.length} (контрольный сайт не открылся, в вердикты не входят)</h3>` +
    '<ul>' + down.map(e => `<li><b>${esc(e.label || e.id)}</b> ${esc(e.country || '')} ${e.lastError ? '<span class="muted">· ' + esc(e.lastError) + '</span>' : ''}</li>`).join('') + '</ul>';
}

function renderVerdicts(job, rows, idx) {
  const el = $('verdicts');
  if (!job.urls || !job.urls.length) { el.innerHTML = ''; return; }
  el.innerHTML = job.urls.map(url => {
    const v = verdictFor(job, url, rows, idx);
    const chips = Object.entries(v.counts).map(([s, n]) => `<span class="chip chip-${STATUS[s]?.tone || 'grey'}">${esc(STATUS[s]?.label || s)} ${n}</span>`).join('');
    return `<article class="verdict v-${v.tone}">
      <h3 title="${esc(url)}">${esc(shortUrl(url))}</h3>
      <p class="v-head">${esc(v.head)}</p>
      ${v.detail ? `<p class="v-detail">${esc(v.detail)}</p>` : ''}
      <div class="chips">${chips}</div>
    </article>`;
  }).join('');
}

function cellHtml(c, job) {
  if (!c) {
    const txt = job.state && TERMINAL.has(job.state) ? '—' : '…';
    return `<td class="cell st-pending" title="не измерено"><span class="cl">${txt}</span></td>`;
  }
  const meta = STATUS[c.status] || { label: c.status, tone: 'grey' };
  const sub = [c.code ? c.code : '', c.ms != null ? fmtMs(c.ms) : ''].filter(Boolean).join(' · ');
  const reps = (c.repeats || []).map(r => `${r.code || '—'} ${fmtMs(r.ms) || ''} ${STATUS[r.status]?.label || r.status}`).join(' | ');
  const title = [reps && 'повторы: ' + reps, c.cfRay && 'CF-RAY ' + c.cfRay, c.note, c.error].filter(Boolean).join(' · ');
  return `<td class="cell st-${meta.tone}" title="${esc(title)}"><span class="cl">${esc(meta.label)}</span>${sub ? `<small>${esc(sub)}</small>` : ''}</td>`;
}

function renderMatrix(job, rows, idx) {
  const t = $('matrix');
  if (!job.urls || !job.urls.length) { t.innerHTML = '<tr><td class="empty">здесь появятся результаты после запуска</td></tr>'; return; }
  const head = '<thead><tr><th scope="col">выход</th>' +
    job.urls.map(u => `<th scope="col" title="${esc(u)}">${esc(shortUrl(u))}</th>`).join('') + '</tr></thead>';
  const live = rows.filter(r => r.status !== 'down');
  const dead = rows.filter(r => r.status === 'down');
  const rowHtml = r => `<tr class="${r.status === 'down' ? 'dead-row' : ''}"><th scope="row">${esc(r.label)}<small>${esc(r.country || '')} · ${esc(SOURCE_LABEL[r.source] || r.source)}${r.exitIp ? ' · ' + esc(r.exitIp) : ''}</small></th>` +
    job.urls.map(u => cellHtml(idx.get(u + '\n' + r.key), job)).join('') + '</tr>';
  let body = live.map(rowHtml).join('');
  if (dead.length) {
    body += `<tr class="group"><th colspan="${job.urls.length + 1}">выходы не работают: не входят в вердикт</th></tr>`;
    body += dead.map(r => rowHtml({ ...r, status: 'down' })).join('');
  }
  if (!live.length && !dead.length) body = `<tr><td class="empty" colspan="${job.urls.length + 1}">выходов пока нет</td></tr>`;
  t.innerHTML = head + '<tbody>' + body + '</tbody>';
}

function renderMirrors(job, rows, idx) {
  const el = $('mirrors');
  if (!job.urls || job.urls.length < 2) {
    el.innerHTML = '<p class="empty">Добавьте два и больше адресов-зеркал (например .com, ru. и .ru), чтобы увидеть расхождения.</p>';
    return;
  }
  const live = rows.filter(r => r.status !== 'down');
  let diverge = 0;
  const body = live.map(r => {
    const cells = job.urls.map(u => idx.get(u + '\n' + r.key));
    const measured = cells.filter(c => c && c.status !== 'pending' && c.status !== 'exit-down');
    const flags = new Set(measured.map(c => FAILS.has(c.status)));
    const div = flags.size > 1;
    if (div) diverge++;
    return `<tr class="${div ? 'diverge' : ''}"><th scope="row">${esc(r.label)}<small>${esc(r.country || '')} · ${esc(SOURCE_LABEL[r.source] || r.source)}</small></th>` +
      cells.map(c => cellHtml(c, job)).join('') +
      `<td class="flag">${div ? 'расходятся' : (measured.length ? 'одинаково' : '')}</td></tr>`;
  }).join('');
  el.innerHTML = `<p class="v-head">Расходятся на ${diverge} из ${live.length} выходов: одно зеркало открывается, другое нет. Такие строки подсвечены.</p>
    <div class="table-wrap"><table aria-label="сравнение зеркал"><thead><tr><th scope="col">выход</th>` +
    job.urls.map(u => `<th scope="col" title="${esc(u)}">${esc(shortUrl(u))}</th>`).join('') +
    '<th scope="col">итог</th></tr></thead><tbody>' + body + '</tbody></table></div>';
}

function render() {
  const job = st.job;
  if (!job) return;
  renderProgress(job);
  const rows = buildRows(job);
  const idx = cellIndex(job);
  renderDeadExits(job.exits || []);
  renderVerdicts(job, rows, idx);
  renderMatrix(job, rows, idx);
  renderMirrors(job, rows, idx);
  setButtons();
}

async function renderHistory() {
  const el = $('history');
  el.innerHTML = '<p class="empty">загружаю…</p>';
  try {
    const { jobs } = await api('/api/history?limit=50');
    if (!jobs.length) { el.innerHTML = '<p class="empty">прогонов пока нет</p>'; return; }
    el.innerHTML = '<ul class="hist-list">' + jobs.map(j => {
      const s = j.summary || {};
      const when = j.createdAt ? new Date(j.createdAt).toLocaleString() : '';
      const stateTxt = { done: 'готово', cancelled: 'отменено', failed: 'ошибка', running: 'идёт', queued: 'в очереди' }[j.state] || j.state;
      return `<li><button class="hist-item" data-id="${esc(j.id)}">
        <span class="hi-when">${esc(when)}</span>
        <span class="hi-urls">${esc((j.urls || []).map(shortUrl).join(', '))}</span>
        <span class="hi-meta">${esc(stateTxt)}${s.cells != null ? ` · замеров ${s.cells}, сбоев ${s.failures ?? 0}` : ''}</span></button></li>`;
    }).join('') + '</ul>';
  } catch (e) {
    el.innerHTML = `<p class="empty">история недоступна: ${esc(e.message)}</p>`;
  }
}

async function loadJob(id) {
  setNotice('открываю прогон…');
  try {
    const job = await api(`/api/history/${encodeURIComponent(id)}`);
    st.jobId = null;
    st.job = job;
    setNotice('прогон открыт из истории', 'ok');
    showView('results');
    render();
  } catch (e) {
    setNotice('не открылось: ' + e.message, 'err');
  }
}

function showView(name) {
  st.view = name;
  document.querySelectorAll('.tab').forEach(b => {
    const on = b.dataset.view === name;
    b.classList.toggle('active', on);
    b.setAttribute('aria-selected', on ? 'true' : 'false');
  });
  document.querySelectorAll('.view').forEach(v => v.classList.toggle('hidden', v.id !== 'view-' + name));
  if (name === 'history') renderHistory();
  if (name === 'mirrors' && st.job) render();
}

/* ---------- export ---------- */

function csvCell(v) {
  let s = v == null ? '' : String(v);
  if (/^[=+\-@]/.test(s)) s = "'" + s;   // keep spreadsheets from running formulas
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement('a');
  a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function exportCsv() {
  const job = st.job; if (!job) return;
  const cols = ['url', 'source', 'exit_id', 'exit_label', 'country', 'exit_ip', 'status', 'code', 'ms', 'error_class', 'cf_ray', 'cf_mitigated', 'repeats', 'note'];
  const lines = [cols.join(',')];
  for (const c of job.results || []) {
    const reps = (c.repeats || []).map(r => `${r.status}:${r.code ?? ''}`).join(' | ');
    lines.push([c.url, c.source, c.exitId, c.exitLabel, c.country, c.exitIp, c.status, c.code, c.ms, c.errorClass, c.cfRay, c.cfMitigated, reps, c.note]
      .map(csvCell).join(','));
  }
  download(`geocheck-${job.id}.csv`, '﻿' + lines.join('\r\n') + '\r\n', 'text/csv;charset=utf-8');
}

function exportJson() {
  const job = st.job; if (!job) return;
  download(`geocheck-${job.id}.json`, JSON.stringify(job, null, 2), 'application/json');
}

/* ---------- prefs and boot ---------- */

function savePrefs() {
  const prefs = {
    urls: $('urls').value,
    sources: { localExits: $('srcLocal').checked, checkHost: $('srcCheckHost').checked, globalPing: $('srcGlobalPing').checked, browser: $('srcBrowser').checked },
    domainFirst: $('domainFirst').checked,
    repeats: $('repeats').value, maxNodes: $('maxNodes').value,
    apiBase: $('apiBase').value,
  };
  try { localStorage.setItem(LS_PREFS, JSON.stringify(prefs)); } catch { /* storage full or disabled */ }
}

function loadPrefs() {
  let p = {};
  try { p = JSON.parse(localStorage.getItem(LS_PREFS)) || {}; } catch { /* ignore */ }
  if (p.urls != null) $('urls').value = p.urls;
  const s = p.sources || {};
  if (s.localExits != null) $('srcLocal').checked = !!s.localExits;
  if (s.checkHost != null) $('srcCheckHost').checked = !!s.checkHost;
  if (s.globalPing != null) $('srcGlobalPing').checked = !!s.globalPing;
  if (s.browser != null) $('srcBrowser').checked = !!s.browser;
  if (p.domainFirst != null) $('domainFirst').checked = !!p.domainFirst;
  if (p.repeats != null) $('repeats').value = p.repeats;
  if (p.maxNodes != null) $('maxNodes').value = p.maxNodes;
  if (p.apiBase != null) $('apiBase').value = p.apiBase;
}

function init() {
  loadPrefs();
  const saved = sessionStorage.getItem(SS_TOKEN);
  if (saved) { $('token').value = saved; $('rememberToken').checked = true; }

  $('btnConnect').addEventListener('click', connect);
  $('token').addEventListener('keydown', e => { if (e.key === 'Enter') connect(); });
  $('btnStart').addEventListener('click', startJob);
  $('btnCancel').addEventListener('click', cancelJob);
  $('btnCsv').addEventListener('click', exportCsv);
  $('btnJson').addEventListener('click', exportJson);
  document.querySelectorAll('.tab').forEach(b => b.addEventListener('click', () => showView(b.dataset.view)));
  $('history').addEventListener('click', e => {
    const b = e.target.closest('.hist-item');
    if (b) loadJob(b.dataset.id);
  });
  ['urls', 'srcLocal', 'srcCheckHost', 'srcGlobalPing', 'srcBrowser', 'domainFirst', 'repeats', 'maxNodes', 'apiBase']
    .forEach(id => $(id).addEventListener('change', savePrefs));

  setButtons();
  if (saved) connect(); else setConn('grey', 'нужен токен');
}

init();
})();
