'use strict';
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
let PUBLIC = false, DATA = null;
const sortKey = { tTargets: 'target', tExits: 'availability' };
const sortDir = { tTargets: 1, tExits: -1 };

async function dFetch(path, retried) {
  const h = {}; let t = '';
  try { t = sessionStorage.getItem('rg.token') || ''; } catch { }
  if (t) h['X-RG-Token'] = t;
  const r = await fetch(path, { headers: h });
  if (r.status === 401 && !PUBLIC && !retried) {
    const v = prompt('Токен демона (пароль закрытой страницы):');
    if (v) { try { sessionStorage.setItem('rg.token', v.trim()); } catch { } return dFetch(path, true); }
  }
  return r;
}
const cls = p => p == null ? 'p-na' : p >= 95 ? 'p-ok' : p >= 70 ? 'p-mid' : 'p-bad';
const pct = p => `<span class="pct ${cls(p)}">${p == null ? '—' : p + '%'}</span>`;
const ms = v => v == null ? '—' : (v >= 1000 ? (v / 1000).toFixed(2) + ' с' : v + ' мс');
const when = ts => ts ? new Date(ts * 1000).toLocaleString('ru-RU') : '—';
const short = u => u.replace(/^https?:\/\//, '').replace(/\/$/, '');

function sorted(rows, id) {
  const k = sortKey[id], d = sortDir[id];
  return rows.slice().sort((a, b) => {
    const x = a[k], y = b[k];
    if (x == null && y == null) return 0;
    if (x == null) return 1;
    if (y == null) return -1;
    return (x > y ? 1 : x < y ? -1 : 0) * d;
  });
}
function head(id, cols) {
  return '<tr>' + cols.map(([k, t]) => `<th data-t="${id}" data-k="${k}">${t}${sortKey[id] === k ? (sortDir[id] > 0 ? ' ▲' : ' ▼') : ''}</th>`).join('') + '</tr>';
}
function render() {
  const d = DATA; if (!d) return;
  document.getElementById('meta').textContent = `прогонов в выборке: ${d.runs}`;
  document.getElementById('tTargets').innerHTML =
    head('tTargets', [['target', 'Ресурс'], ['availability', 'Доступность'], ['avgMs', 'Средний отклик'], ['checks', 'Замеров'], ['fail', 'Сбоев'], ['last', 'Последняя проверка']]) +
    sorted(d.targets, 'tTargets').map(t => `<tr><td>${esc(short(t.target))}${t.active ? '' : '<span class="tag">сейчас не проверяется</span>'}</td><td>${pct(t.availability)}</td><td class="n">${ms(t.avgMs)}</td><td class="n">${t.checks}</td><td class="n">${t.fail}</td><td>${when(t.last)}</td></tr>`).join('');
  document.getElementById('tExits').innerHTML =
    head('tExits', [['label', 'Выход'], ['availability', 'Доступность'], ['avgMs', 'Средний отклик'], ['checks', 'Замеров'], ['down', 'Выход не отвечал'], ['last', 'Последняя проверка']]) +
    sorted(d.exits, 'tExits').map(e => `<tr><td>${esc(e.label)}</td><td>${pct(e.availability)}</td><td class="n">${ms(e.avgMs)}</td><td class="n">${e.checks}</td><td class="n">${e.down}</td><td>${when(e.last)}</td></tr>`).join('');
  const exits = d.exits.map(e => e.label), targets = d.targets.map(t => t.target);
  const idx = {};
  d.matrix.forEach(c => { idx[c.target + '\n' + c.exit] = c; });
  document.getElementById('tMatrix').innerHTML =
    '<tr><th>Выход \\ ресурс</th>' + targets.map(t => `<th title="${esc(t)}">${esc(short(t))}</th>`).join('') + '</tr>' +
    exits.map(e => '<tr><td>' + esc(e) + '</td>' + targets.map(t => {
      const c = idx[t + '\n' + e];
      return '<td>' + (c && c.checks ? pct(c.availability) + ' <span class="tag">' + ms(c.avgMs) + '</span>' : '<span class="pct p-na">нет данных</span>') + '</td>';
    }).join('') + '</tr>').join('');
}
document.addEventListener('click', e => {
  const th = e.target.closest('th[data-t]');
  if (!th) return;
  const id = th.dataset.t, k = th.dataset.k;
  if (sortKey[id] === k) sortDir[id] *= -1; else { sortKey[id] = k; sortDir[id] = k === 'availability' ? -1 : 1; }
  render();
});
async function load() {
  const days = document.getElementById('days').value;
  try {
    const r = await dFetch('/stats' + (days ? '?days=' + days : ''));
    DATA = await r.json();
    if (!DATA.ok) throw new Error(DATA.error || r.status);
  } catch (e) { document.getElementById('meta').textContent = 'не удалось загрузить: ' + (e.message || e); return; }
  render();
  loadErrors(days);
}
const KIND = { nginx: '🛑 NGINX 503', unreachable: '⛔ недоступна', exit_down: 'выход не отвечал', http: 'ошибка HTTP' };
async function loadErrors(days) {
  const el = document.getElementById('tErrors');
  try {
    const j = await (await dFetch('/errors' + (days ? '?days=' + days : ''))).json();
    const rows = (j.errors || []).map(e => `<tr><td>${when(e.at)}</td><td>${esc(short(e.target))}</td><td>${esc(e.exit)}</td><td>${esc(e.exitIp || '—')}${e.exitLoc ? ' · ' + esc(e.exitLoc) : ''}</td><td>${KIND[e.kind] || e.kind}${e.code ? ' ' + e.code : ''}</td><td>${esc(e.note)}</td></tr>`).join('');
    el.innerHTML = '<tr><th>Время</th><th>Ресурс</th><th>Выход</th><th>IP выхода · страна</th><th>Что случилось</th><th>Причина</th></tr>' +
      (rows || '<tr><td colspan="6">ошибок нет</td></tr>');
  } catch (e) { el.innerHTML = '<tr><td>не удалось загрузить журнал</td></tr>'; }
}
document.getElementById('days').onchange = load;
(async () => {
  try { PUBLIC = !!(await (await fetch('/api/health')).json()).public; } catch { }
  document.body.classList.toggle('public', PUBLIC);
  load();
})();
