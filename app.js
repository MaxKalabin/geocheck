/* GeoCheck — логика дашборда.
 * Внешние проверки: check-host.net API + GlobalPing API (из браузера, при неудаче — через демон).
 * Локальные: демон 127.0.0.1 (daemon/checkdaemon.py) + браузерный no-cors пробник.
 * Секреты (подписки) никогда не сохраняются; закрытая страница ходит к демону с токеном (X-RG-Token).
 *
 * Модель: lastModel = {at, domains, groups:[{id,title,rows:[{key,title,sub,cells:{di:cell},isMsg?}]}]}
 * Выбор: rowSel {key:{c,f}}, domSel [0/1], hideUnchecked — в localStorage.
 */
'use strict';

const LS_KEY = 'geocheck.settings.v2';
const LS_HISTORY = 'geocheck.history.v1';
const LS_LAST = 'geocheck.lastrun.v1';
const LS_SEL = 'geocheck.sel.v1';
const DEFAULTS = {
  domains: [
    'https://ru.restaurantguru.com/',
    'https://restaurantguru.ru/',
    'https://restaurantguru.com/',
  ],
  useCheckHost: true,
  useGlobalPing: true,
  useBrowser: true,
  domainFirst: true,
  slowMs: 10000,
  maxNodes: 30,
  daemonPort: 8787,
  exitLabels: ['Этот ПК (системный канал)'],
};

let PUBLIC = false;      // открыто снаружи: настройки, подписки, прогрев скрыты
let settings = loadSettings();
let runSeq = 0;
let daemonExits = [];
let lastModel = null;
let lastAt = null;
let spin = { local: false, ch: false, gp: false };
let rowSel = {}, domSel = null, hideUnchecked = false, grpCol = {};
let hideOkGlobal = false, grpHideOk = {};
let grpDeadOpen = {};        // развёрнут ли блок «недоступные ноды» (сессия)
let deletedRows = new Set(); // ноды, удалённые пользователем — не возвращаем
let openDetailKey = null;   // какая нода сейчас раскрыта (детали строкой под ней)
try {
  const s = JSON.parse(localStorage.getItem(LS_SEL) || '{}');
  rowSel = s.rowSel || {};
  domSel = s.domSel || null;
  hideUnchecked = !!s.hideUnchecked;
  grpCol = s.grpCol || {};
  hideOkGlobal = !!s.hideOkGlobal;
  grpHideOk = s.grpHideOk || {};
  deletedRows = new Set(s.deletedRows || []);
} catch { }

/* ---------------- утилиты ---------------- */
function loadSettings() {
  try {
    const s = JSON.parse(localStorage.getItem(LS_KEY));
    return { ...DEFAULTS, ...s, domains: (s && s.domains || DEFAULTS.domains).filter(Boolean) };
  } catch { return { ...DEFAULTS }; }
}
function saveSettings() { localStorage.setItem(LS_KEY, JSON.stringify(settings)); }
function shortDomain(u) {
  try { const p = new URL(u); return p.host + (p.pathname !== '/' ? p.pathname : ''); }
  catch { return u; }
}
function normUrl(u) { u = String(u || '').trim(); return !u ? '' : (/^[a-z][a-z0-9+.-]*:\/\//i.test(u) ? u : 'https://' + u); }
function esc(s) { return String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }
const RED_MS = 30000;   // дольше — красный; от slowMs (10 с) до этого — жёлтый
function cellClass(code, c) {
  if (c && c.hardBlock) return 'bad';
  if (c && c.antibot) return (c.captcha === 'failed' || c.ms > RED_MS) ? 'bad' : 'warn';
  if (c && c.engine === 'browser' && code && c.ms > RED_MS) return 'bad';
  if (c && c.engine === 'browser' && code && c.ms > settings.slowMs) return 'warn';
  if (!code) return 'err';
  if (code >= 200 && code < 300) return 'ok';
  if (code >= 300 && code < 400) return 'redir';
  if (code >= 400 && code < 500) return 'warn';
  if (code >= 500) return 'bad';
  return 'err';
}
function isFailed(c) { return !c || (!c.hardBlock && (!c.code || c.code >= 500 || (c.antibot && c.captcha === 'failed') || (c.engine === 'browser' && c.ms > RED_MS))); }
function cellText(code, ms, note, c) {
  if (c && c.hardBlock) return '⛔ NGINX 503';
  if (c && c.antibot && c.captcha === 'failed') return '🛡 Send не прошёл';
  if (c && c.antibot) return `🛡 Send · ${((c.ms || 0) / 1000).toFixed(1)}s`;
  if (c && c.skipped) return 'домен не грузится';
  if (c && c.engine === 'browser' && code && ms > settings.slowMs) return `${code} · ${ms > RED_MS ? 'очень медленно' : 'медленно'} ${(ms / 1000).toFixed(1)}s`;
  if (!code) return `ERR${note ? ' · ' + note : ''}`;
  const sec = (ms == null || isNaN(ms)) ? '' : ` · ${(ms / 1000).toFixed(2)}s`;
  const tag = code === 403 ? ' ⚠CF' : '';
  return `${code}${tag}${sec}`;
}
/* кто отдал ошибку: cf-ray есть — фронт CloudFlare (отсечение на CDN), нет — сам сайт */
function errorOrigin(c) {
  if (!c || !c.code) return '';
  return c.cfRay ? 'cf' : 'origin';
}
function verdict(code, c) {
  if (c && c.hardBlock) return 'жёсткий антибот сайта: nginx 503 Service Temporarily Unavailable — обходить нельзя, это не заглушка со Send';
  if (c && c.antibot) return c.captcha === 'failed' ? 'заглушка со Send: после нажатия страница не открылась' : `заглушка со Send пройдена одним нажатием: заглушка ${((c.msLanding||0)/1000).toFixed(1)}s + загрузка после Send ${((c.msAfterCaptcha||0)/1000).toFixed(1)}s = ${((c.ms||0)/1000).toFixed(1)}s`;
  if (c && c.skipped) return c.note;
  if (c && c.engine === 'browser' && !c.code) return c.note || 'страница не грузится';
  if (c && c.engine === 'browser' && c.ms > settings.slowMs) return `загрузилась, но очень долго: ${(c.ms / 1000).toFixed(1)} с (порог ${settings.slowMs / 1000} с)`;
  const byCf = errorOrigin(c) === 'cf';
  if (!code) return 'обрыв соединения / таймаут — нода или сеть недоступны';
  if (code >= 200 && code < 300) return 'ок';
  if (code >= 300 && code < 400) return 'редирект';
  if (code === 403) return byCf
    ? 'доступ запрещён фронтом CloudFlare — челлендж/бот-блок по IP/ASN; сам VPN жив, отсечение на CDN'
    : 'доступ запрещён самим сайтом';
  if (code >= 500) return byCf
    ? `${code} отдал фронт CloudFlare (cf-ray есть) — отсечение на CDN по IP/ASN; VPN не виноват, сайт может быть жив`
    : `${code} отдал сам сайт (ориджин, cf-ray отсутствует) — сервер недоступен или перегружен`;
  return byCf ? 'клиентская ошибка от фронта CloudFlare' : 'клиентская ошибка от сайта';
}

/* бейдж рядом с кодом: CF = ошибку отдал CloudFlare, «сайт» = ориджин (только где сняты заголовки) */
function cellBadge(c, key) {
  if (!c || !c.code || c.code < 400) return '';
  if (c.cfRay)
    return ' <span class="cfbadge" title="ошибку отдал фронт CloudFlare (cf-ray есть) — отсечение на CDN, VPN жив">CF</span>';
  if (key.startsWith('daemon:') || key.startsWith('gp:') || key === 'local-browser')
    return ' <span class="orgbadge" title="ошибку отдал сам сайт (ориджин) — cf-ray не выставлен">сайт</span>';
  return '';
}

/* ---------------- журнал выполнения ---------------- */
function setAction(t) {
  const el = document.getElementById('lastAction');
  if (el) el.textContent = t;
}
/* живой лоадер: крутилка + секунды, пока идёт прогон (пробники ждут до 60с) */
let runTick = null;
const SPIN_CHARS = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏';
let spinIdx = 0;
function startRunIndicator(label) {
  stopRunIndicator();
  const t0 = Date.now();
  runTick = setInterval(() => {
    const el = document.getElementById('lastAction');
    if (el) el.textContent = `${SPIN_CHARS[spinIdx++ % SPIN_CHARS.length]} ${label} — идёт проверка, ${((Date.now() - t0) / 1000).toFixed(0)} с…`;
    document.title = `⏳ ${((Date.now() - t0) / 1000).toFixed(0)} с · GeoCheck`;
  }, 250);
}
function stopRunIndicator() {
  if (runTick) { clearInterval(runTick); runTick = null; }
  document.title = 'GeoCheck';
}
function log(msg, cls = '') {
  const el = document.getElementById('log');
  if (!el) return;
  const t = new Date().toLocaleTimeString('ru-RU');
  el.insertAdjacentHTML('beforeend',
    `<div${cls ? ` class="${cls}"` : ''}><span class="t">${t}</span><span class="${cls}">${esc(msg)}</span></div>`);
  while (el.children.length > 200) el.firstChild.remove();
  el.scrollTop = el.scrollHeight;
}

/* ---------------- выбор (чекбоксы/избранное) ---------------- */
function selGet(key) { const s = rowSel[key]; return s ? s.c !== false : true; }
function favGet(key) { const s = rowSel[key]; return !!(s && s.f); }
function persistSel() {
  localStorage.setItem(LS_SEL, JSON.stringify({ rowSel, domSel, hideUnchecked, grpCol, hideOkGlobal, grpHideOk, deletedRows: [...deletedRows] }));
}
function domChecked(i) { return !domSel || !!domSel[i]; }
function activeDomainIdxs() { return settings.domains.map((_, i) => i).filter(domChecked); }

/* «свернуть успешные»: точка считается успешной, если по ВСЕМ выбранным доменам
   ответ 2xx/3xx; свёрнутые успешные исключаются из прогонов и перепроверок */
function rowOk(r, diList) {
  if (!diList.length) return false;
  return diList.every(di => {
    const c = r.cells[di];
    if (!c || c.loading) return false;
    const cls = cellClass(c.code, c);
    return cls === 'ok' || cls === 'redir';
  });
}
function groupIdOf(model, r) {
  if (!model) return '';
  for (const g of model.groups) if (g.rows.includes(r)) return g.id;
  return '';
}
/* «мёртвая» нода: есть данные и по ВСЕМ выбранным доменам — обрыв соединения.
   HTTP-ошибка (403/503 и т.п.) НЕ делает ноду мёртвой: сервер ответил — узел жив,
   пусть и с ошибкой. Различие CF vs origin см. в cellBadge/verdict */
function isDeadRow(r, doms) {
  const checked = doms.map((_, di) => di).filter(domChecked);
  const list = checked.length ? checked : doms.map((_, i) => i);
  const cells = list.map(di => r.cells[di]);
  if (!cells.some(c => c && !c.loading)) return false;
  return cells.every(c => c && !c.loading && !c.code);   // код 0 = обрыв/таймаут
}
/* выход демона для daemon-строки */
function daemonExitOf(key) {
  if (!key || !key.startsWith('daemon:')) return null;
  return daemonExits.find(e => e.id === key.slice(7)) || null;
}
/* по результатам прогрева выход помечен мёртвым («⚠ мёртв — …») */
function isWarmupDead(r) {
  const ex = daemonExitOf(r.key);
  return !!(ex && String(ex.status || '').startsWith('⚠'));
}
function isRowOkHidden(model, r) {
  if (!model || r.isMsg) return false;
  const gid = groupIdOf(model, r);
  if (!(hideOkGlobal || grpHideOk[gid])) return false;
  return rowOk(r, activeDomainIdxs());
}

/* ---------------- таймер паузы между прогонами (не бомбим сервисы проверок) ---------------- */
const PACE_MIN_MS = 20000;
let paceNextAt = 0, paceTick = null;
function paceRun(label, fn) {
  const wait = paceNextAt - Date.now();
  const start = () => {
    paceNextAt = Date.now() + PACE_MIN_MS;
    if (paceTick) { clearInterval(paceTick); paceTick = null; }
    fn();
  };
  if (wait <= 0) { start(); return; }
  const secs = Math.ceil(wait / 1000);
  log(`⏱ ${label}: пауза ${secs} с — не бомбим сервисы проверок`);
  let left = secs;
  setAction(`⏱ ${label} через ${left} с…`);
  if (paceTick) clearInterval(paceTick);
  paceTick = setInterval(() => {
    left--;
    if (left <= 0) { start(); return; }
    setAction(`⏱ ${label} через ${left} с…`);
  }, 1000);
}

/* ---------------- домены ---------------- */
function renderDomains() {
  const bar = document.getElementById('domainsBar');
  bar.innerHTML = settings.domains.map((d, i) =>
    `<span class="chip ${domChecked(i) ? 'active' : 'dim'}">${esc(shortDomain(d))}<span class="x" data-i="${i}" title="убрать из списка">✕</span></span>`
  ).join('') + `<span class="chip" id="chipAdd" title="добавить домен">＋ домен</span>`;
  bar.querySelectorAll('.x').forEach(x => x.onclick = e => {
    e.stopPropagation();
    settings.domains.splice(+x.dataset.i, 1);
    domSel = null;
    saveSettings(); persistSel(); renderDomains(); renderRows(lastModel);
  });
  document.getElementById('chipAdd').onclick = () => {
    const v = normUrl(prompt('Домен или адрес страницы (например example.com):'));
    if (v) { settings.domains.push(v); domSel = null; saveSettings(); persistSel(); renderDomains(); renderRows(lastModel); }
  };
}

/* ---------------- модель и рендер ---------------- */
function freshModel() {
  return {
    at: Date.now(), domains: settings.domains.slice(),
    groups: [
      { id: 'local', title: 'Локально', rows: [] },
      { id: 'ch', title: 'check-host.net', rows: [] },
      { id: 'gp', title: 'GlobalPing', rows: [] },
    ],
  };
}
function getGroup(model, id) { return model.groups.find(g => g.id === id); }
function getRow(model, key) {
  for (const g of model.groups) { const r = g.rows.find(r => r.key === key); if (r) return r; }
  return null;
}
function addRow(model, gid, row) { getGroup(model, gid).rows.push(row); return row; }
function addMsg(model, gid, text) {
  return addRow(model, gid, { key: 'msg' + Math.random(), title: text, isMsg: true, isPending: true, cells: {} });
}
function dropMsg(model, r) {
  for (const g of model.groups) { const i = g.rows.indexOf(r); if (i > -1) { g.rows.splice(i, 1); return; } }
}
function markLoading(model, diList, rowFilter) {
  for (const g of model.groups) {
    for (const r of g.rows) {
      if (r.isMsg) { r.isPending = true; continue; }
      if (rowFilter && !rowFilter.has(r.key)) continue;
      if (!selGet(r.key)) continue;
      if (!rowFilter && isRowOkHidden(lastModel, r)) continue;  // успешные свёрнуты — не трогаем
      diList.forEach(di => r.cells[di] = { loading: true });
    }
  }
}

function cntHtml(t) {
  return `<b class="c-ok">${t.ok}</b> <b class="c-warn">${t.warn}</b> <b class="c-err">${t.err}</b> <b class="c-na">${t.na}</b>`;
}

function renderRows(model) {
  const t = document.getElementById('matrix');
  const doms = model ? model.domains : settings.domains;
  const groups = model ? model.groups : [];
  const nCols = doms.length + 1;

  // счётчики по доменам
  const tall = doms.map(() => ({ ok: 0, warn: 0, err: 0, na: 0 }));
  if (model) {
    for (const g of groups) for (const r of g.rows) {
      if (r.isMsg) continue;
      doms.forEach((_, di) => {
        const c = r.cells[di];
        if (!c) { tall[di].na++; return; }
        const cls = c.loading ? 'na' : cellClass(c.code, c);
        if (cls === 'ok' || cls === 'redir') tall[di].ok++;
        else if (cls === 'warn') tall[di].warn++;
        else if (cls === 'na') tall[di].na++;
        else tall[di].err++;
      });
    }
  }
  // все ключи строк для мастер-чекбокса
  const allKeys = [];
  if (model) for (const g of groups) for (const r of g.rows) if (!r.isMsg) allKeys.push(r.key);
  const checkedCnt = allKeys.filter(selGet).length;
  const allOn = allKeys.length > 0 && checkedCnt === allKeys.length;

  let h = '<thead><tr class="head-row"><th class="sel-head"><label class="cbline"><input type="checkbox" id="cbAll" ' +
    (allOn ? 'checked' : '') + '> Точка наблюдения</label>' +
    '<div class="prov"><a href="#" id="lnkAll">все</a> · <a href="#" id="lnkNone">никто</a>' +
    (checkedCnt !== allKeys.length ? ` · выбрано ${checkedCnt}/${allKeys.length}` : '') + '</div>' +
    `<label class="cbline hokg" title="свернуть точки, у которых все выбранные домены отвечают успешно (2xx/3xx); такие точки исключаются из прогонов"><input type="checkbox" id="cbHideOk"${hideOkGlobal ? ' checked' : ''}> свернуть успешные</label></th>`;
  h += doms.map((d, di) =>
    `<th class="${domChecked(di) ? '' : 'dim'}"><label class="cbline"><input type="checkbox" class="domcb" data-d="${di}" ${domChecked(di) ? 'checked' : ''}> ${esc(shortDomain(d))}</label><div class="cnt" title="ок / предупр. / ошибок / нет данных">${model ? cntHtml(tall[di]) : ''}</div></th>`
  ).join('') + '</tr></thead><tbody>';

  // избранные сверху
  const favRows = [];
  if (model) for (const g of groups) for (const r of g.rows) {
    if (!r.isMsg && favGet(r.key) && selGet(r.key)) favRows.push(r);
  }
  const sections = [];
  if (favRows.length) sections.push({ id: 'fav', title: '⭐ Избранные', rows: favRows });
  if (model) for (const g of groups) sections.push(g);

  for (const g of sections) {
    const dataRows = g.rows.filter(r => !r.isMsg && !deletedRows.has(r.key));
    const okHiddenRows = dataRows.filter(r => isRowOkHidden(model, r));
    const visRows = dataRows.filter(r => !okHiddenRows.includes(r));
    // мёртвые (недоступные) — вниз, серые; живые — сверху.
    // Мёртвыми считаются и обрывы по ячейкам, и ноды, помеченные прогревом «⚠ мёртв»
    const aliveRows = [], deadRows = [];
    for (const r of visRows) (isDeadRow(r, doms) || isWarmupDead(r) ? deadRows : aliveRows).push(r);
    // доступные — наверх: сначала точки с успешными ответами (2xx/3xx) или OK по прогреву
    const chkD = doms.map((_, di) => di).filter(domChecked);
    const listD = chkD.length ? chkD : doms.map((_, i) => i);
    const rowRank = r => {
      if (listD.some(di => { const c = r.cells[di]; return c && !c.loading && c.code >= 200 && c.code < 400; })) return 0;
      const ex = daemonExitOf(r.key);
      return (ex && String(ex.status || '').startsWith('OK')) ? 0 : 1;
    };
    aliveRows.sort((a, b) => rowRank(a) - rowRank(b));
    // счётчики ok/warn/err/na по каждому домену — только по живым видимым точкам
    const gt = doms.map(() => ({ ok: 0, warn: 0, err: 0, na: 0 }));
    for (const r of aliveRows) {
      doms.forEach((_, di) => {
        const c = r.cells[di];
        if (!c) { gt[di].na++; return; }
        const cls = c.loading ? 'na' : cellClass(c.code, c);
        if (cls === 'ok' || cls === 'redir') gt[di].ok++;
        else if (cls === 'warn') gt[di].warn++;
        else if (cls === 'na') gt[di].na++;
        else gt[di].err++;
      });
    }
    const failedCnt = aliveRows.filter(r => doms.some((_, di) => r.cells[di] && isFailed(r.cells[di]))).length;
    const col = !!grpCol[g.id];
    // строка группы: ячейка управления + счётчики РОВНО под колонками доменов
    h += `<tr class="group">` +
      `<td class="gh-cell">` +
      `<button class="caret" data-collapse="${esc(g.id)}" title="свернуть/развернуть группу">${col ? '▸' : '▾'}</button>` +
      `<span class="gtitle">${esc(g.title)}</span>` +
      (g.id !== 'fav' ? `<button class="btn mini" data-recheck="${esc(g.id)}" title="перепроверить все точки источника">↻ все</button>` : '') +
      (g.id !== 'fav' && failedCnt ? `<button class="btn mini" data-recheckfailed="${esc(g.id)}" title="перепроверить только упавшие точки этой группы">⟳ упавшие (${failedCnt})</button>` : '') +
      `<span class="spin ${spin[g.id] ? '' : 'hidden'}">⟳</span>` +
      `<span class="gsub">${visRows.length} точек</span>` +
      `<label class="grphok" title="свернуть успешные точки этой группы (из прогонов исключаются)"><input type="checkbox" class="grphideok" data-g="${esc(g.id)}"${grpHideOk[g.id] ? ' checked' : ''}> успешные</label>` +
      `</td>` +
      doms.map((d, di) => `<td class="gh-cnt" title="${esc(shortDomain(d))} — ок/предупр./ошибок/нет данных">${cntHtml(gt[di])}</td>`).join('') +
      `</tr>`;
    if (col) {
      h += `<tr class="msg"><td colspan="${nCols}"><a href="#" class="lnkOff" data-g="${esc(g.id)}">▸ группа свёрнута: ${dataRows.length} точек — развернуть</a></td></tr>`;
      continue;
    }
    let offRows = [];
    for (const r of g.rows) {
      if (deletedRows.has(r.key)) continue;
      if (r.isMsg) {
        h += `<tr class="msg${r.isPending ? ' pending' : ''}"><td colspan="${nCols}">${esc(r.title)}` +
          (r.retry ? ` <button class="btn mini" data-msgretry="${esc(r.retry)}" title="повторить проверку этого источника">↻ повторить</button>` : '') +
          `</td></tr>`;
        continue;
      }
      if (hideUnchecked && !selGet(r.key)) { offRows.push(r); continue; }
      if (okHiddenRows.includes(r)) continue;
      if (deadRows.includes(r)) continue;
      h += rowHtml(r, doms);
      if (openDetailKey === r.key) h += detailRowHtml(r, doms, nCols);
    }
    // блок недоступных: >5 — схлопывается в одну строку
    if (deadRows.length) {
      if (deadRows.length > 5 && !grpDeadOpen[g.id]) {
        h += `<tr class="msg dead-line"><td colspan="${nCols}"><button type="button" class="btn mini lnkDead" data-g="${esc(g.id)}">⚠ недоступные ноды (${deadRows.length}) — развернуть</button></td></tr>`;
      } else {
        for (const r of deadRows) {
          h += rowHtml(r, doms, true);
          if (openDetailKey === r.key) h += detailRowHtml(r, doms, nCols);
        }
        if (deadRows.length > 5) {
          h += `<tr class="msg dead-line"><td colspan="${nCols}"><button type="button" class="btn mini lnkDead" data-g="${esc(g.id)}">▾ свернуть недоступные (${deadRows.length})</button></td></tr>`;
        }
      }
    }
    if (okHiddenRows.length) {
      h += `<tr class="msg ok-line"><td colspan="${nCols}"><a href="#" class="lnkOk" data-g="${esc(g.id)}">✓ ${okHiddenRows.length} успешных свёрнуто — развернуть (перепроверка не нужна)</a></td></tr>`;
    }
    if (offRows.length && hideUnchecked) {
      h += `<tr class="msg"><td colspan="${nCols}"><a href="#" class="lnkOff" data-g="${esc(g.id)}">▸ ${offRows.length} невыбранных — развернуть</a></td></tr>`;
    }
  }
  t.innerHTML = h + '</tbody>';
  wireTableEvents(t, model, allKeys);
}

function rowHtml(r, doms, dead = false) {
  const on = selGet(r.key);
  // реальный IP, который выход отдаёт в интернет (после «♨ Прогрев VPN»)
  let exip = '';
  if (r.key.startsWith('daemon:')) {
    const ex = daemonExits.find(e => e.id === r.key.slice(7));
    if (ex && ex.exit_ip) exip = ` <span class="exip" title="exit-IP, видимый из интернета">${esc(ex.exit_ip)}${ex.exit_loc ? ' · ' + esc(ex.exit_loc) : ''}</span>`;
  }
  let h = `<tr class="${dead ? 'row-dead' : on ? '' : 'row-off'}" data-k="${esc(r.key)}">`;
  h += `<td class="node"><div class="rowctl">` +
    `<input type="checkbox" class="rowcb" data-k="${esc(r.key)}" ${on ? 'checked' : ''} title="участвует в прогоне">` +
    `<button class="star retry" data-retry="${esc(r.key)}" title="перепроверить только эту точку">⟳</button>` +
    `<button class="star ${favGet(r.key) ? 'on' : ''}" data-k="${esc(r.key)}" title="в избранное">${favGet(r.key) ? '★' : '☆'}</button>` +
    (dead ? `<button class="star del" data-delrow="${esc(r.key)}" title="удалить ноду из списка">✕</button>` : '') +
    `</div><div class="ntext">${esc(r.title)}${exip}<div class="prov">${esc(r.sub || '')}</div></div></td>`;
  h += doms.map((_, di) => {
    const c = r.cells[di];
    const rb = `<button class="cellretry" data-k="${esc(r.key)}" data-d="${di}" title="перепроверить только эту ячейку">⟳</button>`;
    if (!c) return `<td><span class="cellwrap"><span class="cell empty" title="не участвует в прогоне / не проверялось">—</span>${rb}</span></td>`;
    if (c.loading) return `<td><span class="cellwrap"><span class="cell loading">…</span>${rb}</span></td>`;
    const cls = cellClass(c.code, c);
    return `<td><span class="cellwrap"><span class="cell ${cls}" data-k="${esc(r.key)}" data-d="${di}">${esc(cellText(c.code, c.ms, c.note, c))}</span>${cellBadge(c, r.key)}${rb}</span></td>`;
  }).join('');
  return h + '</tr>';
}

function wireTableEvents(t, model, allKeys) {
  t.querySelectorAll('.rowcb').forEach(cb => cb.onchange = () => {
    const k = cb.dataset.k;
    rowSel[k] = { ...(rowSel[k] || {}), c: cb.checked };
    persistSel(); renderRows(lastModel);
  });
  t.querySelectorAll('.domcb').forEach(cb => cb.onchange = () => {
    const i = +cb.dataset.d;
    if (!domSel) domSel = settings.domains.map((_, j) => j !== i);
    else domSel[i] = cb.checked ? 1 : 0;
    persistSel(); renderDomains(); renderRows(lastModel);
  });
  const cbAll = t.querySelector('#cbAll');
  if (cbAll) cbAll.onchange = () => {
    allKeys.forEach(k => rowSel[k] = { ...(rowSel[k] || {}), c: cbAll.checked });
    persistSel(); renderRows(lastModel);
  };
  const lAll = t.querySelector('#lnkAll'), lNone = t.querySelector('#lnkNone');
  if (lAll) lAll.onclick = e => { e.preventDefault(); allKeys.forEach(k => rowSel[k] = { ...(rowSel[k] || {}), c: true }); persistSel(); renderRows(lastModel); };
  if (lNone) lNone.onclick = e => { e.preventDefault(); allKeys.forEach(k => rowSel[k] = { ...(rowSel[k] || {}), c: false }); persistSel(); renderRows(lastModel); };
  t.querySelectorAll('.star:not(.retry):not(.del)').forEach(b => b.onclick = () => {
    const k = b.dataset.k;
    rowSel[k] = { ...(rowSel[k] || {}), f: !favGet(k) };
    persistSel(); renderRows(lastModel);
  });
  t.querySelectorAll('[data-recheck]').forEach(b => b.onclick = () => reCheckSource(b.dataset.recheck));
  t.querySelectorAll('.lnkOff').forEach(a => a.onclick = e => {
    e.preventDefault();
    const gid = a.dataset.g;
    if (grpCol[gid]) { grpCol[gid] = false; persistSel(); renderRows(lastModel); return; }
    hideUnchecked = false;
    document.getElementById('chkHide').checked = false;
    persistSel(); renderRows(lastModel);
  });
  const cbOk = t.querySelector('#cbHideOk');
  if (cbOk) cbOk.onchange = () => {
    hideOkGlobal = cbOk.checked;
    persistSel(); renderRows(lastModel);
  };
  t.querySelectorAll('.grphideok').forEach(cb => cb.onchange = () => {
    grpHideOk[cb.dataset.g] = cb.checked;
    persistSel(); renderRows(lastModel);
  });
  t.querySelectorAll('.lnkOk').forEach(a => a.onclick = e => {
    e.preventDefault();
    if (hideOkGlobal) hideOkGlobal = false;
    else grpHideOk[a.dataset.g] = false;
    persistSel(); renderRows(lastModel);
  });
  t.querySelectorAll('[data-collapse]').forEach(b => b.onclick = () => {
    grpCol[b.dataset.collapse] = !grpCol[b.dataset.collapse];
    persistSel(); renderRows(lastModel);
  });
  t.querySelectorAll('[data-closedetail]').forEach(b => b.onclick = () => {
    if (openDetailKey === b.dataset.closedetail) openDetailKey = null;
    renderRows(lastModel);
  });
  t.querySelectorAll('[data-retry]').forEach(b => b.onclick = () => reCheckRow(b.dataset.retry));
  t.querySelectorAll('.cellretry').forEach(b => b.onclick = e => {
    e.stopPropagation();
    reCheckCell(b.dataset.k, +b.dataset.d);
  });
  t.querySelectorAll('[data-recheckfailed]').forEach(b => b.onclick = () => reCheckGroupFailed(b.dataset.recheckfailed));
  t.querySelectorAll('[data-msgretry]').forEach(b => b.onclick = () => reCheckSource(b.dataset.msgretry));
  t.querySelectorAll('[data-delrow]').forEach(b => b.onclick = () => {
    const k = b.dataset.delrow;
    for (const g of lastModel.groups) { const i = g.rows.findIndex(r => r.key === k); if (i > -1) { g.rows.splice(i, 1); break; } }
    deletedRows.add(k);
    if (openDetailKey === k) openDetailKey = null;
    persistSel(); renderRows(lastModel);
    log('нода удалена из списка: ' + k, 'warn');
  });
  t.querySelectorAll('.lnkDead').forEach(a => a.onclick = e => {
    e.preventDefault();
    grpDeadOpen[a.dataset.g] = !grpDeadOpen[a.dataset.g];
    log(grpDeadOpen[a.dataset.g] ? `недоступные ноды развёрнуты` : `недоступные ноды свёрнуты`);
    renderRows(lastModel);
  });
  t.querySelectorAll('.cell[data-k]').forEach(el => {
    el.onclick = () => {
      const k = el.dataset.k;
      openDetailKey = (openDetailKey === k) ? null : k;   // повторный клик — закрыть
      renderRows(lastModel);
    };
  });
}

/* детали выезжают строкой ПОД нодой: одна строка на домен, код цветом результата */
let statsCache = null, statsLoading = false;
function loadStatsOnce() {
  if (statsLoading || (statsCache && Date.now() - statsCache.at < 60000)) return;
  statsLoading = true;
  dFetch('/stats').then(r => r.json()).then(j => {
    if (j && j.ok) { const idx = {}; (j.matrix || []).forEach(c => { idx[c.target.replace(/\/$/, '') + '\n' + c.exit] = c; }); statsCache = { at: Date.now(), idx }; }
  }).catch(() => { }).finally(() => { statsLoading = false; if (lastModel) renderRows(lastModel); });
}
function statHtml(r, d) {
  if (!r.key.startsWith('daemon:')) return '';
  if (!statsCache) { loadStatsOnce(); return ''; }
  const c = statsCache.idx[String(d).replace(/\/$/, '') + '\n' + r.title];
  if (!c || !c.total) return ' · <span class="dextra">история: нет данных</span>';
  const f = n => `${n}/${c.total} (${Math.round(100 * n / c.total)}%)`;
  return ` · <span class="dextra">среднее за ${c.total} проверок:</span> <b class="st-g">${f(c.good)}</b> <b class="st-y">${f(c.warn)}</b> <b class="st-r">${f(c.bad)}</b>`;
}
function detailRowHtml(r, doms, nCols) {
  const lines = doms.map((d, di) => {
    const c = r.cells[di];
    const dom = `<b>${esc(shortDomain(d))}</b>`;
    if (!c) return `<div class="dline"><span class="cell empty">—</span> ${dom} · нет данных${statHtml(r, d)}</div>`;
    if (c.loading) return `<div class="dline"><span class="cell loading">…</span> ${dom} · проверяю…</div>`;
    const cls = cellClass(c.code, c);
    const ms = (c.ms != null && !isNaN(c.ms)) ? ` · ${(c.ms / 1000).toFixed(2)}s` : '';
    const extras = [];
    if (c.code) {
      if (c.note) extras.push(c.note);
      if (c.cfRay) extras.push('cf-ray ' + c.cfRay);
      if (c.cfMitigated) extras.push('cf-mitigated: ' + c.cfMitigated);
      if (c.ip) extras.push('ip ' + c.ip);
      if (c.server) extras.push(c.server);
    }
    return `<div class="dline"><span class="cell ${cls}">${esc(cellText(c.code, null, c.note, c))}</span> ${dom}${ms} · ${esc(verdict(c.code, c))}` +
      (extras.length ? ` · <span class="dextra">${esc(extras.join(' · '))}</span>` : '') + statHtml(r, d) + `</div>`;
  }).join('');
  return `<tr class="detail-row" data-k="${esc(r.key)}"><td colspan="${nCols}"><div class="dbox">${lines}` +
    `<button class="btn mini" data-closedetail="${esc(r.key)}">▾ свернуть</button></div></td></tr>`;
}

/* ---------------- история ---------------- */
let histViewAt = null;   // просматриваемый снапшот (null = текущий)
function histLoad() { let h = []; try { h = JSON.parse(localStorage.getItem(LS_HISTORY)) || []; } catch { } return h; }
function histSave(h) {
  h = h.slice(-30);
  // снапшоты модели храним только у 6 последних — экономим localStorage
  h.forEach((e, i) => { if (i < h.length - 6) delete e.model; });
  try { localStorage.setItem(LS_HISTORY, JSON.stringify(h)); } catch { }
}
function pushHistory(summary, model) {
  const h = histLoad();
  h.push({
    at: Date.now(), ok: summary.ok, warn: summary.warn, err: summary.err,
    domains: model.domains.slice(),
    model: model.groups.map(g => ({ ...g, rows: g.rows.map(r => ({ ...r })) })),
  });
  histSave(h);
  renderHistory();
}
function renderHistory() {
  const h = histLoad();
  const el = document.getElementById('history');
  if (!h.length && !lastAt) { el.innerHTML = ''; return; }
  el.innerHTML = '<span>История прогонов (клик — просмотр, ✕ — удалить):</span>' + h.slice(-15).map(r =>
    `<span class="hdot${histViewAt === r.at ? ' cur' : ''}" data-at="${r.at}"
      style="background:${r.err > 0 ? 'var(--red)' : r.warn > 0 ? 'var(--orange)' : 'var(--green)'}"
      title="${new Date(r.at).toLocaleString()} — ок:${r.ok} предупр.:${r.warn} ошибок:${r.err}${r.model ? '' : ' · снапшот не сохранён'}"></span>`
  ).join('') + (lastAt ? `<span style="margin-left:10px">последний прогон: ${new Date(lastAt).toLocaleString()}</span>` +
    `<button class="btn mini" id="btnRefreshResults" title="обновить результаты (полный прогон)">↻ обновить</button>` : '');
  el.querySelectorAll('.hdot').forEach(d => d.onclick = () => viewRun(+d.dataset.at));
  const rb = el.querySelector('#btnRefreshResults');
  if (rb) rb.onclick = () => runAll();
}
function viewRun(at) {
  const e = histLoad().find(x => x.at === at);
  if (!e) return;
  const banner = document.getElementById('histBanner');
  if (histViewAt === at) { closeHistView(); return; }  // повторный клик — закрыть
  if (!e.model) { log('снапшот этого прогона не сохранён (старше 6 последних)', 'warn'); return; }
  histViewAt = at;
  banner.classList.remove('hidden');
  banner.innerHTML = `👁 Просмотр прогона от ${new Date(at).toLocaleString()} (ок:${e.ok} предупр.:${e.warn} ошибок:${e.err})` +
    ` <button class="btn mini" id="btnHistBack">← вернуться к текущему</button>` +
    ` <button class="btn mini" id="btnHistDel">✕ удалить этот прогон</button>`;
  document.getElementById('btnHistBack').onclick = closeHistView;
  document.getElementById('btnHistDel').onclick = () => deleteRun(at);
  renderRows({ at, domains: e.domains, groups: e.model });
  renderHistory();
  log(`история: открыт снапшот прогона от ${new Date(at).toLocaleString()}`);
}
function closeHistView() {
  histViewAt = null;
  document.getElementById('histBanner').classList.add('hidden');
  renderRows(lastModel);
  renderHistory();
}
function deleteRun(at) {
  histSave(histLoad().filter(x => x.at !== at));
  log(`история: прогон от ${new Date(at).toLocaleString()} удалён`, 'warn');
  if (histViewAt === at) closeHistView(); else renderHistory();
}

/* ---------------- выгрузка ---------------- */
function downloadFile(name, text, mime) {
  const b = new Blob([text], { type: mime });
  const u = URL.createObjectURL(b);
  const a = document.createElement('a');
  a.href = u; a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(u), 5000);
}
function stamp() { return new Date().toISOString().replace(/[:T]/g, '-').slice(0, 19); }
function exportCSV() {
  if (!lastModel) return;
  const q = v => '"' + String(v ?? '').replace(/"/g, '""') + '"';
  const head = ['source', 'node', 'provider', 'domain', 'code', 'ms', 'verdict',
    'cf_ray', 'cf_mitigated', 'server', 'ip', 'error'].join(',');
  const lines = [head];
  for (const g of lastModel.groups) {
    for (const r of g.rows) {
      if (r.isMsg) continue;
      lastModel.domains.forEach((d, di) => {
        const c = r.cells[di] || {};
        lines.push([q(g.title), q(r.title), q(r.sub || ''), q(d),
          c.code || '', c.ms ?? '', q(verdict(c.code, c)),
          q(c.cfRay || ''), q(c.cfMitigated || ''), q(c.server || ''),
          q(c.ip || ''), q(c.error || c.note || '')].join(','));
      });
    }
  }
  downloadFile('geocheck-' + stamp() + '.csv', lines.join('\r\n'), 'text/csv;charset=utf-8');
}
function exportJSON() {
  if (!lastModel) return;
  downloadFile('geocheck-' + stamp() + '.json',
    JSON.stringify({ at: new Date(lastAt || Date.now()).toISOString(), domains: lastModel.domains, groups: lastModel.groups }, null, 2),
    'application/json');
}

/* ---------------- сохранение/восстановление ---------------- */
function saveLastRun(model) {
  const clean = {
    at: Date.now(), domains: model.domains,
    groups: model.groups.map(g => ({
      ...g,
      rows: g.rows.map(r => ({
        ...r,
        cells: Object.fromEntries(Object.entries(r.cells).map(([k, c]) =>
          [k, c.loading ? { code: 0, note: 'нет ответа' } : c])),
      })),
    })),
  };
  lastAt = clean.at;
  try { localStorage.setItem(LS_LAST, JSON.stringify(clean)); } catch { }
  dFetch('/lastmodel', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ model: clean }) }).catch(() => { });
}
async function restoreServerRun() {
  try {
    const r = await dFetch('/lastmodel');
    const j = await r.json();
    const s = j && j.model;
    if (!s || !s.groups || !(s.at > (lastAt || 0))) return;
    const norm = a => JSON.stringify((a || []).map(x => String(x).replace(/\/$/, '')));
    if (norm(s.domains) !== norm(settings.domains)) return;
    restoreLastRun(s);
  } catch { }
}
function restoreLastRun(given) {
  try {
    const s = given || JSON.parse(localStorage.getItem(LS_LAST));
    if (!s || !s.groups) return;
    if (!given && JSON.stringify(s.domains) !== JSON.stringify(settings.domains)) return;
    const idByTitle = { 'Локально': 'local', 'check-host.net': 'ch', 'GlobalPing': 'gp' };
    s.groups.forEach(g => { if (!g.id) g.id = idByTitle[g.title] || g.title; });
    lastModel = s;
    lastAt = s.at;
    renderRows(lastModel);
    document.getElementById('btnCsv').disabled = false;
    document.getElementById('btnJson').disabled = false;
  } catch { }
}

/* ---------------- API-хелперы ---------------- */
function daemonBase() { return /^https?:$/.test(location.protocol) ? location.origin : `http://127.0.0.1:${settings.daemonPort}`; }
function rgToken() { try { return sessionStorage.getItem('rg.token') || ''; } catch { return ''; } }
async function dFetch(path, opts = {}, retried = false) {
  const headers = { ...(opts.headers || {}) };
  const t = rgToken();
  if (t) headers['X-RG-Token'] = t;
  const r = await fetch(daemonBase() + path, { ...opts, headers });
  if (r.status === 401 && !PUBLIC && !retried) {
    const v = prompt('Токен демона (пароль закрытой страницы):');
    if (v) { try { sessionStorage.setItem('rg.token', v.trim()); } catch { } return dFetch(path, opts, true); }
  }
  return r;
}
async function daemonPing() {
  try {
    const r = await dFetch('/status', { signal: AbortSignal.timeout(8000) });
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}
async function apiFetch(url, opts = {}, label = '') {
  try {
    const r = await fetch(url, opts);
    if (!r.ok) throw new Error(label + ' HTTP ' + r.status);
    return r.json();
  } catch (e) {
    const j = await daemonPing();
    if (!j) throw e;
    log(label + ': прямой доступ не удался (' + (e.message || e) + ') — иду через демон', 'warn');
    const r2 = await dFetch('/fwd?url=' + encodeURIComponent(url),
      { ...opts, headers: { ...(opts.headers || {}), 'X-Via-Daemon': '1' } });
    if (!r2.ok) throw new Error(label + ' (через демон) HTTP ' + r2.status);
    return r2.json();
  }
}
async function chFetch(path) {
  return apiFetch('https://check-host.net' + path, { headers: { 'Accept': 'application/json' } }, 'check-host');
}
function parseChAttempt(a) {
  // формат 2026: [ok, time_s, status, http_code, ip] | {"Message": ...} | null
  if (a == null) return { code: 0, note: 'нет ответа' };
  if (!Array.isArray(a)) {
    const m = a.Message || a.message || JSON.stringify(a);
    return { code: 0, note: m, error: m };
  }
  const [ok, time, status, code, ip] = a;
  const ms = time != null && !isNaN(time) ? time * 1000 : null;
  if (ok === 1 && code) return { code: +code, ms, ip: ip || '' };
  return { code: 0, note: status || 'ошибка', error: status || '', ms };
}
function pollCheckHost(id) {
  return new Promise((resolve, reject) => {
    const t0 = Date.now();
    let n = 0;
    const tick = async () => {
      try {
        const res = await chFetch(`/check-result/${id}`);
        const done = Object.values(res).every(v => v != null);
        if (done) {
          log(`check-host: ${id.slice(0, 8)} — ответ собран за ${((Date.now() - t0) / 1000).toFixed(0)} с`, 'ok');
          return resolve(res);
        }
        if (++n % 4 === 1) log(`check-host: опрос ${id.slice(0, 8)}… ${((Date.now() - t0) / 1000).toFixed(0)} с`);
        if (Date.now() - t0 > 60000) return resolve(res);
        setTimeout(tick, 1500);
      } catch (e) { reject(e); }
    };
    tick();
  });
}
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function gpStart(domain, locations) {
  const u = new URL(domain);
  const body = JSON.stringify({
    type: 'http', target: u.hostname, limit: 24,
    ...(locations ? { locations } : {}),
    measurementOptions: { protocol: 'HTTPS', request: { method: 'GET', path: u.pathname || '/', headers: {} } },
  });
  // 429 у GlobalPing — обычное дело: ждём и повторяем, максимум 3 раза
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const j = await apiFetch('https://api.globalping.io/v1/measurements', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body,
      }, 'GlobalPing');
      return j.id;
    } catch (e) {
      const is429 = /429/.test(e.message || '');
      if (!is429 || attempt === 3) throw e;
      const wait = 15000 * attempt;
      log(`GlobalPing: 429 — пауза ${wait / 1000} с перед повтором (${attempt}/3)`, 'warn');
      setAction(`GlobalPing: жду ${wait / 1000} с (rate limit)…`);
      await sleep(wait);
    }
  }
}
async function gpPoll(id) {
  const t0 = Date.now();
  let n = 0;
  while (Date.now() - t0 < 90000) {
    const j = await apiFetch(`https://api.globalping.io/v1/measurements/${id}`, {}, 'GlobalPing');
    if (j.status === 'finished') {
      log(`GlobalPing: ${id.slice(0, 8)} завершено, ответов от проб: ${(j.results || []).length}`, 'ok');
      return j.results || [];
    }
    if (++n % 4 === 1) log(`GlobalPing: ждём пробы ${id.slice(0, 8)}… ${((Date.now() - t0) / 1000).toFixed(0)} с`);
    await new Promise(res => setTimeout(res, 2000));
  }
  log(`GlobalPing: измерение ${id.slice(0, 8)} не завершилось за 90 с`, 'warn');
  return [];
}
async function daemonRun(domains) {
  try {
    const r = await dFetch('/jobs', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domains, browser: !!settings.useBrowser, domainFirst: !!settings.domainFirst }),
    });
    const j = await r.json();
    if (!j.ok) return { error: j.error || ('HTTP ' + r.status) };
    const t0 = Date.now();
    let n = 0;
    while (Date.now() - t0 < 1800000) {
      await new Promise(res => setTimeout(res, 2500));
      const sr = await dFetch('/jobs/' + j.id);
      const sj = await sr.json();
      const job = sj.job;
      if (!job) return { error: sj.error || 'задание потеряно' };
      if (++n % 4 === 0) setAction(`демон: ${job.progress.done}/${job.progress.total} замеров…`);
      if (['done', 'error', 'cancelled'].includes(job.status)) return { results: job.results || {}, exits: job.exits, warnings: job.warnings };
    }
    return { error: 'задание не завершилось за 30 мин' };
  } catch { return null; }
}
async function browserProbe(domain) {
  try {
    await fetch(domain, { mode: 'no-cors', signal: AbortSignal.timeout(60000), cache: 'no-store' });
    return 'ok';
  } catch { return 'fail'; }
}

/* ---------------- прогоны по источникам ---------------- */
async function runLocal(model, seq, diList, rowFilter) {
  const g = getGroup(model, 'local');
  const want = k => !rowFilter || rowFilter.has(k);
  spin.local = true; renderRows(model);
  // браузерный пробник
  const brow = getRow(model, 'local-browser');
  if (brow && want(brow.key) && selGet(brow.key) && (rowFilter || !isRowOkHidden(model, brow))) {
    for (const di of diList) {
      const res = await browserProbe(model.domains[di]);
      if (seq !== runSeq) return;
      brow.cells[di] = { code: res === 'ok' ? 204 : 0, note: res === 'ok' ? 'доступен (opaque)' : 'обрыв' };
      log(`браузер: ${shortDomain(model.domains[di])} — ${res === 'ok' ? 'доступен' : 'обрыв'}`, res === 'ok' ? 'ok' : 'err');
      renderRows(model);
    }
  }
  // демон
  const dexits = daemonExits.filter(ex => {
    const r = getRow(model, 'daemon:' + ex.id);
    return r && want(r.key) && selGet(r.key) && (rowFilter || !isRowOkHidden(model, r));
  });
  if (dexits.length) {
    const tDaemon = Date.now();
    log(`демон: отправил ${diList.length} домен(ов) на прогон…`);
    const dRes = await daemonRun(diList.map(di => model.domains[di]));
    if (dRes && dRes.results) {
      for (const ex of dexits) {
        const r = getRow(model, 'daemon:' + ex.id);
        diList.forEach(di => {
          const c = dRes.results[ex.id] && dRes.results[ex.id][model.domains[di]];
          r.cells[di] = c ? { ...c } : { code: 0, note: 'выход не вернул результат (соединение не поднялось)' };
        });
      }
      log(`демон: ответ за ${((Date.now() - tDaemon) / 1000).toFixed(1)} с — ${dexits.length} строк`, 'ok');
    } else {
      log('демон: ' + (dRes && dRes.error ? dRes.error : 'нет ответа'), 'err');
    }
    renderRows(model);
  }
  spin.local = false; renderRows(model);
}

async function runCh(model, seq, diList, rowFilter) {
  if (!settings.useCheckHost && !rowFilter) { return; }
  spin.ch = true;
  const g = getGroup(model, 'ch');
  const pend = addMsg(model, 'ch', 'запрашиваю узлы check-host.net…');
  renderRows(model);
  try {
    const doms = diList.map(di => model.domains[di]);
    // те же узлы для всех доменов: первый запрос выбирает узлы, остальные получают их явно (node=)
    // (иначе check-host берёт случайный набор на каждый запрос и сравнивать домены нечем)
    const q = d => `/check-http?host=${encodeURIComponent(d)}`;
    let nodeQs;
    const starts = [];
    if (rowFilter) {
      const want = [...rowFilter].filter(k => k.startsWith('ch:')).map(k => k.slice(3));
      if (!want.length) { dropMsg(model, pend); spin.ch = false; renderRows(model); return; }
      nodeQs = want.map(n => '&node=' + encodeURIComponent(n)).join('');
      starts.push(...await Promise.all(doms.map(d => chFetch(q(d) + nodeQs))));
    } else {
      const first = await chFetch(q(doms[0]) + `&max_nodes=${settings.maxNodes}`);
      starts.push(first);
      nodeQs = Object.keys(first.nodes || {}).map(n => '&node=' + encodeURIComponent(n)).join('');
      starts.push(...await Promise.all(doms.slice(1).map(d => chFetch(q(d) + nodeQs))));
    }
    if (seq !== runSeq) return;
    const nodeMeta = {};
    for (const s of starts) {
      for (const [name, info] of Object.entries(s.nodes || {})) {
        if (Array.isArray(info)) {
          nodeMeta[name] = {
            location: info[2] && info[1] ? info[2] + ', ' + info[1] : (info[1] || name),
            provider: info[4] || '',
          };
        }
      }
    }
    doms.forEach((d, i) => log(`check-host: запрос ${shortDomain(d)} → ${starts[i].request_id || 'без id'}`));
    dropMsg(model, pend);
    const results = await Promise.all(starts.map(s => pollCheckHost(s.request_id)));
    if (seq !== runSeq) return;
    let skipped = 0;
    results.forEach((nodes, ri) => {
      const di = diList[ri];
      for (const [node, attempts] of Object.entries(nodes || {})) {
        const key = 'ch:' + node;
        if (deletedRows.has(key)) { skipped++; continue; }
        if (rowFilter && !rowFilter.has(key)) { skipped++; continue; }
        let r = getRow(model, key);
        if (!r) {
          if (!selGet(key)) { skipped++; continue; }  // новый узел, но выключен чекбоксом
          const meta = nodeMeta[node] || {};
          r = addRow(model, 'ch', { key, title: meta.location || node, sub: meta.provider || '', cells: {} });
          log(`➕ узел check-host: ${meta.location || node}${meta.provider ? ' · ' + meta.provider : ''}`);
        }
        if (!selGet(r.key)) continue;
        if (!rowFilter && isRowOkHidden(model, r)) { skipped++; continue; }
        const list = (attempts || []).filter(Boolean);
        const a = list.find(x => Array.isArray(x) && x[0] === 1) || list[0] || null;
        r.cells[di] = parseChAttempt(a);
        renderRows(model);
      }
    });
    if (skipped) log(`check-host: пропущено ${skipped} результатов (выключены чекбоксами)`);
  } catch (e) {
    console.warn('check-host:', e);
    pend.title = '⚠ check-host.net недоступен: ' + (e.message || e);
    pend.isPending = false;
    pend.retry = 'ch';
    log('check-host: ошибка — ' + (e.message || e), 'err');
  }
  spin.ch = false; renderRows(model);
}

async function runGp(model, seq, diList, rowFilter) {
  if (!settings.useGlobalPing && !rowFilter) { return; }
  spin.gp = true;
  const pend = addMsg(model, 'gp', 'запрашиваю пробы GlobalPing…');
  renderRows(model);
  try {
    const doms = diList.map(di => model.domains[di]);
    // создаём измерения ПО ОДНОМУ с паузой — не бомбим API (429)
    // ВАЖНО: все домены меряются ОДНИМИ И ТЕМИ ЖЕ пробами (locations = id первого измерения),
    // иначе сравнение «.com vs .ru из одной точки» невозможно — GlobalPing иначе берёт случайные пробы
    let locs = null;
    if (rowFilter) {
      locs = [...rowFilter].filter(k => k.startsWith('gp:')).map(k => {
        const [country, city, network] = k.slice(3).split('|');
        const l = { limit: 1 };
        if (country) l.country = country;
        if (city) l.city = city;
        if (network) l.network = network;
        return l;
      });
      if (!locs.length) { dropMsg(model, pend); spin.gp = false; renderRows(model); return; }
    }
    const ids = [];
    for (const d of doms) {
      ids.push(await gpStart(d, locs || (ids.length ? ids[0] : null)));
      if (doms.length > 1) await sleep(2500);
    }
    log(`GlobalPing: измерения созданы: ${ids.map(x => x.slice(0, 8)).join(', ')}`);
    const all = await Promise.all(ids.map(gpPoll));
    if (seq !== runSeq) return;
    dropMsg(model, pend);
    all.forEach((results, ri) => {
      const di = diList[ri];
      for (const item of results) {
        const p = item.probe || {};
        const res = item.result || {};
        const t = res.timings || {};
        const hdr = res.headers || {};
        const key = 'gp:' + [p.country, p.city, p.network].join('|');
        if (deletedRows.has(key)) continue;
        if (rowFilter && !rowFilter.has(key)) continue;
        let r = getRow(model, key);
        if (!r) {
          if (!selGet(key)) continue;
          r = addRow(model, 'gp', { key, title: [p.country, p.city].filter(Boolean).join(', '), sub: p.network || '', cells: {} });
          log(`➕ проба GlobalPing: ${[p.country, p.city].filter(Boolean).join(', ')}`);
        }
        if (!selGet(r.key)) continue;
        if (!rowFilter && isRowOkHidden(model, r)) continue;
        r.cells[di] = res.statusCode
          ? { code: res.statusCode, ms: t.total != null ? t.total : null, ip: res.resolvedAddress || '',
              cfRay: hdr['cf-ray'] || '', cfMitigated: hdr['cf-mitigated'] || '', server: hdr['server'] || '' }
          : { code: 0, note: res.statusCodeName || 'ошибка пробы',
              error: res.rawError || res.statusCodeName || res.status || '' };
        renderRows(model);
      }
    });
  } catch (e) {
    console.warn('globalping:', e);
    pend.title = '⚠ GlobalPing недоступен: ' + (e.message || e);
    pend.isPending = false;
    pend.retry = 'gp';
    log('GlobalPing: ошибка — ' + (e.message || e), 'err');
  }
  spin.gp = false; renderRows(model);
}

function tallyModel(model) {
  const summary = { ok: 0, warn: 0, err: 0 };
  for (const g of model.groups) for (const r of g.rows) {
    if (r.isMsg) continue;
    Object.values(r.cells).forEach(c => {
      if (!c || c.loading) return;
      const cls = cellClass(c.code, c);
      if (cls === 'ok' || cls === 'redir') summary.ok++;
      else if (cls === 'warn') summary.warn++;
      else summary.err++;
    });
  }
  return summary;
}

function releaseRunButton() {
  const btn = document.getElementById('btnRun');
  btn.disabled = false; btn.textContent = '▶ Запустить проверку';
  document.title = 'GeoCheck';
}

function finalize(model, seq, tRun, full = false) {
  // честные «нет данных»: точка участвовала в прогоне, а ячейка пуста/висит в loading —
  // значит источник не довёз результат. Красный ERR с причиной вместо серого «—»
  // («—» остаётся только у точек, выключенных чекбоксом, и у свёрнутых успешных)
  const diList = activeDomainIdxs();
  let filled = 0;
  for (const g of model.groups) for (const r of g.rows) {
    if (r.isMsg || !selGet(r.key) || isRowOkHidden(model, r)) continue;
    for (const di of diList) {
      const c = r.cells[di];
      if (c && c.loading) { r.cells[di] = { code: 0, note: 'источник не довёл проверку до конца' }; filled++; }
      else if (!c) { r.cells[di] = { code: 0, note: 'источник не вернул результат' }; filled++; }
    }
  }
  if (filled) log(`⚠ ${filled} ячеек без результата — источники не довезли данные (красные ERR с пояснением; перепроверьте кнопкой ⟳)`, 'warn');
  stopRunIndicator();
  const summary = tallyModel(model);
  log(`прогон ${seq} завершён за ${((Date.now() - tRun) / 1000).toFixed(1)} с — ок: ${summary.ok}, предупр.: ${summary.warn}, ошибок: ${summary.err}`, summary.err ? 'warn' : 'ok');
  saveLastRun(model);
  document.getElementById('btnCsv').disabled = false;
  document.getElementById('btnJson').disabled = false;
  if (full) pushHistory(summary, model);   // перепроверки точек/ячеек историю не засоряют
  setAction(`прогон ${seq} завершён — ок: ${summary.ok}, предупр.: ${summary.warn}, ошибок: ${summary.err} · ${new Date().toLocaleTimeString('ru-RU')}`);
  if (histViewAt) closeHistView(); else renderRows(model);
}

async function runAll() { paceRun('прогон', runAllNow); }
async function runAllNow() {
  if (!settings.domains.length) { alert('Добавьте хотя бы один домен.'); return; }
  const seq = ++runSeq;
  const tRun = Date.now();
  const diList = activeDomainIdxs();
  if (!diList.length) { alert('Отметьте хотя бы один домен.'); return; }
  const btn = document.getElementById('btnRun');
  btn.disabled = true; btn.textContent = '⏳ Проверяю…';
  log(`прогон ${seq}: ${diList.length}/${settings.domains.length} домен(ов) · ${settings.useCheckHost ? 'check-host ' : ''}${settings.useGlobalPing ? 'GlobalPing' : ''} · демон: ${daemonExits.length ? daemonExits.length + ' выходов' : 'не подключён'}`);
  setAction(`прогон ${seq} запущен — ${diList.length} домен(ов), идёт проверка…`);
  startRunIndicator(`прогон ${seq}`);

  // ноды СОХРАНЯЮТСЯ между прогонами: переиспользуем модель, если домены те же;
  // новые ноды добавятся, старые останутся — не возвращаем только удалённые вручную
  let model;
  if (lastModel && JSON.stringify(lastModel.domains) === JSON.stringify(settings.domains)) {
    model = lastModel;
    for (const g of model.groups) g.rows = g.rows.filter(r => !r.isMsg);  // старые статусные строки — в мусор
  } else {
    model = freshModel();
  }
  lastModel = model;
  document.getElementById('btnCsv').disabled = true;
  document.getElementById('btnJson').disabled = true;
  openDetailKey = null;

  if (!getRow(model, 'local-browser'))
    addRow(model, 'local', { key: 'local-browser', title: 'Этот браузер (ваш канал)', sub: 'no-cors пробник: ок/обрыв', cells: {} });
  if (daemonExits.length) {
    daemonExits.forEach(ex => {
      const k = 'daemon:' + ex.id;
      const r = getRow(model, k);
      if (r) { r.title = ex.label; r.sub = ex.status || ''; }  // обновим статус, ячейки сохраним
      else addRow(model, 'local', { key: k, title: ex.label, sub: ex.status || '', cells: {} });
    });
  } else {
    addMsg(model, 'local', `сервер проверки не отвечает — VPN-выходы недоступны`);
  }
  markLoading(model, diList, null);
  renderRows(model);

  try {
    await runLocal(model, seq, diList, null);
    if (seq !== runSeq) return;
    await runCh(model, seq, diList, null);
    if (seq !== runSeq) return;
    await runGp(model, seq, diList, null);
    if (seq !== runSeq) return;
    finalize(model, seq, tRun, true);
  } finally {
    releaseRunButton();   // даже если прогон прерван перепроверкой или упал
    spin.local = spin.ch = spin.gp = false;
  }
}

async function reCheckSource(id) {
  if (!lastModel) { alert('Сначала запустите полную проверку — источнику нужны строки для обновления.'); return; }
  const seq = ++runSeq;
  const tRun = Date.now();
  const diList = activeDomainIdxs();
  if (!diList.length) { alert('Отметьте хотя бы один домен.'); return; }
  const g = getGroup(lastModel, id);
  if (!g) return;
  const keys = new Set(g.rows.filter(r => !r.isMsg && selGet(r.key) && !isRowOkHidden(lastModel, r)).map(r => r.key));
  if (!keys.size) { log(`перепроверка ${g.title}: нет выбранных точек`, 'warn'); return; }
  log(`↻ перепроверка источника «${g.title}»: ${keys.size} точек × ${diList.length} домен(ов)`);
  setAction(`перепроверяю «${g.title}»…`);
  startRunIndicator(`перепроверка «${g.title}»`);
  markLoading(lastModel, diList, keys);
  renderRows(lastModel);
  if (id === 'local') await runLocal(lastModel, seq, diList, keys);
  else if (id === 'ch') await runCh(lastModel, seq, diList, keys);
  else if (id === 'gp') await runGp(lastModel, seq, diList, keys);
  if (seq !== runSeq) return;
  finalize(lastModel, seq, tRun);
}

/* универсальный перезапуск набора точек */
async function recheckKeys(keys, label) {
  if (!lastModel || !keys.size) return;
  const diList = activeDomainIdxs();
  if (!diList.length) { alert('Отметьте хотя бы один домен.'); return; }
  const seq = ++runSeq;
  const tRun = Date.now();
  const rf = new Set(keys);
  log(`↻ ${label}: ${keys.size} точек × ${diList.length} домен(ов)`);
  setAction(`${label}…`);
  startRunIndicator(label);
  markLoading(lastModel, diList, rf);
  renderRows(lastModel);
  await runLocal(lastModel, seq, diList, rf);
  if (seq !== runSeq) return;
  await runCh(lastModel, seq, diList, rf);
  if (seq !== runSeq) return;
  await runGp(lastModel, seq, diList, rf);
  if (seq !== runSeq) return;
  finalize(lastModel, seq, tRun);
}

function failedKeys(rows, diList) {
  const keys = new Set();
  for (const r of rows) {
    if (r.isMsg) continue;
    if (isRowOkHidden(lastModel, r)) continue;   // свёрнутые успешные не перепроверяем
    if (diList.some(di => r.cells[di] && isFailed(r.cells[di]))) keys.add(r.key);
  }
  return keys;
}

async function recheckFailed() {
  if (!lastModel) { alert('Сначала запустите полную проверку.'); return; }
  const rows = lastModel.groups.flatMap(g => g.rows);
  const keys = failedKeys(rows, activeDomainIdxs());
  if (!keys.size) { log('↻ упавшие: всё зелёное, перепроверять нечего', 'ok'); return; }
  await recheckKeys(keys, 'перезапуск упавших');
}

/* упавшие только внутри одной группы */
async function reCheckGroupFailed(gid) {
  if (!lastModel) return;
  const g = getGroup(lastModel, gid);
  if (!g) return;
  const keys = failedKeys(g.rows, activeDomainIdxs());
  if (!keys.size) { log(`↻ «${g.title}»: упавших нет`, 'ok'); return; }
  await recheckKeys(keys, `упавшие «${g.title}»`);
}

/* одна точка */
async function reCheckRow(key) {
  if (!lastModel) return;
  const r = getRow(lastModel, key);
  if (!r || r.isMsg) return;
  await recheckKeys(new Set([key]), `точка «${r.title}»`);
}

/* одна ячейка (точка × домен) */
async function reCheckCell(key, di) {
  if (!lastModel) return;
  const r = getRow(lastModel, key);
  if (!r || r.isMsg) return;
  if (!selGet(key)) { alert('Точка выключена чекбоксом — включите её, чтобы перепроверить ячейку.'); return; }
  const seq = ++runSeq;
  const tRun = Date.now();
  r.cells[di] = { loading: true };
  renderRows(lastModel);
  log(`⟳ ячейка: «${r.title}» × ${shortDomain(lastModel.domains[di])}`);
  setAction(`перепроверяю одну ячейку…`);
  startRunIndicator('перепроверка ячейки');
  const rf = new Set([key]);
  if (key.startsWith('ch:')) await runCh(lastModel, seq, [di], rf);
  else if (key.startsWith('gp:')) await runGp(lastModel, seq, [di], rf);
  else await runLocal(lastModel, seq, [di], rf);   // local-browser + daemon:*
  if (seq !== runSeq) return;
  finalize(lastModel, seq, tRun);
}

/* ---------------- прогрев VPN (пинг всех выходов) ---------------- */
async function warmupLocal() {
  const j = await daemonPing();
  if (!j || !j.ok) { log('прогрев: демон не отвечает', 'err'); setAction('прогрев невозможен — демон не отвечает'); return; }
  const btn = document.getElementById('btnWarmup');
  btn.disabled = true; btn.textContent = '♨ Прогреваю…';
  setAction('прогрев VPN: пингую каждый выход…');
  log(`прогрев: пингую ${(j.exits || []).length} выход(ов) через trace cloudflare…`);
  const t0 = Date.now();
  try {
    const r = await dFetch('/warmup', { signal: AbortSignal.timeout(300000) });
    const w = await r.json();
    if (!w.ok) throw new Error(w.error || 'демон вернул ошибку');
    let alive = 0, dead = 0;
    for (const [id, res] of Object.entries(w.results || {})) {
      const ex = daemonExits.find(e => e.id === id);
      if (!ex) continue;
      if (res.code >= 200 && res.code < 400) {
        alive++;
        ex.status = `OK ${res.ms}мс · exit ${res.ip || '?'} (${res.loc || '??'})`;
      } else {
        dead++;
        ex.status = `⚠ мёртв — ${res.error || 'нет ответа'}`;
      }
    }
    // подтянем exit-IP из демона и обновим sub строк в текущей модели
    await refreshDaemonState();
    if (lastModel) {
      for (const ex of daemonExits) {
        const row = getRow(lastModel, 'daemon:' + ex.id);
        if (row) row.sub = ex.status || '';
      }
      renderRows(lastModel);
    }
    log(`прогрев завершён за ${((Date.now() - t0) / 1000).toFixed(1)} с — живых выходов: ${alive}, мёртвых: ${dead}`, dead ? 'warn' : 'ok');
    setAction(`прогрев: живых выходов ${alive} / мёртвых ${dead} · ${new Date().toLocaleTimeString('ru-RU')}`);
  } catch (e) {
    log('прогрев: ошибка — ' + (e.message || e), 'err');
    setAction('прогрев завершился с ошибкой');
  }
  btn.disabled = false; btn.textContent = '♨ Прогрев VPN';
}

/* ---------------- демон: статус ---------------- */
async function refreshDaemonState(badge) {
  const j = await daemonPing();
  const dot = document.getElementById('daemonDot');
  if (j && j.ok) {
    dot.className = 'dot dot-green';
    dot.title = 'Сервер проверки — активен';
    daemonExits = j.exits || [];
    if (badge) { badge.textContent = 'демон активен · выходов: ' + daemonExits.length; badge.style.color = 'var(--green)'; }
  } else {
    dot.className = 'dot dot-grey';
    dot.title = 'Сервер проверки не отвечает';
    daemonExits = [];
    if (badge) { badge.textContent = 'демон не отвечает'; badge.style.color = ''; }
  }
  return !!j;
}

/* ---------------- настройки ---------------- */
function openSettings() {
  document.getElementById('setDomains').value = settings.domains.join('\n');
  document.getElementById('setUseCheckHost').checked = settings.useCheckHost;
  document.getElementById('setUseGlobalPing').checked = settings.useGlobalPing;
  document.getElementById('setUseBrowser').checked = !!settings.useBrowser;
  document.getElementById('setDomainFirst').checked = !!settings.domainFirst;
  document.getElementById('setMaxNodes').value = settings.maxNodes;
  document.getElementById('setDaemonPort').value = settings.daemonPort;
  document.getElementById('setExitLabels').value = (settings.exitLabels || []).join(', ');
  document.getElementById('setSubs').value = '';
  document.getElementById('settingsMsg').textContent = '';
  document.getElementById('subsMsg').textContent = '';
  document.getElementById('modal').classList.remove('hidden');
}
function closeSettings() { document.getElementById('modal').classList.add('hidden'); }

/* ---------------- инициализация ---------------- */
document.getElementById('btnClearLog').onclick = () => { document.getElementById('log').innerHTML = ''; };
document.getElementById('btnToggleLog').onclick = () => {
  const w = document.getElementById('logWrap');
  w.classList.toggle('collapsed');
  document.getElementById('btnToggleLog').textContent = w.classList.contains('collapsed') ? '▸ развернуть' : '▾ свернуть';
};
document.getElementById('btnLogFull').onclick = () => {
  const w = document.getElementById('logWrap');
  w.classList.remove('collapsed');
  document.getElementById('btnToggleLog').textContent = '▾ свернуть';
  w.classList.toggle('max');
  document.getElementById('btnLogFull').textContent = w.classList.contains('max') ? '✕' : '⛶';
};
document.getElementById('btnLogWin').onclick = () => {
  const txt = document.getElementById('log').innerText || '(журнал пуст)';
  const w = window.open('', 'geocheck-log', 'width=900,height=600');
  if (!w) { log('не удалось открыть окно — разрешите всплывающие окна', 'warn'); return; }
  w.document.write('<!DOCTYPE html><html><head><meta charset="utf-8"><title>GeoCheck — журнал (снимок)</title>' +
    '<style>body{background:#0d1117;color:#e6edf3;font:12px/1.6 Consolas,monospace;padding:12px;white-space:pre-wrap}' +
    '.t{color:#6e7681}</style></head><body>' +
    txt.replace(/&/g, '&amp;').replace(/</g, '&lt;') +
    '\n\n--- снимок на момент открытия; живой журнал — в основном окне ---</body></html>');
  w.document.close();
};
document.getElementById('chkLogBad').onchange = e => {
  document.getElementById('logWrap').classList.toggle('only-bad', e.target.checked);
};
document.getElementById('btnRun').onclick = runAll;
document.getElementById('btnCsv').onclick = exportCSV;
document.getElementById('btnJson').onclick = exportJSON;
document.getElementById('btnRecheckFailed').onclick = recheckFailed;
document.getElementById('btnWarmup').onclick = warmupLocal;
document.getElementById('chkHide').checked = hideUnchecked;
document.getElementById('chkHide').onchange = e => {
  hideUnchecked = e.target.checked;
  persistSel(); renderRows(lastModel);
};
document.getElementById('btnSettings').onclick = openSettings;
document.getElementById('btnCancel').onclick = closeSettings;
document.getElementById('btnSave').onclick = () => {
  const doms = document.getElementById('setDomains').value.split('\n').map(s => s.trim()).filter(Boolean).map(normUrl);
  settings.domains = doms.length ? doms : settings.domains;
  domSel = null;
  settings.useCheckHost = document.getElementById('setUseCheckHost').checked;
  settings.useGlobalPing = document.getElementById('setUseGlobalPing').checked;
  settings.useBrowser = document.getElementById('setUseBrowser').checked;
  settings.domainFirst = document.getElementById('setDomainFirst').checked;
  settings.maxNodes = Math.min(40, Math.max(5, +document.getElementById('setMaxNodes').value || 30));
  settings.daemonPort = Math.min(65535, Math.max(1024, +document.getElementById('setDaemonPort').value || 8787));
  settings.exitLabels = document.getElementById('setExitLabels').value.split(',').map(s => s.trim()).filter(Boolean);
  saveSettings(); persistSel(); renderDomains(); renderRows(null); closeSettings();
  refreshDaemonState();
};
document.getElementById('btnReset').onclick = () => {
  if (!confirm('Сбросить все настройки (кроме истории и выбора)?')) return;
  settings = { ...DEFAULTS }; domSel = null; saveSettings(); closeSettings();
  renderDomains(); renderRows(null); refreshDaemonState();
};
document.getElementById('btnDaemonPing').onclick = async () => {
  settings.daemonPort = Math.min(65535, Math.max(1024, +document.getElementById('setDaemonPort').value || 8787));
  const badge = document.getElementById('daemonState');
  badge.textContent = 'проверяю…'; badge.style.color = '';
  await refreshDaemonState(badge);
};
document.getElementById('btnSendSubs').onclick = async () => {
  const raw = document.getElementById('setSubs').value.split('\n').map(s => s.trim()).filter(Boolean);
  const msg = document.getElementById('subsMsg');
  if (!raw.length) { msg.textContent = 'пусто — вставьте URL подписки или ссылки vless://…'; return; }
  msg.textContent = 'отправляю на 127.0.0.1…';
  try {
    const r = await dFetch('/set_subscriptions', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        urls: raw.filter(s => /^https?:\/\//i.test(s)),
        inline: [raw.filter(s => !/^https?:\/\//i.test(s)).join('\n')].filter(Boolean),
      }), signal: AbortSignal.timeout(120000),
    });
    const j = await r.json();
    if (j.ok) {
      msg.textContent = 'принято демоном · выходов: ' + (j.exits || []).length + (j.warnings ? ' · ⚠ ' + j.warnings.join('; ') : '');
      document.getElementById('setSubs').value = '';
      await refreshDaemonState(document.getElementById('daemonState'));
    } else { msg.textContent = 'демон: ' + (j.error || 'ошибка'); }
  } catch { msg.textContent = 'демон не отвечает на 127.0.0.1:' + settings.daemonPort; }
};

(async function boot() {
  try {
    const h = await fetch(daemonBase() + '/api/health', { signal: AbortSignal.timeout(5000) });
    const j = await h.json();
    PUBLIC = !!(j && j.public);
  } catch { }
  document.body.classList.toggle('public', PUBLIC);
  renderDomains();
  renderRows(null);
  renderHistory();
  restoreLastRun();
  refreshDaemonState().then(() => renderRows(lastModel)).then(restoreServerRun);
  log('Готово. Отметьте домены и точки, нажмите «Запустить проверку».');
})();
