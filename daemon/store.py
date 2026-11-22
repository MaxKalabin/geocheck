"""История прогонов в SQLite (stdlib). Пишутся только результаты замеров.

Не пишутся: подписки, URL конфигов, токены, тела ответов, заголовки. Файл лежит в data/ (в .gitignore).
"""
import json
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    created REAL NOT NULL,
    finished REAL,
    status TEXT NOT NULL,
    targets TEXT NOT NULL,
    params TEXT NOT NULL,
    summary TEXT
);
CREATE TABLE IF NOT EXISTS cells (
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    exit_id TEXT NOT NULL,
    exit_label TEXT,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    result TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS cells_run ON cells(run_id);
"""

# поля замера, которые в историю не кладём (объём и шум)
_DROP = ('headers', 'body')


def _cls3(st, res):
    """good — открылось, warn — отказ (4xx, антибот, капча), bad — обрыв, 5xx, выход не работал."""
    if st == 'skipped':
        return None
    if st in ('exit_down', 'excluded'):
        return 'bad'
    code = res.get('code') or 0
    ms = res.get('ms') or 0
    if res.get('hardBlock'):                     # nginx 503 на нашей стороне: IP заблокирован, выход жив
        return 'warn'
    if res.get('captcha') == 'failed':
        return 'bad'
    if res.get('antibot'):                       # 503-заглушка со Send: минимум жёлтый
        return 'bad' if ms > 30000 else 'warn'
    if code == 0 or code >= 500:
        return 'bad'
    if res.get('engine') == 'browser' and ms > 30000:
        return 'bad'
    if 400 <= code < 500 or (res.get('engine') == 'browser' and ms > 10000):
        return 'warn'
    return 'good'


class History:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute('PRAGMA foreign_keys = ON')
        self._db.executescript(SCHEMA)
        self._db.commit()

    def save_run(self, job):
        """Сохранить завершённый прогон (job — объект из jobs.py)."""
        with self._lock:
            self._db.execute(
                'INSERT OR REPLACE INTO runs (id, created, finished, status, targets, params, summary) '
                'VALUES (?,?,?,?,?,?,?)',
                (job.id, job.created, job.finished or time.time(), job.status,
                 json.dumps(job.targets, ensure_ascii=False), json.dumps(job.params, ensure_ascii=False),
                 json.dumps(job.summary, ensure_ascii=False)))
            self._db.execute('DELETE FROM cells WHERE run_id = ?', (job.id,))
            rows = []
            for exit_id, per_target in job.results.items():
                label = job.exit_labels.get(exit_id, '')
                for target, cell in per_target.items():
                    clean = {k: v for k, v in cell.items() if k not in _DROP}
                    rows.append((job.id, exit_id, label, target, cell.get('status', ''),
                                 json.dumps(clean, ensure_ascii=False)))
            self._db.executemany(
                'INSERT INTO cells (run_id, exit_id, exit_label, target, status, result) VALUES (?,?,?,?,?,?)', rows)
            self._db.commit()

    def list_runs(self, limit=20):
        with self._lock:
            rows = self._db.execute(
                'SELECT id, created, finished, status, targets, params, summary FROM runs '
                'ORDER BY created DESC LIMIT ?', (max(1, min(int(limit), 200)),)).fetchall()
        return [_run_row(r, full=False) for r in rows]

    def get_run(self, run_id):
        with self._lock:
            row = self._db.execute(
                'SELECT id, created, finished, status, targets, params, summary FROM runs WHERE id = ?',
                (run_id,)).fetchone()
            if not row:
                return None
            cells = self._db.execute(
                'SELECT exit_id, exit_label, target, status, result FROM cells WHERE run_id = ?',
                (run_id,)).fetchall()
        out = _run_row(row, full=True)
        results = {}
        for c in cells:
            cell = json.loads(c['result'])
            cell['status'] = c['status']
            results.setdefault(c['exit_id'], {})[c['target']] = cell
        out['results'] = results
        out['exitLabels'] = {c['exit_id']: c['exit_label'] for c in cells}
        return out

    def stats(self, days=None, only_target=None):
        """Сводка по всей истории: по выходам, по ресурсам и матрица ресурс × выход.

        Доступность = ok / (ok + fail); exit_down и skipped не считаются (это не вина ресурса).
        only_target(target, params) -> bool отфильтровывает ячейки (для публичной выдачи)."""
        since = time.time() - days * 86400 if days else 0
        with self._lock:
            rows = self._db.execute(
                'SELECT r.id, r.created, r.params, c.exit_id, c.exit_label, c.target, c.status, c.result '
                'FROM cells c JOIN runs r ON r.id = c.run_id WHERE r.created >= ? ORDER BY r.created', (since,)).fetchall()
            runs_total = self._db.execute('SELECT COUNT(*) FROM runs WHERE created >= ?', (since,)).fetchone()[0]
        ex, tg, mx = {}, {}, {}
        last_run, last_targets = 0, set()

        def acc(d, key):
            return d.setdefault(key, {'ok': 0, 'fail': 0, 'down': 0, 'ms': 0, 'msn': 0, 'last': 0, 'good': 0, 'warn': 0, 'bad': 0})
        for r in rows:
            params = json.loads(r['params'] or '{}')
            if only_target and not only_target(r['target'], params):
                continue
            res = json.loads(r['result'])
            tkey = r['target'].rstrip('/')
            st = r['status']
            if st == 'geo_mismatch':
                st = res.get('rawStatus') or 'fail'
            label = r['exit_label'] or r['exit_id']
            for d, key in ((ex, label), (tg, tkey), (mx, (tkey, label))):
                a = acc(d, key)
                a['last'] = max(a['last'], r['created'])
                k3 = _cls3(st, res)
                if k3:
                    a[k3] += 1
                if st == 'ok':
                    a['ok'] += 1
                    if res.get('ms'):
                        a['ms'] += res['ms']
                        a['msn'] += 1
                elif st == 'fail':
                    a['fail'] += 1
                elif st in ('exit_down', 'excluded'):
                    a['down'] += 1
            if r['created'] > last_run:
                last_run, last_targets = r['created'], set()
            if r['created'] == last_run:
                last_targets.add(tkey)

        def fin(a):
            n = a['ok'] + a['fail']
            return {'ok': a['ok'], 'fail': a['fail'], 'down': a['down'], 'checks': n,
                    'availability': round(100 * a['ok'] / n, 1) if n else None,
                    'avgMs': round(a['ms'] / a['msn']) if a['msn'] else None, 'last': a['last'],
                    'good': a['good'], 'warn': a['warn'], 'bad': a['bad'], 'total': a['good'] + a['warn'] + a['bad']}
        return {'runs': runs_total, 'days': days,
                'exits': sorted(({'label': k, **fin(v)} for k, v in ex.items()),
                                key=lambda x: (x['availability'] is None, -(x['availability'] or 0), x['avgMs'] or 1e9)),
                'targets': sorted(({'target': k, 'active': k in last_targets, **fin(v)} for k, v in tg.items()),
                                  key=lambda x: x['target']),
                'matrix': [{'target': t, 'exit': e, **fin(v)} for (t, e), v in mx.items()]}

    def errors(self, days=None, limit=500):
        """Журнал сбоев: время, ресурс, выход, IP и страна выхода, причина (новые сверху)."""
        since = time.time() - days * 86400 if days else 0
        with self._lock:
            rows = self._db.execute(
                'SELECT r.created, c.exit_id, c.exit_label, c.target, c.status, c.result '
                'FROM cells c JOIN runs r ON r.id = c.run_id '
                "WHERE r.created >= ? AND c.status NOT IN ('ok','skipped') ORDER BY r.created DESC LIMIT ?",
                (since, int(limit))).fetchall()
            known = {}
            for kr in self._db.execute(
                    "SELECT exit_label, exit_id, result FROM cells WHERE result LIKE '%\"exitIp\": \"_%' "
                    'ORDER BY rowid DESC LIMIT 20000').fetchall():
                key = kr['exit_label'] or kr['exit_id']
                if key not in known:
                    try:
                        kj = json.loads(kr['result'])
                        if kj.get('exitIp'):
                            known[key] = (kj['exitIp'], kj.get('exitLoc') or '')
                    except ValueError:
                        pass
        out = []
        for r in rows:
            res = json.loads(r['result'])
            if not res.get('exitIp'):
                kip = known.get(r['exit_label'] or r['exit_id'])
                if kip:
                    res['exitIp'], res['exitLoc'] = kip[0], (kip[1] + ' · последний известный') if kip[1] else 'последний известный'
            st = r['status']
            if st == 'geo_mismatch':
                st = res.get('rawStatus') or 'fail'
            k3 = _cls3(st, res)
            if k3 == 'good':
                continue
            kind = ('nginx' if res.get('hardBlock') else 'exit_down' if st in ('exit_down', 'excluded')
                    else 'unreachable' if not res.get('code') else 'http')
            out.append({'at': res.get('at') or r['created'], 'target': r['target'],
                        'exit': r['exit_label'] or r['exit_id'], 'exitIp': res.get('exitIp') or '',
                        'exitLoc': res.get('exitLoc') or '', 'code': res.get('code') or 0, 'kind': kind,
                        'level': k3, 'note': (res.get('symptom') or res.get('note') or res.get('error') or '')[:160]})
        return out

    def close(self):
        with self._lock:
            self._db.close()


def _run_row(r, full):
    out = {'id': r['id'], 'created': r['created'], 'finished': r['finished'], 'status': r['status'],
           'targets': json.loads(r['targets']), 'params': json.loads(r['params']),
           'summary': json.loads(r['summary']) if r['summary'] else None}
    if not full:
        out.pop('params', None)
    return out
