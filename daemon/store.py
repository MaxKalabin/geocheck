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
