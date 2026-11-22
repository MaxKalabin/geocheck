"""Асинхронные прогоны: очередь с одним рабочим потоком, прогресс, частичные результаты, отмена.

Прогоны идут по одному (на Raspberry Pi и на ноутбуке не даём двум прогонам драться за ядра и сеть).
Сам прогон делает функция runner(job), переданная снаружи; она вызывает job.record(...) и
проверяет job.cancelled между замерами.
"""
import queue
import threading
import time
import uuid


class Job:
    def __init__(self, targets, params):
        self.id = uuid.uuid4().hex[:12]
        self.targets = list(targets)
        self.params = dict(params)
        self.status = 'queued'            # queued | running | done | cancelled | error
        self.created = time.time()
        self.started = None
        self.finished = None
        self.total = 0
        self.done = 0
        self.results = {}                 # exit_id -> target -> cell
        self.exit_labels = {}
        self.exits = []                   # публичное состояние выходов (контрольная проверка, GeoIP)
        self.warnings = []
        self.summary = None
        self.error = ''
        self.cancelled = threading.Event()
        self.finished_event = threading.Event()
        self._lock = threading.Lock()

    def record(self, exit_id, target, cell):
        with self._lock:
            self.results.setdefault(exit_id, {})[target] = cell
            self.done += 1

    def snapshot(self, full=True):
        with self._lock:
            out = {'id': self.id, 'status': self.status, 'created': self.created,
                   'started': self.started, 'finished': self.finished,
                   'progress': {'done': self.done, 'total': self.total},
                   'targets': self.targets, 'warnings': list(self.warnings), 'summary': self.summary,
                   'error': self.error}
            if full:
                out['exits'] = list(self.exits)
                out['results'] = {e: dict(t) for e, t in self.results.items()}
            return out


class JobManager:
    def __init__(self, runner, history=None, keep=50):
        self._runner = runner
        self._history = history
        self._keep = keep
        self._jobs = {}
        self._order = []
        self._queue = queue.Queue()
        self._lock = threading.Lock()
        self._worker = threading.Thread(target=self._loop, name='geocheck-jobs', daemon=True)
        self._worker.start()

    def create(self, targets, params):
        job = Job(targets, params)
        with self._lock:
            self._jobs[job.id] = job
            self._order.append(job.id)
            while len(self._order) > self._keep:
                old = self._jobs.get(self._order[0])
                if old and old.status in ('done', 'cancelled', 'error'):
                    self._jobs.pop(self._order.pop(0), None)
                else:
                    break
        self._queue.put(job)
        return job

    def get(self, job_id):
        with self._lock:
            return self._jobs.get(job_id)

    def list(self, limit=20):
        with self._lock:
            ids = self._order[-max(1, min(int(limit), 200)):]
            return [self._jobs[i].snapshot(full=False) for i in reversed(ids) if i in self._jobs]

    def cancel(self, job_id):
        job = self.get(job_id)
        if not job or job.status in ('done', 'cancelled', 'error'):
            return False
        job.cancelled.set()
        if job.status == 'queued':
            job.status = 'cancelled'
            job.finished = time.time()
            job.finished_event.set()
        return True

    def wait(self, job, timeout=None):
        job.finished_event.wait(timeout)
        return job

    def _loop(self):
        while True:
            job = self._queue.get()
            if job.cancelled.is_set() and job.status == 'cancelled':
                continue
            job.status = 'running'
            job.started = time.time()
            try:
                self._runner(job)
                if job.cancelled.is_set():
                    job.status = 'cancelled'
                else:
                    job.status = 'done'
            except Exception as e:   # прогон не должен валить поток очереди
                job.status = 'error'
                job.error = f'{type(e).__name__}: {e}'[:300]
            finally:
                job.finished = time.time()
                if self._history is not None:
                    try:
                        self._history.save_run(job)
                    except Exception as e:
                        job.warnings.append(f'история не сохранена: {type(e).__name__}')
                job.finished_event.set()
