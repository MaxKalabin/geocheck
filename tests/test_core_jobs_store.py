"""Очередь заданий (daemon/jobs.py) и история SQLite (daemon/store.py). Без сети: runner подменяется."""
import os
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'daemon'))

from jobs import JobManager  # noqa: E402
from store import History  # noqa: E402


def _ok_runner(job):
    for ex in ('direct', 'px0'):
        for t in job.targets:
            job.total += 1
            job.record(ex, t, {'code': 200, 'ms': 5})
    job.exits = [{'id': 'direct'}, {'id': 'px0'}]
    job.summary = {t: {'verdict': 'ok'} for t in job.targets}


def test_job_runs_to_done_with_progress():
    jm = JobManager(_ok_runner)
    job = jm.create(['https://a.example.invalid/'], {})
    jm.wait(job, 5)
    snap = job.snapshot()
    assert snap['status'] == 'done'
    assert snap['progress'] == {'done': 2, 'total': 2}
    assert set(snap['results']) == {'direct', 'px0'}
    assert jm.get(job.id) is job
    assert jm.list(5)[0]['id'] == job.id


def test_queued_job_cancel_is_immediate():
    gate = threading.Event()

    def slow(job):
        gate.wait(5)
        _ok_runner(job)

    jm = JobManager(slow)
    first = jm.create(['https://a.example.invalid/'], {})
    second = jm.create(['https://b.example.invalid/'], {})
    assert jm.cancel(second.id) is True
    assert second.status == 'cancelled' and second.finished_event.is_set()
    gate.set()
    jm.wait(first, 5)
    assert first.status == 'done'
    assert jm.cancel(first.id) is False          # уже завершён


def test_running_job_cancel_sets_flag_and_ends_cancelled():
    started = threading.Event()
    release = threading.Event()

    def runner(job):
        started.set()
        release.wait(5)                  # прогон сам видит флаг через job.cancelled

    jm = JobManager(runner)
    job = jm.create(['https://a.example.invalid/'], {})
    assert started.wait(5)
    assert jm.cancel(job.id) is True
    assert job.cancelled.is_set()
    release.set()
    jm.wait(job, 5)
    assert job.status == 'cancelled'


def test_runner_exception_becomes_error_and_queue_survives():
    def boom(job):
        raise RuntimeError('ядро упало')

    jm = JobManager(boom)
    bad = jm.wait(jm.create(['https://a.example.invalid/'], {}), 5)
    assert bad.status == 'error' and 'RuntimeError' in bad.error
    jm._runner = _ok_runner            # следующий прогон идёт штатно
    good = jm.wait(jm.create(['https://b.example.invalid/'], {}), 5)
    assert good.status == 'done'


def test_history_round_trip_drops_headers_and_body(tmp_path):
    hist = History(str(tmp_path / 'history.db'))
    jm = JobManager(_ok_runner, history=hist)
    job = jm.create(['https://a.example.invalid/'], {})
    jm.wait(job, 5)
    # добавим «секретный» мусор в ячейку — в историю он попасть не должен
    job.results['px0']['https://a.example.invalid/']['headers'] = {'Authorization': 'Bearer SECRET'}
    job.results['px0']['https://a.example.invalid/']['body'] = '<html>page</html>'
    hist.save_run(job)

    runs = hist.list_runs(10)
    assert runs and runs[0]['status'] == 'done'
    rec = hist.get_run(runs[0]['id'])
    blob = repr(rec)
    assert 'SECRET' not in blob and '<html>' not in blob and 'Authorization' not in blob
    assert rec is not None
