"""Прогон демона с подменённым curl-пробником (сети и ядер нет): контроль выходов, GeoIP,
повторы с большинством, автоисключение, очередь заданий, HTTP-охрана токеном и раздача статики."""
import json
import os
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'daemon'))

import checkdaemon  # noqa: E402
from jobs import Job, JobManager  # noqa: E402

TARGET = 'https://example.invalid/page'
# порт → (страна, которую покажет контрольный сайт) или None (выход мёртв)
CTRL = {21000: 'DE', 21001: 'FI', 21002: None, 21003: 'DE'}
CELLS = {}   # порт → список кодов по вызовам (для повторов)


def fake_probe(url, port=None, capture_body=False):
    if url == checkdaemon.CONTROL_URL:
        loc = CTRL.get(port, 'DE')
        if loc is None:
            return {'code': 0, 'note': 'x', 'errorKind': 'reset'}
        return {'code': 200, 'ms': 20, 'body': f'ip=203.0.113.{port - 21000}\nloc={loc}\n'}
    seq = CELLS.get(port)
    code = seq.pop(0) if seq else 200
    return {'code': code, 'ms': 100}


def _exits():
    def ex(eid, label, port):
        return checkdaemon._new_exit(eid, label, port, 'x')
    return [checkdaemon._new_exit('direct', 'Этот ПК', None, 'x'),
            ex('px0', '\U0001F1E9\U0001F1EA Berlin', 21000),
            ex('px1', 'Netherlands', 21001),
            ex('px2', 'Dead node', 21002),
            ex('px3', 'Germany flaky', 21003)]


@pytest.fixture
def daemon(monkeypatch, tmp_path):
    monkeypatch.setattr(checkdaemon, 'probe', fake_probe)
    monkeypatch.setattr(checkdaemon, 'WORK', str(tmp_path))
    monkeypatch.setitem(checkdaemon.STATE, 'exits', _exits())
    monkeypatch.setitem(checkdaemon.STATE, 'warnings', [])
    CELLS.clear()
    CELLS[21003] = [200, 403, 200]        # два из трёх — ок → статус ok, нестабильно
    yield checkdaemon


def _run(daemon_mod):
    job = Job([TARGET], {'repeats': 3})
    daemon_mod.run_job(job)
    return job


def test_control_geo_repeats_and_exit_down(daemon):
    job = _run(daemon)
    res = job.results
    assert res['px0'][TARGET]['status'] == 'ok'                    # DE заявлена, DE видна
    assert res['px1'][TARGET]['status'] == 'geo_mismatch'          # Netherlands, а видна FI
    assert res['px1'][TARGET]['rawStatus'] == 'ok'
    assert res['px2'][TARGET]['status'] == 'exit_down'             # контроль не прошёл
    flaky = res['px3'][TARGET]
    assert flaky['repeats'] == ['ok', 'fail', 'ok']
    assert flaky['status'] == 'ok' and flaky['stable'] is False
    assert res['direct'][TARGET]['status'] == 'ok'


def test_summary_counts_only_live_matching_exits(daemon):
    job = _run(daemon)
    v = job.summary[TARGET]
    # живые и сверенные: direct, px0, px3 (все ok); geo_mismatch и exit_down в вердикт не идут
    assert (v['ok'], v['fail'], v['live']) == (3, 0, 3)
    assert v['verdict'] == 'ok'


def test_exit_auto_excluded_after_consecutive_control_failures(daemon):
    _run(daemon)
    _run(daemon)
    job3 = _run(daemon)
    dead = next(e for e in daemon.STATE['exits'] if e['id'] == 'px2')
    assert dead['excluded'] is True and dead['fails'] >= 3
    assert job3.results['px2'][TARGET]['status'] == 'excluded'
    assert any(e['id'] == 'px2' and e['excluded'] for e in daemon.public_exits())


def test_reset_exits_clears_exclusion(daemon):
    _run(daemon)
    _run(daemon)
    _run(daemon)
    daemon.reset_exits()
    dead = next(e for e in daemon.STATE['exits'] if e['id'] == 'px2')
    assert dead['excluded'] is False and dead['fails'] == 0


def test_public_exits_has_no_secrets_fields(daemon):
    for e in daemon.public_exits():
        assert set(e) <= {'id', 'label', 'port', 'status', 'exit_ip', 'exit_loc', 'claimed', 'geo', 'fails', 'excluded'}


def test_cancelled_job_stops_before_measuring(daemon):
    job = Job([TARGET], {'repeats': 3})
    job.cancelled.set()
    daemon.run_job(job)
    assert job.results == {}


# ---------------------------------------------------------------- HTTP: token guard, static, async jobs
def _serve(monkeypatch, token):
    monkeypatch.setattr(checkdaemon, 'TOKEN', token)
    srv = ThreadingHTTPServer(('127.0.0.1', 0), checkdaemon.H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _req(port, method, path, token=None, body=None, origin=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(f'http://127.0.0.1:{port}{path}', data=data, method=method)
    if data is not None:
        r.add_header('Content-Type', 'application/json')
    if token:
        r.add_header('Authorization', 'Bearer ' + token)
    if origin:
        r.add_header('Origin', origin)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, resp.headers.get('Content-Type', ''), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get('Content-Type', ''), e.read()


def test_token_required_for_api_static_is_open(daemon, monkeypatch):
    srv = _serve(monkeypatch, 'tok-123')
    port = srv.server_address[1]
    try:
        assert _req(port, 'GET', '/status')[0] == 401
        assert _req(port, 'GET', '/status', token='wrong')[0] == 401
        code, _, body = _req(port, 'GET', '/status', token='tok-123')
        assert code == 200 and json.loads(body)['auth'] == 'token'
        assert _req(port, 'POST', '/jobs', body={'targets': [TARGET]})[0] == 401
        code, ctype, _ = _req(port, 'GET', '/')
        assert code == 200 and ctype.startswith('text/html')
        assert _req(port, 'GET', '/app.js')[0] == 200
        # не-whitelist пути: без токена 401 (охрана раньше статики), с токеном 404 — файлы не отдаются
        for secret in ('/../subs.txt', '/subs.txt', '/user_nodes.txt'):
            assert _req(port, 'GET', secret)[0] == 401
            assert _req(port, 'GET', secret, token='tok-123')[0] == 404
    finally:
        srv.shutdown()


def test_foreign_origin_rejected_even_with_token(daemon, monkeypatch):
    srv = _serve(monkeypatch, 'tok-123')
    port = srv.server_address[1]
    try:
        assert _req(port, 'GET', '/status', token='tok-123', origin='https://evil.example')[0] == 403
    finally:
        srv.shutdown()


def test_loopback_mode_without_token(daemon, monkeypatch):
    srv = _serve(monkeypatch, '')
    port = srv.server_address[1]
    try:
        assert _req(port, 'GET', '/status')[0] == 200
        assert _req(port, 'GET', '/status', origin='https://evil.example')[0] == 403
    finally:
        srv.shutdown()


def test_async_job_over_http_with_partial_progress_and_history_off(daemon, monkeypatch):
    srv = _serve(monkeypatch, 'tok-123')
    port = srv.server_address[1]
    jm = JobManager(daemon.run_job)
    monkeypatch.setattr(daemon, 'JOBS', jm)
    try:
        code, _, body = _req(port, 'POST', '/jobs', token='tok-123',
                             body={'targets': ['example.invalid/page', 'ftp://bad'], 'repeats': 1})
        assert code == 200
        jid = json.loads(body)['id']
        job = jm.get(jid)
        jm.wait(job, 10)
        code, _, body = _req(port, 'GET', f'/jobs/{jid}', token='tok-123')
        snap = json.loads(body)['job']
        assert code == 200 and snap['status'] == 'done'
        assert snap['progress']['total'] == snap['progress']['done'] == len(snap['exits']) * 1
        assert _req(port, 'GET', '/jobs/nope', token='tok-123')[0] == 404
    finally:
        srv.shutdown()
