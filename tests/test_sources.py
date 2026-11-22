"""Тесты необязательных источников (GlobalPing, ping-admin) и модели сравнения зеркал. Сети нет: opener подменяется."""
import io
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'daemon'))

from sources import globalping, pingadmin, mirrors  # noqa: E402
from sources import source_status  # noqa: E402

SECRET = 'gp_test_token_SECRET_123456'


class FakeOpener:
    """Запоминает запрос и отдаёт заготовленный JSON. Живой сети не трогает."""

    def __init__(self, payload):
        self.payload = payload
        self.requests = []

    def __call__(self, req, timeout=None):
        self.requests.append(req)
        data = json.dumps(self.payload).encode('utf-8')
        return _Resp(data)


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


# --- GlobalPing: токен только из env ---

def test_token_read_from_env_only():
    assert globalping.token_from_env({'GLOBALPING_TOKEN': '  abc  '}) == 'abc'
    assert globalping.token_from_env({}) == ''


def test_source_status_never_returns_token_value():
    st = source_status({'GLOBALPING_TOKEN': SECRET})
    assert st['globalping'] == {'enabled': True, 'authenticated': True}
    assert SECRET not in json.dumps(st)


def test_token_goes_only_to_authorization_header_not_url():
    op = FakeOpener({'id': 'abcdef123456'})
    body = globalping.build_request('https://example.com/a?x=1', ['ru'])
    globalping.submit(body, token=SECRET, opener=op)
    req = op.requests[0]
    assert req.get_header('Authorization') == 'Bearer ' + SECRET
    assert SECRET not in req.full_url
    assert SECRET not in (req.data or b'').decode('utf-8')


def test_anonymous_request_has_no_authorization_header():
    op = FakeOpener({'id': 'abcdef123456'})
    globalping.submit(globalping.build_request('https://example.com/', ['DE']), token=None, opener=op)
    assert op.requests[0].get_header('Authorization') is None


def test_build_request_shape():
    body = globalping.build_request('https://ru.example.com/path?q=1', ['ru', 'de'], limit=2)
    assert body['type'] == 'http'
    assert body['target'] == 'ru.example.com'
    assert body['locations'] == [{'country': 'RU', 'limit': 2}, {'country': 'DE', 'limit': 2}]
    assert body['measurementOptions']['request'] == {'method': 'GET', 'path': '/path?q=1'}


@pytest.mark.parametrize('url, countries', [
    ('ftp://example.com/', ['RU']),
    ('not a url', ['RU']),
    ('https://example.com/', ['RUS']),
    ('https://example.com/', ['--x']),
    ('https://example.com/', []),
])
def test_build_request_rejects_bad_input(url, countries):
    with pytest.raises(ValueError):
        globalping.build_request(url, countries)


def test_fetch_rejects_suspicious_id():
    with pytest.raises(ValueError):
        globalping.fetch('../../etc')


def test_parse_results_handles_missing_fields():
    payload = {'results': [
        {'probe': {'country': 'RU'}, 'result': {'status': 'finished', 'statusCode': 200, 'timings': {'total': 412.5}}},
        {'probe': {'country': 'DE'}, 'result': {'status': 'failed', 'error': 'timeout'}},
        {'probe': {}, 'result': {}},
    ]}
    out = globalping.parse_results(payload)
    assert out[0] == {'country': 'RU', 'status': 'finished', 'code': 200, 'ms': 412.5, 'error': None}
    assert out[1] == {'country': 'DE', 'status': 'failed', 'code': None, 'ms': None, 'error': 'timeout'}
    assert out[2] == {'country': None, 'status': None, 'code': None, 'ms': None, 'error': None}
    assert globalping.parse_results({}) == []


# --- ping-admin: отключён ---

def test_pingadmin_is_disabled_and_does_not_request():
    assert pingadmin.status()['enabled'] is False
    with pytest.raises(RuntimeError):
        pingadmin.check('https://example.com/')
    st = source_status({'PINGADMIN_TOKEN': SECRET})
    assert st['pingadmin']['enabled'] is False
    assert SECRET not in json.dumps(st)


# --- mirrors ---

def test_default_group_from_base_domain():
    assert mirrors.default_group('example.com') == [
        'https://example.com/', 'https://ru.example.com/', 'https://example.ru/']


def test_divergent_when_some_mirrors_fail():
    group = ['https://a.com/', 'https://ru.a.com/', 'https://a.ru/']
    cells = {'exit1': {
        'https://a.com/': {'status': 'ok'},
        'https://ru.a.com/': {'status': 'err'},
        'https://a.ru/': {'status': 'ok'},
    }}
    v = mirrors.compare(group, cells)['exit1']
    assert v['verdict'] == 'divergent'
    assert v['partial'] is False
    assert v['statuses']['https://ru.a.com/'] == 'err'


def test_all_ok_and_all_failed():
    group = ['https://a.com/', 'https://a.ru/']
    cells = {
        'good': {'https://a.com/': {'status': 'ok'}, 'https://a.ru/': {'status': 'captcha_passed'}},
        'bad': {'https://a.com/': {'status': 'hard_block_503'}, 'https://a.ru/': {'status': 'err'}},
    }
    out = mirrors.compare(group, cells)
    assert out['good']['verdict'] == 'all_ok'
    assert out['bad']['verdict'] == 'all_failed'


def test_hard_block_is_left_out_of_mirror_verdict():
    group = ['https://a.com/', 'https://a.ru/']
    cells = {'e': {'https://a.com/': {'status': 'hard_block_503'}, 'https://a.ru/': {'status': 'ok'}}}
    v = mirrors.compare(group, cells)['e']
    assert v['verdict'] == 'all_ok'          # блок не считается ни сбоем, ни успехом
    assert v['partial'] is True


def test_partial_and_no_data():
    group = ['https://a.com/', 'https://ru.a.com/', 'https://a.ru/']
    cells = {'p': {'https://a.com/': {'status': 'err'}}, 'n': {}}
    out = mirrors.compare(group, cells)
    assert out['p'] == {'verdict': 'all_failed', 'partial': True,
                        'statuses': {'https://a.com/': 'err', 'https://ru.a.com/': None, 'https://a.ru/': None}}
    assert out['n']['verdict'] == 'no_data'


def test_excluded_exit_is_left_out_of_verdict():
    group = ['https://a.com/']
    cells = {'down': {'https://a.com/': {'status': 'err'}}, 'up': {'https://a.com/': {'status': 'ok'}}}
    out = mirrors.compare(group, cells, exclude={'down'})
    assert 'down' not in out
    assert out['up']['verdict'] == 'all_ok'
