"""Тесты классификации браузерного пробника на подменах страницы (без реального браузера)."""
import contextlib
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'daemon'))

import browser_probe as bp  # noqa: E402

SEND = bp.SEND_SELECTOR
FORM = bp.ANTIBOT_FORM
NGINX_503 = '<html><head><title>503 Service Temporarily Unavailable</title></head><body><center>nginx</center></body></html>'


class FakeResponse:
    def __init__(self, status):
        self.status = status


class FakeLocator:
    def __init__(self, page, sel):
        self.page, self.sel = page, sel

    @property
    def first(self):
        return self

    def count(self):
        return 1 if self.sel in self.page.present else 0

    def click(self, timeout=None):
        self.page.clicks.append(self.sel)
        self.page.present = set(self.page.after_send['present'])
        self.page.body_text = self.page.after_send['body_text']


class FakePage:
    """Минимальная подмена page из Playwright: только то, что использует probe_page."""

    def __init__(self, status=200, body='<html>ok</html>', present=(), body_text='', after_send=None,
                 goto_error=None):
        self.status = status
        self.body = body
        self.present = set(present)
        self.body_text = body_text
        self.after_send = after_send or {'present': set(), 'body_text': ''}
        self.goto_error = goto_error
        self.clicks = []

    def goto(self, url, wait_until=None, timeout=None):
        if self.goto_error:
            raise self.goto_error
        return FakeResponse(self.status)

    def locator(self, sel):
        return FakeLocator(self, sel)

    def inner_text(self, sel, timeout=None):
        return self.body_text

    def content(self):
        return self.body

    @contextlib.contextmanager
    def expect_navigation(self, **kw):
        yield

    def wait_for_load_state(self, *a, **kw):
        return None


URL = 'https://example.test/page'


def probe(page, **kw):
    return bp.probe_page(page, URL, slow_ms=kw.pop('slow_ms', 10 ** 9), **kw)


# --- обычная страница и коды ---

def test_plain_page_is_ok():
    r = probe(FakePage(status=200))
    assert r['status'] == 'ok'
    assert r['code'] == 200
    assert not bp.is_failed(r['status'])


def test_403_is_not_a_failure():
    r = probe(FakePage(status=403))
    assert r['status'] == 'http_4xx'
    assert not bp.is_failed(r['status'])


def test_plain_503_is_5xx_failure_not_hard_block():
    r = probe(FakePage(status=503, body='<html>Service Unavailable</html>'))
    assert r['status'] == 'http_5xx'
    assert not r.get('hardBlock')
    assert bp.is_failed(r['status'])


def test_nginx_503_is_hard_block_and_not_counted_as_failure():
    r = probe(FakePage(status=503, body=NGINX_503))
    assert r['hardBlock'] is True
    assert r['status'] == 'hard_block_503'
    assert not bp.is_failed(r['status'])
    assert 'не обходим' in r['note']


def test_nginx_503_is_not_sent_through_captcha():
    page = FakePage(status=503, body=NGINX_503)
    probe(page)
    assert page.clicks == []


def test_network_error_is_err():
    r = probe(FakePage(goto_error=Exception('net::ERR_TIMED_OUT at https://example.test')))
    assert r['code'] == 0
    assert r['status'] == 'err'
    assert r['note'].startswith('сайт не грузится: ERR_TIMED_OUT')
    assert bp.is_failed(r['status'])


def test_timeout_message_is_human_readable():
    r = probe(FakePage(goto_error=Exception('Timeout 45000ms exceeded')))
    assert r['status'] == 'err'
    assert 'не загрузился' in r['note']


# --- заглушка со Send ---

def test_send_captcha_passed_with_one_click():
    page = FakePage(status=403, present={FORM}, after_send={'present': set(), 'body_text': 'hello'})
    r = probe(page)
    assert r['antibot'] is True
    assert r['captcha'] == 'passed'
    assert r['code'] == 200
    assert r['status'] == 'captcha_passed'
    assert not bp.is_failed(r['status'])
    assert page.clicks == [SEND]          # Send нажат ровно один раз


def test_send_captcha_failed_when_form_stays():
    page = FakePage(status=403, present={FORM}, after_send={'present': {FORM}, 'body_text': ''})
    r = probe(page)
    assert r['captcha'] == 'failed'
    assert r['status'] == 'captcha_failed'
    assert bp.is_failed(r['status'])


def test_unusual_traffic_text_counts_as_antibot():
    page = FakePage(status=200, body_text='Our systems detected unusual traffic from your network',
                    after_send={'present': set(), 'body_text': 'fine'})
    r = probe(page)
    assert r['antibot'] is True
    assert r['captcha'] == 'passed'


def test_send_captcha_passed_but_slow_is_slow():
    page = FakePage(status=403, present={FORM}, after_send={'present': set(), 'body_text': ''})
    r = probe(page, slow_ms=-1)           # любой замер «медленный»
    assert r['status'] == 'slow'
    assert r['captcha'] == 'passed'
    assert bp.is_failed(r['status'])


def test_slow_page_counts_as_failure():
    r = probe(FakePage(status=200), slow_ms=-1)
    assert r['status'] == 'slow'
    assert bp.is_failed(r['status'])


# --- classify(): приоритеты без браузера ---

@pytest.mark.parametrize('res, expected', [
    ({'skipped': True, 'code': 0}, 'domain_down'),
    ({'code': 503, 'hardBlock': True}, 'hard_block_503'),
    ({'code': 200, 'captcha': 'failed'}, 'captcha_failed'),
    ({'code': 0}, 'err'),
    ({'code': 502}, 'http_5xx'),
    ({'code': 200, 'ms': 11000}, 'slow'),
    ({'code': 200, 'ms': 500, 'captcha': 'passed'}, 'captcha_passed'),
    ({'code': 404, 'ms': 500}, 'http_4xx'),
    ({'code': 200, 'ms': 500}, 'ok'),
])
def test_classify_priorities(res, expected):
    assert bp.classify(res, slow_ms=10000) == expected


def test_domain_down_beats_everything_and_is_failed():
    assert bp.classify({'skipped': True, 'code': 200, 'ms': 1}) == 'domain_down'
    assert bp.is_failed('domain_down')


def test_failed_set_matches_mirrors_module():
    sys.path.insert(0, os.path.join(ROOT, 'daemon'))
    from sources import mirrors
    assert mirrors.FAILED == bp.FAILED_STATUSES


def test_all_statuses_are_known():
    for s in ('ok', 'slow', 'captcha_passed', 'captcha_failed', 'err', 'http_4xx', 'http_5xx',
              'hard_block_503', 'domain_down', 'no_browser', 'probe_error'):
        assert s in bp.STATUSES


# --- запуск браузера: откат и режим слабого железа ---

class FakeChromium:
    def __init__(self, fail_channels=(), fail_all=False):
        self.calls = []
        self.fail_channels = set(fail_channels)
        self.fail_all = fail_all

    def launch(self, **kw):
        self.calls.append(kw)
        if self.fail_all or kw.get('channel') in self.fail_channels:
            raise RuntimeError('Executable doesn\'t exist')
        return object()


class FakePW:
    def __init__(self, chromium):
        self.chromium = chromium


def test_launch_falls_back_chrome_then_edge_then_bundled():
    ch = FakeChromium(fail_channels={'chrome', 'msedge'})
    bp.launch_browser(FakePW(ch))
    channels = [c.get('channel') for c in ch.calls]
    assert channels == ['chrome', 'msedge', None]
    assert 'channel' not in ch.calls[-1]  # последний вариант — встроенный Chromium


def test_launch_uses_explicit_executable_first():
    ch = FakeChromium()
    bp.launch_browser(FakePW(ch), executable='/usr/bin/chromium')
    assert len(ch.calls) == 1
    assert ch.calls[0]['executable_path'] == '/usr/bin/chromium'


def test_launch_raises_when_nothing_works():
    with pytest.raises(RuntimeError):
        bp.launch_browser(FakePW(FakeChromium(fail_all=True)))


def test_low_mem_args_and_socks_proxy():
    ch = FakeChromium()
    bp.launch_browser(FakePW(ch), port=21005, low_mem=True, no_sandbox=True)
    kw = ch.calls[0]
    assert '--disable-dev-shm-usage' in kw['args']
    assert '--no-sandbox' in kw['args']
    assert kw['proxy'] == {'server': 'socks5://127.0.0.1:21005'}


def test_default_args_have_no_low_mem_flags():
    args = bp.launch_args(low_mem=False, no_sandbox=False)
    assert '--disable-dev-shm-usage' not in args
    assert '--no-sandbox' not in args


class FakeRoute:
    def __init__(self, rtype):
        self.request = type('R', (), {'resource_type': rtype})()
        self.action = None

    def abort(self):
        self.action = 'abort'

    def continue_(self):
        self.action = 'continue'


class FakeCtx:
    def __init__(self):
        self.handler = None

    def route(self, pattern, handler):
        self.handler = handler


def test_low_mem_blocks_images_fonts_media_only():
    ctx = FakeCtx()
    bp._block_heavy(ctx)
    for rtype in ('image', 'media', 'font'):
        r = FakeRoute(rtype)
        ctx.handler(r)
        assert r.action == 'abort', rtype
    for rtype in ('document', 'script', 'stylesheet', 'xhr'):
        r = FakeRoute(rtype)
        ctx.handler(r)
        assert r.action == 'continue', rtype


@pytest.mark.parametrize('env, expected', [
    ({}, 4),
    ({'GC_LOW_MEM': '1'}, 2),
    ({'GC_BROWSER_CONCURRENCY': '1'}, 1),
    ({'GC_BROWSER_CONCURRENCY': '99'}, 8),
    ({'GC_BROWSER_CONCURRENCY': '0'}, 1),
    ({'GC_BROWSER_CONCURRENCY': 'abc'}, 4),
    ({'GC_LOW_MEM': '1', 'GC_BROWSER_CONCURRENCY': '3'}, 3),
])
def test_browser_concurrency_cap(env, expected):
    assert bp.browser_concurrency(env) == expected
