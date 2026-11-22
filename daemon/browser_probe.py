"""Браузерный пробник: python browser_probe.py URL [SOCKS_PORT] -> JSON в stdout.

Открывает URL в браузере (через SOCKS ядра, если задан порт), узнаёт антибот-заглушку
(«unusual traffic», форма .ab_check_form), заглушку со Send жмёт один раз и мерит время;
nginx-503 помечает отдельно (hardBlock) и не обходит.

Запускается демоном как отдельный процесс (`python -I browser_probe.py`), поэтому
модуль самодостаточен: без импорта соседних пакетов.

Настройки через env (все необязательные):
  GC_BROWSER_EXECUTABLE   путь к готовому браузеру (например /usr/bin/chromium на Raspberry Pi)
  GC_LOW_MEM=1            режим для слабого железа: мало памяти, без картинок/шрифтов/медиа
  GC_NO_SANDBOX=1         добавить --no-sandbox (нужно, если Chromium запущен под root в контейнере)
  GC_BROWSER_CONCURRENCY  сколько браузерных проверок идут одновременно (1..8)
  GC_SLOW_MS              порог «медленно», мс (по умолчанию 10000)
  GC_LOAD_TIMEOUT_MS      таймаут загрузки, мс (по умолчанию 45000)
"""
import json
import os
import sys
import time


def _env_int(name, default, lo=None, hi=None):
    try:
        v = int(os.environ.get(name, '') or default)
    except ValueError:
        v = default
    if lo is not None:
        v = max(lo, v)
    if hi is not None:
        v = min(hi, v)
    return v


def _env_flag(name):
    return os.environ.get(name, '').strip().lower() in ('1', 'true', 'yes', 'on')


LOAD_TIMEOUT = _env_int('GC_LOAD_TIMEOUT_MS', 45000, lo=1000)
SLOW_MS = _env_int('GC_SLOW_MS', 10000, lo=0)
LOW_MEM = _env_flag('GC_LOW_MEM')
NO_SANDBOX = _env_flag('GC_NO_SANDBOX')
EXECUTABLE = os.environ.get('GC_BROWSER_EXECUTABLE', '').strip() or None

SEND_SELECTOR = 'form.ab_check_form input[type=submit], form.ab_check_form button[type=submit]'
ANTIBOT_FORM = 'form.ab_check_form'

# Статусы ячейки браузерной проверки. FAILED_STATUSES должен совпадать с
# daemon/sources/mirrors.py (проверяется тестом).
STATUSES = ('ok', 'slow', 'captcha_passed', 'captcha_failed', 'err', 'http_4xx', 'http_5xx',
            'hard_block_503', 'domain_down', 'no_browser', 'probe_error')
FAILED_STATUSES = frozenset({'slow', 'captcha_failed', 'err', 'http_5xx', 'domain_down'})


def browser_concurrency(env=None):
    """Сколько браузерных проверок одновременно. На слабом железе (GC_LOW_MEM) по умолчанию 2."""
    env = os.environ if env is None else env
    default = 2 if str(env.get('GC_LOW_MEM', '')).strip().lower() in ('1', 'true', 'yes', 'on') else 4
    try:
        n = int(env.get('GC_BROWSER_CONCURRENCY') or default)
    except ValueError:
        n = default
    return max(1, min(8, n))


def classify(res, slow_ms=SLOW_MS):
    """Чистая функция: результат пробы -> статус. Порядок приоритетов:
    domain_down > hard_block_503 > captcha_failed > err (код 0) > http_5xx > slow > captcha_passed > http_4xx > ok."""
    if res.get('skipped'):
        return 'domain_down'
    if res.get('hardBlock'):
        return 'hard_block_503'
    if res.get('captcha') == 'failed':
        return 'captcha_failed'
    code = int(res.get('code') or 0)
    if code == 0:
        return 'err'
    if code >= 500:
        return 'http_5xx'
    if (res.get('ms') or 0) > slow_ms:
        return 'slow'
    if res.get('captcha') == 'passed':
        return 'captcha_passed'
    if code >= 400:
        return 'http_4xx'
    return 'ok'


def is_failed(status):
    return status in FAILED_STATUSES


def human(err):
    m = str(err)
    for k, t in (('ERR_TIMED_OUT', 'сайт не грузится: ERR_TIMED_OUT (нет ответа)'),
                 ('Timeout', f'не загрузился за {LOAD_TIMEOUT // 1000}с'),
                 ('ERR_CONNECTION_RESET', 'соединение сброшено'),
                 ('ERR_CONNECTION_CLOSED', 'соединение закрыто'),
                 ('ERR_CONNECTION_REFUSED', 'соединение отклонено'),
                 ('ERR_PROXY', 'прокси/туннель недоступен'),
                 ('ERR_SOCKS', 'прокси/туннель недоступен'),
                 ('ERR_NAME_NOT_RESOLVED', 'домен не резолвится'),
                 ('ERR_SSL', 'ошибка TLS'), ('ERR_CERT', 'ошибка сертификата')):
        if k in m:
            return t
    return m.splitlines()[0][:160] if m else 'неизвестная ошибка'


def _ms(t0):
    return round((time.time() - t0) * 1000)


def antibot(page):
    try:
        if page.locator(ANTIBOT_FORM).count():
            return True
        return 'unusual traffic' in (page.inner_text('body', timeout=3000) or '').lower()
    except Exception:
        return False


def _click_send(page, load_timeout):
    """Нажать Send на заглушке один раз и дождаться загрузки."""
    btn = page.locator(SEND_SELECTOR).first
    try:
        with page.expect_navigation(wait_until='load', timeout=load_timeout):
            btn.click(timeout=5000)
    except Exception:
        pass
    try:
        page.wait_for_load_state('load', timeout=load_timeout)
    except Exception:
        pass


def _body(page):
    try:
        return page.content() or ''
    except Exception:
        return ''


def probe_page(page, url, slow_ms=SLOW_MS, load_timeout=LOAD_TIMEOUT):
    """Проба одной страницы на уже открытой странице браузера (page). Без запуска браузера,
    поэтому тестируется на подменах."""
    res = {'code': 0, 'antibot': False, 'captcha': None, 'engine': 'browser'}
    t0 = time.time()
    try:
        r = page.goto(url, wait_until='load', timeout=load_timeout)
        res['msLanding'] = _ms(t0)
        res['code'] = r.status if r else 0
        if antibot(page):
            res['antibot'] = True
            res['landingCode'] = res['code']
            t1 = time.time()
            _click_send(page, load_timeout)
            res['msAfterCaptcha'] = _ms(t1)
            if antibot(page):
                res['captcha'] = 'failed'
                res['note'] = 'заглушка со Send: после нажатия страница не открылась'
            else:
                res['captcha'] = 'passed'
                res['code'] = 200
                res['note'] = 'заглушка со Send пройдена одним нажатием; время — по факту загрузки'
        res['ms'] = _ms(t0)
        if not res['antibot'] and res['code'] == 503:
            body = _body(page)
            if 'Service Temporarily Unavailable' in body and 'nginx' in body.lower():
                res['hardBlock'] = True
                res['note'] = 'жёсткий антибот: nginx 503 Service Temporarily Unavailable (не обходим, отдельно от заглушки Send)'
            else:
                res['note'] = '503 от сайта'
        elif not res['antibot'] and res['code'] >= 500:
            res['note'] = f"{res['code']} от сайта"
    except Exception as e:
        res['code'] = 0
        res['ms'] = _ms(t0)
        res['note'] = human(e)
    res['status'] = classify(res, slow_ms)
    return res


LAUNCH_CHANNELS = ('chrome', 'msedge', None)   # None = Chromium, поставленный через `playwright install chromium`


def launch_args(low_mem=LOW_MEM, no_sandbox=NO_SANDBOX):
    args = ['--disable-blink-features=AutomationControlled']
    if no_sandbox:
        args.append('--no-sandbox')
    if low_mem:
        args += ['--disable-dev-shm-usage', '--disable-gpu', '--js-flags=--max-old-space-size=192']
    return args


def launch_browser(pw, port=None, low_mem=LOW_MEM, executable=EXECUTABLE, no_sandbox=NO_SANDBOX):
    """Запуск браузера с откатом: готовый путь (GC_BROWSER_EXECUTABLE) -> Chrome -> Edge -> встроенный Chromium."""
    kw = {'headless': True, 'args': launch_args(low_mem, no_sandbox)}
    if port:
        kw['proxy'] = {'server': f'socks5://127.0.0.1:{port}'}
    if executable:
        return pw.chromium.launch(executable_path=executable, **kw)
    last = None
    for ch in LAUNCH_CHANNELS:
        try:
            k = dict(kw)
            if ch:
                k['channel'] = ch
            return pw.chromium.launch(**k)
        except Exception as e:
            last = e
    raise last


def _block_heavy(ctx):
    """Режим слабого железа: не грузить картинки, шрифты и медиа (статус страницы и антибот-форма это не меняют)."""
    def handler(route):
        if route.request.resource_type in ('image', 'media', 'font'):
            route.abort()
        else:
            route.continue_()
    ctx.route('**/*', handler)


def run(url, port, low_mem=LOW_MEM):
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        try:
            br = launch_browser(pw, port, low_mem)
        except Exception as e:
            # Беда окружения, а не сайта: статус no_browser, в сбои выхода не попадает.
            return {'code': 0, 'engine': 'browser', 'status': 'no_browser',
                    'note': 'не найден браузер: нет Chrome/Edge и встроенного Chromium (python -m playwright install chromium или GC_BROWSER_EXECUTABLE)',
                    'error': str(e)[:300]}
        try:
            ctx = br.new_context(ignore_https_errors=True, locale='ru-RU')
            if low_mem:
                _block_heavy(ctx)
            return probe_page(ctx.new_page(), url)
        finally:
            try:
                br.close()
            except Exception:
                pass


if __name__ == '__main__':
    u = sys.argv[1]
    p = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else None
    try:
        out = run(u, p)
    except Exception as e:
        out = {'code': 0, 'note': 'ошибка браузерного пробника', 'error': str(e)[:300], 'status': 'probe_error'}
    print(json.dumps(out, ensure_ascii=False))
