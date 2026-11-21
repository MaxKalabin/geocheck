"""Браузерный пробник: python browser_probe.py URL [SOCKS_PORT] -> JSON в stdout.
Открывает URL в настоящем Chrome/Edge (через SOCKS ядра, если задан порт), узнаёт антибот-заглушку
(«unusual traffic», форма .ab_check_form), заглушку со Send жмёт один раз и мерит время; nginx-503 помечает отдельно (hardBlock)."""
import json
import sys
import time

LOAD_TIMEOUT = 45000


def antibot(page):
    try:
        if page.locator('form.ab_check_form').count():
            return True
        return 'unusual traffic' in (page.inner_text('body', timeout=3000) or '').lower()
    except Exception:
        return False


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
    return m.splitlines()[0][:160]


def run(url, port):
    from playwright.sync_api import sync_playwright
    res = {'code': 0, 'antibot': False, 'captcha': None, 'engine': 'browser'}
    with sync_playwright() as pw:
        br = None
        last = None
        for ch in ('chrome', 'msedge'):
            try:
                kw = {'channel': ch, 'headless': True, 'args': ['--disable-blink-features=AutomationControlled']}
                if port:
                    kw['proxy'] = {'server': f'socks5://127.0.0.1:{port}'}
                br = pw.chromium.launch(**kw)
                break
            except Exception as e:
                last = e
        if not br:
            res['note'] = 'не найден Chrome/Edge для браузерной проверки'
            res['error'] = str(last)[:300]
            return res
        ctx = br.new_context(ignore_https_errors=True, locale='ru-RU')
        page = ctx.new_page()
        t0 = time.time()
        try:
            r = page.goto(url, wait_until='load', timeout=LOAD_TIMEOUT)
            res['msLanding'] = round((time.time() - t0) * 1000)
            res['code'] = r.status if r else 0
            if antibot(page):
                res['antibot'] = True
                res['landingCode'] = res['code']
                btn = page.locator('form.ab_check_form input[type=submit], form.ab_check_form button[type=submit]').first
                t1 = time.time()
                try:
                    with page.expect_navigation(wait_until='load', timeout=LOAD_TIMEOUT):
                        btn.click(timeout=5000)
                except Exception:
                    pass
                try:
                    page.wait_for_load_state('load', timeout=LOAD_TIMEOUT)
                except Exception:
                    pass
                res['msAfterCaptcha'] = round((time.time() - t1) * 1000)
                if antibot(page):
                    res['captcha'] = 'failed'
                    res['note'] = 'заглушка со Send: после нажатия страница не открылась'
                else:
                    res['captcha'] = 'passed'
                    res['code'] = 200
                    res['note'] = 'заглушка со Send пройдена одним нажатием; время — по факту загрузки'
            res['ms'] = round((time.time() - t0) * 1000)
            if not res['antibot'] and res['code'] == 503:
                try:
                    body = page.content()
                except Exception:
                    body = ''
                if 'Service Temporarily Unavailable' in body and 'nginx' in body.lower():
                    res['hardBlock'] = True
                    res['note'] = 'жёсткий антибот: nginx 503 Service Temporarily Unavailable (не обходим, отдельно от заглушки Send)'
                else:
                    res['note'] = '503 от сайта'
            elif not res['antibot'] and res['code'] >= 500:
                res['note'] = f"{res['code']} от сайта"
        except Exception as e:
            res['code'] = 0
            res['ms'] = round((time.time() - t0) * 1000)
            res['note'] = human(e)
        finally:
            try:
                br.close()
            except Exception:
                pass
    return res


if __name__ == '__main__':
    u = sys.argv[1]
    p = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else None
    try:
        out = run(u, p)
    except Exception as e:
        out = {'code': 0, 'note': 'ошибка браузерного пробника', 'error': str(e)[:300]}
    print(json.dumps(out, ensure_ascii=False))
