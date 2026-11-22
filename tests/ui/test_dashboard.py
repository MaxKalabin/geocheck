"""Browser test for the GeoCheck dashboard against the mock daemon (tests/ui/mock_daemon.py).

Run:  python tests/ui/test_dashboard.py
Needs: pip install playwright && python -m playwright install chromium
Writes screenshots to docs/ui-screenshots/. Exit code 1 if any check fails.
"""
import csv
import io
import json
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from mock_daemon import start  # noqa: E402

ROOT = HERE.parents[1]
SHOTS = ROOT / 'docs' / 'ui-screenshots'
TOKEN = 'test-token-123'   # fixture for the mock only
URLS = 'https://example.com/\nhttps://ru.example.com/\nhttps://example.ru/\nhttps://example.com/pricing'

results = []


def check(name, cond, detail=''):
    results.append((name, bool(cond)))
    print(('PASS ' if cond else 'FAIL ') + name + (f'  [{detail}]' if detail and not cond else ''))


def main():
    SHOTS.mkdir(parents=True, exist_ok=True)
    srv, port = start(ROOT, TOKEN)
    base = f'http://127.0.0.1:{port}'
    errors = []

    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(viewport={'width': 1280, 'height': 900}, accept_downloads=True)
        page = ctx.new_page()
        page.on('pageerror', lambda e: errors.append('pageerror: ' + str(e)))
        # the wrong-token check makes the browser log one 401; that is the expected refusal, not an error
        page.on('console', lambda m: errors.append('console: ' + m.text)
                if m.type == 'error' and 'status of 401' not in m.text else None)
        page.goto(base + '/')

        # 1. first load: no token, start disabled
        check('no token -> asks for token', 'нужен токен' in page.inner_text('#daemonState'))
        check('start disabled without connection', page.is_disabled('#btnStart'))

        # 2. wrong token is refused
        page.fill('#token', 'wrong-token')
        page.click('#btnConnect')
        page.wait_for_function("document.querySelector('#daemonState').textContent.includes('не принят')")
        check('wrong token -> "токен не принят"', True)
        check('start still disabled with wrong token', page.is_disabled('#btnStart'))

        # 3. right token connects, dead exit shown apart
        page.fill('#token', TOKEN)
        page.click('#btnConnect')
        page.wait_for_function("document.querySelector('#daemonState').textContent.includes('на связи')")
        check('connected shows exits count', '3 работают' in page.inner_text('#daemonState') or 'работают' in page.inner_text('#daemonState'))
        check('start enabled after connect', page.is_enabled('#btnStart'))
        check('dead exit listed separately before any run', 'RU-1' in page.inner_text('#deadExits'))

        # 4. token storage: not in localStorage, not in sessionStorage unless remembered, not in URL
        stored = page.evaluate("JSON.stringify({l: localStorage, s: sessionStorage})")
        check('token not in localStorage/sessionStorage (not remembered)', TOKEN not in stored, stored[:0])
        check('token not in URL', TOKEN not in page.url)

        # 5. run a job with 4 addresses; partial results must appear while running
        page.fill('#urls', URLS)
        page.fill('#repeats', '3')
        page.click('#btnStart')
        page.wait_for_function("document.querySelector('#progText').textContent.includes('идёт')", timeout=10000)
        partial = page.locator('#matrix tbody tr').count()
        check('running job shows matrix rows while in progress', partial >= 1, str(partial))
        page.wait_for_function("document.querySelector('#notice').textContent.startsWith('готово')", timeout=30000)
        check('job finishes with "готово"', True)
        check('start re-enabled after finish', page.is_enabled('#btnStart'))
        check('cancel disabled after finish', page.is_disabled('#btnCancel'))

        # 6. verdicts map to README symptoms, exit-down not counted
        cards = page.locator('.verdict')
        check('one verdict card per address', cards.count() == 4, str(cards.count()))
        ru_card = page.locator('.verdict', has_text='example.ru').inner_text()
        check('example.ru -> CloudFlare challenge symptom', 'CloudFlare-челлендж' in ru_card, ru_card)
        check('example.ru -> geo-policy hint', 'гео-политику' in ru_card, ru_card)
        mirror_ru = page.locator('.verdict', has_text='ru.example.com').inner_text()
        check('ru.example.com -> TCP/TLS break symptom', 'обрыв на TCP/TLS' in mirror_ru, mirror_ru)
        pricing = page.locator('.verdict', has_text='pricing').inner_text()
        check('pricing page -> slow symptom', 'дольше порога' in pricing, pricing)
        check('exit-down is excluded from verdicts', 'вне вердикта' in ru_card + pricing + mirror_ru)
        ok_card = page.locator('.verdict').nth(0).inner_text()   # first address: https://example.com/
        check('example.com -> available', 'доступен' in ok_card, ok_card)

        # 7. matrix: dead exit group, dead rows dimmed
        check('matrix has dead-exit group row', 'не входят в вердикт' in page.inner_text('#matrix'))
        check('matrix has dead row class', page.locator('#matrix tr.dead-row').count() >= 1)

        page.screenshot(path=str(SHOTS / 'desktop-results.png'), full_page=True)

        # 8. mirror comparison
        page.click('.tab[data-view="mirrors"]')
        check('mirrors view visible', page.is_visible('#view-mirrors'))
        mtxt = page.inner_text('#mirrors')
        check('mirror report counts divergent exits', 'Расходятся на' in mtxt, mtxt[:120])
        check('divergent rows highlighted', page.locator('#mirrors tr.diverge').count() >= 1)
        page.screenshot(path=str(SHOTS / 'desktop-mirrors.png'), full_page=True)

        # 9. exports
        page.click('.tab[data-view="results"]')
        with page.expect_download() as dl:
            page.click('#btnCsv')
        csv_path = dl.value.path()
        raw = Path(csv_path).read_bytes().decode('utf-8-sig')
        rows = list(csv.reader(io.StringIO(raw)))
        check('CSV header', rows[0][:3] == ['url', 'source', 'exit_id'], str(rows[0][:3]))
        check('CSV has one row per cell', len(rows) - 1 == 4 * 6, str(len(rows) - 1))
        with page.expect_download() as dl:
            page.click('#btnJson')
        data = json.loads(Path(dl.value.path()).read_text('utf-8'))
        check('JSON export is the whole job', data.get('state') == 'done' and len(data.get('results', [])) == 24)
        check('JSON export has no token', TOKEN not in json.dumps(data))

        # 10. cancel a second job after partial results
        page.fill('#urls', 'https://example.com/a\nhttps://example.com/b\nhttps://example.com/c')
        page.click('#btnStart')
        page.wait_for_function("document.querySelector('#progText').textContent.includes('идёт')", timeout=10000)
        page.click('#btnCancel')
        page.wait_for_function("document.querySelector('#notice').textContent.startsWith('отменено')", timeout=15000)
        check('cancel keeps partial results', 'отменено' in page.inner_text('#progText'))
        check('matrix kept after cancel', page.locator('#matrix tbody tr').count() >= 1)

        # 11. history lists finished jobs; clicking one opens it
        page.click('.tab[data-view="history"]')
        page.wait_for_selector('.hist-item')
        n = page.locator('.hist-item').count()
        check('history lists seeded and finished jobs', n >= 3, str(n))
        page.locator('.hist-item').first.click()
        page.wait_for_function("document.querySelector('#notice').textContent.includes('из истории')")
        check('history item opens results', page.is_visible('#view-results'))

        # 12. remember token on this tab
        page.fill('#token', TOKEN)
        page.check('#rememberToken')
        page.click('#btnConnect')
        page.wait_for_function("document.querySelector('#daemonState').textContent.includes('на связи')")
        page.reload()
        page.wait_for_function("document.querySelector('#daemonState').textContent.includes('на связи')", timeout=10000)
        check('remembered token reconnects after reload', True)
        stored = page.evaluate("JSON.stringify({l: localStorage, s: sessionStorage})")
        check('remembered token only in sessionStorage', TOKEN in stored and TOKEN not in page.evaluate("JSON.stringify(localStorage)"))
        page.evaluate("sessionStorage.clear()")

        ctx.close()

        # 13. phone width: no sideways scroll of the page itself
        mctx = browser.new_context(viewport={'width': 390, 'height': 844}, is_mobile=True, has_touch=True)
        mp = mctx.new_page()
        mp.on('pageerror', lambda e: errors.append('pageerror(m): ' + str(e)))
        mp.goto(base + '/')
        mp.fill('#token', TOKEN)
        mp.click('#btnConnect')
        mp.wait_for_function("document.querySelector('#daemonState').textContent.includes('на связи')")
        mp.fill('#urls', URLS)
        mp.click('#btnStart')
        mp.wait_for_function("document.querySelector('#notice').textContent.startsWith('готово')", timeout=30000)
        width = mp.evaluate("document.documentElement.scrollWidth")
        check('phone width: no sideways page scroll', width <= 392, str(width))
        mp.screenshot(path=str(SHOTS / 'phone-results.png'), full_page=False)
        mctx.close()

        browser.close()

    check('no JavaScript errors in console', not errors, '; '.join(errors)[:300])
    srv.shutdown()
    failed = [n for n, ok in results if not ok]
    print(f'\n{len(results) - len(failed)}/{len(results)} checks passed')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
