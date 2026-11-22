"""Классификация ошибок curl, статусы ячеек, большинство по повторам, вердикт по сайту,
нормализация целей (домен / страница) и сверка страны выхода. Без сети, без файлов.
"""
import re
from collections import Counter
from urllib.parse import urlparse

# ---------------------------------------------------------------- curl errors
KIND_NOTES = {
    'connect_timeout': 'нет ответа: соединение не установлено за 20с — сервер/фаервол роняет пакеты',
    'response_timeout': 'сервер отвечал дольше 60с — обрыв по потолку ожидания',
    'tunnel_down': 'туннель не поднялся — ядро sing-box или сервер VPN недоступны',
    'tls': 'ошибка TLS-рукопожатия — режут на пути (DPI/фаервол) или сертификат',
    'dns': 'домен не резолвится',
    'reset': 'соединение сброшено/отказано',
    'other': 'обрыв/таймаут (curl {rc})',
}


def classify_curl_error(rc, stderr=''):
    """Тип ошибки по коду выхода curl (и, где код неоднозначен, по тексту stderr).

    Возвращает ключ из KIND_NOTES. Текст ошибки не попадает в результат целиком.
    """
    low = (stderr or '').lower()
    if rc == 28 and 'connection timed out' in low:
        return 'connect_timeout'
    if rc == 28:
        return 'response_timeout'
    if rc == 97 or 'socks5' in low:
        return 'tunnel_down'
    if rc in (35, 51, 58, 60):
        return 'tls'
    if rc == 6:
        return 'dns'
    if rc in (7, 52, 56):
        return 'reset'
    return 'other'


def curl_note(kind, rc=0):
    return KIND_NOTES.get(kind, KIND_NOTES['other']).format(rc=rc)


# ---------------------------------------------------------------- cell status
def cell_status(res, slow_ms=None):
    """Статус ячейки одного замера: ok | fail | exit_down | skipped.

    exit_down — выход не прошёл контрольную проверку (ставится снаружи через exitDown).
    slow_ms — только браузерный режим: загрузка дольше порога считается сбоем.
    """
    if res.get('exitDown'):
        return 'exit_down'
    if res.get('skipped'):
        return 'skipped'
    code = res.get('code') or 0
    if res.get('hardBlock') or not (200 <= code < 400):
        return 'fail'
    if slow_ms and (res.get('ms') or 0) > slow_ms:
        return 'fail'
    return 'ok'


def majority(statuses):
    """Большинство из повторов. Ничья → fail (консервативно). Возвращает (статус, единогласно?)."""
    if not statuses:
        return 'fail', False
    cnt = Counter(statuses)
    top = max(cnt.values())
    winners = [s for s, c in cnt.items() if c == top]
    winner = 'fail' if 'fail' in winners else winners[0]
    return winner, len(cnt) == 1


# ---------------------------------------------------------------- verdict per site
LIVE = ('ok', 'fail')


def symptom(res):
    """Симптом по таблице README (строка «Интерпретация результатов») или пустая строка."""
    code = res.get('code') or 0
    if code == 403 and 'challenge' in (res.get('cfMitigated') or '').lower():
        return 'CloudFlare-челлендж (403 + cf-mitigated)'
    if code >= 500 and res.get('cfRay'):
        return 'origin не отвечает / CF обрывает сессию (5xx + CF-RAY)'
    kind = res.get('errorKind')
    if kind in ('tls', 'reset', 'connect_timeout', 'response_timeout', 'tunnel_down'):
        return 'обрыв на TCP/TLS: режется сеть или выход'
    if kind == 'dns':
        return 'домен не резолвится'
    return ''


def site_verdict(statuses, results=None):
    """Вердикт по одной цели по статусам её ячеек на живых выходах.

    statuses — список ok/fail/exit_down/geo_mismatch/excluded/skipped (по выходам).
    results  — необязательный список результатов (для подсказки-симптома у сбойных).
    Учитываются только ok и fail: мёртвые, исключённые и не сверенные по стране выходы в вердикт не идут.
    """
    live = [s for s in statuses if s in LIVE]
    ok = live.count('ok')
    fail = live.count('fail')
    if not live:
        verdict = 'no_data'
    elif fail == 0:
        verdict = 'ok'
    elif ok == 0:
        verdict = 'down'
    else:
        verdict = 'partial'
    hint = ''
    if results and fail:
        syms = Counter(symptom(r) for r, s in zip(results, statuses) if s == 'fail')
        syms.pop('', None)
        if syms:
            hint = syms.most_common(1)[0][0]
    return {'verdict': verdict, 'ok': ok, 'fail': fail, 'live': len(live),
            'excludedOrDown': len(statuses) - len(live), 'hint': hint}


# ---------------------------------------------------------------- targets
def normalize_target(raw):
    """Домен или страница → 'https://host[/path]'. Без userinfo и фрагмента.

    Возвращает строку или None, если цель не разбирается.
    """
    s = (raw or '').strip()
    if not s or any(c.isspace() for c in s):
        return None
    if '://' in s:
        if not re.match(r'^https?://', s, re.I):
            return None          # ftp://, file://, ... — не цели
    else:
        s = 'https://' + s
    p = urlparse(s)
    if p.scheme not in ('http', 'https') or not p.hostname or '@' in p.netloc:
        return None
    path = p.path or ''
    out = f'{p.scheme.lower()}://{p.netloc}{path}'
    if p.query:
        out += '?' + p.query
    return out


def root_of(url):
    """https://host/path → https://host/ (корень домена для режима «сначала домен»)."""
    p = urlparse(url)
    return f'{p.scheme}://{p.netloc}/'


# ---------------------------------------------------------------- GeoIP
_FLAG_RE = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')
_COUNTRY_NAMES = [
    (r'germany|deutschland|frankfurt|berlin', 'DE'), (r'netherlands|holland|amsterdam', 'NL'),
    (r'finland|helsinki', 'FI'), (r'sweden|stockholm', 'SE'), (r'france|paris', 'FR'),
    (r'united states|usa|\bus\b|new york|los angeles|chicago|miami', 'US'),
    (r'japan|tokyo', 'JP'), (r'singapore', 'SG'), (r'hong kong|\bhk\b', 'HK'),
    (r'turkey|türkiye|turkiye|istanbul', 'TR'), (r'united kingdom|london|\buk\b', 'GB'),
    (r'poland|warsaw', 'PL'), (r'russia|moscow', 'RU'), (r'estonia|tallinn', 'EE'),
    (r'latvia|riga', 'LV'), (r'lithuania|vilnius', 'LT'), (r'kazakhstan|almaty', 'KZ'),
    (r'switzerland|zurich', 'CH'), (r'austria|vienna', 'AT'), (r'canada|toronto', 'CA'),
    (r'romania|bucharest', 'RO'), (r'bulgaria|sofia', 'BG'), (r'israel|tel aviv', 'IL'),
    (r'emirates|dubai|\buae\b', 'AE'), (r'korea|seoul', 'KR'), (r'india|mumbai', 'IN'),
    (r'brazil|sao paulo', 'BR'), (r'australia|sydney', 'AU'), (r'italy|milan', 'IT'),
    (r'spain|madrid', 'ES'), (r'ukraine|kyiv|kiev', 'UA'),
]


def claimed_country(label):
    """Страна, которую обещает название ноды: флаг-эмодзи или слово. '' если неизвестно."""
    label = label or ''
    m = _FLAG_RE.search(label)
    if m:
        return ''.join(chr(ord(c) - 0x1F1E6 + ord('A')) for c in m.group(0))
    low = label.lower()
    for pattern, cc in _COUNTRY_NAMES:
        if re.search(pattern, low):
            return cc
    return ''


def geo_verdict(claimed, real):
    """match | mismatch | unknown — заявленная страна ноды против страны, которую видит Cloudflare."""
    if not claimed or not real:
        return 'unknown'
    return 'match' if claimed.upper() == real.upper() else 'mismatch'
