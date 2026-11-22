"""GlobalPing как необязательный источник замеров (HTTP из проб по странам).

Без токена работает анонимно с меньшим лимитом. Токен берётся ТОЛЬКО из env GLOBALPING_TOKEN
и уходит только в заголовок Authorization. В URL, логи и ответы демона он не попадает.

Форма запроса и имена полей ответа заданы по документации GlobalPing, как её знает автор
модуля. Живых запросов при написании не делали: при первом реальном прогоне сверить поля.
"""
import json
import os
import re
import urllib.parse
import urllib.request

API = 'https://api.globalping.io/v1/measurements'
TOKEN_ENV = 'GLOBALPING_TOKEN'
USER_AGENT = 'geocheck/1.0'


def token_from_env(env=None):
    env = os.environ if env is None else env
    return (env.get(TOKEN_ENV) or '').strip()


def build_request(url, countries, limit=1):
    """Тело POST-запроса: одна HTTP-проба на URL из указанных стран (коды ISO-3166, две буквы)."""
    parts = urllib.parse.urlsplit(url or '')
    if parts.scheme not in ('http', 'https') or not parts.hostname:
        raise ValueError('нужен URL с http:// или https://')
    codes = [str(c).strip().upper() for c in countries]
    for c in codes:
        if not re.fullmatch(r'[A-Z]{2}', c):
            raise ValueError(f'код страны не похож на ISO-3166: {c!r}')
    if not codes:
        raise ValueError('нужна хотя бы одна страна')
    path = parts.path or '/'
    if parts.query:
        path += '?' + parts.query
    return {
        'type': 'http',
        'target': parts.hostname,
        'locations': [{'country': c, 'limit': max(1, int(limit))} for c in codes],
        'measurementOptions': {'protocol': parts.scheme.upper(), 'request': {'method': 'GET', 'path': path}},
    }


def _headers(token):
    h = {'Content-Type': 'application/json', 'Accept': 'application/json', 'User-Agent': USER_AGENT}
    if token:
        h['Authorization'] = 'Bearer ' + token
    return h


def submit(body, token=None, opener=None, timeout=30):
    """Создать замер. Возвращает {'id': ...} из ответа API. opener подменяется в тестах."""
    req = urllib.request.Request(API, data=json.dumps(body).encode('utf-8'),
                                 headers=_headers(token), method='POST')
    opener = opener or urllib.request.urlopen
    with opener(req, timeout=timeout) as r:
        return json.loads(r.read().decode('utf-8'))


def fetch(measurement_id, token=None, opener=None, timeout=30):
    if not re.fullmatch(r'[A-Za-z0-9_-]{6,64}', str(measurement_id or '')):
        raise ValueError('bad measurement id')
    req = urllib.request.Request(f'{API}/{measurement_id}', headers=_headers(token), method='GET')
    opener = opener or urllib.request.urlopen
    with opener(req, timeout=timeout) as r:
        return json.loads(r.read().decode('utf-8'))


def parse_results(payload):
    """Ответ GET /measurements/{id} -> список {country, status, code, ms, error}. Пустые поля — None."""
    out = []
    for item in (payload or {}).get('results') or []:
        probe = item.get('probe') or {}
        res = item.get('result') or {}
        timings = res.get('timings') or {}
        status = res.get('status')
        out.append({
            'country': probe.get('country'),
            'status': status,
            'code': res.get('statusCode') if isinstance(res.get('statusCode'), int) else None,
            'ms': timings.get('total') if isinstance(timings.get('total'), (int, float)) else None,
            'error': res.get('error') if status == 'failed' else None,
        })
    return out
