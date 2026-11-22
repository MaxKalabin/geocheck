"""Сравнение зеркал: один и тот же сайт в нескольких адресах (example.com, ru.example.com, example.ru)
на одном выходе. Вход — уже классифицированные статусы из browser_probe.classify (или curl-классификатора).

Жёсткий антибот (nginx 503) и беды окружения в вердикт не входят: зеркало без вердикта.

Вердикт по выходу:
  no_data     — ни по одному зеркалу нет результата
  all_ok      — все зеркала с данными отвечают нормально
  all_failed  — все зеркала с данными сбоят
  divergent   — одни отвечают, другие сбоят: прямой признак блокировки конкретного адреса
Флаг partial=True — часть зеркал без данных (вердикт считан по остальным).
Выходы из exclude (например «exit down») в вердикт не попадают.
"""
from urllib.parse import urlsplit

# Должно совпадать с daemon/browser_probe.FAILED_STATUSES (проверяется тестом).
FAILED = frozenset({'slow', 'captcha_failed', 'err', 'http_5xx', 'domain_down'})
# Не участвуют в вердикте: жёсткая блокировка nginx 503 (сайт отвечает, но мы его не обходим)
# и беды окружения. Такие зеркала считаются «без данных» (partial=True).
NEUTRAL = frozenset({'hard_block_503', 'no_browser', 'probe_error', None, ''})


def default_group(base_domain):
    """'example.com' -> три зеркала из README: example.com, ru.example.com, example.ru (по умолчанию, можно задать своё)."""
    host = urlsplit('//' + base_domain).hostname or base_domain
    labels = host.split('.')
    sld = labels[-2] if len(labels) >= 2 else labels[0]
    return [f'https://{sld}.com/', f'https://ru.{sld}.com/', f'https://{sld}.ru/']


def compare(group, cells, exclude=()):
    """group: список URL зеркал.
    cells: {exit_id: {url: {'status': ...}}} — результаты проб.
    Возвращает {exit_id: {'verdict': ..., 'partial': bool, 'statuses': {url: status or None}}}."""
    excluded = set(exclude)
    out = {}
    for exit_id, by_url in cells.items():
        if exit_id in excluded:
            continue
        statuses = {u: ((by_url or {}).get(u) or {}).get('status') for u in group}
        have = {u: s for u, s in statuses.items() if s not in NEUTRAL}
        if not have:
            verdict = 'no_data'
        else:
            failed = [u for u, s in have.items() if s in FAILED]
            ok = [u for u, s in have.items() if s not in FAILED]
            if failed and ok:
                verdict = 'divergent'
            elif failed:
                verdict = 'all_failed'
            else:
                verdict = 'all_ok'
        out[exit_id] = {'verdict': verdict, 'partial': len(have) < len(group), 'statuses': statuses}
    return out
