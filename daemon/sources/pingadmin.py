"""ping-admin.com как источник: ОТКЛЮЧЁН.

В исследовании (README, 2026-11-22) у ping-admin найдена только проверка по кнопке на сайте,
публичного API нет. Поэтому адаптер не делает запросов и токен не читает. Включать, когда
появится документированный API: тогда токен — из env PINGADMIN_TOKEN, как у GlobalPing.
"""
ENABLED = False
REASON = 'ping-admin: публичного API не найдено, есть только проверка по кнопке на сайте'


def status(env=None):
    return {'enabled': ENABLED, 'reason': REASON}


def check(*args, **kwargs):
    raise RuntimeError(REASON)
