"""Необязательные внешние источники замеров. Токены читаются только из env и наружу не отдаются."""
import os

from . import globalping, pingadmin


def source_status(env=None):
    """Для дашборда/эндпоинта статуса: что включено. Значение токена не возвращается, только факт наличия."""
    env = os.environ if env is None else env
    return {
        'globalping': {'enabled': True, 'authenticated': bool(globalping.token_from_env(env))},
        'pingadmin': pingadmin.status(env),
    }
