"""Классификатор ошибок curl, статусы ячеек, большинство по повторам, вердикт по сайту, цели, GeoIP.
Фикстуры — реальные прогоны run_vko.json и run_browser.json (22.11)."""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'daemon'))
FIXTURES = os.path.join(ROOT, 'tests', 'fixtures')

from classify import (cell_status, claimed_country, classify_curl_error, curl_note, geo_verdict,  # noqa: E402
                      majority, normalize_target, root_of, site_verdict, symptom)


def _load(name):
    with open(os.path.join(FIXTURES, name), encoding='utf-8') as f:
        return json.load(f)


# ---------------------------------------------------------------- curl error classifier
@pytest.mark.parametrize('rc,err,kind', [
    (28, 'curl: (28) Connection timed out after 20001 milliseconds', 'connect_timeout'),
    (28, 'curl: (28) Operation timed out', 'response_timeout'),
    (97, '', 'tunnel_down'),
    (0, 'socks5 connect failed', 'tunnel_down'),
    (35, '', 'tls'), (51, '', 'tls'), (58, '', 'tls'), (60, '', 'tls'),
    (6, '', 'dns'),
    (7, '', 'reset'), (52, '', 'reset'), (56, '', 'reset'),
    (99, '', 'other'),
])
def test_classify_curl_error(rc, err, kind):
    assert classify_curl_error(rc, err) == kind


def test_exit_code_not_matched_by_digits_in_text():
    # раньше подстрока «97» в тексте ошибки давала «туннель»; теперь решает код выхода
    assert classify_curl_error(0, 'error 97 in some body text') == 'other'


def test_curl_note_formats_rc():
    assert 'curl 99' in curl_note('other', 99)
    assert curl_note('dns').startswith('домен не резолвится')


# ---------------------------------------------------------------- cell status
def test_cell_status_basics():
    assert cell_status({'code': 200, 'ms': 900}) == 'ok'
    assert cell_status({'code': 301}) == 'ok'
    assert cell_status({'code': 403}) == 'fail'
    assert cell_status({'code': 0, 'note': 'x'}) == 'fail'
    assert cell_status({'code': 503, 'hardBlock': True}) == 'fail'
    assert cell_status({'exitDown': True, 'code': 0}) == 'exit_down'
    assert cell_status({'skipped': True, 'code': 0}) == 'skipped'


def test_cell_status_slow_only_when_threshold_given():
    assert cell_status({'code': 200, 'ms': 18000}, slow_ms=10000) == 'fail'
    assert cell_status({'code': 200, 'ms': 18000}) == 'ok'
    assert cell_status({'code': 200, 'ms': 3600}, slow_ms=10000) == 'ok'


# ---------------------------------------------------------------- majority of repeats
def test_majority_stable_and_unstable():
    assert majority(['ok', 'ok', 'ok']) == ('ok', True)
    assert majority(['ok', 'ok', 'fail']) == ('ok', False)
    assert majority(['fail', 'fail', 'ok']) == ('fail', False)


def test_majority_tie_is_conservative_fail():
    assert majority(['ok', 'fail']) == ('fail', False)


def test_majority_empty():
    assert majority([]) == ('fail', False)


# ---------------------------------------------------------------- verdict per site
def test_site_verdict_all_ok_partial_down_nodata():
    assert site_verdict(['ok', 'ok'])['verdict'] == 'ok'
    assert site_verdict(['fail', 'fail'])['verdict'] == 'down'
    assert site_verdict(['ok', 'fail'])['verdict'] == 'partial'
    assert site_verdict(['exit_down', 'excluded', 'geo_mismatch'])['verdict'] == 'no_data'


def test_dead_and_mismatched_exits_do_not_count():
    v = site_verdict(['ok', 'exit_down', 'excluded', 'geo_mismatch', 'fail'])
    assert (v['ok'], v['fail'], v['live'], v['excludedOrDown']) == (1, 1, 2, 3)
    assert v['verdict'] == 'partial'


def test_site_verdict_hint_from_symptom():
    statuses = ['fail', 'fail', 'ok']
    results = [{'code': 403, 'cfMitigated': 'challenge'}, {'code': 403, 'cfMitigated': 'challenge'}, {'code': 200}]
    assert site_verdict(statuses, results)['hint'].startswith('CloudFlare-челлендж')


# ---------------------------------------------------------------- symptoms
def test_symptom_mapping():
    assert symptom({'code': 5, 'cfRay': 'x'}) == ''
    assert symptom({'code': 502, 'cfRay': 'abc'}).startswith('origin')
    assert symptom({'code': 0, 'errorKind': 'tls'}).startswith('обрыв')
    assert symptom({'code': 0, 'errorKind': 'dns'}) == 'домен не резолвится'


# ---------------------------------------------------------------- targets
@pytest.mark.parametrize('raw,expected', [
    ('example.com', 'https://example.com'),
    ('  https://example.com/a/b?x=1  ', 'https://example.com/a/b?x=1'),
    ('http://example.com', 'http://example.com'),
    ('ftp://example.com', None),
    ('user:pw@example.com', None),
    ('https://user@example.com/', None),
    ('bad host.com', None),
    ('', None),
    (None, None),
])
def test_normalize_target(raw, expected):
    assert normalize_target(raw) == expected


def test_root_of_page_url():
    assert root_of('https://restaurantguru.ru/Vnukovo-a') == 'https://restaurantguru.ru/'


# ---------------------------------------------------------------- GeoIP
@pytest.mark.parametrize('label,cc', [
    ('\U0001F1E9\U0001F1EA Frankfurt 01', 'DE'),
    ('Netherlands-2', 'NL'),
    ('Istanbul relay', 'TR'),
    ('proxy-3', ''),
    ('', ''),
])
def test_claimed_country(label, cc):
    assert claimed_country(label) == cc


def test_geo_verdict():
    assert geo_verdict('DE', 'DE') == 'match'
    assert geo_verdict('DE', 'nl') == 'mismatch'
    assert geo_verdict('', 'NL') == 'unknown'
    assert geo_verdict('DE', '') == 'unknown'


# ---------------------------------------------------------------- real run fixtures
def _cells(fixture, target):
    res = _load(fixture)['results']
    return [per_target[target] for per_target in res.values()]


def test_fixture_vko_matches_readme_counts():
    """run_vko.json (22.11): 41 выход; 2 ok; 28 nginx-503 + 1 медленный (18.7 с) = 29 fail; 10 skipped («домен не грузится»)."""
    target = 'https://restaurantguru.ru/Vnukovo-International-Airport-VKO-a'
    cells = _cells('run_vko.json', target)
    statuses = [cell_status(c, slow_ms=10000) for c in cells]
    assert len(statuses) == 41
    assert statuses.count('ok') == 2
    assert statuses.count('fail') == 29
    assert statuses.count('skipped') == 10
    v = site_verdict(statuses, cells)
    assert v['verdict'] == 'partial' and v['ok'] == 2 and v['fail'] == 29


def test_fixture_browser_run_has_no_ok_cells():
    target = 'https://restaurantguru.com/Rusiko-Warsaw/reviews?bylang=1'
    cells = _cells('run_browser.json', target)
    statuses = [cell_status(c, slow_ms=10000) for c in cells]
    assert statuses.count('ok') == 0
    assert site_verdict(statuses, cells)['verdict'] == 'down'
