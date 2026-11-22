"""Адаптер: внутренние структуры демона → контракт /api/* из docs/API.md (его читает app.js).
Чистые функции, без обращения к сети. Секретов здесь нет: выходы описываются без портов и ссылок."""
import datetime


def _iso(ts):
    if not ts:
        return None
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def api_status(cell):
    """Статус ячейки демона → слово из таблицы API."""
    st = cell.get('status')
    if st in ('exit_down', 'excluded'):
        return 'exit-down'
    if st == 'skipped' or cell.get('skipped'):
        return 'domain-down'
    if st == 'geo_mismatch':
        st = cell.get('rawStatus') or 'fail'
    if cell.get('hardBlock'):
        return 'nginx-503'
    if cell.get('captcha') == 'passed':
        return 'antibot-passed'
    if cell.get('captcha') == 'failed':
        return 'antibot-failed'
    code = cell.get('code') or 0
    if st == 'ok':
        return 'ok'
    if code == 403 and 'challenge' in (cell.get('cfMitigated') or '').lower():
        return 'challenge'
    if code >= 500:
        return 'server-error'
    if code >= 400:
        return 'blocked'
    if code == 0:
        return 'network-error'
    return 'slow'          # 2xx/3xx, но признан сбоем: медленно


def _cell(url, ex, cell):
    reps = cell.get('repeats') or []
    return {
        'url': url, 'exitId': ex['id'], 'exitLabel': ex.get('label') or ex['id'],
        'source': 'local', 'country': ex.get('claimed') or ex.get('exit_loc') or None,
        'exitIp': ex.get('exit_ip') or None,
        'status': api_status(cell), 'code': cell.get('code') or 0, 'ms': cell.get('ms'),
        'errorClass': cell.get('errorKind'), 'cfRay': cell.get('cfRay') or None,
        'cfMitigated': cell.get('cfMitigated') or None,
        'note': cell.get('symptom') or cell.get('note') or '',
        'repeats': [{'status': r if isinstance(r, str) else api_status(r), 'code': cell.get('code') or 0,
                     'ms': cell.get('ms')} for r in reps][:3],
    }


def exit_api(ex):
    st = 'down' if (ex.get('excluded') or ex.get('ok') is False) else (
        'up' if ex.get('status') in ('up', 'ok', 'direct') or ex.get('ok') else 'unknown')
    if ex.get('status') == 'down':
        st = 'down'
    if ex.get('port', 1) is None and st == 'unknown':
        st = 'up'          # системный канал: контрольная проверка не нужна
    return {'id': ex['id'], 'label': ex.get('label') or ex['id'],
            'country': ex.get('claimed') or ex.get('exit_loc') or None, 'source': 'local',
            'status': st, 'exitIp': ex.get('exit_ip') or None, 'lastCheckAt': None,
            'consecutiveFailures': ex.get('fails') or 0, 'lastError': None}


def job_api(snap):
    """Снимок Job.snapshot() (или запись истории) → объект задания по контракту."""
    state = {'error': 'failed'}.get(snap.get('status'), snap.get('status'))
    exits = snap.get('exits') or []
    by_id = {e['id']: e for e in exits}
    labels = snap.get('exit_labels') or snap.get('exitLabels') or {}
    results = []
    res = snap.get('results') or {}
    if isinstance(res, dict):
        for eid, cells in res.items():
            ex = by_id.get(eid) or {'id': eid, 'label': labels.get(eid)}
            for url, cell in cells.items():
                results.append(_cell(url, ex, cell))
    prog = snap.get('progress') or {'done': 0, 'total': 0}
    targets = snap.get('targets') or []
    summary = snap.get('summary') or {}
    out = {'id': snap['id'], 'state': state, 'createdAt': _iso(snap.get('created')),
           'finishedAt': _iso(snap.get('finished')), 'urls': targets,
           'options': snap.get('params') or {}, 'progress': dict(prog, stage=''),
           'exits': [exit_api(e) for e in exits], 'results': results,
           'error': snap.get('error') or None, 'warnings': snap.get('warnings') or []}
    if summary:
        fails = sum(1 for r in results if r['status'] in
                    ('slow', 'challenge', 'blocked', 'server-error', 'network-error', 'antibot-failed', 'domain-down'))
        out['summary'] = {'cells': len(results), 'failures': fails}
    return out


def history_item(run):
    item = {'id': run['id'], 'createdAt': _iso(run.get('created')), 'finishedAt': _iso(run.get('finished')),
            'state': {'error': 'failed'}.get(run.get('status'), run.get('status')),
            'urls': run.get('targets') or []}
    return item


def request_to_params(body):
    """Тело POST /api/jobs → (urls, params демона). Источники check-host/GlobalPing обрабатывает демон отдельно."""
    src = body.get('sources') or {}
    return (body.get('urls') or [], {
        'browser': bool(src.get('browser')), 'domainFirst': bool(body.get('domainFirst')),
        'repeats': body.get('repeats'), 'slowMs': body.get('slowMs'),
        'maxNodes': body.get('maxNodes')})
