#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GeoCheck daemon — проверка доступности доменов и страниц через выходы (VPN-ядра sing-box + системный канал).

Что делает:
  * читает подписки (env RG_SUBS, subs.txt, POST /set_subscriptions) и ссылки из user_nodes.txt — ТОЛЬКО в памяти;
  * разбирает конфиги (parse в linkparse.py), поднимает ядра sing-box на 127.0.0.1:порты (tun не создаёт);
  * перед замерами проверяет каждый выход контрольным сайтом (RG_CONTROL_URL): не прошёл — «выход не работает»;
    сверяет страну, которую видит Cloudflare, с названием ноды (GeoIP);
  * меряет каждую цель 1–3 раза и берёт большинство; выход, который N раз подряд не прошёл контроль,
    исключается (RG_EXCLUDE_AFTER);
  * прогоны — асинхронные задания (POST /jobs, GET /jobs/<id>, отмена), история в SQLite (data/history.db);
  * отдаёт дашборд сам (index.html, app.js, styles.css), Node не нужен.

Секреты: подписки и конфиги не пишутся ни на диск, ни в историю, ни в логи. Токен доступа — только в env.

Переменные окружения:
  RG_DAEMON_PORT (8787)   RG_BIND (127.0.0.1)   RG_TOKEN (пусто = только loopback без токена)
  RG_SUBS, RG_MAX_EXITS (40), RG_IFACE (выключено), SINGBOX_PATH, SINGBOX_MODE (run|srun)
  RG_CONTROL_URL (https://www.cloudflare.com/cdn-cgi/trace), RG_REPEATS (3), RG_EXCLUDE_AFTER (3)
  RG_DATA_DIR (ROOT/data), RG_ORIGINS (доп. разрешённые Origin через запятую)

Запуск:
  python daemon/checkdaemon.py
  RG_BIND=0.0.0.0 RG_TOKEN=... python daemon/checkdaemon.py   # в LAN / Tailscale, только с токеном
"""
import atexit
import glob
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from classify import (cell_status, claimed_country, classify_curl_error, curl_note,  # noqa: E402
                      geo_verdict, majority, normalize_target, root_of, site_verdict, symptom)
import apiv1  # noqa: E402
from jobs import JobManager  # noqa: E402
from linkparse import parse_subscription  # noqa: E402
from store import History  # noqa: E402

VERSION = '2.0'
PORT = int(os.environ.get('RG_DAEMON_PORT', '8787'))
BIND = os.environ.get('RG_BIND', '127.0.0.1').strip() or '127.0.0.1'
TOKEN = os.environ.get('RG_TOKEN', '').strip()
BASE_PORT = 21000
MAX_EXITS = int(os.environ.get('RG_MAX_EXITS', '40'))
REPEATS_DEFAULT = int(os.environ.get('RG_REPEATS', '3'))
EXCLUDE_AFTER = int(os.environ.get('RG_EXCLUDE_AFTER', '3'))
CONTROL_URL = os.environ.get('RG_CONTROL_URL', 'https://www.cloudflare.com/cdn-cgi/trace').strip()
SLOW_MS_DEFAULT = 10000
MAX_TARGETS = 500
MAX_BODY = 1_000_000
UA = 'GeoCheck/2.0 (availability checker)'
ROOT = os.path.dirname(HERE)
DATA_DIR = os.environ.get('RG_DATA_DIR') or os.path.join(ROOT, 'data')
SECRETS_DIR = os.environ.get('RG_SECRETS_DIR') or ROOT   # subs.txt, user_nodes.txt
PUBLIC_PORT = int(os.environ.get('RG_PUBLIC_PORT', '0') or 0)   # 0 = публичной части нет
PUB_MAX_TARGETS = 5
PUB_LIMIT_IP = (6, 600)          # не больше 6 проверок за 10 минут с одного адреса
PUB_LIMIT_ALL = (60, 3600)       # и 60 в час на всех
PUB_MAX_PENDING = 3
FAKE_IP_NET = ipaddress.ip_network('198.18.0.0/15')
STATIC_FILES = ('index.html', 'app.js', 'styles.css', 'compare.html', 'compare.js')
LOOPBACK = ('127.0.0.1', 'localhost', '::1')
# какие страницы вправе дёргать демон (CORS/Origin). Свои: RG_ORIGINS=https://geocheck.example.com,...
ALLOWED_ORIGINS = {'http://127.0.0.1:7100', 'http://localhost:7100'}
ALLOWED_ORIGINS |= {o.strip().rstrip('/') for o in os.environ.get('RG_ORIGINS', '').split(',') if o.strip()}

WORK = None          # приватная временная папка (конфиги ядер); создаётся в main()
JOBS = None          # JobManager; создаётся в main()
HISTORY = None

STATE = {
    'subs_urls': [u for u in re.split(r'[\n;]', os.environ.get('RG_SUBS', '')) if u.strip()],
    'exits': [],     # [{'id','label','port','status','proc','cfg','claimed','fails','excluded','exit_ip','exit_loc','geo'}]
    'lock': threading.Lock(),
    'warnings': [],
}


# ---------------------------------------------------------------- sing-box
def curl_bin():
    return shutil.which('curl') or shutil.which('curl.exe')


def _mode_for(exe):
    env = os.environ.get('SINGBOX_MODE', '').strip()
    if env in ('run', 'srun'):
        return env
    return 'srun' if 'hiddify' in os.path.basename(exe).lower() else 'run'


def find_singbox():
    """Возвращает (exe, mode). Порядок: SINGBOX_PATH → PATH → (Windows) установки Hiddify/Program Files."""
    env = os.environ.get('SINGBOX_PATH', '').strip()
    if env and os.path.exists(env):
        return env, _mode_for(env)
    for name in ('sing-box', 'sing-box.exe', 'HiddifyCore', 'HiddifyCore.exe'):
        found = shutil.which(name)
        if found:
            return found, _mode_for(found)
    if os.name == 'nt':
        roots = [os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Programs'),
                 r'C:\Program Files', r'C:\Program Files (x86)']
        for root in roots:
            for d in glob.glob(os.path.join(root, 'Hiddify*')) + glob.glob(os.path.join(root, '*hiddify*')):
                for pat in ('sing-box*.exe', 'HiddifyCore.exe'):
                    for exe in glob.glob(os.path.join(d, '**', pat), recursive=True):
                        return exe, _mode_for(exe)
    return None, None


def find_physical_interface():
    """Физический интерфейс для route.default_interface — ТОЛЬКО по RG_IFACE. По умолчанию выключено:
    на машине с активным tun-VPN привязка ломает исходящий трафик ядра (проверено 2026-11-21)."""
    env = os.environ.get('RG_IFACE', '').strip()
    if env and env.lower() != 'off':
        return env
    return None


def sb_config(proxy, port):
    proxy = dict(proxy)
    name = proxy.pop('_name', '')
    proxy.pop('tag', None)
    proxy['tag'] = 'proxy'
    cfg = {
        'log': {'level': 'warn', 'timestamp': True},
        'dns': {'strategy': 'ipv4_only'},
        'inbounds': [{'type': 'mixed', 'tag': 'in', 'listen': '127.0.0.1', 'listen_port': port}],
        'outbounds': [proxy, {'type': 'direct', 'tag': 'direct'}],
    }
    iface = find_physical_interface()
    if iface:
        cfg['route'] = {'default_interface': iface, 'auto_detect_interface': False}
    return cfg, name


def resolve_ipv4(host):
    """Резолв через DoH (1.1.1.1), минуя системный DNS tun-VPN (fake-ip!)."""
    import socket
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    try:
        req = urllib.request.Request(
            f'https://1.1.1.1/dns-query?name={host}&type=A',
            headers={'Accept': 'application/dns-json', 'User-Agent': UA})
        with urllib.request.urlopen(req, timeout=10) as r:
            j = json.loads(r.read().decode())
        for a in j.get('Answer', []):
            if a.get('type') == 1:
                return a['data']
    except Exception:
        pass
    return None


# ---------------------------------------------------------------- curl probe
def probe(url, port=None, capture_body=False):
    """curl-замер; port=None → системный маршрут. capture_body=True — тело в res['body'] (для GeoIP)."""
    curl = curl_bin()
    if not curl:
        return {'code': 0, 'note': 'curl не найден', 'errorKind': 'other'}
    if not re.match(r'^https?://\S+$', url or '', re.I):
        return {'code': 0, 'note': 'недопустимый URL (нужен http/https)', 'errorKind': 'other'}
    tmp = WORK or tempfile.gettempdir()
    tid = threading.get_ident()
    hdr = os.path.join(tmp, f'geocheck-h-{tid}.txt')
    body_f = os.path.join(tmp, f'geocheck-b-{tid}.txt')
    fmt = r'\n%{http_code}|%{time_namelookup}|%{time_connect}|%{time_appconnect}|%{time_starttransfer}|%{time_total}|%{remote_ip}'
    cmd = [curl, '-sS', '-4']
    if os.name == 'nt':
        cmd.append('--ssl-no-revoke')   # Schannel: иначе CRYPT_E_REVOCATION_OFFLINE
    cmd += ['-o', body_f if capture_body else os.devnull, '-D', hdr, '-w', fmt,
            '--max-time', '60', '--connect-timeout', '20', '-A', UA]
    if port:
        cmd += ['-x', f'socks5h://127.0.0.1:{port}']
    cmd += ['--', url]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=85)
        out = (p.stdout or '').strip().splitlines()
        code, dns, conn, tls, ttfb, total, ip = 0, '', '', '', '', '', ''
        if out:
            parts = out[-1].split('|')
            if len(parts) >= 7:
                code = int(parts[0] or 0)
                dns, conn, tls, ttfb, total, ip = parts[1:7]
        res = {
            'code': code, 'ip': ip,
            'ms': round(float(total) * 1000) if total else None,
            'timings': f'DNS {dns}s · TCP {conn}s · TLS {tls}s · TTFB {ttfb}s · total {total}s',
            'cfRay': '', 'cfMitigated': '', 'server': '',
        }
        try:
            heads = open(hdr, encoding='utf-8', errors='ignore').read()
            for line in heads.splitlines():
                if ':' not in line:
                    continue
                k, v = line.split(':', 1)
                kl = k.strip().lower()
                if kl == 'cf-ray':
                    res['cfRay'] = v.strip()
                elif kl == 'cf-mitigated':
                    res['cfMitigated'] = v.strip()
                elif kl == 'server':
                    res['server'] = v.strip()
            res['headers'] = '\n'.join([l for l in heads.splitlines()
                                        if re.match(r'^(HTTP/|cf-ray|cf-mitigated|server|location)', l, re.I)])
        except OSError:
            pass
        if not code:
            err = (p.stderr or '').strip()
            kind = classify_curl_error(p.returncode, err)
            res['errorKind'] = kind
            res['note'] = curl_note(kind, p.returncode)
            res['error'] = err[:400]
        if capture_body:
            try:
                res['body'] = open(body_f, encoding='utf-8', errors='ignore').read()
            except OSError:
                res['body'] = ''
        return res
    except Exception as e:
        return {'code': 0, 'note': 'ошибка демона', 'errorKind': 'other', 'error': str(e)[:400]}
    finally:
        for f in (hdr, body_f) if capture_body else (hdr,):
            try:
                os.remove(f)
            except OSError:
                pass


# ---------------------------------------------------------------- lifecycle
def _new_exit(eid, label, port, status):
    return {'id': eid, 'label': label, 'port': port, 'status': status, 'claimed': claimed_country(label),
            'fails': 0, 'excluded': False, 'exit_ip': '', 'exit_loc': '', 'geo': 'unknown'}


def _nodes_path():
    return os.path.join(DATA_DIR, 'nodes.json')


def _load_nodes():
    try:
        with open(_nodes_path(), encoding='utf-8') as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_nodes(reg):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        tmp = _nodes_path() + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(reg, f, ensure_ascii=False)
        os.replace(tmp, _nodes_path())
    except OSError:
        pass


def _node_id(label, used):
    import hashlib
    base = 'n' + hashlib.sha1(label.encode('utf-8')).hexdigest()[:8]
    nid, k = base, 2
    while nid in used:
        nid, k = f'{base}-{k}', k + 1
    used.add(nid)
    return nid


def configure(urls, inline=None):
    warnings = []
    with STATE['lock']:
        for ex in STATE['exits']:
            kill_exit(ex)
        STATE['exits'] = []
        STATE['subs_urls'] = list(urls)
        sb, sb_mode = find_singbox()
        env_sb = os.environ.get('SINGBOX_PATH', '').strip()
        if env_sb and not os.path.exists(env_sb):
            warnings.append('SINGBOX_PATH задан, но файла нет')
        if not sb:
            warnings.append('sing-box не найден — задайте SINGBOX_PATH или положите в PATH. '
                            'Локальных выходов нет, работает только системный канал.')
        texts = list(inline or [])
        for u in urls:
            try:
                req = urllib.request.Request(u, headers={'User-Agent': UA})
                with urllib.request.urlopen(req, timeout=30) as r:
                    texts.append(r.read().decode('utf-8', 'ignore'))
            except Exception as e:
                warnings.append(f'не удалось скачать подписку: {type(e).__name__}')
        proxies = []
        for t in texts:
            proxies.extend(parse_subscription(t))
        if not proxies and texts:
            warnings.append('подписка скачалась, но конфиги не распознаны')
        STATE['exits'].append(_new_exit('direct', 'Этот ПК (системный канал)', None,
                                        'через текущий VPN/провайдера'))
        STATE['sb'] = sb
        STATE['sb_mode'] = sb_mode
        if len(proxies) > MAX_EXITS:
            warnings.append(f'нод в подписках {len(proxies)}, взято первых {MAX_EXITS} (RG_MAX_EXITS)')
        reg = _load_nodes()
        used_ids, seen_ids = set(), set()
        for i, p in enumerate(proxies[:MAX_EXITS]):
            port = BASE_PORT + i
            label = p.get('_name') or f'proxy-{i+1}'
            nid = _node_id(label, used_ids)
            seen_ids.add(nid)
            reg[nid] = {'label': label, 'last_seen': time.time(), 'first_seen': (reg.get(nid) or {}).get('first_seen', time.time())}
            host = p.get('server', '')
            if host and not re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
                ip = resolve_ipv4(host)
                if ip:
                    p['server'] = ip
                else:
                    warnings.append(f'{label}: не удалось резолвить сервер вне tun-DNS')
            ex = _new_exit(nid, label, port, 'запускается…')
            STATE['exits'].append(ex)
            if sb:
                cfg, _ = sb_config(p, port)
                cfg_path = os.path.join(WORK, f'sb-{port}.json')
                with open(cfg_path, 'w', encoding='utf-8') as f:
                    json.dump(cfg, f)
                ex['cfg'] = cfg_path
                if not start_core(ex):
                    warnings.append(f'{label}: sing-box не запустился')
            else:
                ex['status'] = 'нет sing-box'
        if proxies:
            _save_nodes(reg)
            # пропавшие из подписки ноды остаются в списке: недоступны, статистика сохраняется
            for nid, meta in reg.items():
                if nid not in seen_ids:
                    g = _new_exit(nid, meta.get('label') or nid, None, '⚠ нет в подписке — условно недоступна')
                    g['excluded'] = True
                    g['gone'] = True
                    STATE['exits'].append(g)
        STATE['warnings'] = warnings
    return {'exits': public_exits(), 'warnings': warnings}


def start_core(ex):
    sb, sb_mode = STATE.get('sb'), STATE.get('sb_mode')
    if not sb or not ex.get('cfg'):
        return False
    try:
        errf = ex['cfg'] + '.err'
        with open(errf, 'wb') as ef:
            proc = subprocess.Popen([sb, sb_mode, '-c', ex['cfg']],
                                    stdout=subprocess.DEVNULL, stderr=ef, cwd=WORK)
        ex['proc'] = proc
        time.sleep(0.4)
        if proc.poll() is not None:
            ex['status'] = 'ядро не запустилось'
            try:
                err = re.sub(r'\[[0-9;]*m', '', open(errf, encoding='utf-8', errors='ignore').read())
                m = re.search(r'unknown transport type: (\w+)', err)
                if m:
                    ex['status'] = f'⚠ не поддерживается ядром sing-box: транспорт {m.group(1)}'
                elif err.strip():
                    ex['status'] = 'ядро не запустилось: ' + err.strip().splitlines()[-1][:160]
            except OSError:
                pass
            return False
        ex['status'] = f"127.0.0.1:{ex['port']}"
        return True
    except Exception:
        ex['status'] = 'ошибка запуска'
        return False


def ensure_cores():
    """Авто-рестарт ядер, которые умерли со времени последнего прогона."""
    restarted = 0
    with STATE['lock']:
        for ex in STATE['exits']:
            if ex.get('port') is None or not ex.get('cfg'):
                continue
            p = ex.get('proc')
            if p is not None and p.poll() is None:
                continue
            if start_core(ex):
                restarted += 1
    if restarted:
        print(f'ensure_cores: перезапущено ядер sing-box: {restarted}', flush=True)


def kill_exit(ex):
    p = ex.get('proc')
    if p and p.poll() is None:
        try:
            p.terminate()
            p.wait(timeout=5)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    if ex.get('cfg'):
        try:
            os.remove(ex['cfg'])
        except OSError:
            pass


def public_exits():
    keys = ('id', 'label', 'port', 'ok', 'status', 'exit_ip', 'exit_loc', 'claimed', 'geo', 'fails', 'excluded', 'gone')
    return [{k: e.get(k) for k in keys} for e in STATE['exits']]


def reset_exits():
    with STATE['lock']:
        for ex in STATE['exits']:
            ex['fails'] = 0
            ex['excluded'] = False
    return public_exits()


# ---------------------------------------------------------------- control probe + GeoIP
def control_check(ex):
    """Контрольный сайт через выход: жив ли выход и какая страна у его IP. Меняет счётчик отказов."""
    r = probe(CONTROL_URL, ex['port'], capture_body=True)
    ok = 200 <= (r.get('code') or 0) < 400
    ip = loc = ''
    for line in (r.get('body') or '').splitlines():
        if line.startswith('ip='):
            ip = line[3:]
        elif line.startswith('loc='):
            loc = line[4:]
    if ok:
        ex['fails'] = 0
        ex['excluded'] = False
        ex['exit_ip'], ex['exit_loc'] = ip or ex.get('exit_ip', ''), loc
    else:
        ex['fails'] = ex.get('fails', 0) + 1
        if ex['fails'] >= EXCLUDE_AFTER:
            ex['excluded'] = True
    ex['ok'] = ok
    ex['geo'] = geo_verdict(ex.get('claimed', ''), loc if ok else '')
    if ok:
        ex['status'] = f"OK {r.get('ms')}мс · exit {ip or '?'} ({loc or '??'})"
        if ex['geo'] == 'mismatch':
            ex['status'] += f" · ⚠ заявлена {ex.get('claimed') or '?'}"
    elif not str(ex.get('status') or '').startswith(('⚠ не поддерж', 'ядро не запустилось')):
        ex['status'] = '⚠ мёртв — ' + ((r.get('error') or r.get('note') or 'нет ответа')[:120])
    return {'code': r.get('code', 0), 'ms': r.get('ms'), 'ip': ip, 'loc': loc, 'ok': ok,
            'error': (r.get('error') or r.get('note') or '')[:200] if not ok else '',
            'fails': ex['fails'], 'excluded': ex['excluded'], 'geo': ex['geo']}


def warmup():
    """Прогрев: контрольная проверка каждого живого выхода; отдаёт exit-IP и страну."""
    ensure_cores()
    with STATE['lock']:
        exits = list(STATE['exits'])        # и исключённые: прогрев даёт им шанс вернуться
    with ThreadPoolExecutor(max_workers=16) as pool:
        futs = {ex['id']: pool.submit(control_check, ex) for ex in exits if not ex.get('gone')}
        out = {eid: f.result() for eid, f in futs.items()}
    for ex in exits:
        if ex.get('gone'):
            out[ex['id']] = {'code': 0, 'ms': None, 'ip': '', 'loc': '', 'ok': False, 'gone': True,
                             'error': 'нет в подписке', 'fails': ex.get('fails', 0), 'excluded': True, 'geo': 'unknown'}
    return out


# ---------------------------------------------------------------- measurement
def browser_probe(url, port):
    """Проверка настоящим браузером (daemon/browser_probe.py): антибот-заглушка со Send, время загрузки."""
    if not re.match(r'^https?://\S+$', url or '', re.I):
        return {'code': 0, 'note': 'недопустимый URL (нужен http/https)', 'errorKind': 'other'}
    try:
        p = subprocess.run([sys.executable, '-I', os.path.join(HERE, 'browser_probe.py'), url, str(port or '')],
                           capture_output=True, text=True, timeout=150)
        return json.loads((p.stdout or '').strip().splitlines()[-1])
    except Exception as e:
        return {'code': 0, 'note': 'браузерный пробник не ответил', 'errorKind': 'other', 'error': str(e)[:300]}


def _one_probe(ex, target, browser, domain_first):
    fn = browser_probe if browser else probe
    if domain_first:
        root = root_of(target)
        if root != target:
            rr = fn(root, ex['port'])
            if not rr.get('code') and not rr.get('hardBlock'):
                return {'code': 0, 'note': 'домен не грузится — страница не проверялась: ' + (rr.get('note') or ''),
                        'rootCode': 0, 'rootMs': rr.get('ms'), 'skipped': True}
            res = fn(target, ex['port'])
            res['rootCode'], res['rootMs'] = rr.get('code'), rr.get('ms')
            return res
    return fn(target, ex['port'])


def measure_cell(job, ex, target, browser, domain_first, repeats, slow_ms):
    """Один выход × одна цель: несколько повторов, большинство побеждает."""
    if job.cancelled.is_set():
        return
    statuses, reps = [], []
    for _ in range(repeats):
        if job.cancelled.is_set():
            return
        res = _one_probe(ex, target, browser, domain_first)
        statuses.append(cell_status(res, slow_ms if browser else None))
        reps.append(res)
    winner, stable = majority(statuses)
    cell = dict(next(r for r, s in zip(reps, statuses) if s == winner))
    cell['status'] = winner
    cell['repeats'] = statuses
    cell['stable'] = stable
    cell.pop('body', None)
    if winner == 'fail':
        cell['symptom'] = symptom(cell)
    if ex.get('geo') == 'mismatch' and winner in ('ok', 'fail'):
        cell['rawStatus'] = winner
        cell['status'] = 'geo_mismatch'
    job.record(ex['id'], target, cell)


def run_job(job):
    """Раннер прогона (вызывается из рабочего потока JobManager)."""
    p = job.params
    browser = bool(p.get('browser'))
    domain_first = bool(p.get('domainFirst'))
    default_rep = 1 if browser else REPEATS_DEFAULT
    try:
        repeats = max(1, min(3, int(p.get('repeats') or default_rep)))
    except (TypeError, ValueError):
        repeats = default_rep
    try:
        slow_ms = max(1000, int(p.get('slowMs') or SLOW_MS_DEFAULT))
    except (TypeError, ValueError):
        slow_ms = SLOW_MS_DEFAULT
    only = p.get('only')
    if not only:
        ensure_cores()
    with STATE['lock']:
        exits = [e for e in STATE['exits'] if not only or e['id'] in only]
    targets = list(job.targets)
    job.total = len(exits) * len(targets)
    job.warnings.extend(STATE.get('warnings', [])[:5])

    # 1) контрольная проверка выходов (исключённые пропускаем)
    to_check = [ex for ex in exits if not ex.get('excluded') and ex.get('port') is not None]
    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(control_check, to_check))
    if job.cancelled.is_set():
        return
    for ex in exits:
        if ex.get('port') is None:
            ex['ok'] = True          # системный канал не проверяем контрольно — его замеры идут как есть
    job.exits = public_exits()
    job.exit_labels = {ex['id']: ex['label'] for ex in exits}

    # 2) замеры
    workers = 4 if browser else 16
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for ex in exits:
            for t in targets:
                if ex.get('excluded'):
                    job.record(ex['id'], t, {'code': 0, 'status': 'excluded',
                                             'note': f'выход исключён: {EXCLUDE_AFTER} проверок подряд не прошли'})
                elif ex.get('ok') is False:
                    job.record(ex['id'], t, {'code': 0, 'exitDown': True, 'status': 'exit_down',
                                             'note': 'выход не прошёл контрольную проверку — замер не учитывается'})
                else:
                    pool.submit(measure_cell, job, ex, t, browser, domain_first, repeats, slow_ms)
    # ждём пул (выход из with ждёт завершения задач)

    # 3) итог по целям
    summary = {}
    for t in targets:
        statuses, results = [], []
        for ex in exits:
            cell = job.results.get(ex['id'], {}).get(t)
            statuses.append(cell.get('status', 'skipped') if cell else 'skipped')
            results.append(cell or {})
        summary[t] = site_verdict(statuses, results)
    job.summary = summary


def _targets(raw):
    targets, bad = [], 0
    for r in list(raw or [])[:MAX_TARGETS]:
        t = normalize_target(r) if isinstance(r, str) else None
        if t is None:
            bad += 1
        elif t not in targets:
            targets.append(t)
    return targets, bad


# ---------------------------------------------------------------- HTTP
FWD_HOSTS = ('check-host.net', 'api.globalping.io')
CTYPES = {'.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
          '.css': 'text/css; charset=utf-8'}


LAST_MAX = 1_500_000


def _last_path(kind):
    return os.path.join(DATA_DIR, f'lastmodel_{kind}.json')


def _is_default_model(m):
    doms = [str(d).rstrip('/') for d in (m.get('domains') or [])]
    return sorted(doms) == sorted(d.rstrip('/') for d in PUB_DEFAULT_TARGETS)


def scrub_model(m):
    """Сохранённую проверку отдаём публично без IP выходов и сырых ошибок."""
    for g in m.get('groups', []):
        for r in g.get('rows', []):
            if isinstance(r.get('sub'), str):
                r['sub'] = re.sub(r'exit [0-9a-fA-F.:]+ \(', '(', r['sub'])
            for c in (r.get('cells') or {}).values():
                if isinstance(c, dict):
                    for k in ('error', 'headers', 'body'):
                        c.pop(k, None)
    return m


ACTIVITY = {}          # общий статус «идёт проверка» для всех открытых страниц
ACTIVITY_TTL = 20      # нет сигнала дольше — считаем, что вкладку закрыли
_act_lock = threading.Lock()


def activity_set(body):
    if not isinstance(body, dict):
        return False
    rid = str(body.get('id') or '')[:40]
    if not rid:
        return False
    with _act_lock:
        if body.get('end'):
            if ACTIVITY.get('id') == rid:
                ACTIVITY.clear()
            return True
        if ACTIVITY.get('id') not in (None, rid) and time.time() - ACTIVITY.get('updated', 0) < ACTIVITY_TTL:
            return False   # уже идёт чужая проверка
        since = ACTIVITY.get('since') if ACTIVITY.get('id') == rid else time.time()
        ACTIVITY.clear()
        ACTIVITY.update({'id': rid, 'since': since, 'updated': time.time(),
                         'label': str(body.get('label') or '')[:80], 'text': str(body.get('text') or '')[:200]})
    return True


def activity_get():
    with _act_lock:
        if ACTIVITY and time.time() - ACTIVITY.get('updated', 0) < ACTIVITY_TTL:
            a = dict(ACTIVITY)
            a['elapsed'] = int(time.time() - a['since'])
            return a
    return None


def save_lastmodel(m, public):
    if not isinstance(m, dict) or not isinstance(m.get('groups'), list) or not isinstance(m.get('domains'), list):
        return False
    raw = json.dumps(m, ensure_ascii=False)
    if len(raw) > LAST_MAX:
        return False
    if public and not _is_default_model(m):
        return False
    kinds = ['pub'] if public else (['priv', 'pub'] if _is_default_model(m) else ['priv'])
    for k in kinds:
        data = raw if k == 'priv' else json.dumps(scrub_model(json.loads(raw)), ensure_ascii=False)
        tmp = _last_path(k) + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            f.write(data)
        os.replace(tmp, _last_path(k))
    return True


def load_lastmodel(kind):
    for k in ([kind, 'pub'] if kind == 'priv' else ['pub']):
        try:
            with open(_last_path(k), encoding='utf-8') as f:
                return json.load(f)
        except (OSError, ValueError):
            continue
    return None


class H(BaseHTTPRequestHandler):
    server_version = 'GeoCheck'

    def log_message(self, *a):
        pass

    # --- guards
    def _auth_ok(self):
        got = self.headers.get('Authorization', '') or ''
        if got.lower().startswith('bearer '):
            got = got[7:]
        else:
            got = self.headers.get('X-GeoCheck-Token', '') or self.headers.get('X-RG-Token', '') or ''
        return hmac.compare_digest(got.strip().encode(), TOKEN.encode())

    def _guard(self, api=True):
        """Токен задан → API требует токен, Origin — из списка или тот же хост.
        Токена нет → только loopback (защита от DNS-rebinding и чужих сайтов)."""
        host_hdr = (self.headers.get('Host') or '').strip().lower()
        hostname = host_hdr[1:].split(']')[0] if host_hdr.startswith('[') else host_hdr.split(':')[0]
        origin = (self.headers.get('Origin') or '').rstrip('/')
        if TOKEN:
            if api and not self._auth_ok():
                self._json({'ok': False, 'error': 'unauthorized'}, 401)
                return False
            same = origin.lower() in (f'http://{host_hdr}', f'https://{host_hdr}')
            if origin and origin not in ALLOWED_ORIGINS and not same:
                self._json({'ok': False, 'error': 'forbidden (origin)'}, 403)
                return False
            return True
        if hostname not in LOOPBACK or (origin and origin not in ALLOWED_ORIGINS):
            self._json({'ok': False, 'error': 'forbidden (origin/host)'}, 403)
            return False
        return True

    def _cors(self):
        origin = (self.headers.get('Origin') or '').rstrip('/')
        self.send_header('Access-Control-Allow-Origin', origin if origin in ALLOWED_ORIGINS else 'null')
        self.send_header('Vary', 'Origin')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-GeoCheck-Token, X-RG-Token')
        self.send_header('Access-Control-Allow-Private-Network', 'true')

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self._cors()
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _static(self, path):
        name = 'index.html' if path in ('', '/') else path.lstrip('/')
        if name not in STATIC_FILES:
            return self._json({'ok': False, 'error': 'unknown'}, 404)
        try:
            with open(os.path.join(ROOT, name), 'rb') as f:
                data = f.read()
        except OSError:
            return self._json({'ok': False, 'error': 'unknown'}, 404)
        self.send_response(200)
        self.send_header('Content-Type', CTYPES.get(os.path.splitext(name)[1], 'application/octet-stream'))
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get('Content-Length', '0') or 0)
        if n > MAX_BODY:
            raise ValueError('too large')
        return json.loads(self.rfile.read(n) or b'{}')

    # --- forwarder (check-host / GlobalPing, обход блокировок в браузере)
    def fwd_request(self, method):
        from urllib.parse import urlparse, parse_qs, unquote
        qs = parse_qs(urlparse(self.path).query)
        u = unquote(qs.get('url', [''])[0])
        p = urlparse(u)
        if p.scheme != 'https' or p.hostname not in FWD_HOSTS:
            return self._json({'ok': False, 'error': 'host not allowed'}, 403)
        body = None
        if method == 'POST':
            n = int(self.headers.get('Content-Length', '0') or 0)
            if n > MAX_BODY:
                return self._json({'ok': False, 'error': 'too large'}, 413)
            body = self.rfile.read(n) if n else None
        req = urllib.request.Request(u, data=body, method=method, headers={
            'User-Agent': UA, 'Accept': 'application/json',
            'Content-Type': self.headers.get('Content-Type', 'application/json'),
        })
        try:
            with urllib.request.urlopen(req, timeout=90) as r:
                data = r.read()
                self.send_response(r.status)
                self._cors()
                self.send_header('Content-Type', r.headers.get('Content-Type', 'application/json; charset=utf-8'))
        except urllib.error.HTTPError as e:
            data = e.read()
            self.send_response(e.code)
            self._cors()
            self.send_header('Content-Type', 'application/json; charset=utf-8')
        except Exception as e:
            return self._json({'ok': False, 'error': f'{type(e).__name__}: {e}'[:300]}, 502)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # --- /api/*: контракт для app.js (docs/API.md)
    def api_get(self, path):
        qs = self.path.split('?', 1)[1] if '?' in self.path else ''
        if path == '/exits':
            return self._json({'exits': [apiv1.exit_api(e) for e in public_exits()]})
        if path.startswith('/jobs/'):
            job = JOBS.get(path[6:].strip('/'))
            if not job:
                return self._json({'error': 'нет такого задания'}, 404)
            return self._json(apiv1.job_api(job.snapshot(full=True)))
        if path == '/history':
            try:
                lim = int(dict(x.split('=', 1) for x in qs.split('&') if '=' in x).get('limit', 50))
            except ValueError:
                lim = 50
            return self._json({'jobs': [apiv1.history_item(r) for r in HISTORY.list_runs(lim)]})
        if path.startswith('/history/'):
            run = HISTORY.get_run(path[9:].strip('/'))
            if not run:
                return self._json({'error': 'нет такого прогона'}, 404)
            return self._json(apiv1.job_api(run))
        return self._json({'error': 'unknown'}, 404)

    def api_post(self, path):
        try:
            body = self._body()
        except Exception:
            return self._json({'error': 'bad json'}, 400)
        if path == '/jobs':
            urls, params = apiv1.request_to_params(body)
            targets, bad = _targets(urls)
            if not targets:
                return self._json({'error': 'нет адресов'}, 400)
            job = JOBS.create(targets, params)
            return self._json({'id': job.id, 'state': job.status}, 202)
        if path.startswith('/jobs/') and path.endswith('/cancel'):
            jid = path[6:-7].strip('/')
            job = JOBS.get(jid)
            if not job:
                return self._json({'error': 'нет такого задания'}, 404)
            JOBS.cancel(jid)
            return self._json(apiv1.job_api(job.snapshot(full=True)))
        return self._json({'error': 'unknown'}, 404)

    # --- verbs
    def do_OPTIONS(self):
        if not self._guard(api=False):
            return
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        path = self.path.split('?', 1)[0]
        if path in ('/', '') or path.lstrip('/') in STATIC_FILES:
            if not self._guard(api=False):
                return
            return self._static(path)
        if path == '/api/health':
            if not self._guard(api=False):
                return
            return self._json({'ok': True, 'version': VERSION})
        if not self._guard():
            return
        if path.startswith('/api/'):
            return self.api_get(path[4:])
        if path.startswith('/fwd'):
            return self.fwd_request('GET')
        if path == '/status':
            return self._json({'ok': True, 'version': VERSION, 'exits': public_exits(),
                               'auth': 'token' if TOKEN else 'loopback'})
        if path == '/warmup':
            return self._json({'ok': True, 'results': warmup()})
        if path == '/jobs':
            return self._json({'ok': True, 'jobs': JOBS.list()})
        if path.startswith('/jobs/'):
            job = JOBS.get(path[6:].strip('/'))
            if not job:
                return self._json({'ok': False, 'error': 'нет такого задания'}, 404)
            return self._json({'ok': True, 'job': job.snapshot(full=True)})
        if path == '/lastmodel':
            return self._json({'ok': True, 'model': load_lastmodel('priv')})
        if path == '/activity':
            return self._json({'ok': True, 'activity': activity_get()})
        if path == '/stats':
            return self._json({'ok': True, **HISTORY.stats(_days(self.path))})
        if path == '/history':
            return self._json({'ok': True, 'runs': HISTORY.list_runs()})
        if path.startswith('/history/'):
            run = HISTORY.get_run(path[9:].strip('/'))
            if not run:
                return self._json({'ok': False, 'error': 'нет такого прогона'}, 404)
            return self._json({'ok': True, 'run': run})
        return self._json({'ok': False, 'error': 'unknown'}, 404)

    def do_POST(self):
        path = self.path.split('?', 1)[0]
        if not self._guard():
            return
        if path.startswith('/fwd'):
            return self.fwd_request('POST')
        if path.startswith('/api/'):
            return self.api_post(path[4:])
        try:
            body = self._body()
        except ValueError as e:
            code = 413 if str(e) == 'too large' else 400
            return self._json({'ok': False, 'error': 'слишком большой запрос' if code == 413 else 'bad json'}, code)
        except Exception:
            return self._json({'ok': False, 'error': 'bad json'}, 400)

        if path == '/set_subscriptions':
            urls = [u for u in body.get('urls', []) if isinstance(u, str) and u.startswith(('http://', 'https://'))]
            inline = [t for t in body.get('inline', []) if isinstance(t, str) and t.strip()]
            if not urls and not inline:
                return self._json({'ok': False, 'error': 'пустой список URL'}, 400)
            r = configure(urls, inline)
            return self._json({'ok': True, 'exits': r['exits'], 'warnings': r['warnings']})

        if path == '/lastmodel':
            return self._json({'ok': save_lastmodel(body.get('model'), False)})
        if path == '/activity':
            return self._json({'ok': activity_set(body)})

        if path == '/exits/reset':
            return self._json({'ok': True, 'exits': reset_exits()})

        if path == '/run':   # совместимость: синхронный прогон
            targets, bad = _targets(body.get('domains') or body.get('targets'))
            if not targets:
                return self._json({'ok': False, 'error': 'нет доменов или страниц'}, 400)
            job = JOBS.create(targets, _params(body))
            JOBS.wait(job)
            snap = job.snapshot(full=True)
            return self._json({'ok': True, 'id': job.id, 'results': snap['results'],
                               'summary': snap['summary'], 'exits': snap['exits'],
                               'warnings': snap['warnings'] + ([f'{bad} целей отброшено (не похожи на URL)'] if bad else []),
                               'status': snap['status']})

        if path == '/jobs':
            targets, bad = _targets(body.get('targets') or body.get('domains'))
            if not targets:
                return self._json({'ok': False, 'error': 'нет доменов или страниц'}, 400)
            job = JOBS.create(targets, _params(body))
            return self._json({'ok': True, 'id': job.id, 'status': job.status,
                               'skipped': bad, 'total': len(targets)})

        if path.startswith('/jobs/') and path.endswith('/cancel'):
            jid = path[6:-7].strip('/')
            return self._json({'ok': JOBS.cancel(jid)}, 200 if JOBS.get(jid) else 404)

        return self._json({'ok': False, 'error': 'unknown'}, 404)


# ---------------------------------------------------------------- публичная часть
PUB = {'jobs': set(), 'hits': {}, 'all': [], 'lock': threading.Lock()}


def ssrf_reason(target):
    """Почему публичному посетителю нельзя проверять этот адрес (или '' если можно)."""
    from urllib.parse import urlparse
    p = urlparse(target)
    host = (p.hostname or '').lower()
    if p.port not in (None, 80, 443):
        return 'допустимы только порты 80 и 443'
    if not host or '.' not in host or host.endswith(('.local', '.internal', '.lan', '.ts.net', '.localhost')):
        return 'нужен публичный домен'
    try:
        ipaddress.ip_address(host)
        return 'IP-адреса не принимаются, укажите домен'
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return ''            # не резолвится: это и есть результат проверки, внутрь он не ведёт
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0].split('%')[0])
            if ip in FAKE_IP_NET:      # fake-ip у VPN-клиентов (198.18/15): наружу не маршрутизируется
                continue
            if not ip.is_global:
                return 'домен указывает на внутренний адрес'
        except ValueError:
            return 'странный адрес'
    return ''


def pub_rate_ok(key, now=None):
    now = now or time.time()
    with PUB['lock']:
        PUB['all'] = [t for t in PUB['all'] if now - t < PUB_LIMIT_ALL[1]]
        hits = [t for t in PUB['hits'].get(key, []) if now - t < PUB_LIMIT_IP[1]]
        if len(hits) >= PUB_LIMIT_IP[0] or len(PUB['all']) >= PUB_LIMIT_ALL[0]:
            PUB['hits'][key] = hits
            return False
        hits.append(now)
        PUB['hits'][key] = hits
        PUB['all'].append(now)
        if len(PUB['hits']) > 2000:
            PUB['hits'] = {k: v for k, v in PUB['hits'].items() if v and now - v[-1] < PUB_LIMIT_IP[1]}
        return True


def pub_view(job):
    snap = job.snapshot(full=True)
    rows = []
    for t in snap['targets']:
        cell = None
        for cells in snap['results'].values():
            cell = cells.get(t) or cell
        row = {'target': t}
        if cell:
            row.update({'status': apiv1.api_status(cell), 'code': cell.get('code') or 0, 'ms': cell.get('ms'),
                        'note': cell.get('symptom') or cell.get('note') or ''})
        rows.append(row)
    state = {'error': 'failed'}.get(snap['status'], snap['status'])
    return {'id': snap['id'], 'state': state, 'results': rows}


PUB_EXIT_LABEL = 'Сервер проверки'
PUB_DEFAULT_TARGETS = ('https://ru.restaurantguru.com/', 'https://restaurantguru.ru/', 'https://restaurantguru.com/')


def _days(path):
    from urllib.parse import urlparse, parse_qs
    try:
        d = int(parse_qs(urlparse(path).query).get('days', [''])[0])
        return d if 0 < d <= 3650 else None
    except ValueError:
        return None


def pub_exit():
    return {'id': 'direct', 'label': PUB_EXIT_LABEL, 'country': None, 'source': 'local', 'status': 'up',
            'exitIp': None, 'lastCheckAt': None, 'consecutiveFailures': 0, 'lastError': None}


def pub_job_api(job):
    """Задание для публичного дашборда: только прямой канал, без адресов выходов и внутренних параметров."""
    out = apiv1.job_api(job.snapshot(full=True))
    out['exits'] = [pub_exit()]
    for r in out['results']:
        r.update({'exitLabel': PUB_EXIT_LABEL, 'exitIp': None, 'country': None, 'exitId': 'direct'})
    out['options'] = {}
    out['warnings'] = []
    return out


PUB_CELL_DROP = ('error', 'headers', 'body')


def pub_exits_legacy():
    """VPN-выходы для публичной страницы: название и страна видны, IP/порты выходов — нет."""
    out = []
    for e in STATE['exits']:
        if e.get('gone'):
            st = '⚠ нет в подписке — условно недоступна'
        elif e.get('ok') is None:
            st = ''
        elif e.get('ok'):
            st = f"OK · страна выхода {e.get('exit_loc') or '??'}" + (' · ⚠ не совпадает с заявленной' if e.get('geo') == 'mismatch' else '')
        else:
            st = '⚠ выход не отвечает'
        out.append({'id': e['id'], 'label': PUB_EXIT_LABEL if e['id'] == 'direct' else e['label'],
                    'ok': e.get('ok'), 'status': st, 'exit_loc': e.get('exit_loc'),
                    'claimed': e.get('claimed'), 'geo': e.get('geo'), 'excluded': e.get('excluded')})
    return out


def pub_snapshot(job):
    snap = job.snapshot(full=True)
    res = {}
    for eid, cells in snap['results'].items():
        res[eid] = {t: {k: v for k, v in c.items() if k not in PUB_CELL_DROP} for t, c in cells.items()}
    return {'id': snap['id'], 'status': snap['status'], 'progress': snap['progress'], 'targets': snap['targets'],
            'results': res, 'summary': snap['summary'], 'exits': pub_exits_legacy(), 'warnings': []}


FWD_LIMIT = (900, 3600)   # запросов на IP за час через /fwd


def _fwd_ok(key):
    now = time.time()
    with PUB['lock']:
        hits = [t for t in PUB['hits'].get('fwd:' + key, []) if now - t < FWD_LIMIT[1]]
        if len(hits) >= FWD_LIMIT[0]:
            PUB['hits']['fwd:' + key] = hits
            return False
        hits.append(now)
        PUB['hits']['fwd:' + key] = hits
        return True


def _act_ok(client):
    now = time.time()
    with PUB['lock']:
        hits = [t for t in PUB['hits'].get('act:' + client, []) if now - t < 60]
        if len(hits) >= 40:
            PUB['hits']['act:' + client] = hits
            return False
        hits.append(now)
        PUB['hits']['act:' + client] = hits
        return True


class P(BaseHTTPRequestHandler):
    """Публичный обработчик: форма проверки и больше ничего. Слушает loopback, наружу его выводит Tailscale Funnel."""
    server_version = 'GeoCheck-public'

    def log_message(self, *a):
        pass

    def _send(self, obj, code=200, ctype='application/json; charset=utf-8', raw=None):
        body = raw if raw is not None else json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy',
                         "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' https:; img-src 'self' data:")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        return self._send(obj, code)

    def _cors(self):
        pass                      # публичная страница и демон на одном адресе

    fwd_request = H.fwd_request   # только check-host.net и api.globalping.io

    def _client(self):
        xff = (self.headers.get('X-Forwarded-For') or '').split(',')[0].strip()
        return xff or self.client_address[0]

    def _static(self, path):
        name = 'index.html' if path in ('/', '') else path.lstrip('/')
        if name not in STATIC_FILES:
            return self._send({'error': 'unknown'}, 404)
        try:
            with open(os.path.join(ROOT, name), 'rb') as f:
                return self._send(None, ctype=CTYPES.get(os.path.splitext(name)[1], 'application/octet-stream'),
                                  raw=f.read())
        except OSError:
            return self._send({'error': 'unknown'}, 404)

    def _pub_job(self, jid):
        return JOBS.get(jid) if jid in PUB['jobs'] else None

    def do_GET(self):
        path = self.path.split('?', 1)[0]
        if path in ('/', '') or path.lstrip('/') in STATIC_FILES:
            return self._static(path)
        if path == '/api/health':
            return self._send({'ok': True, 'version': VERSION, 'public': True})
        if path == '/status':
            return self._send({'ok': True, 'version': VERSION, 'public': True, 'exits': pub_exits_legacy()})
        if path == '/lastmodel':
            return self._send({'ok': True, 'model': load_lastmodel('pub')})
        if path == '/activity':
            return self._send({'ok': True, 'activity': activity_get()})
        if path == '/stats':
            dflt = [d.rstrip('/') for d in PUB_DEFAULT_TARGETS]
            st = HISTORY.stats(_days(self.path), only_target=lambda t, p: not p.get('public') or t.rstrip('/') in dflt)
            for e in st['exits']:
                if e['label'].startswith('Этот ПК'):
                    e['label'] = PUB_EXIT_LABEL
            for c in st['matrix']:
                if c['exit'].startswith('Этот ПК'):
                    c['exit'] = PUB_EXIT_LABEL
            return self._send({'ok': True, **st})
        if path.startswith('/fwd'):
            if not _fwd_ok(self._client()):
                return self._send({'ok': False, 'error': 'слишком много запросов'}, 429)
            return self.fwd_request('GET')
        if path.startswith('/jobs/'):
            job = self._pub_job(path[6:].strip('/'))
            if not job:
                return self._send({'ok': False, 'error': 'нет такого задания'}, 404)
            return self._send({'ok': True, 'job': pub_snapshot(job)})
        if path == '/api/exits':
            return self._send({'exits': [pub_exit()]})
        if path == '/api/history':
            return self._send({'jobs': []})
        if path.startswith('/api/jobs/'):
            job = self._pub_job(path[10:].strip('/'))
            if not job:
                return self._send({'error': 'нет такого задания'}, 404)
            return self._send(pub_job_api(job))
        if path.startswith('/pub/job/'):
            job = self._pub_job(path[9:].strip('/'))
            if not job:
                return self._send({'error': 'нет такой проверки'}, 404)
            return self._send(pub_view(job))
        return self._send({'error': 'unknown'}, 404)

    def _create(self, raw, browser=True, domain_first=False):
        """Проверка входа и создание публичного задания → (job, None) или (None, (ответ, код))."""
        targets, bad = _targets(list(raw)[:PUB_MAX_TARGETS + 5])
        if not targets:
            return None, ({'error': 'введите домен или адрес страницы'}, 400)
        if len(targets) > PUB_MAX_TARGETS:
            return None, ({'error': f'не больше {PUB_MAX_TARGETS} адресов за раз'}, 400)
        for t in targets:
            why = ssrf_reason(t)
            if why:
                return None, ({'error': f'{t}: {why}'}, 400)
        with PUB['lock']:
            ids = list(PUB['jobs'])
        pending = sum(1 for j in ids if JOBS.get(j) and JOBS.get(j).status in ('queued', 'running'))
        if pending >= PUB_MAX_PENDING:
            return None, ({'error': 'сейчас очередь занята, попробуйте через минуту'}, 429)
        if not pub_rate_ok(self._client()):
            return None, ({'error': 'слишком много проверок, подождите несколько минут'}, 429)
        job = JOBS.create(targets, {'browser': bool(browser), 'domainFirst': bool(domain_first),
                                    'repeats': 1, 'public': True})
        with PUB['lock']:
            PUB['jobs'].add(job.id)
        return job, None

    def do_POST(self):
        path = self.path.split('?', 1)[0]
        if path.startswith('/fwd'):
            if not _fwd_ok(self._client()):
                return self._send({'ok': False, 'error': 'слишком много запросов'}, 429)
            return self.fwd_request('POST')
        if path == '/lastmodel':
            if not _fwd_ok('lm' + self._client()):
                return self._send({'ok': False}, 429)
            try:
                n = int(self.headers.get('Content-Length', '0') or 0)
                if n > LAST_MAX:
                    return self._send({'ok': False, 'error': 'too large'}, 413)
                body = json.loads(self.rfile.read(n) or b'{}')
            except Exception:
                return self._send({'ok': False, 'error': 'bad json'}, 400)
            return self._send({'ok': save_lastmodel(body.get('model'), True)})
        if path == '/activity':
            if not _act_ok(self._client()):
                return self._send({'ok': False}, 429)
            try:
                n = int(self.headers.get('Content-Length', '0') or 0)
                body = json.loads(self.rfile.read(min(n, 2000)) or b'{}')
            except Exception:
                return self._send({'ok': False}, 400)
            return self._send({'ok': activity_set(body)})
        if path == '/jobs/cancel' or (path.startswith('/jobs/') and path.endswith('/cancel')):
            job = self._pub_job(path[6:-7].strip('/'))
            if not job:
                return self._send({'ok': False, 'error': 'нет такого задания'}, 404)
            return self._send({'ok': JOBS.cancel(job.id)})
        if path not in ('/pub/check', '/api/jobs', '/jobs') and not (path.startswith('/api/jobs/') and path.endswith('/cancel')):
            return self._send({'error': 'unknown'}, 404)
        try:
            n = int(self.headers.get('Content-Length', '0') or 0)
            if n > 4096:
                return self._send({'error': 'слишком большой запрос'}, 413)
            body = json.loads(self.rfile.read(n) or b'{}')
        except Exception:
            return self._send({'error': 'bad json'}, 400)
        if path.endswith('/cancel'):
            job = self._pub_job(path[10:-7].strip('/'))
            if not job:
                return self._send({'error': 'нет такого задания'}, 404)
            JOBS.cancel(job.id)
            return self._send(pub_job_api(job))
        if path == '/jobs':
            raw = body.get('targets') or body.get('domains') or []
            if isinstance(raw, str):
                raw = raw.split()
            job, err = self._create(raw, browser=body.get('browser', True), domain_first=body.get('domainFirst'))
            if err:
                return self._send({'ok': False, 'error': err[0].get('error')}, err[1])
            return self._send({'ok': True, 'id': job.id, 'status': job.status, 'total': len(job.targets)}, 202)
        raw = body.get('urls') if path == '/api/jobs' else body.get('targets')
        raw = raw or []
        if isinstance(raw, str):
            raw = raw.split()
        job, err = self._create(raw)
        if err:
            return self._send(*err)
        if path == '/api/jobs':
            return self._send({'id': job.id, 'state': job.status}, 202)
        return self._send({'id': job.id}, 202)


def _params(body):
    return {'browser': bool(body.get('browser')), 'domainFirst': bool(body.get('domainFirst')),
            'repeats': body.get('repeats'), 'slowMs': body.get('slowMs')}


# ---------------------------------------------------------------- startup
def load_local_files():
    """subs.txt и user_nodes.txt рядом с проектом. Файлы читает только демон; содержимое не выводится."""
    urls, inline = [], []
    for name in ('subs.txt', 'user_nodes.txt'):
        path = os.path.join(SECRETS_DIR, name)
        if not os.path.exists(path):
            continue
        for line in open(path, encoding='utf-8', errors='ignore').read().splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            (urls if line.lower().startswith(('http://', 'https://')) else inline).append(line)
    return urls, (['\n'.join(inline)] if inline else [])


def shutdown_cores():
    for ex in list(STATE['exits']):
        kill_exit(ex)
    if WORK:
        shutil.rmtree(WORK, ignore_errors=True)


atexit.register(shutdown_cores)


def main():
    global WORK, JOBS, HISTORY
    if not curl_bin():
        raise SystemExit('curl не найден в PATH')
    if BIND not in LOOPBACK and not TOKEN:
        raise SystemExit(f'RG_BIND={BIND} — не loopback: задайте RG_TOKEN (без токена демон слушает только 127.0.0.1)')
    WORK = tempfile.mkdtemp(prefix='geocheck-')   # приватная папка: конфиги ядер содержат учётные данные
    os.makedirs(DATA_DIR, exist_ok=True)
    HISTORY = History(os.path.join(DATA_DIR, 'history.db'))
    JOBS = JobManager(run_job, HISTORY)
    if not STATE['exits']:
        STATE['exits'].append(_new_exit('direct', 'Этот ПК (системный канал)', None,
                                        'через текущий VPN/провайдера'))
    urls, inline = load_local_files()
    urls = STATE['subs_urls'] + [u for u in urls if u not in STATE['subs_urls']]
    if urls or inline:
        r = configure(urls, inline)
        print('Подписки загружены · выходов:', len(r['exits']))
        for w in r['warnings']:
            print('WARN:', w)
    mode = 'с токеном' if TOKEN else 'только loopback, без токена'
    print(f'GeoCheck daemon {VERSION}: http://{BIND}:{PORT}  ({mode}; секреты не сохраняются)', flush=True)
    if PUBLIC_PORT:
        pub = ThreadingHTTPServer(('127.0.0.1', PUBLIC_PORT), P)
        threading.Thread(target=pub.serve_forever, daemon=True).start()
        print(f'Публичная форма: 127.0.0.1:{PUBLIC_PORT} (наружу только через Tailscale Funnel)', flush=True)
    ThreadingHTTPServer((BIND, PORT), H).serve_forever()


if __name__ == '__main__':
    main()
