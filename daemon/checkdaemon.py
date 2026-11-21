#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GeoCheck local daemon — локальный помощник дашборда.

Что делает:
  * читает URL VPN-подписок (env RG_SUBS или POST /set_subscriptions) — ТОЛЬКО в памяти;
  * извлекает конфиги прокси (vless/vmess/trojan/ss, формат share-link или sing-box JSON);
  * поднимает sing-box-ядра на 127.0.0.1:порты (системный трафик НЕ трогает — tun не создаёт,
    работающий VPN-клиент (Throne/Hiddify) не мешает);
  * гоняет curl-замеры доменов через каждый выход и отдаёт результаты дашборду.

Секреты: ни в каких файлах и логах не сохраняются; при убийстве процесса забываются.
Слушает только 127.0.0.1 — снаружи недоступен по построению.

Запуск:
  python daemon/checkdaemon.py              # порт по умолчанию 8787
  set RG_SUBS=https://...;https://...        # необязательно — можно передать из дашборда
  set SINGBOX_PATH=C:\\path\\sing-box.exe   # если ядро не найдено автоматически
"""
import base64
import glob
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get('RG_DAEMON_PORT', '8787'))
BASE_PORT = 21000
UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) GeoCheck/1.0'
CURL = shutil.which('curl') or shutil.which('curl.exe')

STATE = {
    'subs_urls': [u for u in re.split(r'[\n;]', os.environ.get('RG_SUBS', '')) if u.strip()],
    'exits': [],          # [{'id','label','port','status','proc','cfg'}]
    'lock': threading.Lock(),
}

# ---------------------------------------------------------------- sing-box
def find_singbox():
    """Возвращает (exe, mode): mode='run' для sing-box, 'srun' для HiddifyCore (hiddify-sing-box)."""
    env = os.environ.get('SINGBOX_PATH')
    if env and os.path.exists(env):
        mode = 'srun' if 'hiddify' in env.lower() else 'run'
        return env, mode
    roots = [
        os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Programs'),
        r'C:\Program Files', r'C:\Program Files (x86)',
    ]
    candidates = []
    for root in roots:
        for d in glob.glob(os.path.join(root, 'Hiddify*')) + glob.glob(os.path.join(root, '*hiddify*')):
            candidates += glob.glob(os.path.join(d, '**', 'sing-box*.exe'), recursive=True)
            candidates += glob.glob(os.path.join(d, '**', 'HiddifyCore.exe'), recursive=True)
    for exe in candidates:
        return exe, ('srun' if 'hiddify' in os.path.basename(exe).lower() else 'run')
    return None, None


def _b64d(s):
    s = s.strip().replace('-', '+').replace('_', '/')
    s += '=' * (-len(s) % 4)
    return base64.b64decode(s)


def parse_subscription(text):
    """Возвращает список outbound-словарей для sing-box."""
    text = text.strip()
    outs = []
    if text.startswith('{'):
        try:
            j = json.loads(text)
            for o in j.get('outbounds', []):
                if o.get('type') in ('vless', 'vmess', 'trojan', 'shadowsocks') and o.get('server'):
                    outs.append(o)
        except Exception:
            pass
        if outs:
            return outs
    try:
        dec = _b64d(text).decode('utf-8', 'ignore')
        lines = [l.strip() for l in dec.splitlines() if l.strip()]
    except Exception:
        lines = [l.strip() for l in text.splitlines() if l.strip()]
    for line in lines:
        o = parse_share_link(line)
        if o:
            outs.append(o)
    return outs


def parse_share_link(line):
    m = re.match(r'^(vless|vmess|trojan|ss)://(.+)$', line, re.I)
    if not m:
        return None
    scheme = m.group(1).lower()
    rest = m.group(2)
    name = ''
    if '#' in rest:
        rest, frag = rest.split('#', 1)
        from urllib.parse import unquote as _u
        name = _u(frag)
    from urllib.parse import urlparse, parse_qs, unquote
    try:
        if scheme == 'vmess':
            j = json.loads(_b64d(rest).decode('utf-8', 'ignore'))
            o = {'type': 'vmess', 'tag': 'proxy', 'server': j['add'], 'server_port': int(j['port']),
                 'uuid': j['id'], 'security': 'auto'}
            if j.get('tls'):
                o['tls'] = {'enabled': True, 'server_name': j.get('sni') or j['add'], 'insecure': False}
            if j.get('net') == 'ws':
                o['transport'] = {'type': 'ws', 'path': j.get('path', '/'),
                                  'headers': {'Host': j.get('host') or j['add']}}
            o['_name'] = j.get('ps') or name
            return o
        u = urlparse(f'{scheme}://{rest}')
        qs = {k: v[0] for k, v in parse_qs(u.query).items()}
        if scheme == 'vless':
            o = {'type': 'vless', 'tag': 'proxy', 'server': u.hostname,
                 'server_port': u.port or 443, 'uuid': u.username}
            if qs.get('flow'):
                o['flow'] = qs['flow']
            sec = qs.get('security', '')
            if sec in ('tls', 'reality'):
                tls = {'enabled': True, 'server_name': qs.get('sni') or u.hostname, 'insecure': False,
                       'utls': {'enabled': True, 'fingerprint': 'chrome'}}
                if sec == 'reality' and qs.get('pbk'):
                    tls['reality'] = {'enabled': True, 'public_key': qs['pbk'],
                                      'short_id': qs.get('sid', '')}
                o['tls'] = tls
            ttype = qs.get('type', '')
            if ttype in ('ws', 'websocket'):
                o['transport'] = {'type': 'ws', 'path': qs.get('path', '/'),
                                  'headers': {'Host': qs.get('host') or qs.get('sni') or u.hostname}}
            elif ttype == 'grpc':
                o['transport'] = {'type': 'grpc', 'service_name': qs.get('serviceName', '')}
                if qs.get('packetEncoding'):
                    o['packet_encoding'] = qs['packetEncoding']   # обычно xudp
            elif ttype in ('xhttp', 'httpupgrade'):
                # xhttp (sing-box ≥1.12): path + mode; host — отдельным полем
                # (headers.Host на этом форке даёт FATAL "headers can't contain host")
                o['transport'] = {'type': 'xhttp', 'path': qs.get('path', '/')}
                if qs.get('mode'):
                    o['transport']['mode'] = qs['mode']
                host = qs.get('host') or qs.get('sni') or u.hostname
                if host:
                    o['transport']['host'] = host
            o['_name'] = unquote(name or '')
            return o
        if scheme == 'trojan':
            o = {'type': 'trojan', 'tag': 'proxy', 'server': u.hostname,
                 'server_port': u.port or 443, 'password': unquote(u.username or '')}
            tls = {'enabled': True, 'server_name': qs.get('sni') or u.hostname, 'insecure': False,
                   'utls': {'enabled': True, 'fingerprint': 'chrome'}}
            if qs.get('allowInsecure') == '1':
                tls['insecure'] = True
            o['tls'] = tls
            if qs.get('type') in ('ws', 'websocket'):
                o['transport'] = {'type': 'ws', 'path': qs.get('path', '/'),
                                  'headers': {'Host': qs.get('host') or qs.get('sni') or u.hostname}}
            o['_name'] = unquote(name or '')
            return o
        if scheme == 'ss':
            userinfo = u.username or ''
            try:
                method, pwd = _b64d(userinfo).decode().split(':', 1)
            except Exception:
                method, pwd = userinfo, unquote(u.password or '')
            o = {'type': 'shadowsocks', 'tag': 'proxy', 'server': u.hostname,
                 'server_port': u.port or 8388, 'method': method, 'password': pwd}
            o['_name'] = unquote(name or '')
            return o
    except Exception:
        return None
    return None


IFACE_CACHE = [None, False]  # [name, probed]


def find_physical_interface():
    """Физический интерфейс для route.default_interface sing-box — ТОЛЬКО если задан
    RG_IFACE (например RG_IFACE=Ethernet). По умолчанию выключено: на машине с
    активным tun-VPN (Throne/sing-box-форк) привязка ломает ВЕСЬ исходящий трафик
    ядра (проверено 2026-11-21), а без привязки tun-exit режет reality-TLS.
    Полноценно работает на чистой машине девопсов без конфликтующего VPN."""
    if IFACE_CACHE[1]:
        return IFACE_CACHE[0]
    IFACE_CACHE[1] = True
    env = os.environ.get('RG_IFACE', '').strip()
    if env and env.lower() != 'off':
        IFACE_CACHE[0] = env
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
        # bind исходящих соединений к физическому адаптеру — мимо tun-VPN
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
    """curl-замер; port=None → системный маршрут (через текущий VPN).
    capture_body=True — вернуть тело ответа в res['body'] (для прогрева/exit-IP)."""
    tmp = tempfile.gettempdir()
    hdr = os.path.join(tmp, f'geocheck-h-{threading.get_ident()}.txt')
    body_f = os.path.join(tmp, f'geocheck-b-{threading.get_ident()}.txt')
    fmt = r'\n%{http_code}|%{time_namelookup}|%{time_connect}|%{time_appconnect}|%{time_starttransfer}|%{time_total}|%{remote_ip}'
    cmd = [CURL, '-sS', '-4', '--ssl-no-revoke',  # Schannel: иначе CRYPT_E_REVOCATION_OFFLINE на этой машине
           '-o', body_f if capture_body else 'NUL', '-D', hdr, '-w', fmt,
           '--max-time', '60', '--connect-timeout', '20', '-A', UA]
    if port:
        cmd += ['-x', f'socks5h://127.0.0.1:{port}']
    cmd.append(url)
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
            low = err.lower()
            if 'connection timed out' in low:
                res['note'] = 'нет ответа: соединение не установлено за 20с — сервер/фаервол роняет пакеты'
            elif 'operation timed out' in low or 'timed out' in low:
                res['note'] = 'сервер отвечал дольше 60с — обрыв по потолку ожидания'
            elif 'socks5' in low or '97' in low:
                res['note'] = 'туннель не поднялся — ядро sing-box или сервер VPN недоступны'
            else:
                res['note'] = 'обрыв/таймаут'
            res['error'] = err[:400]
        if capture_body:
            try:
                res['body'] = open(body_f, encoding='utf-8', errors='ignore').read()
            except OSError:
                res['body'] = ''
        return res
    except Exception as e:
        return {'code': 0, 'note': 'ошибка демона', 'error': str(e)[:400]}
    finally:
        for f in (hdr, body_f) if capture_body else (hdr,):
            try:
                os.remove(f)
            except OSError:
                pass


# ---------------------------------------------------------------- lifecycle
def configure(urls, inline=None):
    warnings = []
    with STATE['lock']:
        for ex in STATE['exits']:
            kill_exit(ex)
        STATE['exits'] = []
        STATE['subs_urls'] = list(urls)
        sb, sb_mode = find_singbox()
        if not sb:
            warnings.append('sing-box не найден — задайте SINGBOX_PATH. Локальных выходов нет, '
                            'работает только системный маршрут.')
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
        STATE['exits'].append({'id': 'direct', 'label': 'Этот ПК (системный канал)',
                               'port': None, 'status': 'через текущий VPN/провайдера'})
        STATE['sb'] = sb
        STATE['sb_mode'] = sb_mode
        for i, p in enumerate(proxies[:24]):
            port = BASE_PORT + i
            label = p.get('_name') or f'proxy-{i+1}'
            host = p.get('server', '')
            if host and not re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
                ip = resolve_ipv4(host)
                if ip:
                    p['server'] = ip  # TLS SNI/Host берутся из server_name/transport отдельно
                else:
                    warnings.append(f'{label}: не удалось резолвить сервер вне tun-DNS')
            ex = {'id': f'px{i}', 'label': label, 'port': port, 'status': 'запускается…'}
            STATE['exits'].append(ex)
            if sb:
                cfg, _ = sb_config(p, port)
                cfg_path = os.path.join(tempfile.gettempdir(), f'geocheck-sb-{port}.json')
                with open(cfg_path, 'w', encoding='utf-8') as f:
                    json.dump(cfg, f)
                try:
                    proc = subprocess.Popen([sb, sb_mode, '-c', cfg_path],
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                            cwd=tempfile.gettempdir())  # не мусорить в папке проекта
                    ex['proc'] = proc
                    ex['cfg'] = cfg_path
                    time.sleep(0.4)
                    if proc.poll() is not None:
                        ex['status'] = 'ядро не запустилось (см. конфиг)'
                        warnings.append(f'{label}: sing-box упал сразу после старта')
                    else:
                        ex['status'] = f'127.0.0.1:{port}'
                except Exception as e:
                    ex['status'] = 'ошибка запуска'
                    warnings.append(f'{label}: {e}')
            else:
                ex['status'] = 'нет sing-box'
    return {'exits': public_exits(), 'warnings': warnings}


def start_core(ex):
    """Запустить sing-box-ядро выхода (используется при конфигурации и авто-рестарте)."""
    sb, sb_mode = STATE.get('sb'), STATE.get('sb_mode')
    if not sb or not ex.get('cfg'):
        return False
    try:
        proc = subprocess.Popen([sb, sb_mode, '-c', ex['cfg']],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                cwd=tempfile.gettempdir())
        ex['proc'] = proc
        time.sleep(0.4)
        if proc.poll() is not None:
            ex['status'] = 'ядро не запустилось (см. конфиг)'
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
                continue  # живо
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
    return [{'id': e['id'], 'label': e['label'], 'port': e['port'], 'status': e['status'],
             'exit_ip': e.get('exit_ip', ''), 'exit_loc': e.get('exit_loc', '')}
            for e in STATE['exits']]


def run_checks(domains):
    ensure_cores()   # поднять ядра, которые умерли между прогонами
    exits = list(STATE['exits'])
    jobs = [(ex, d) for ex in exits for d in domains]
    results = {e['id']: {} for e in exits}
    with ThreadPoolExecutor(max_workers=16) as pool:
        futs = {pool.submit(probe, d, ex['port']): (ex, d) for ex, d in jobs}
        for fut, (ex, d) in futs.items():
            results[ex['id']][d] = fut.result()
    return results


TRACE_URL = 'https://www.cloudflare.com/cdn-cgi/trace'


def warmup():
    """Прогрев: пингануть каждый выход, для живых показать exit-IP/страну."""
    ensure_cores()
    def job(ex):
        if ex['port'] is None:
            r = probe(TRACE_URL, None, capture_body=True)
        else:
            r = probe(TRACE_URL, ex['port'], capture_body=True)
        out = {'code': r['code'], 'ms': r.get('ms')}
        if not r['code']:
            out['error'] = (r.get('error') or r.get('note') or '')[:200]
        for line in (r.get('body') or '').splitlines():
            if line.startswith('ip='):
                out['ip'] = line[3:]
            elif line.startswith('loc='):
                out['loc'] = line[4:]
        # запоминаем exit-IP на самом выходе — /status отдаст его дашборду
        if out.get('ip'):
            ex['exit_ip'] = out['ip']
            ex['exit_loc'] = out.get('loc', '')
        return out
    res = {}
    with ThreadPoolExecutor(max_workers=16) as pool:
        futs = {pool.submit(job, ex): ex for ex in list(STATE['exits'])}
        for fut, ex in futs.items():
            res[ex['id']] = fut.result()
    return res


# ---------------------------------------------------------------- HTTP
FWD_HOSTS = ('check-host.net', 'api.globalping.io')


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def fwd_request(self, method):
        """Узкий форвардер для внешних API проверки доступности (обход блокировок
        в браузере). Разрешены только хосты из FWD_HOSTS, схема — только https."""
        from urllib.parse import urlparse, parse_qs, unquote
        qs = parse_qs(urlparse(self.path).query)
        u = unquote(qs.get('url', [''])[0])
        p = urlparse(u)
        if p.scheme != 'https' or p.hostname not in FWD_HOSTS:
            return self._json({'ok': False, 'error': 'host not allowed'}, 403)
        body = None
        if method == 'POST':
            n = int(self.headers.get('Content-Length', '0') or 0)
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

    def _cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.send_header('Access-Control-Allow-Private-Network', 'true')

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self._cors()
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        if self.path.startswith('/fwd'):
            return self.fwd_request('GET')
        if self.path.startswith('/warmup'):
            self._json({'ok': True, 'results': warmup()})
        elif self.path.startswith('/status'):
            self._json({'ok': True, 'version': '1.0', 'exits': public_exits()})
        elif self.path.startswith('/run'):
            self._json({'ok': True, 'results': run_checks(json.loads('{}').get('domains', []))})
        else:
            self._json({'ok': False, 'error': 'unknown'}, 404)

    def do_POST(self):
        if self.path.startswith('/fwd'):
            return self.fwd_request('POST')
        try:
            n = int(self.headers.get('Content-Length', '0'))
            body = json.loads(self.rfile.read(n) or b'{}')
        except Exception:
            return self._json({'ok': False, 'error': 'bad json'}, 400)
        if self.path.startswith('/set_subscriptions'):
            urls = [u for u in body.get('urls', []) if isinstance(u, str) and u.startswith(('http://', 'https://'))]
            # inline: пользователь вставил список ссылок (vless://...) напрямую — секрет не уходит с машины
            inline = [t for t in body.get('inline', []) if isinstance(t, str) and t.strip()]
            if not urls and not inline:
                return self._json({'ok': False, 'error': 'пустой список URL'}, 400)
            r = configure(urls, inline)
            self._json({'ok': True, 'exits': r['exits'], 'warnings': r['warnings']})
        elif self.path.startswith('/run'):
            domains = [d for d in body.get('domains', []) if isinstance(d, str)]
            if not domains:
                return self._json({'ok': False, 'error': 'нет доменов'}, 400)
            self._json({'ok': True, 'results': run_checks(domains)})
        else:
            self._json({'ok': False, 'error': 'unknown'}, 404)


def main():
    if not CURL:
        raise SystemExit('curl.exe не найден в PATH')
    if not STATE['exits']:
        STATE['exits'].append({'id': 'direct', 'label': 'Этот ПК (системный канал)',
                               'port': None, 'status': 'через текущий VPN/провайдера'})
    if STATE['subs_urls']:
        r = configure(STATE['subs_urls'])
        print('Подписки из RG_SUBS загружены · выходов:', len(r['exits']))
        for w in r['warnings']:
            print('WARN:', w)
    print(f'GeoCheck daemon: http://127.0.0.1:{PORT}  (только локально, секреты не сохраняются)')
    ThreadingHTTPServer(('127.0.0.1', PORT), H).serve_forever()


if __name__ == '__main__':
    main()
