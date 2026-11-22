"""Разбор VPN-подписок и share-ссылок (vless/vmess/trojan/ss) в outbound-словари sing-box.

Чистые функции, без сети и файлов: их покрывают тесты (tests/test_linkparse.py).
"""
import base64
import json
import re
from urllib.parse import parse_qs, unquote, urlparse

SCHEMES_RE = re.compile(r'^(vless|vmess|trojan|ss)://', re.I | re.M)


def b64decode_loose(s):
    """base64 с url-safe алфавитом и без паддинга."""
    s = s.strip().replace('-', '+').replace('_', '/')
    s += '=' * (-len(s) % 4)
    return base64.b64decode(s)


def parse_subscription(text):
    """Возвращает список outbound-словарей для sing-box.

    Понимает: sing-box JSON (outbounds), список share-ссылок, base64 от списка ссылок.
    """
    text = (text or '').strip()
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
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if not SCHEMES_RE.search(text):   # не открытые ссылки → пробуем base64
        try:
            lines = [l.strip() for l in b64decode_loose(text).decode('utf-8', 'ignore').splitlines() if l.strip()]
        except Exception:
            pass
    for line in lines:
        o = parse_share_link(line)
        if o:
            outs.append(o)
    return outs


def parse_share_link(line):
    """Одна ссылка → outbound-словарь (с служебным ключом _name — подпись ноды) или None."""
    m = re.match(r'^(vless|vmess|trojan|ss)://(.+)$', (line or '').strip(), re.I)
    if not m:
        return None
    scheme = m.group(1).lower()
    rest = m.group(2)
    name = ''
    if '#' in rest:
        rest, frag = rest.split('#', 1)
        name = unquote(frag)
    try:
        if scheme == 'vmess':
            j = json.loads(b64decode_loose(rest).decode('utf-8', 'ignore'))
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
            elif ttype == 'httpupgrade':
                o['transport'] = {'type': 'httpupgrade', 'path': qs.get('path', '/')}
                host = qs.get('host') or qs.get('sni') or u.hostname
                if host:
                    o['transport']['host'] = host
            elif ttype in ('xhttp', 'splithttp'):
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
                method, pwd = b64decode_loose(userinfo).decode().split(':', 1)
            except Exception:
                method, pwd = userinfo, unquote(u.password or '')
            o = {'type': 'shadowsocks', 'tag': 'proxy', 'server': u.hostname,
                 'server_port': u.port or 8388, 'method': method, 'password': pwd}
            o['_name'] = unquote(name or '')
            return o
    except Exception:
        return None
    return None
