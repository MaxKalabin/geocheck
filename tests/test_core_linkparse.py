"""Парсер подписок и share-ссылок демона (daemon/linkparse.py). Все адреса и ключи — выдуманные."""
import base64
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'daemon'))

from linkparse import parse_share_link, parse_subscription  # noqa: E402

UUID = '00000000-0000-0000-0000-000000000000'


def b64(s):
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip('=')


def test_vless_reality_fields():
    link = (f'vless://{UUID}@node.example.invalid:443?security=reality&sni=www.example.invalid'
            f'&pbk=FAKEPUBKEY&sid=ab&flow=xtls-rprx-vision&type=tcp#%F0%9F%87%A9%F0%9F%87%AA%20Berlin')
    o = parse_share_link(link)
    assert o['type'] == 'vless'
    assert o['server'] == 'node.example.invalid'
    assert o['server_port'] == 443
    assert o['uuid'] == UUID
    assert o['flow'] == 'xtls-rprx-vision'
    assert o['tls']['reality'] == {'enabled': True, 'public_key': 'FAKEPUBKEY', 'short_id': 'ab'}
    assert o['tls']['server_name'] == 'www.example.invalid'
    assert 'transport' not in o
    assert o['_name'] == '\U0001F1E9\U0001F1EA Berlin'


def test_vless_ws_transport_and_default_port():
    o = parse_share_link(f'vless://{UUID}@h.example.invalid?type=ws&path=%2Fws&host=cdn.example.invalid&security=tls')
    assert o['server_port'] == 443
    assert o['transport'] == {'type': 'ws', 'path': '/ws', 'headers': {'Host': 'cdn.example.invalid'}}


def test_trojan_allow_insecure():
    o = parse_share_link('trojan://secretpw@t.example.invalid:8443?allowInsecure=1&sni=t.example.invalid#Poland')
    assert o['type'] == 'trojan'
    assert o['password'] == 'secretpw'
    assert o['server_port'] == 8443
    assert o['tls']['insecure'] is True
    assert o['_name'] == 'Poland'


def test_vmess_base64_json():
    payload = json.dumps({'add': 'v.example.invalid', 'port': '10086', 'id': UUID, 'ps': 'NL 1',
                          'tls': 'tls', 'sni': 'v.example.invalid', 'net': 'ws', 'path': '/p', 'host': 'h'})
    o = parse_share_link('vmess://' + b64(payload))
    assert o['type'] == 'vmess'
    assert o['server'] == 'v.example.invalid'
    assert o['server_port'] == 10086
    assert o['uuid'] == UUID
    assert o['tls']['enabled'] is True
    assert o['transport']['path'] == '/p'
    assert o['_name'] == 'NL 1'


def test_ss_sip002_base64_userinfo():
    userinfo = b64('aes-256-gcm:fakepass')
    o = parse_share_link(f'ss://{userinfo}@s.example.invalid:8388#Finland')
    assert o['type'] == 'shadowsocks'
    assert o['method'] == 'aes-256-gcm'
    assert o['password'] == 'fakepass'
    assert o['server'] == 's.example.invalid'
    assert o['_name'] == 'Finland'


def test_garbage_line_is_none():
    assert parse_share_link('not a link') is None
    assert parse_share_link('') is None
    assert parse_share_link('http://example.invalid') is None


def test_subscription_base64_of_several_links():
    links = ['trojan://pw@a.example.invalid:443#A', 'trojan://pw@b.example.invalid:443#B']
    outs = parse_subscription(b64('\n'.join(links)))
    assert [o['server'] for o in outs] == ['a.example.invalid', 'b.example.invalid']


def test_subscription_plain_links_and_comments_skipped():
    text = f'\n# comment\nvless://{UUID}@x.example.invalid:443?security=tls#X\nbogus line\n'
    outs = parse_subscription(text)
    assert len(outs) == 1 and outs[0]['server'] == 'x.example.invalid'


def test_subscription_singbox_json():
    cfg = {'outbounds': [
        {'type': 'vless', 'server': 'j.example.invalid', 'server_port': 443, 'uuid': UUID},
        {'type': 'direct', 'tag': 'direct'},
        {'type': 'trojan', 'server': ''},
    ]}
    outs = parse_subscription(json.dumps(cfg))
    assert len(outs) == 1 and outs[0]['server'] == 'j.example.invalid'


def test_empty_subscription():
    assert parse_subscription('') == []
    assert parse_subscription(None) == []
