import os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'daemon'))
import checkdaemon as d
import apiv1


def test_ssrf_blocks_internal():
    for t in ('https://127.0.0.1/', 'https://localhost/', 'https://192.168.0.1/', 'https://x.ts.net/',
              'https://example.com:8080/', 'https://intranet/'):
        assert d.ssrf_reason(t), t


def test_rate_limit():
    key = 'rl-test'
    ok = [d.pub_rate_ok(key, now=1000 + i) for i in range(8)]
    assert ok[:6] == [True] * 6 and ok[6:] == [False, False]
    assert d.pub_rate_ok(key, now=1000 + 700)


def test_api_status_mapping():
    assert apiv1.api_status({'status': 'ok', 'code': 200}) == 'ok'
    assert apiv1.api_status({'status': 'fail', 'code': 0}) == 'network-error'
    assert apiv1.api_status({'status': 'fail', 'code': 403, 'cfMitigated': 'challenge'}) == 'challenge'
    assert apiv1.api_status({'status': 'fail', 'code': 503, 'hardBlock': True}) == 'nginx-503'
    assert apiv1.api_status({'status': 'exit_down'}) == 'exit-down'


def test_secrets_dir(tmp_path, monkeypatch):
    (tmp_path / 'subs.txt').write_text('https://sub.example/x\n')
    monkeypatch.setattr(d, 'SECRETS_DIR', str(tmp_path))
    urls, inline = d.load_local_files()
    assert urls == ['https://sub.example/x'] and inline == []
