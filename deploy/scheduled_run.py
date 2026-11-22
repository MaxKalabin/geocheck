"""Scheduled GeoCheck run: reads config/domains.txt, asks the local daemon for a run, saves the JSON.

Run by geocheck-scan.service (systemd timer). Needs RG_TOKEN and RG_DAEMON_PORT in the environment (EnvironmentFile).
Writes only to RG_DATA_DIR/runs (no secrets). Exit code 1 if the daemon is down or refuses.
"""
import json
import os
import sys
import time
import urllib.request

PORT = os.environ.get('RG_DAEMON_PORT', '8787')
TOKEN = os.environ.get('RG_TOKEN', '')
DOMAINS_FILE = os.environ.get('RG_SCAN_DOMAINS', os.path.expanduser('~/geocheck/config/domains.txt'))
DATA_DIR = os.environ.get('RG_DATA_DIR', os.path.expanduser('~/geocheck/data'))


def read_domains(path):
    with open(path, encoding='utf-8') as f:
        return [l.strip() for l in f if l.strip() and not l.lstrip().startswith('#')]


def main():
    if not TOKEN:
        print('RG_TOKEN is not set', file=sys.stderr)
        return 1
    domains = read_domains(DOMAINS_FILE)
    if not domains:
        print('no domains in', DOMAINS_FILE, file=sys.stderr)
        return 1
    body = json.dumps({'domains': domains}).encode()
    req = urllib.request.Request(
        f'http://127.0.0.1:{PORT}/run', data=body, method='POST',
        headers={'Content-Type': 'application/json', 'Authorization': f'Bearer {TOKEN}'})
    try:
        with urllib.request.urlopen(req, timeout=1800) as r:
            payload = json.loads(r.read().decode())
    except Exception as e:  # daemon down, auth refused, or timeout
        print('scheduled run failed:', type(e).__name__, str(e)[:200], file=sys.stderr)
        return 1
    runs = os.path.join(DATA_DIR, 'runs')
    os.makedirs(runs, exist_ok=True)
    out = os.path.join(runs, time.strftime('%Y%m%d-%H%M%S') + '.json')
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(payload, f, ensure_ascii=False, indent=1)
    print(f'scheduled run ok: {len(domains)} domains -> {out}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
