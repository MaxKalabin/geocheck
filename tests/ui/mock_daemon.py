"""Mock of the GeoCheck daemon API (docs/API.md) for dashboard tests.

Serves the repo's static files (index.html, app.js, styles.css) on the same origin, like the real daemon.
Test-only: fake exits, fake results, fixed token. Nothing here touches the network or real exits.
"""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

FAILS = {'slow', 'challenge', 'blocked', 'server-error', 'network-error', 'antibot-failed', 'domain-down'}
EXITS = [
    {'id': 'loc-tr', 'label': 'Этот ПК (напрямую)', 'country': 'TR', 'source': 'local', 'status': 'up', 'exitIp': '198.51.100.2', 'lastError': None},
    {'id': 'vpn-de-1', 'label': 'DE-1', 'country': 'DE', 'source': 'local', 'status': 'up', 'exitIp': '203.0.113.7', 'lastError': None},
    {'id': 'vpn-nl-1', 'label': 'NL-1', 'country': 'NL', 'source': 'local', 'status': 'up', 'exitIp': '203.0.113.9', 'lastError': None},
    {'id': 'vpn-ru-1', 'label': 'RU-1', 'country': 'RU', 'source': 'local', 'status': 'down', 'exitIp': None,
     'lastError': 'контрольный сайт не открылся (timeout)'},
    {'id': 'node-ru-1', 'label': 'узел RU', 'country': 'RU', 'source': 'check-host', 'status': 'up', 'exitIp': None, 'lastError': None},
    {'id': 'gp-us-1', 'label': 'GlobalPing US', 'country': 'US', 'source': 'globalping', 'status': 'up', 'exitIp': None, 'lastError': None},
]
CELLS_PER_POLL = 3


def outcome(url, ex, k):
    """Deterministic fake measurement for one url x exit."""
    u = urlparse(url)
    host, path, c = u.hostname, u.path, ex['country']
    if ex['status'] == 'down':
        return {'status': 'exit-down', 'code': None, 'ms': None, 'errorClass': None, 'cfRay': None, 'cfMitigated': None}
    base_ms = 700 + (len(url) * 13 + k * 37) % 500
    if host == 'example.ru' and c in ('DE', 'NL', 'US'):
        return {'status': 'challenge', 'code': 403, 'ms': 900, 'errorClass': None, 'cfRay': '8c1d2e3f4a5b6c7d-FRA', 'cfMitigated': 'challenge'}
    if host == 'ru.example.com' and c == 'NL':
        return {'status': 'network-error', 'code': None, 'ms': 4100, 'errorClass': 'tls-timeout', 'cfRay': None, 'cfMitigated': None}
    if path == '/pricing' and c == 'DE':
        return {'status': 'slow', 'code': 200, 'ms': 12400, 'errorClass': None, 'cfRay': '8c1d2e3f4a5b6c7d-FRA', 'cfMitigated': None}
    return {'status': 'ok', 'code': 200, 'ms': base_ms, 'errorClass': None, 'cfRay': None, 'cfMitigated': None}


def build_cells(url, ex, repeats):
    if ex['status'] == 'down':
        o = outcome(url, ex, 0)
        return {'url': url, 'exitId': ex['id'], 'exitLabel': ex['label'], 'source': ex['source'], 'country': ex['country'],
                'exitIp': None, 'note': 'выход не работает: вне вердикта', 'repeats': [], **o}
    reps = [outcome(url, ex, k) for k in range(repeats)]
    main = reps[0]
    return {'url': url, 'exitId': ex['id'], 'exitLabel': ex['label'], 'source': ex['source'], 'country': ex['country'],
            'exitIp': ex['exitIp'], 'note': '', **main,
            'repeats': [{'status': r['status'], 'code': r['code'], 'ms': r['ms']} for r in reps]}


class Store:
    def __init__(self, token):
        self.token = token
        self.lock = threading.Lock()
        self.jobs = {}          # id -> job dict (active and finished)
        self.pending = {}       # id -> list of cells still to release
        self.seq = 0
        seeded = {
            'id': 'j-20261121-007', 'state': 'done', 'createdAt': '2026-11-21T08:00:00Z', 'finishedAt': '2026-11-21T08:04:00Z',
            'urls': ['https://restaurantguru.com/'], 'options': {}, 'progress': {'done': 1, 'total': 1, 'stage': 'готово'},
            'exits': [EXITS[0]], 'results': [build_cells('https://restaurantguru.com/', EXITS[0], 1)], 'error': None,
        }
        self.jobs[seeded['id']] = seeded

    def create(self, body):
        with self.lock:
            self.seq += 1
            jid = 'j-20261122-%03d' % self.seq
            urls = body['urls']
            repeats = int(body.get('repeats', 3))
            cells = [build_cells(u, ex, repeats) for u in urls for ex in EXITS]
            job = {
                'id': jid, 'state': 'queued', 'createdAt': '2026-11-22T10:00:00Z', 'finishedAt': None,
                'urls': urls, 'options': body, 'progress': {'done': 0, 'total': len(cells), 'stage': 'очередь'},
                'exits': EXITS, 'results': [], 'error': None,
            }
            self.jobs[jid] = job
            self.pending[jid] = cells
            return job

    def get(self, jid):
        with self.lock:
            job = self.jobs.get(jid)
            if job is None:
                return None
            if job['state'] in ('queued', 'running') and jid in self.pending:
                job['state'] = 'running'
                take = self.pending[jid][:CELLS_PER_POLL]
                self.pending[jid] = self.pending[jid][CELLS_PER_POLL:]
                job['results'].extend(take)
                job['progress'] = {'done': len(job['results']), 'total': job['progress']['total'],
                                   'stage': 'измерения' if self.pending[jid] else 'сведение'}
                if not self.pending[jid]:
                    job['state'] = 'done'
                    job['finishedAt'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
                    del self.pending[jid]
            return json.loads(json.dumps(job))

    def cancel(self, jid):
        with self.lock:
            job = self.jobs.get(jid)
            if job and job['state'] in ('queued', 'running'):
                job['state'] = 'cancelled'
                job['finishedAt'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
                job['progress']['stage'] = 'отменено'
                self.pending.pop(jid, None)
            return json.loads(json.dumps(job)) if job else None

    def history(self):
        with self.lock:
            out = []
            for j in sorted(self.jobs.values(), key=lambda j: j['id'], reverse=True):
                fails = sum(1 for c in j['results'] if c['status'] in FAILS)
                out.append({'id': j['id'], 'createdAt': j['createdAt'], 'finishedAt': j['finishedAt'], 'state': j['state'],
                            'urls': j['urls'], 'summary': {'cells': len(j['results']), 'failures': fails}})
            return out


def make_handler(root, store):
    mime = {'.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8'}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, code, obj):
            data = json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _static(self, p):
            if p == '/':
                p = '/index.html'
            fp = (root / p.lstrip('/')).resolve()
            if root not in fp.parents and fp != root or not fp.is_file():
                self.send_response(404); self.end_headers(); return
            data = fp.read_bytes()
            self.send_response(200)
            self.send_header('Content-Type', mime.get(fp.suffix, 'application/octet-stream'))
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _auth(self):
            if self.headers.get('X-RG-Token') != store.token:
                self._json(401, {'error': 'unauthorized'})
                return False
            return True

        def do_GET(self):
            u = urlparse(self.path)
            if not u.path.startswith('/api/'):
                return self._static(u.path)
            if u.path == '/api/health':
                return self._json(200, {'ok': True, 'version': 'mock-1'})
            if not self._auth():
                return
            if u.path == '/api/exits':
                return self._json(200, {'exits': EXITS})
            if u.path == '/api/history':
                limit = int(parse_qs(u.query).get('limit', ['50'])[0])
                return self._json(200, {'jobs': store.history()[:limit]})
            if u.path.startswith('/api/history/'):
                job = store.jobs.get(u.path.rsplit('/', 1)[1])
                return self._json(200, job) if job else self._json(404, {'error': 'not found'})
            if u.path.startswith('/api/jobs/'):
                job = store.get(u.path.rsplit('/', 1)[1])
                return self._json(200, job) if job else self._json(404, {'error': 'not found'})
            self._json(404, {'error': 'not found'})

        def do_POST(self):
            u = urlparse(self.path)
            if not self._auth():
                return
            n = int(self.headers.get('Content-Length') or 0)
            body = json.loads(self.rfile.read(n) or b'{}')
            if u.path == '/api/jobs':
                if not body.get('urls'):
                    return self._json(400, {'error': 'urls required'})
                job = store.create(body)
                return self._json(202, {'id': job['id'], 'state': 'queued'})
            if u.path.startswith('/api/jobs/') and u.path.endswith('/cancel'):
                job = store.cancel(u.path.split('/')[3])
                return self._json(200, job) if job else self._json(404, {'error': 'not found'})
            self._json(404, {'error': 'not found'})

    return H


def start(root, token, port=0):
    """Start the mock in a background thread; returns (server, port)."""
    store = Store(token)
    srv = ThreadingHTTPServer(('127.0.0.1', port), make_handler(Path(root).resolve(), store))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]
