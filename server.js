// GeoCheck — минимальный статический сервер для локального превью.
// Пробрасывает --host и --port, как ожидает Kimi Work.
const http = require('http');
const fs = require('fs');
const path = require('path');

const args = process.argv.slice(2);
const arg = (name, dflt) => {
  const i = args.indexOf(name);
  return i > -1 && args[i + 1] ? args[i + 1] : dflt;
};
const host = arg('--host', '127.0.0.1');
const port = parseInt(arg('--port', '7100'), 10);
const root = __dirname;

const mime = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.md': 'text/markdown; charset=utf-8',
};

http.createServer((req, res) => {
  let p = decodeURIComponent(req.url.split('?')[0]);
  if (p === '/') p = '/index.html';
  const fp = path.normalize(path.join(root, p));
  if (!fp.startsWith(root)) { res.writeHead(403); return res.end('forbidden'); }
  fs.readFile(fp, (err, data) => {
    if (err) { res.writeHead(404); return res.end('not found'); }
    res.writeHead(200, { 'Content-Type': mime[path.extname(fp)] || 'application/octet-stream' });
    res.end(data);
  });
}).listen(port, host, () => console.log(`GeoCheck: http://${host}:${port}/`));
