# GeoCheck daemon API (frontend contract)

Status: **assumed contract** for the dashboard (slice C). The daemon (slice A) must match it;
if the daemon ends up different, change this file and `app.js` together.

The daemon serves the dashboard itself (same origin), so the page uses relative URLs.
A different base can be set in the dashboard settings (`адрес демона`) for development.

## Auth

- Every `/api/*` request except `GET /api/health` needs the header `X-RG-Token: <token>`.
- Token = `RG_TOKEN` from the daemon's EnvironmentFile (mode 600). Never put it in a URL.
- Missing or wrong token → `401 {"error":"unauthorized"}`.
- The dashboard keeps the token in memory. It is written to `sessionStorage` only if the user ticks
  «запомнить на вкладке»; never to `localStorage`.

## Endpoints

### `GET /api/health` (no token)
```json
{"ok": true, "version": "2.0.0"}
```

### `GET /api/exits`
```json
{"exits": [
  {"id": "vpn-de-1", "label": "DE-1", "country": "DE", "source": "local",
   "status": "up", "exitIp": "203.0.113.7", "lastCheckAt": "2026-11-22T10:00:00Z",
   "consecutiveFailures": 0, "lastError": null}
]}
```
`status`: `up` | `down` | `unknown`. `down` = control probe against a known-good site failed;
such exits are excluded from verdicts. Subscription URLs and node links are never returned.

### `POST /api/jobs` → `202`
Request:
```json
{"urls": ["https://example.com/", "https://ru.example.com/pricing"],
 "sources": {"localExits": true, "checkHost": true, "globalPing": true, "browser": false},
 "repeats": 3, "domainFirst": false, "maxNodes": 20}
```
- `urls`: 1–50 `http(s)://` URLs; a path is allowed (page-level check).
- `repeats`: 1–3; each cell is measured that many times, `status` is the majority.
- Response: `{"id": "j-20261122-001", "state": "queued"}`

### `GET /api/jobs/{id}`
Also used for partial results: poll it while `state` is `queued` or `running`.
```json
{"id": "j-20261122-001", "state": "running",
 "createdAt": "...", "finishedAt": null,
 "urls": ["..."], "options": {"...": "same as the POST body"},
 "progress": {"done": 12, "total": 60, "stage": "local exits"},
 "exits": [{"id": "vpn-de-1", "label": "DE-1", "country": "DE", "source": "local",
            "status": "up", "exitIp": "203.0.113.7"}],
 "results": [
   {"url": "https://example.com/", "exitId": "vpn-de-1", "exitLabel": "DE-1",
    "source": "local", "country": "DE", "exitIp": "203.0.113.7",
    "status": "ok", "code": 200, "ms": 1180, "errorClass": null,
    "cfRay": "8a1b...-FRA", "cfMitigated": null,
    "note": "",
    "repeats": [{"status": "ok", "code": 200, "ms": 1180}, {"status": "ok", "code": 200, "ms": 1203}, {"status": "ok", "code": 200, "ms": 1150}]}
 ],
 "error": null}
```
`state`: `queued` | `running` | `done` | `cancelled` | `failed` (`error` holds a short text when failed).

Cell `status` values (the dashboard maps them to the README symptom table):

| status | meaning | counts as failure |
|---|---|---|
| `ok` | page loaded (2xx/3xx) | no |
| `slow` | loaded, but over `slowMs` | yes |
| `challenge` | 403 with `cf-mitigated: challenge` | yes |
| `blocked` | other 4xx refusal | yes |
| `server-error` | 5xx with CF-RAY | yes |
| `network-error` | TCP/TLS/timeout, did not reach the site | yes |
| `nginx-503` | hard anti-bot 503 page (not bypassed) | no (shown separately) |
| `antibot-passed` | interstitial with a form, Send worked | no |
| `antibot-failed` | interstitial, Send did not lead to the page | yes |
| `domain-down` | domain root failed (`domainFirst`), page not checked | yes |
| `exit-down` | the exit failed its control probe; excluded from verdicts | no (not counted) |
| `pending` | not measured yet (only while running) | no |

`results` holds only what is measured so far; the dashboard renders whatever is there.

### `POST /api/jobs/{id}/cancel` → `200`
Returns the job object with `state` `cancelled` (or the final state if it had already finished).

### `GET /api/history?limit=50`
```json
{"jobs": [{"id": "j-...", "createdAt": "...", "finishedAt": "...", "state": "done",
           "urls": ["..."], "summary": {"cells": 60, "failures": 14}}]}
```

### `GET /api/history/{id}`
The same shape as `GET /api/jobs/{id}`.

## Exports

Done in the browser from the job object: CSV (one row per cell) and JSON (the job object as returned).
The job object contains no secrets, so the exports contain none either.

## Not in this contract yet

- Scheduled runs (slice B/D) and their list endpoint.
- Server-side export; the GlobalPing token and ping-admin are used only on the daemon.
