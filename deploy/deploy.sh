#!/usr/bin/env bash
# Deploy GeoCheck to the Raspberry Pi. Run from the dev machine (Git Bash / Linux / macOS).
#
#   deploy/deploy.sh [--host jg@maxpi] [--port 8787] [--secrets-dir DIR] [--no-secrets] [--prepare-only]
#   --prepare-only: upload, secrets, venv, sing-box and token only; services are not installed or started.
#
# What it does (repeatable; safe to re-run):
#   1. Packs the COMMITTED tree (git archive HEAD) — uncommitted files and secrets never go into the release.
#   2. Uploads it to ~/geocheck/releases/<rev> and points ~/geocheck/current at it.
#   3. Streams subs.txt and user_nodes.txt (if present in --secrets-dir) to ~/geocheck/secrets with mode 600.
#      Their contents are never printed; only sizes and a sha256 match are reported.
#   4. Runs deploy/pi-install.sh on the Pi (venv, sing-box core, env file with a generated token,
#      systemd units, firewall rule, service restart) and a status check with the token.
set -euo pipefail

HOST="jg@maxpi"
PORT="8787"
SECRETS_DIR=""
SEND_SECRETS=1
PREPARE_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --secrets-dir) SECRETS_DIR="$2"; shift 2 ;;
    --no-secrets) SEND_SECRETS=0; shift ;;
    --prepare-only) PREPARE_ONLY=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
[ -n "$SECRETS_DIR" ] || SECRETS_DIR="$REPO"

cd "$REPO"
REV="$(git rev-parse --short HEAD)"
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo "WARN: tracked files have uncommitted changes; only the committed HEAD ($REV) is deployed." >&2
fi
echo "==> release $REV to $HOST"

ssh -o BatchMode=yes "$HOST" 'mkdir -p ~/geocheck/releases ~/geocheck/bin ~/geocheck/data/runs ~/geocheck/config && mkdir -m 700 -p ~/geocheck/secrets && chmod 700 ~/geocheck/secrets'

echo "==> upload code"
git archive --format=tar HEAD | ssh -o BatchMode=yes "$HOST" "rm -rf ~/geocheck/releases/$REV && mkdir -p ~/geocheck/releases/$REV && tar -x -C ~/geocheck/releases/$REV"

if [ "$SEND_SECRETS" = "1" ]; then
  echo "==> secrets (contents not printed)"
  for name in subs.txt user_nodes.txt; do
    src="$SECRETS_DIR/$name"
    if [ -f "$src" ]; then
      ssh -o BatchMode=yes "$HOST" "umask 077; cat > ~/geocheck/secrets/$name.tmp && mv ~/geocheck/secrets/$name.tmp ~/geocheck/secrets/$name && chmod 600 ~/geocheck/secrets/$name" < "$src"
      local_sum="$(sha256sum "$src" | cut -d' ' -f1)"
      remote_sum="$(ssh -o BatchMode=yes "$HOST" "sha256sum ~/geocheck/secrets/$name | cut -d' ' -f1")"
      if [ "$local_sum" = "$remote_sum" ]; then echo "    $name: copied, sha256 match, mode 600"; else echo "    $name: CHECKSUM MISMATCH" >&2; exit 1; fi
    else
      echo "    $name: not found in $SECRETS_DIR, skipped"
    fi
  done
fi

echo "==> install and start on the Pi"
ssh -o BatchMode=yes "$HOST" "PREPARE_ONLY=$PREPARE_ONLY bash -s -- '$REV' '$PORT'" < "$HERE/pi-install.sh"

if [ "$PREPARE_ONLY" = "1" ]; then echo "==> prepare-only done (release $REV on $HOST, not started)"; exit 0; fi
echo "==> health check (token read on the Pi, not shown here)"
code="$(ssh -o BatchMode=yes "$HOST" "tok=\$(sed -n 's/^RG_TOKEN=//p' ~/geocheck/secrets/geocheck.env); curl -s -o /dev/null -w '%{http_code}' -H \"Authorization: Bearer \$tok\" http://127.0.0.1:$PORT/status || true")"
echo "    GET /status with token -> HTTP $code"
[ "$code" = "200" ] || { echo "health check failed" >&2; exit 1; }
echo "==> done: release $REV is running on $HOST port $PORT"
