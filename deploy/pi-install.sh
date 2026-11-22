#!/usr/bin/env bash
# Runs ON the Raspberry Pi (streamed by deploy.sh): bash -s -- <rev> <port>
# Idempotent. Keeps secrets in ~/geocheck/secrets (mode 600, outside releases and web root).
set -euo pipefail
REV="${1:?release id}"
PORT="${2:-8787}"
SINGBOX_VERSION="${SINGBOX_VERSION:-1.14.4}"
BASE="$HOME/geocheck"
cd "$BASE"
mkdir -p bin data/runs config secrets
chmod 700 secrets

echo "[pi] release $REV, port $PORT, user $(id -un), $(uname -m), $(python3 --version)"
ln -sfn "releases/$REV" current

# 1. Python venv with the daemon's optional requirements (Playwright; no browser download,
#    the daemon uses the system chromium through RG_CHROMIUM_PATH).
if [ ! -x venv/bin/python ]; then python3 -m venv venv; fi
venv/bin/pip install -q --upgrade pip
venv/bin/pip install -q -r current/deploy/requirements.txt
echo "[pi] venv ok: $(venv/bin/python -c 'import playwright, importlib.metadata as m; print("playwright", m.version("playwright"))' 2>/dev/null || echo 'playwright import failed')"

# 2. sing-box core for linux (arm64 on this Pi). Pinned version.
if ! { [ -x bin/sing-box ] && bin/sing-box version 2>/dev/null | head -1 | grep -q "version $SINGBOX_VERSION"; }; then
  case "$(uname -m)" in
    aarch64|arm64) arch=arm64 ;;
    x86_64) arch=amd64 ;;
    *) echo "[pi] unsupported arch $(uname -m)"; exit 1 ;;
  esac
  tmp="$(mktemp -d)"
  url="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${arch}.tar.gz"
  echo "[pi] downloading sing-box $SINGBOX_VERSION ($arch)"
  curl -fsSL -o "$tmp/sb.tgz" "$url"
  tar -xzf "$tmp/sb.tgz" -C "$tmp"
  install -m 755 "$(find "$tmp" -type f -name sing-box | head -1)" bin/sing-box
  rm -rf "$tmp"
fi
echo "[pi] $(bin/sing-box version | head -1)"

# 3. Env file with the access token. Created once; the token is generated here and never printed.
ENV=secrets/geocheck.env
if [ ! -f "$ENV" ]; then
  umask 077
  tok="$(openssl rand -hex 32 2>/dev/null || python3 -c 'import secrets; print(secrets.token_hex(32))')"
  printf 'RG_TOKEN=%s\n' "$tok" > "$ENV"
  unset tok
  echo "[pi] created $ENV (token generated)"
fi
chmod 600 "$ENV"

# 4. Default scan domains (not secret). Edit config/domains.txt on the Pi to change them.
if [ ! -f config/domains.txt ]; then
  printf '%s\n' '# one domain or URL per line; used by the scheduled run' \
    'restaurantguru.com' 'ru.restaurantguru.com' 'restaurantguru.ru' > config/domains.txt
fi

# 5. systemd units with paths, user and port filled in.
if [ "${PREPARE_ONLY:-0}" = 1 ]; then echo "[pi] prepare-only: services not installed or started"; exit 0; fi
tmpd="$(mktemp -d)"
for f in current/deploy/systemd/*.service current/deploy/systemd/*.timer; do
  sed -e "s#__HOME__#$HOME#g" -e "s#__USER__#$(id -un)#g" -e "s#__PORT__#$PORT#g" "$f" > "$tmpd/$(basename "$f")"
done
sudo install -m 644 "$tmpd"/*.service "$tmpd"/*.timer /etc/systemd/system/
rm -rf "$tmpd"
sudo systemctl daemon-reload
sudo systemctl enable geocheck-fw.service geocheck.service geocheck-scan.timer >/dev/null
sudo systemctl restart geocheck-fw.service
sudo systemctl restart geocheck.service
sudo systemctl start geocheck-scan.timer
sleep 3
echo "[pi] geocheck.service: $(systemctl is-active geocheck.service)"
echo "[pi] geocheck-scan.timer: $(systemctl is-active geocheck-scan.timer)"
echo "[pi] listening: $(ss -ltn | grep ":$PORT " || echo none)"
