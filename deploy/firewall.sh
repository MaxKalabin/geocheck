#!/usr/bin/env bash
# Restrict the GeoCheck port to the home LAN, Tailscale and loopback. Run as root (systemd oneshot).
# Idempotent: removes its own rules for the port first, then appends them in order.
set -euo pipefail
PORT="${1:?port}"
IPT="iptables"
while $IPT -D INPUT -p tcp --dport "$PORT" -s 127.0.0.0/8 -j ACCEPT 2>/dev/null; do :; done
while $IPT -D INPUT -p tcp --dport "$PORT" -s 192.168.0.0/24 -j ACCEPT 2>/dev/null; do :; done
while $IPT -D INPUT -p tcp --dport "$PORT" -s 100.64.0.0/10 -j ACCEPT 2>/dev/null; do :; done
while $IPT -D INPUT -p tcp --dport "$PORT" -j DROP 2>/dev/null; do :; done
$IPT -A INPUT -p tcp --dport "$PORT" -s 127.0.0.0/8 -j ACCEPT
$IPT -A INPUT -p tcp --dport "$PORT" -s 192.168.0.0/24 -j ACCEPT
$IPT -A INPUT -p tcp --dport "$PORT" -s 100.64.0.0/10 -j ACCEPT
$IPT -A INPUT -p tcp --dport "$PORT" -j DROP
echo "firewall: port $PORT open only to 127.0.0.0/8, 192.168.0.0/24, 100.64.0.0/10"
