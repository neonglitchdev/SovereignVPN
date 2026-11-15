#!/usr/bin/env bash
# Prova dei sysctl VERI (runner Linux, root) in un network namespace: net.* vale per namespace, l'host non cambia.
#   sudo bash control-plane/tests/prova_sysctl_vero.sh
set -Eeuo pipefail
IFS=$'\n\t'
[ "$(id -u)" -eq 0 ] || { echo "prova_sysctl_vero: serve root"; exit 1; }
NS=sysprova
trap 'ip netns del "$NS" 2>/dev/null || true' EXIT
ip netns add "$NS"
cd "$(dirname "$0")/.."
dentro() { ip netns exec "$NS" "$@"; }
PRIMA="$(dentro sysctl -n net.ipv4.ip_forward)"
[ "$PRIMA" = "0" ] || { echo "ROSSO: nel namespace nuovo ip_forward e' gia' $PRIMA, la prova non distinguerebbe"; exit 1; }
dentro python3 -m sovereignctl host apply --json
DOPO="$(dentro sysctl -n net.ipv4.ip_forward) $(dentro sysctl -n net.ipv6.conf.all.forwarding)"
[ "$DOPO" = "1 0" ] || { echo "ROSSO: dopo apply ip_forward e IPv6 forwarding = $DOPO, attesi 1 0"; exit 1; }
grep -q '^net.ipv4.ip_forward = 1$' /etc/sysctl.d/90-sovereignvpn.conf || { echo "ROSSO: file persistente mancante"; exit 1; }
echo "OK: nel namespace ip_forward da $PRIMA a 1, IPv6 forwarding 0, file persistente in /etc/sysctl.d"
