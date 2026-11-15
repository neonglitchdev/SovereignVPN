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
# il namespace eredita dall'host (sul runner Docker accende ip_forward): lo si porta ai valori OPPOSTI, cosi' la prova distingue
dentro sysctl -q -w net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=1
PRIMA="$(dentro sysctl -n net.ipv4.ip_forward) $(dentro sysctl -n net.ipv6.conf.all.forwarding)"
[ "$PRIMA" = "0 1" ] || { echo "ROSSO: non riesco a portare il namespace a 0 1 (letto $PRIMA), la prova non distinguerebbe"; exit 1; }
dentro python3 -m sovereignctl host apply --json
DOPO="$(dentro sysctl -n net.ipv4.ip_forward) $(dentro sysctl -n net.ipv6.conf.all.forwarding)"
[ "$DOPO" = "1 0" ] || { echo "ROSSO: dopo apply ip_forward e IPv6 forwarding = $DOPO, attesi 1 0"; exit 1; }
grep -q '^net.ipv4.ip_forward = 1$' /etc/sysctl.d/90-sovereignvpn.conf || { echo "ROSSO: file persistente mancante"; exit 1; }
echo "OK: nel namespace da «$PRIMA» a «$DOPO» (ip_forward, IPv6 forwarding), file persistente in /etc/sysctl.d"
