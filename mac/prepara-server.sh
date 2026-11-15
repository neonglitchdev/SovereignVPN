#!/usr/bin/env bash
# SovereignVPN per Mac: prepara il server nella VM Linux (Ubuntu 24.04 amd64, la piattaforma della 1.0) [H47].
# Gira come root dentro la VM, dalla copia delle sorgenti che l'app vi ha messo. Idempotente: si puo' rifare.
#   prepara-server.sh <endpoint> <rete delle sorgenti SSH di colima>
set -Eeuo pipefail
IFS=$'\n\t'
ENDPOINT="${1:?endpoint mancante}"; SSH_RETE="${2:?rete SSH mancante}"
RADICE="$(cd "$(dirname "$0")/.." && pwd)"
export DEBIAN_FRONTEND=noninteractive
if ! command -v wg >/dev/null; then
  apt-get update -qq
  apt-get install -y -qq wireguard-tools >/dev/null
fi
if ! docker compose version >/dev/null 2>&1; then  # col Docker di colima c'e' gia'; altrimenti il plugin del suo repository
  apt-get update -qq
  apt-get install -y -qq docker-compose-plugin >/dev/null 2>&1 || apt-get install -y -qq docker-compose-v2 >/dev/null
fi
modprobe wireguard
bash "$RADICE/ops/install.sh"
if [ ! -f /etc/sovereignvpn/server.toml ]; then
  cat > /etc/sovereignvpn/server.toml <<EOF
# SovereignVPN per Mac: configurazione scritta da prepara-server.sh
schema_version = 1
endpoint = "$ENDPOINT"
wan_interface = "eth0"
subnet = "10.66.0.0/24"
admin_ssh_sources = ["$SSH_RETE"]   # colima entra da qui: senza, il firewall chiuderebbe fuori l'app (ANC-0182)
EOF
  chmod 0600 /etc/sovereignvpn/server.toml
fi
if [ ! -f /var/lib/sovereignvpn/manifest.json ]; then
  sovereignctl init --apply --config /etc/sovereignvpn/server.toml --wan-interface eth0
else
  sovereignctl reconcile --config /etc/sovereignvpn/server.toml
fi
sovereignctl dns apply --interfaccia wg0 >/dev/null
systemctl start sovereignvpn-unbound.service sovereignvpn-pihole.service || true
echo "SERVER PRONTO"
