#!/usr/bin/env bash
# T-018 su un server INSTALLATO (non nel CI: riguarda il Docker dell'host, che un namespace non vede): dopo il riavvio
# di Docker le regole di sicurezza restano valide. Confronta la tabella inet sovereignvpn (senza i contatori delle
# quote, che cambiano col traffico) prima, subito dopo e a servizi tornati, e pretende tutti i controlli di status OK.
# Il confronto deve saper dire «diversa»: una policy cambiata sulla lista deve cambiare l'impronta, o la prova e' cieca.
#   sudo bash control-plane/tests/prova_t018_vero.sh [/etc/sovereignvpn/server.toml]
# Misurato il 15/11/2026 sulla VM colima amd64: Docker su in 40 s, tabella identica, tutto OK dopo 58 s.
set -Eeuo pipefail
CONFIG="${1:-/etc/sovereignvpn/server.toml}"
rosso() { echo "ROSSO: $*"; exit 1; }
[ "$(id -u)" -eq 0 ] || rosso "serve root"
impronta() { nft list table inet sovereignvpn | grep -v quota | sha256sum | cut -c1-16; }
tutto_ok() { /usr/local/bin/sovereignctl status --config "$CONFIG" --json | python3 -c 'import json,sys; sys.exit(0 if all(c["esito"] == "OK" for c in json.load(sys.stdin)["controlli"]) else 1)'; }
tutto_ok || rosso "status non e' tutto OK prima del riavvio: la prova non distinguerebbe"
PRIMA="$(impronta)"
FINTA="$(nft list table inet sovereignvpn | grep -v quota | sed '0,/policy drop/s//policy accept/' | sha256sum | cut -c1-16)"
[ "$FINTA" != "$PRIMA" ] || rosso "l'impronta non vede una policy cambiata: il confronto e' cieco"
T0=$(date +%s)
systemctl restart docker
for _ in $(seq 60); do docker info >/dev/null 2>&1 && break; sleep 2; done
[ "$(impronta)" = "$PRIMA" ] || rosso "subito dopo il riavvio di Docker la tabella inet sovereignvpn e' cambiata"
for _ in $(seq 60); do tutto_ok && break; sleep 5; done
tutto_ok || rosso "dopo 5 minuti dal riavvio di Docker status non e' tutto OK"
[ "$(impronta)" = "$PRIMA" ] || rosso "a servizi tornati la tabella inet sovereignvpn e' cambiata"
echo "OK: T-018, Docker riavviato: tabella identica ($PRIMA), policy a drop, status tutto OK dopo $(( $(date +%s) - T0 )) s"
