#!/usr/bin/env bash
# Prova con WireGuard VERO (runner Linux, root): interfaccia vera, chiavi da `wg genkey` (FR-WG-002), riconciliazione,
# revoca effettiva entro 5 secondi (FR-PEER-004), chiave privata del server mai nell'output. Sul Mac non gira.
#   sudo bash control-plane/tests/prova_wg_vero.sh
set -Eeuo pipefail
contiene() { local t; t="$(cat)"; grep -q "$@" <<<"$t"; }  # legge tutto: un grep -q in una pipeline esce presto e,
# con pipefail, il SIGPIPE di chi scrive diventa un rosso finto, o un verde finto in un controllo negativo
IFS=$'\n\t'
[ "$(id -u)" -eq 0 ] || { echo "prova_wg_vero: serve root"; exit 1; }
command -v wg >/dev/null || { echo "prova_wg_vero: serve wireguard-tools"; exit 1; }
IF=wgprova0
D="$(mktemp -d)"
trap 'ip link del "$IF" 2>/dev/null || true; rm -rf "$D"' EXIT
ip link add "$IF" type wireguard
(umask 077; wg genkey > "$D/server.key")
cd "$(dirname "$0")/.."
CONFIG=../config/examples/server.toml  # subnet6 di base [H38]
peer() { python3 -m sovereignctl peer "$@"; }
id_di() { python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])'; }
K1="$(wg genkey | wg pubkey)"; K2="$(wg genkey | wg pubkey)"
ID1="$(peer add --db "$D/r.db" --name uno --public-key "$K1" --json | id_di)"
peer add --db "$D/r.db" --name due --public-key "$K2" --json >/dev/null
USCITA="$(peer reconcile --db "$D/r.db" --interface "$IF" --server-key "$D/server.key" --config "$CONFIG" 2>&1)"
echo "$USCITA"
if grep -qF "$(cat "$D/server.key")" <<<"$USCITA"; then echo "ROSSO: la chiave privata del server e' nell'output"; exit 1; fi
N="$(wg show "$IF" peers | wc -l | tr -d ' ')"
[ "$N" -eq 2 ] || { echo "ROSSO: nel runtime $N peer, attesi 2"; exit 1; }
wg show "$IF" allowed-ips | contiene -F "$K1"$'\t'"10.66.0.2/32" || { echo "ROSSO: AllowedIPs del primo peer diversa da 10.66.0.2/32"; exit 1; }
wg show "$IF" allowed-ips | grep -F "$K1" | contiene -F "fdd3:5205:9303::a42:2/128" || { echo "ROSSO: il primo peer senza il suo IPv6 ULA fdd3:5205:9303::a42:2/128 [H38]"; exit 1; }
echo "OK: 2 peer nel runtime, AllowedIPs /32 come il registro e /128 ULA ricavata dall'IPv4"
T0="$(date +%s.%N)"
peer revoke --db "$D/r.db" "$ID1" >/dev/null
peer reconcile --db "$D/r.db" --interface "$IF" --server-key "$D/server.key" --config "$CONFIG" >/dev/null
T1="$(date +%s.%N)"
if wg show "$IF" peers | contiene -xF "$K1"; then echo "ROSSO: la chiave revocata e' ancora nel runtime"; exit 1; fi
SEC="$(python3 -c "print(round($T1 - $T0, 3))")"
python3 -c "import sys; sys.exit(0 if $T1 - $T0 < 5 else 1)" || { echo "ROSSO: revoca effettiva in $SEC s, oltre 5 (FR-PEER-004)"; exit 1; }
STATO="$(peer show --db "$D/r.db" "$ID1" --json | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["stato"], d["saga"])')"
[ "$STATO" = "REVOKED APPLIED" ] || { echo "ROSSO: registro $STATO, atteso REVOKED APPLIED"; exit 1; }
echo "OK: revoca effettiva in $SEC s (soglia 5 s), chiave fuori dal runtime, registro REVOKED APPLIED"
# scadenza (FR-PEER-005): l'orologio si controlla spostando nel passato la scadenza scritta nel registro
K3="$(wg genkey | wg pubkey)"
ID3="$(peer add --db "$D/r.db" --name tre --public-key "$K3" --ttl-days 1 --json | id_di)"
peer reconcile --db "$D/r.db" --interface "$IF" --server-key "$D/server.key" --config "$CONFIG" >/dev/null
wg show "$IF" peers | contiene -xF "$K3" || { echo "ROSSO: il peer col TTL non e' entrato nel runtime"; exit 1; }
NONSCAD="$(peer expire-sweep --db "$D/r.db" --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["scaduti"])')"
[ "$NONSCAD" = "0" ] || { echo "ROSSO: col TTL di un giorno sono scaduti $NONSCAD peer adesso, attesi 0"; exit 1; }
python3 - "$D/r.db" "$ID3" <<'PY'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
db.execute("UPDATE peer SET scade = '2000-01-01T00:00:00Z' WHERE id = ?", (sys.argv[2],))
db.commit()
PY
SCAD="$(peer expire-sweep --db "$D/r.db" --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["scaduti"])')"
[ "$SCAD" = "1" ] || { echo "ROSSO: scaduti $SCAD, atteso 1"; exit 1; }
peer reconcile --db "$D/r.db" --interface "$IF" --server-key "$D/server.key" --config "$CONFIG" >/dev/null
if wg show "$IF" peers | contiene -xF "$K3"; then echo "ROSSO: la chiave scaduta e' ancora nel runtime"; exit 1; fi
wg show "$IF" peers | contiene -xF "$K2" || { echo "ROSSO: la riconciliazione ha tolto anche il peer non scaduto"; exit 1; }
STATO3="$(peer show --db "$D/r.db" "$ID3" --json | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["stato"], d["saga"])')"
[ "$STATO3" = "EXPIRED APPLIED" ] || { echo "ROSSO: registro $STATO3, atteso EXPIRED APPLIED"; exit 1; }
echo "OK: scadenza, 0 peer scaduti col TTL in corso, 1 col TTL passato; chiave fuori dal runtime, l'altro peer resta, EXPIRED APPLIED"
