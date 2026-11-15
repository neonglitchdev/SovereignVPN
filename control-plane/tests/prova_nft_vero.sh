#!/usr/bin/env bash
# Prova con nftables VERO (runner Linux, root) dentro un network namespace: l'host del runner non si tocca.
# Applica il firewall di base, ne verifica le policy, poi prova la transazione: un ruleset rifiutato non cambia niente.
#   sudo bash control-plane/tests/prova_nft_vero.sh
set -Eeuo pipefail
contiene() { local t; t="$(cat)"; grep -q "$@" <<<"$t"; }  # legge tutto: un grep -q in una pipeline esce presto e,
# con pipefail, il SIGPIPE di chi scrive diventa un rosso finto, o un verde finto in un controllo negativo
IFS=$'\n\t'
[ "$(id -u)" -eq 0 ] || { echo "prova_nft_vero: serve root"; exit 1; }
command -v nft >/dev/null || { echo "prova_nft_vero: serve nftables"; exit 1; }
NS=fwprova
trap 'ip netns del "$NS" 2>/dev/null || true' EXIT
ip netns add "$NS"
cd "$(dirname "$0")/.."
dentro() { ip netns exec "$NS" "$@"; }
dentro python3 -m sovereignctl firewall apply --config ../config/examples/server.toml --wan-interface ens3 --json
POLICY="$(dentro nft -j list table inet sovereignvpn | python3 -c '
import json,sys; d=json.load(sys.stdin)["nftables"]
print(" ".join("%s=%s" % (o["chain"]["name"], o["chain"].get("policy")) for o in d if "chain" in o))')"
[ "$POLICY" = "input=drop prerouting=accept forward=drop postrouting=accept" ] || { echo "ROSSO: policy $POLICY"; exit 1; }
echo "OK: tabella inet sovereignvpn applicata, policy $POLICY"
dentro nft list table inet sovereignvpn | contiene 'iifname "wg0" oifname "wg0" drop' || { echo "ROSSO: manca l'isolamento fra peer"; exit 1; }
# transazione: un ruleset che nft rifiuta non deve toccare la tabella applicata
PRIMA="$(dentro nft list table inet sovereignvpn)"
if dentro python3 -c 'from sovereignctl import firewall; firewall.applica("table inet sovereignvpn { chain input { regola inventata } }")' 2>/dev/null; then
  echo "ROSSO: un ruleset rotto e' stato accettato"; exit 1
fi
[ "$(dentro nft list table inet sovereignvpn)" = "$PRIMA" ] || { echo "ROSSO: il ruleset rotto ha cambiato la tabella"; exit 1; }
echo "OK: un ruleset rifiutato da nft -c lascia la tabella com'era"
# idempotenza: riapplicare non duplica le regole
N1="$(dentro nft list table inet sovereignvpn | wc -l)"
dentro python3 -m sovereignctl firewall apply --config ../config/examples/server.toml --wan-interface ens3 >/dev/null
N2="$(dentro nft list table inet sovereignvpn | wc -l)"
[ "$N1" = "$N2" ] || { echo "ROSSO: la seconda applicazione ha cambiato il numero di righe ($N1 -> $N2)"; exit 1; }
echo "OK: seconda applicazione identica ($N2 righe), nessuna regola duplicata"
