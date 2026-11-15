#!/usr/bin/env bash
# I modelli dell'app contro i JSON VERI della CLI (peer list, status, audit run); un JSON senza un campo va rifiutato.
set -Eeuo pipefail
QUI="$(cd "$(dirname "$0")" && pwd)"; CP="$(cd "$QUI/../control-plane" && pwd)"
D="$(mktemp -d)"; trap 'rm -rf "$D"' EXIT
swiftc -swift-version 5 -parse-as-library -o "$D/prova" "$QUI/Sources/Modelli.swift" "$QUI/Prove/ProvaModelli.swift"
cd "$CP"
python3 -m sovereignctl peer add --db "$D/r.db" --name telefono --public-key "$(python3 -c 'import base64,os; print(base64.b64encode(os.urandom(32)).decode())')" >/dev/null
python3 -m sovereignctl peer add --db "$D/r.db" --name portatile --public-key "$(python3 -c 'import base64,os; print(base64.b64encode(os.urandom(32)).decode())')" --ttl-days 3 >/dev/null
python3 -m sovereignctl peer list --db "$D/r.db" --json > "$D/peer.json"
python3 -m sovereignctl status --config ../config/examples/server.toml --db "$D/r.db" --json > "$D/status.json" || true
python3 -m sovereignctl audit run --config ../config/examples/server.toml --db "$D/r.db" --json > "$D/audit.json" || true
printf '[Interface]\nPrivateKey = %s\nAddress = 10.64.1.2/32\n[Peer]\nPublicKey = %s\nEndpoint = 185.1.2.3:51820\nAllowedIPs = 0.0.0.0/0\n' \
  "$(python3 -c 'import base64,os; print(base64.b64encode(os.urandom(32)).decode())')" "$(python3 -c 'import base64,os; print(base64.b64encode(os.urandom(32)).decode())')" \
  | python3 -m sovereignctl exit import - --paese DE --nome Francoforte --cartella "$D/uscite" >/dev/null
python3 -m sovereignctl exit list --cartella "$D/uscite" --json > "$D/uscite.json"
"$D/prova" "$D/peer.json" "$D/status.json" "$D/audit.json" "$D/uscite.json"
python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); del r["controlli"][0]["evidenza"]; json.dump(r, open(sys.argv[2],"w"))' "$D/audit.json" "$D/audit-rotto.json"
if "$D/prova" "$D/peer.json" "$D/status.json" "$D/audit-rotto.json" "$D/uscite.json" >/dev/null; then echo "ROSSO: un JSON senza un campo e' stato accettato: la prova non vede"; exit 1; fi
python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); del r["uscite"][0]["bandierina"]; json.dump(r, open(sys.argv[2],"w"))' "$D/uscite.json" "$D/uscite-rotto.json"
if "$D/prova" "$D/peer.json" "$D/status.json" "$D/audit.json" "$D/uscite-rotto.json" >/dev/null; then echo "ROSSO: un'uscita senza bandierina e' stata accettata"; exit 1; fi
echo "OK: i modelli dell'app decodificano i JSON veri di peer list, status, audit run ed exit list; un JSON senza un campo e' rifiutato"
