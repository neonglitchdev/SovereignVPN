#!/usr/bin/env bash
# Prova di `init --apply` VERO (runner Linux, root), workflow 10.1 (ANC-0263-0270). Interfaccia WireGuard, firewall e
# sysctl vivono in un network namespace, cosi' la rete del runner non si tocca; chiave, manifest e registro vanno nei
# percorsi veri [H12][H13] (il runner e' usa e getta). Il preflight si raccoglie sull'host del runner e deve passare.
# UNA eccezione, dichiarata: l'orologio. Il runner non sempre ha l'NTP sincronizzato (15/11: 10 controlli su 11 alle
# 09:25, 11 su 11 alle 09:29) e una prova che a volte salta e' rossa: se manca, `ntp` si forza a True SOLO qui e lo si
# stampa. Il prodotto non ha flag che saltano controlli.
# Sei giri: primo (sei passi), secondo (idempotente, porta nel runtime il peer aggiunto), terzo con la chiave guasta
# (deve fermarsi alla riconciliazione senza sovrascriverla), quarto con la WAN non valida (rifiutato, niente toccato);
# poi il riavvio (FR-NET-007): quinto, si toglie cio' che un riavvio perde e gira la riga ExecStart dell'unita' systemd
# installata, che deve riportare tutto com'era; sesto, lo stesso con la chiave assente, che non si deve rigenerare.
# Il riavvio vero del runner non si puo' fare: e' dichiarato. Richiede ops/install.sh (nel CI e' il passo prima).
#   sudo bash ops/install.sh && sudo bash control-plane/tests/prova_init_vero.sh
set -Eeuo pipefail
IFS=$'\n\t'
[ "$(id -u)" -eq 0 ] || { echo "prova_init_vero: serve root"; exit 1; }
for c in wg nft; do command -v "$c" >/dev/null || { echo "prova_init_vero: serve $c"; exit 1; }; done
NS=initprova
CHIAVE=/etc/sovereignvpn/wg-server.key
MANIFEST=/var/lib/sovereignvpn/manifest.json
REGISTRO=/var/lib/sovereignvpn/registro.sqlite3
rosso() { echo "ROSSO: $*"; exit 1; }
for f in "$CHIAVE" "$MANIFEST" "$REGISTRO"; do
  [ ! -e "$f" ] || rosso "$f esiste gia', la prova non distinguerebbe il primo giro"
done
D="$(mktemp -d)"
trap 'ip netns del "$NS" 2>/dev/null || true; rm -rf "$D"' EXIT
cd "$(dirname "$0")/.."
CONFIG=../config/examples/server.toml
dentro() { ip netns exec "$NS" "$@"; }

# preflight vero sull'host del runner: tutto OK, salvo l'orologio dichiarato
python3 - "$CONFIG" "$D/fatti.json" <<'PY'
import json, sys
from sovereignctl import configurazione, preflight
cfg = configurazione.leggi(sys.argv[1])
campi = ("wg_port", "admin_port", "subnet")
imp = preflight.leggi_impostazioni(**{k: cfg.get(k) for k in campi}, nomi={k: f"config.{k}" for k in campi})
fatti = preflight.raccogli(imp)
falliti = [c for c in preflight.valuta(fatti, imp)[0] if c["esito"] != "OK"]
if [c["id"] for c in falliti] == ["ora"]:
    print(f"DICHIARATO: orologio del runner non sincronizzato (ntp={fatti['ntp']}), forzato a True solo in questa prova")
    fatti["ntp"] = True
controlli = preflight.valuta(fatti, imp)[0]
falliti = [c for c in controlli if c["esito"] != "OK"]
if falliti:
    sys.exit("ROSSO: preflight del runner: " + "; ".join(f"{c['nome']}: {c['dettaglio']}" for c in falliti))
json.dump(fatti, open(sys.argv[2], "w"))
print(f"OK: preflight del runner, {len(controlli)} controlli superati su {len(controlli)}")
PY

ip netns add "$NS"
# il namespace eredita dall'host (sul runner Docker accende ip_forward): valori OPPOSTI, cosi' il passo sysctl si vede
dentro sysctl -q -w net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=1
applica() {  # il bootstrap vero nel namespace; un input rifiutato prima di toccare l'host torna come «rifiutato»
  dentro python3 - "$CONFIG" "$D/fatti.json" "$1" <<'PY'
import json, sys
from sovereignctl import bootstrap, configurazione, preflight
cfg = configurazione.leggi(sys.argv[1])
fatti = json.load(open(sys.argv[2])); fatti["os"] = tuple(fatti["os"])
try:
    passi, errore = bootstrap.esegui(fatti, cfg, sys.argv[1], sys.argv[3])
except preflight.InputNonValido as e:
    passi, errore, rifiutato = [], None, str(e)
else:
    rifiutato = None
print(json.dumps({"passi": passi, "errore": str(errore) if errore else None, "rifiutato": rifiutato}, ensure_ascii=False))
PY
}
riassunto() {  # una riga: passo=esito | ... | errore | rifiutato
  python3 -c 'import json,sys; r=json.loads(sys.argv[1]); print(" | ".join([f"{p}={e}" for p, e in r["passi"]] + [str(r["errore"]), str(r["rifiutato"])]))' "$1"
}
FISSO="interfaccia=wg0 10.66.0.1/24 | sysctl=True | firewall=True"

# 1. primo giro: sei passi, chiave generata
R1="$(applica ens3)"; L1="$(riassunto "$R1")"; echo "giro 1: $L1"
ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id_installazione"])' "$MANIFEST")"
[ "$L1" = "manifest=$ID | chiave del server=generata | $FISSO | riconciliazione=True | None | None" ] || rosso "primo giro diverso dall'atteso"
if grep -qF "$(cat "$CHIAVE")" <<<"$R1"; then rosso "la chiave privata del server e' nel rapporto"; fi
P="$(stat -c '%a' "$CHIAVE" /etc/sovereignvpn /var/lib/sovereignvpn "$REGISTRO" | tr '\n' ' ')"
[ "$P" = "600 700 700 600 " ] || rosso "permessi di chiave, cartelle e registro = $P, attesi 600 700 700 600"
APERTI="$(find /etc/sovereignvpn /var/lib/sovereignvpn -type f -perm /077 ! -name manifest.json)"
[ -z "$APERTI" ] || rosso "file leggibili da altri: $APERTI"
[ "$(dentro wg show wg0 listen-port)" = "51820" ] || rosso "wg0 non ascolta su 51820"
[ "$(dentro wg show wg0 public-key)" = "$(wg pubkey < "$CHIAVE")" ] || rosso "wg0 non usa la chiave di $CHIAVE"
dentro ip -4 -o addr show dev wg0 | grep -qF "inet 10.66.0.1/24" || rosso "wg0 senza 10.66.0.1/24 (primo host, [H11])"
dentro ip -o link show wg0 | grep -q '[<,]UP[,>]' || rosso "wg0 non e' accesa"
POLICY="$(dentro nft -j list table inet sovereignvpn | python3 -c '
import json,sys; d=json.load(sys.stdin)["nftables"]
print(" ".join("%s=%s" % (o["chain"]["name"], o["chain"].get("policy")) for o in d if "chain" in o))')"
[ "$POLICY" = "input=drop forward=drop postrouting=accept" ] || rosso "policy del firewall $POLICY"
SYS="$(dentro sysctl -n net.ipv4.ip_forward) $(dentro sysctl -n net.ipv6.conf.all.forwarding)"
[ "$SYS" = "1 0" ] || rosso "ip_forward e IPv6 forwarding = $SYS, attesi 1 0"
echo "OK: giro 1, wg0 10.66.0.1/24 su 51820 con la chiave del file (0600, mai stampata), firewall $POLICY, sysctl $SYS"

# 2. secondo giro: stesso id, stessa chiave, stesso firewall; il peer aggiunto nel frattempo entra nel runtime
K="$(wg genkey | wg pubkey)"
python3 -m sovereignctl peer add --db "$REGISTRO" --name prova --public-key "$K" >/dev/null
HK="$(sha256sum "$CHIAVE")"; T1="$(dentro nft list table inet sovereignvpn)"
R2="$(applica ens3)"; L2="$(riassunto "$R2")"; echo "giro 2: $L2"
[ "$L2" = "manifest=$ID | chiave del server=gia' presente | $FISSO | riconciliazione=True | None | None" ] || rosso "secondo giro diverso dall'atteso"
[ "$(sha256sum "$CHIAVE")" = "$HK" ] || rosso "la chiave del server e' cambiata al secondo giro"
[ "$(dentro nft list table inet sovereignvpn)" = "$T1" ] || rosso "il secondo giro ha cambiato il firewall"
dentro wg show wg0 allowed-ips | grep -qF "$K"$'\t'"10.66.0.2/32" || rosso "il peer del registro non e' nel runtime dopo init"
echo "OK: giro 2 idempotente (id $ID, chiave e firewall identici), il peer del registro e' in wg0 con 10.66.0.2/32"

# 3. chiave guasta: init non la rigenera sopra (FR-WG-002), si ferma alla riconciliazione e non ne mostra il contenuto
cp -p "$CHIAVE" "$D/chiave"
printf 'non-una-chiave\n' > "$CHIAVE"
R3="$(applica ens3)"; L3="$(riassunto "$R3")"; echo "giro 3: $L3"
[[ "$L3" == "manifest=$ID | chiave del server=gia' presente | $FISSO | "*"non contiene una chiave WireGuard valida"*" | None" ]] || rosso "con la chiave guasta il giro non si e' fermato alla riconciliazione"
[ "$(cat "$CHIAVE")" = "non-una-chiave" ] || rosso "init ha sovrascritto una chiave esistente"
if grep -qF "non-una-chiave" <<<"$R3"; then rosso "il contenuto della chiave guasta e' nel rapporto"; fi
cat "$D/chiave" > "$CHIAVE"
echo "OK: giro 3, chiave guasta lasciata com'era, fermo dopo 5 passi su 6 (la CLI esce con 4)"

# 4. WAN non valida: rifiutata prima di toccare qualunque cosa
HM="$(sha256sum "$MANIFEST")"; T2="$(dentro nft list table inet sovereignvpn)"
R4="$(applica 'ens3;drop')"; L4="$(riassunto "$R4")"; echo "giro 4: $L4"
[[ "$L4" == "None | --wan-interface:"* ]] || rosso "una WAN non valida non e' stata rifiutata prima dei passi"
[ "$(sha256sum "$MANIFEST")" = "$HM" ] || rosso "la WAN non valida ha riscritto il manifest"
[ "$(dentro nft list table inet sovereignvpn)" = "$T2" ] || rosso "la WAN non valida ha cambiato il firewall"
echo "OK: giro 4, WAN non valida rifiutata con 0 passi su 6, manifest e firewall intatti (la CLI esce con 2)"

# 5. riavvio simulato: si toglie cio' che un riavvio perde, poi gira la riga ExecStart dell'unita' come la lancia systemd
UNITA=/etc/systemd/system/sovereignvpn-reconcile.service
[ -f "$UNITA" ] || rosso "manca $UNITA: prima sudo bash ops/install.sh"
{ echo 'wan_interface = "ens3"'; cat "$CONFIG"; } > "$D/server.toml"  # in testa: dopo [flags] finirebbe nella tabella
install -m 0600 "$D/server.toml" /etc/sovereignvpn/server.toml
EXEC="$(sed -n 's/^ExecStart=//p' "$UNITA")"
IFS=' ' read -r -a ESEGUI <<<"$EXEC"
stato() {
  dentro nft list table inet sovereignvpn
  dentro ip -4 -o addr show dev wg0 | awk '{print $4}'
  dentro wg show wg0 listen-port; dentro wg show wg0 public-key; dentro wg show wg0 allowed-ips
  echo "$(dentro sysctl -n net.ipv4.ip_forward) $(dentro sysctl -n net.ipv6.conf.all.forwarding)"
}
perdi() {  # cio' che un riavvio perde; e si controlla che sia perso davvero, o la prova non distinguerebbe
  dentro ip link del wg0
  dentro nft delete table inet sovereignvpn
  dentro sysctl -q -w net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=1
  if dentro ip link show wg0 >/dev/null 2>&1 || dentro nft list table inet sovereignvpn >/dev/null 2>&1; then
    rosso "il riavvio simulato non ha tolto wg0 o la tabella"
  fi
}
PRIMA="$(stato)"
perdi
set +e; R5="$(dentro "${ESEGUI[@]}" 2>&1)"; C5=$?; set -e
echo "giro 5 ($EXEC), codice $C5:"; echo "$R5"
[ "$C5" -eq 0 ] || rosso "il ripristino al riavvio esce con $C5"
ORDINE="$(sed -n 's/^  \[OK\] \([a-z]*\):.*/\1/p' <<<"$R5" | tr '\n' ' ')"
[ "$ORDINE" = "firewall sysctl interfaccia riconciliazione " ] || rosso "ordine dei passi al riavvio: $ORDINE"
[ "$(stato)" = "$PRIMA" ] || rosso "dopo il ripristino lo stato non e' quello di prima del riavvio"
echo "OK: giro 5, dopo il riavvio simulato firewall, sysctl, wg0 e il peer tornano identici, col firewall per primo"

# 6. chiave assente al riavvio: firewall e rete tornano, la chiave NON si rigenera (cambierebbe l'identita' del server)
mv "$CHIAVE" "$D/chiave6"
perdi
set +e; R6="$(dentro "${ESEGUI[@]}" 2>&1)"; C6=$?; set -e
echo "giro 6, codice $C6:"; echo "$R6"
[ ! -e "$CHIAVE" ] || rosso "il ripristino ha generato una chiave del server nuova"
[ "$C6" -eq 4 ] || rosso "chiave assente al riavvio: codice $C6, atteso 4 (applicato in parte)"
dentro nft list table inet sovereignvpn >/dev/null 2>&1 || rosso "con la chiave assente il firewall non e' tornato"
dentro ip link show wg0 >/dev/null 2>&1 || rosso "con la chiave assente wg0 non e' tornata"
mv "$D/chiave6" "$CHIAVE"
echo "OK: giro 6, chiave assente: firewall e wg0 tornano, nessuna chiave nuova, codice 4"
