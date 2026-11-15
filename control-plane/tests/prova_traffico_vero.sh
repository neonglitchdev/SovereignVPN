#!/usr/bin/env bash
# Prova di TRAFFICO VERO (runner Linux, root): un server e due peer WireGuard veri in network namespace separati, una
# «internet» finta (un ponte con un sito, un DNS esterno e una sorgente SSH autorizzata), il firewall e i sysctl di
# sovereignctl. Ogni divieto ha accanto il suo controllo positivo sullo stesso percorso: un «non passa» non puo' venire
# da una rete rotta. In fondo un firewall guastato apposta deve far passare cio' che prima era fermo: se non passa,
# la prova e' cieca.
#   peer -> internet passa, mascherato; il DNS esterno no, la porta 5353 dello stesso host si';
#   peer -> altro peer no (isolamento), server -> peer si';
#   peer -> DNS e amministrazione del server si', amministrazione dal WAN no; SSH solo da admin_ssh_sources (ANC-0182);
#   peer revocato: niente traffico, l'altro peer si' (FR-PEER-004).
# Non provato, e dichiarato: l'IPv6 dei peer (il registro assegna solo IPv4 e WireGuard scarta l'IPv6 prima del firewall).
#   sudo bash control-plane/tests/prova_traffico_vero.sh
set -Eeuo pipefail
IFS=$'\n\t'
[ "$(id -u)" -eq 0 ] || { echo "prova_traffico_vero: serve root"; exit 1; }
for c in wg wg-quick nft ping; do command -v "$c" >/dev/null || { echo "prova_traffico_vero: serve $c"; exit 1; }; done
NSS=(tinet tsrv tp1 tp2)
D="$(mktemp -d)"
PIDS=()
pulizia() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  for n in "${NSS[@]}"; do ip netns del "$n" 2>/dev/null || true; done
  rm -rf "$D"
}
trap pulizia EXIT
cd "$(dirname "$0")/.."
CONFIG=../config/examples/server.toml
rosso() { echo "ROSSO: $*"; exit 1; }
ns() { local n="$1"; shift; ip netns exec "$n" "$@"; }
passa() { ns "$1" python3 tests/rete_finta.py tcp "${@:2}"; }  # ns indirizzo porta [sorgente]
manda() { ns "$1" python3 tests/rete_finta.py udp "$2" "$3" "$4"; }
ascolta() {  # ns proto indirizzo porta file [byte della risposta]
  ns "$1" python3 tests/rete_finta.py ascolta "${@:2}" &
  PIDS+=("$!")
  for _ in $(seq 50); do [ -e "$5" ] && return 0; sleep 0.1; done
  rosso "l'ascoltatore $2 $3:$4 in $1 non parte"
}
arriva() {  # file testo: aspetta fino a 3 s che il testo compaia nel file dell'ascoltatore
  for _ in $(seq 30); do grep -qF "$2" "$1" && return 0; sleep 0.1; done
  return 1
}

# rete: un ponte in «internet»; server (ens3) e peer (u0) attaccati come host pubblici
for n in "${NSS[@]}"; do ip netns add "$n"; ns "$n" ip link set lo up; done
ns tinet ip link add br0 type bridge
ns tinet ip link set br0 up
ns tinet ip address add 203.0.113.254/24 dev br0
ns tinet ip address add 198.51.100.10/32 dev br0  # sorgente SSH autorizzata dalla configurazione d'esempio
ns tinet ip address add 192.0.2.80/32 dev lo      # un sito su internet
ns tinet ip address add 192.0.2.53/32 dev lo      # un DNS esterno
collega() {  # ns interfaccia indirizzo
  ip link add "$2" netns "$1" type veth peer name "v-$1" netns tinet
  ns tinet ip link set "v-$1" master br0 up
  ns "$1" ip address add "$3" dev "$2"
  ns "$1" ip link set "$2" up
}
collega tsrv ens3 203.0.113.1/24
ns tsrv ip route add default via 203.0.113.254
collega tp1 u0 203.0.113.2/24
collega tp2 u0 203.0.113.3/24

# server: wg0, sysctl e firewall di sovereignctl, peer dal registro
(umask 077; wg genkey > "$D/server.key"; wg genkey > "$D/tp1.key"; wg genkey > "$D/tp2.key")
ns tsrv ip link add wg0 type wireguard
ns tsrv ip address add 10.66.0.1/24 dev wg0
ns tsrv ip link set wg0 up
ns tsrv python3 -m sovereignctl host apply >/dev/null
ns tsrv python3 -m sovereignctl firewall apply --config "$CONFIG" --wan-interface ens3 >/dev/null
peer() { python3 -m sovereignctl peer "$@"; }
ID1="$(peer add --db "$D/r.db" --name uno --public-key "$(wg pubkey < "$D/tp1.key")" --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
peer add --db "$D/r.db" --name due --public-key "$(wg pubkey < "$D/tp2.key")" >/dev/null
ns tsrv python3 -m sovereignctl peer reconcile --db "$D/r.db" --interface wg0 --server-key "$D/server.key" >/dev/null
ns tsrv wg show wg0 allowed-ips | grep -qF "$(wg pubkey < "$D/tp2.key")"$'\t'"10.66.0.3/32" || rosso "il secondo peer non ha 10.66.0.3/32"

# peer: WireGuard vero verso il server; nel tunnel solo la VPN e la rete del sito, cosi' il resto resta sul ponte
cliente() {  # ns indirizzo
  ns "$1" ip link add wgp type wireguard
  ns "$1" wg set wgp private-key "$D/$1.key" peer "$(wg pubkey < "$D/server.key")" endpoint 203.0.113.1:51820 allowed-ips 10.66.0.0/24,192.0.2.0/24
  ns "$1" ip address add "$2/32" dev wgp
  ns "$1" ip link set wgp up
  ns "$1" ip route add 10.66.0.0/24 dev wgp src "$2"
  ns "$1" ip route add 192.0.2.0/24 dev wgp src "$2"
  ns "$1" ping -q -c 2 -W 2 10.66.0.1 >/dev/null || rosso "$1 non raggiunge il server nel tunnel"
}
cliente tp1 10.66.0.2
# il peer 2 si configura dal profilo esportato (FR-PEER-007, FR-WG-004): full-tunnel, la chiave privata messa sul
# «dispositivo» al posto del segnaposto [H2]; l'endpoint resta raggiungibile perche' la rotta del ponte e' piu' specifica
ID2="$(peer list --db "$D/r.db" --json | python3 -c 'import json,sys; print([p["id"] for p in json.load(sys.stdin) if p["nome"] == "due"][0])')"
sed 's/^endpoint = .*/endpoint = "203.0.113.1"/' "$CONFIG" > "$D/server.toml"  # l'esempio dice vpn.example.org, qui non risolvibile
python3 -m sovereignctl profile export "$ID2" --conferma --config "$D/server.toml" --db "$D/r.db" --server-key "$D/server.key" --out "$D/export" >/dev/null
PROFILO="$D/export/$ID2.conf"
grep -qx 'Endpoint = 203.0.113.1:51820' "$PROFILO" || rosso "l'endpoint del profilo non e' quello della configurazione"
[ "$(stat -c '%a' "$PROFILO")" = "600" ] || rosso "il profilo esportato non e' 0600"
grep -qx 'AllowedIPs = 0.0.0.0/0, ::/0' "$PROFILO" || rosso "il profilo non e' full-tunnel con l'IPv6 nel tunnel"
if grep -qF "$(cat "$D/server.key")" "$PROFILO"; then rosso "nel profilo c'e' la chiave privata del server"; fi
sed "s|<CHIAVE_PRIVATA_DEL_DISPOSITIVO>|$(cat "$D/tp2.key")|" "$PROFILO" > "$D/tp2.conf"
wg-quick strip "$D/tp2.conf" > "$D/tp2.wg"
ns tp2 ip link add wgp type wireguard
ns tp2 wg setconf wgp "$D/tp2.wg"
ns tp2 ip address add "$(sed -n 's/^Address = //p' "$D/tp2.conf")" dev wgp
ns tp2 ip link set wgp up
ns tp2 ip route add default dev wgp
ns tp2 ping -q -c 2 -W 2 10.66.0.1 >/dev/null || rosso "tp2 col profilo esportato non raggiunge il server"
echo "OK: due peer WireGuard veri collegati al server, il secondo col profilo esportato (full-tunnel, 0600, senza segreti)"

ascolta tinet tcp 192.0.2.80 8080 "$D/sito.txt"
ascolta tinet udp 192.0.2.53 53 "$D/dns53.txt"
ascolta tinet udp 192.0.2.53 5353 "$D/dns5353.txt"
ascolta tsrv tcp 0.0.0.0 22 "$D/ssh.txt"
ascolta tsrv tcp 0.0.0.0 8443 "$D/admin.txt"
ascolta tsrv udp 10.66.0.1 53 "$D/dnsint.txt"
ascolta tp2 tcp 10.66.0.3 9000 "$D/p2.txt"

# 1. internet, mascherato
passa tp1 192.0.2.80 8080 || rosso "il peer non raggiunge internet"
[ "$(tail -1 "$D/sito.txt")" = "203.0.113.1" ] || rosso "il sito vede $(tail -1 "$D/sito.txt"), atteso 203.0.113.1 (masquerade)"
echo "OK: peer -> internet passa, e il sito vede l'indirizzo del server (masquerade)"

# 2. isolamento fra peer, col controllo dal server
if passa tp1 10.66.0.3 9000; then rosso "un peer raggiunge l'altro peer"; fi
passa tsrv 10.66.0.3 9000 || rosso "controllo: il server non raggiunge il peer 2, l'isolamento non sarebbe distinguibile"
echo "OK: peer -> altro peer fermo; server -> peer passa sullo stesso tunnel"

# 3. DNS esterno fermo, la porta accanto passa
manda tp1 192.0.2.53 53 dns-esterno
manda tp1 192.0.2.53 5353 controllo
arriva "$D/dns5353.txt" controllo || rosso "controllo: la porta 5353 del DNS esterno non arriva, la prova non distinguerebbe"
[ ! -s "$D/dns53.txt" ] || rosso "il DNS esterno ha ricevuto dal peer: $(cat "$D/dns53.txt")"
echo "OK: peer -> DNS esterno fermo; la porta 5353 dello stesso host passa"

# 3b. DoT verso fuori fermo (FR-DNS-006, H25), la porta accanto dello stesso host passa; col blocco spento passa la 853
ascolta tinet tcp 192.0.2.53 853 "$D/dot.txt"
ascolta tinet tcp 192.0.2.53 8853 "$D/dot8853.txt"
if passa tp1 192.0.2.53 853; then rosso "DoT verso fuori passa"; fi
passa tp1 192.0.2.53 8853 || rosso "controllo: la 8853 dello stesso host non passa, la prova non distinguerebbe"
ns tsrv python3 -c 'import sys; from sovereignctl import configurazione, firewall; c = configurazione.leggi(sys.argv[1]); firewall.applica(firewall.componi(c["subnet"], "wg0", c["wg_port"], "ens3", c["admin_port"], c["ssh_port"], c["admin_ssh_sources"], c.get("mtu", 1420), False))' "$CONFIG"
passa tp1 192.0.2.53 853 || rosso "col blocco DoT spento la 853 ancora non passa: la prova non vede la regola"
ns tsrv python3 -m sovereignctl firewall apply --config "$CONFIG" --wan-interface ens3 >/dev/null
echo "OK: DoT verso fuori fermo (reject su TCP 853), la 8853 passa, e col blocco spento passa anche la 853"

# 4. DNS e amministrazione del server dalla VPN; amministrazione dal WAN ferma
manda tp1 10.66.0.1 53 dns-interno
arriva "$D/dnsint.txt" "10.66.0.2 dns-interno" || rosso "il DNS interno non riceve dal peer"
passa tp1 10.66.0.1 8443 || rosso "il peer non raggiunge l'amministrazione dalla VPN"
if passa tinet 203.0.113.1 8443; then rosso "l'amministrazione e' raggiungibile dal WAN"; fi
echo "OK: DNS interno e amministrazione dalla VPN passano; l'amministrazione dal WAN e' ferma (ADR-006)"

# 5. SSH solo dalle sorgenti dichiarate
passa tinet 203.0.113.1 22 198.51.100.10 || rosso "SSH dalla sorgente autorizzata non passa"
if passa tinet 203.0.113.1 22 203.0.113.254; then rosso "SSH passa da una sorgente non autorizzata"; fi
echo "OK: SSH da 198.51.100.10 passa, da 203.0.113.254 no (ANC-0182)"

# 6. la prova vede: un firewall guastato apposta (peer non isolati, DNS esterno aperto) deve far passare tutti e due
ns tsrv python3 - "$CONFIG" <<'PY'
import sys
from sovereignctl import configurazione, firewall
c = configurazione.leggi(sys.argv[1])
t = firewall.componi(c["subnet"], "wg0", c["wg_port"], "ens3", c["admin_port"], c["ssh_port"], c["admin_ssh_sources"])
isolamento, dns = 'iifname "wg0" oifname "wg0" drop', 'iifname "wg0" meta l4proto { tcp, udp } th dport 53 drop'
assert isolamento in t and dns in t, "le regole da guastare non ci sono"
firewall.applica(t.replace(isolamento, isolamento.replace("drop", "accept")).replace(dns, ""))
PY
passa tp1 10.66.0.3 9000 || rosso "col firewall guastato il peer ancora non raggiunge l'altro: la prova d'isolamento e' cieca"
manda tp1 192.0.2.53 53 col-guasto
arriva "$D/dns53.txt" col-guasto || rosso "col firewall guastato il DNS esterno ancora non riceve: la prova del DNS e' cieca"
ns tsrv python3 -m sovereignctl firewall apply --config "$CONFIG" --wan-interface ens3 >/dev/null
if passa tp1 10.66.0.3 9000; then rosso "rimesso il firewall vero, i peer si raggiungono ancora"; fi
echo "OK: col firewall guastato isolamento e DNS cadono, col firewall vero tornano: la prova vede la differenza"

# 6b. rotte per peer nel firewall (FR-PEER-008, H33): il peer 1 limitato a 192.0.2.53/32 non raggiunge piu' il sito
#     192.0.2.80, la 8853 di 192.0.2.53 si'; col firewall senza limiti il sito torna raggiungibile
ns tsrv python3 - "$CONFIG" <<'PY'
import sys
from sovereignctl import configurazione, firewall
c = configurazione.leggi(sys.argv[1])
firewall.applica(firewall.componi(c["subnet"], "wg0", c["wg_port"], "ens3", c["admin_port"], c["ssh_port"], c["admin_ssh_sources"],
                                  c.get("mtu", 1420), True, [("10.66.0.2", ["192.0.2.53/32"])]))
PY
if passa tp1 192.0.2.80 8080; then rosso "il peer limitato a 192.0.2.53/32 raggiunge ancora 192.0.2.80"; fi
passa tp1 192.0.2.53 8853 || rosso "il peer limitato non raggiunge nemmeno la sua rotta 192.0.2.53"
ns tsrv python3 -m sovereignctl firewall apply --config "$CONFIG" --wan-interface ens3 --db "$D/r.db" >/dev/null
passa tp1 192.0.2.80 8080 || rosso "col firewall senza limiti il peer 1 non raggiunge piu' il sito"
echo "OK: rotte per peer, col limite il peer esce solo verso 192.0.2.53/32; senza, il sito torna raggiungibile"

# 6c. DNS policy per peer (FR-PEER-008, H34): col DNS libero il peer 1 raggiunge il DNS esterno, senza no
ns tsrv python3 - "$CONFIG" <<'PY'
import sys
from sovereignctl import configurazione, firewall
c = configurazione.leggi(sys.argv[1])
firewall.applica(firewall.componi(c["subnet"], "wg0", c["wg_port"], "ens3", c["admin_port"], c["ssh_port"], c["admin_ssh_sources"],
                                  c.get("mtu", 1420), True, (), ["10.66.0.2"]))
PY
manda tp1 192.0.2.53 53 dns-libero
arriva "$D/dns53.txt" dns-libero || rosso "col DNS libero il peer 1 non raggiunge il DNS esterno"
ns tsrv python3 -m sovereignctl firewall apply --config "$CONFIG" --wan-interface ens3 --db "$D/r.db" >/dev/null
manda tp1 192.0.2.53 53 dns-di-nuovo-interno
manda tp1 192.0.2.53 5353 controllo-6c
arriva "$D/dns5353.txt" controllo-6c || rosso "controllo: la 5353 non arriva, la prova non distinguerebbe"
if grep -qF dns-di-nuovo-interno "$D/dns53.txt"; then rosso "senza DNS libero il peer 1 raggiunge ancora il DNS esterno"; fi
echo "OK: DNS policy per peer, libero raggiunge il DNS esterno, interno no (la 5353 accanto passa)"

# 6d. quota per peer (FR-PEER-008, H35): 100 kB al peer 1 nel registro; la risposta da 300000 byte si ferma; dopo un
#     altro firewall apply (come il reconcile di ogni minuto) una connessione piccola resta ferma: la quota non riparte
#     da zero; tolta la quota il peer torna a passare
quota_peer1() { python3 -c 'import sqlite3,sys; d=sqlite3.connect(sys.argv[1]); d.execute(sys.argv[2]); d.commit()' "$D/r.db" "$1"; }
fw_vero() { ns tsrv python3 -m sovereignctl firewall apply --config "$CONFIG" --wan-interface ens3 --db "$D/r.db" >/dev/null; }
quota_peer1 "UPDATE peer SET quota_byte = 100000 WHERE nome = 'uno'"
fw_vero
ascolta tinet tcp 192.0.2.80 8082 "$D/quota.txt" 300000
if ns tp1 python3 tests/rete_finta.py scarica 192.0.2.80 8082 300000; then rosso "oltre la quota di 100 kB la risposta da 300000 byte arriva"; fi
fw_vero
if passa tp1 192.0.2.80 8080; then rosso "dopo un altro firewall apply la quota e' ripartita da zero"; fi
quota_peer1 "UPDATE peer SET quota_byte = NULL, quota_usati = NULL WHERE nome = 'uno'"
fw_vero
passa tp1 192.0.2.80 8080 || rosso "tolta la quota il peer 1 non passa piu'"
echo "OK: quota per peer, oltre 100 kB il peer si ferma, un firewall apply non la azzera, tolta la quota passa"

# 7. revoca: il peer revocato non passa piu', l'altro si'
peer revoke --db "$D/r.db" "$ID1" >/dev/null
ns tsrv python3 -m sovereignctl peer reconcile --db "$D/r.db" --interface wg0 --server-key "$D/server.key" >/dev/null
if passa tp1 192.0.2.80 8080; then rosso "il peer revocato raggiunge ancora internet"; fi
passa tp2 192.0.2.80 8080 || rosso "controllo: dopo la revoca dell'altro, il peer 2 non raggiunge internet"
echo "OK: dopo la revoca il peer 1 non passa piu', il peer 2 si' (FR-PEER-004)"

# 8. MSS clamping, dove serve (FR-WG-006): il peer 2 porta la sua MTU a 1500 (un client che ignora il profilo) e
#    l'«internet» scarta gli ICMP frag-needed (buco nero PMTUD). Col firewall vero una risposta da 200.000 byte
#    arriva; col firewall senza le due regole MSS non arriva: le regole servono, e la prova vede la differenza.
ascolta tinet tcp 192.0.2.80 8081 "$D/grande.txt" 200000
scarica() { ns "$1" python3 tests/rete_finta.py scarica "${@:2}"; }
ns tp2 ip link set wgp mtu 1500
ns tinet nft add table inet buco
ns tinet nft add chain inet buco entrata '{ type filter hook input priority 0; }'
ns tinet nft add rule inet buco entrata icmp type destination-unreachable drop
scarica tp2 192.0.2.80 8081 200000 || rosso "col firewall vero la risposta grande non arriva al peer con MTU 1500"
ns tsrv python3 - "$CONFIG" <<'PY'
import sys
from sovereignctl import configurazione, firewall
c = configurazione.leggi(sys.argv[1])
t = firewall.componi(c["subnet"], "wg0", c["wg_port"], "ens3", c["admin_port"], c["ssh_port"], c["admin_ssh_sources"], c.get("mtu", 1420))
senza = "".join(r + "\n" for r in t.splitlines() if "maxseg" not in r)
assert t.count("maxseg") == 3 and senza.count("\n") == t.count("\n") - 2, "le regole MSS da togliere non sono due"
firewall.applica(senza)
PY
if scarica tp2 192.0.2.80 8081 200000; then rosso "senza le regole MSS la risposta grande arriva lo stesso: la prova non distingue"; fi
ns tsrv python3 -m sovereignctl firewall apply --config "$CONFIG" --wan-interface ens3 >/dev/null
scarica tp2 192.0.2.80 8081 200000 || rosso "rimesse le regole MSS, la risposta grande non arriva piu'"
echo "OK: MSS, col buco nero PMTUD la risposta da 200000 byte arriva al peer con MTU 1500 solo con le regole MSS (FR-WG-006)"
