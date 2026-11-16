#!/usr/bin/env bash
# Prova VERA delle uscite per paese (FR-NET-008, H48), runner Linux, root. Una «internet» finta (un ponte con un sito
# che scrive chi vede arrivare), il server di sovereignctl con un peer WireGuard vero, e due uscite finte: due server
# WireGuard che mascherano col loro IP «pubblico» (203.0.113.11 e .12), come farebbe un provider.
#   senza uscita il sito vede il server; con l'uscita vede l'uscita scelta; il cambio, la rotazione e il failover
#   cambiano l'IP; con wgx0 sparita niente esce, e ciascuno dei due livelli del kill switch (tabella nft, rotta
#   unreachable) basta da solo; tolti entrambi il sito vede il server: se non lo vede, la prova e' cieca.
#   sudo bash control-plane/tests/prova_uscite_vero.sh
set -Eeuo pipefail
IFS=$'\n\t'
[ "$(id -u)" -eq 0 ] || { echo "prova_uscite_vero: serve root"; exit 1; }
for c in wg nft ip; do command -v "$c" >/dev/null || { echo "prova_uscite_vero: serve $c"; exit 1; }; done
NSS=(uinet usrv up1 ux1 ux2)
# il nome della seconda uscita si risolve dal file hosts del namespace del server (ip netns exec lo monta su /etc/hosts)
[ ! -e /etc/netns/usrv ] || { echo "prova_uscite_vero: /etc/netns/usrv esiste gia' e non e' di questa prova"; exit 1; }
D="$(mktemp -d)"
PIDS=()
pulizia() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  # kill $! colpisce la subshell di bash, non il processo dentro il namespace, e ip netns del non uccide nessuno:
  # si uccide ogni processo del namespace prima di toglierlo (prima restavano vivi gli ascoltatori)
  for n in "${NSS[@]}"; do ip netns pids "$n" 2>/dev/null | xargs -r kill 2>/dev/null || true; ip netns del "$n" 2>/dev/null || true; done
  rm -rf "$D" /etc/netns/usrv
  rmdir /etc/netns 2>/dev/null || true
}
trap pulizia EXIT
cd "$(dirname "$0")/.."
CONFIG=../config/examples/server.toml
rosso() { echo "ROSSO: $*"; exit 1; }
ns() { local n="$1"; shift; ip netns exec "$n" "$@"; }
sovctl() { ns usrv python3 -m sovereignctl exit "$@" --cartella "$D/uscite" --config "$CONFIG"; }

for n in "${NSS[@]}"; do ip netns add "$n"; ns "$n" ip link set lo up; done
ns uinet ip link add br0 type bridge
ns uinet ip link set br0 address 02:00:00:00:00:fe  # MAC fisso: vedi prova_traffico_vero.sh
ns uinet ip link set br0 up
ns uinet ip address add 203.0.113.254/24 dev br0
ns uinet ip address add 192.0.2.80/32 dev lo  # il sito
collega() {  # ns interfaccia indirizzo
  ip link add "$2" netns "$1" type veth peer name "v-$1" netns uinet
  ns uinet ip link set "v-$1" master br0 up
  ns "$1" ip address add "$3" dev "$2"
  ns "$1" ip link set "$2" up
  ns "$1" ip route add default via 203.0.113.254
}
collega usrv ens3 203.0.113.1/24
collega up1 u0 203.0.113.2/24
collega ux1 e0 203.0.113.11/24
collega ux2 e0 203.0.113.12/24

# le due uscite finte: WireGuard in ascolto, inoltro acceso, masquerade verso il ponte col proprio IP
(umask 077; for k in srv p1 x1 x2 c1; do wg genkey > "$D/$k.key"; done)
uscita_finta() {  # ns numero chiave_privata_del_server [testo al posto della privata nel file]
  ns "$1" sysctl -qw net.ipv4.ip_forward=1
  ns "$1" ip link add wge type wireguard
  ns "$1" wg set wge listen-port 51820 private-key "$D/x$2.key" peer "$(wg pubkey < "$3")" allowed-ips "10.64.$2.2/32"
  ns "$1" ip address add "10.64.$2.1/24" dev wge
  ns "$1" ip link set wge up
  ns "$1" nft -f - <<<"table ip nat { chain post { type nat hook postrouting priority srcnat; oifname \"e0\" masquerade; }; }"
  # il file che darebbe il provider (con ::/0 e DNS, come i file veri)
  printf '[Interface]\nPrivateKey = %s\nAddress = 10.64.%s.2/32\nDNS = 10.64.%s.1\n[Peer]\nPublicKey = %s\nEndpoint = %s:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n' \
    "${4:-$(cat "$3")}" "$2" "$2" "$(wg pubkey < "$D/x$2.key")" "${5:-203.0.113.1$2}" > "$D/uscita$2.conf"
}
uscita_finta ux1 1 "$D/c1.key"
# [H50] la seconda e' un altro server SovereignVPN: conosce la chiave nata qui con `exit key`, e il suo profilo
# porta il segnaposto al posto della privata, che exit import scrive da solo
PUB_USCITA="$(sovctl key --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["chiave_pubblica"])')"
[ "$PUB_USCITA" = "$(wg pubkey < "$D/uscite/chiave-uscita.key")" ] || rosso "exit key non stampa la pubblica della chiave che ha creato"
[ "$(stat -c '%a' "$D/uscite/chiave-uscita.key")" = "600" ] || rosso "la chiave d'uscita del server non e' 0600"
if sovctl key | grep -qF "$(cat "$D/uscite/chiave-uscita.key")"; then rosso "exit key stampa la chiave privata"; fi
# ... e il server di casa ha un nome (DNS dinamico), non un IP: exit import lo risolve e salva l'IP
mkdir -p /etc/netns/usrv
printf '127.0.0.1 localhost\n203.0.113.12 casa-b.example\n' > /etc/netns/usrv/hosts
uscita_finta ux2 2 "$D/uscite/chiave-uscita.key" "<CHIAVE_PRIVATA_DEL_DISPOSITIVO>" casa-b.example
grep -qF "PrivateKey = <CHIAVE_PRIVATA_DEL_DISPOSITIVO>" "$D/uscita2.conf" || rosso "il profilo della seconda uscita non ha il segnaposto"

# server: wg0, sysctl, firewall e un peer, come init
ns usrv python3 -c 'import sys; from sovereignctl import bootstrap, configurazione; c = configurazione.leggi(sys.argv[1]); bootstrap.interfaccia("wg0", c["subnet"], c["subnet6"])' "$CONFIG"
ns usrv python3 -m sovereignctl host apply >/dev/null
ns usrv python3 -m sovereignctl firewall apply --config "$CONFIG" --wan-interface ens3 >/dev/null
python3 -m sovereignctl peer add --db "$D/r.db" --name uno --public-key "$(wg pubkey < "$D/p1.key")" >/dev/null
ns usrv python3 -m sovereignctl peer reconcile --db "$D/r.db" --interface wg0 --server-key "$D/srv.key" --config "$CONFIG" >/dev/null
ns up1 ip link add wgp type wireguard
ns up1 wg set wgp private-key "$D/p1.key" peer "$(wg pubkey < "$D/srv.key")" endpoint 203.0.113.1:51820 allowed-ips 10.66.0.0/24,192.0.2.0/24
ns up1 ip address add 10.66.0.2/32 dev wgp
ns up1 ip link set wgp up
ns up1 ip route add 10.66.0.0/24 dev wgp src 10.66.0.2
ns up1 ip route add 192.0.2.0/24 dev wgp src 10.66.0.2
ns up1 ping -q -c 2 -W 2 10.66.0.1 >/dev/null || rosso "il peer non raggiunge il server nel tunnel"

ns uinet python3 tests/rete_finta.py ascolta tcp 192.0.2.80 8080 "$D/sito.txt" &
PIDS+=("$!")
for _ in $(seq 50); do [ -e "$D/sito.txt" ] && break; sleep 0.1; done
vede() {  # il peer apre il sito (con qualche tentativo: un'uscita appena cambiata fa l'handshake) e stampa chi ha visto
  for _ in 1 2 3 4 5; do
    ns up1 python3 tests/rete_finta.py tcp 192.0.2.80 8080 && { tail -1 "$D/sito.txt"; return 0; }
    sleep 1
  done
  echo "niente"
}
non_esce() {  # $1 motivo: il peer non arriva al sito, e il sito non riceve niente di nuovo
  local prima; prima="$(wc -l < "$D/sito.txt")"
  if ns up1 python3 tests/rete_finta.py tcp 192.0.2.80 8080; then rosso "$1: il peer esce (il sito vede $(tail -1 "$D/sito.txt"))"; fi
  [ "$(wc -l < "$D/sito.txt")" = "$prima" ] || rosso "$1: il sito ha ricevuto da $(tail -1 "$D/sito.txt")"
}

# 1. senza uscita il sito vede il server
[ "$(vede)" = "203.0.113.1" ] || rosso "senza uscita il sito non vede il server"
echo "OK: senza uscita il peer esce dal server (203.0.113.1)"

# 2. il pool: due uscite tedesche; a schermo mai la chiave privata
PRIVATE=("$D/c1.key" "$D/uscite/chiave-uscita.key")
for n in 1 2; do
  OUT="$(sovctl import "$D/uscita$n.conf" --paese DE --json)"
  if grep -qF "$(cat "${PRIVATE[$((n - 1))]}")" <<<"$OUT"; then rosso "import stampa la chiave privata dell'uscita"; fi
done
grep -qF "PrivateKey = $(cat "$D/uscite/chiave-uscita.key")" "$D/uscite/de-2.conf" || rosso "exit import non ha scritto la chiave del server al posto del segnaposto"
SCHEDA2="$(sovctl list --json | python3 -c 'import json,sys; s=[u for u in json.load(sys.stdin)["uscite"] if u["id"]=="de-2"][0]; print(s["endpoint"], s.get("nome_endpoint"))')"
[ "$SCHEDA2" = "203.0.113.12:51820 casa-b.example:51820" ] || rosso "l'uscita col nome non ha nome e IP risolto nella scheda: $SCHEDA2"
LISTA="$(sovctl list --json)"
for k in "${PRIVATE[@]}"; do if grep -qF "$(cat "$k")" <<<"$LISTA"; then rosso "list stampa una chiave privata"; fi; done
[ "$(stat -c '%a' "$D/uscite/de-1.conf")" = "600" ] || rosso "il file dell'uscita non e' 0600"
echo "OK: due uscite DE nel pool, file 0600, nessuna chiave privata a schermo"

# 3. scelta per paese, poi per uscita
sovctl set DE >/dev/null
[ "$(vede)" = "203.0.113.11" ] || rosso "con l'uscita DE il sito non vede 203.0.113.11"
sovctl set de-2 >/dev/null
[ "$(vede)" = "203.0.113.12" ] || rosso "con de-2 il sito non vede 203.0.113.12"
echo "OK: il sito vede l'uscita scelta (de-1 203.0.113.11, poi de-2 203.0.113.12)"

# 4. rotazione ogni minuto: si sposta indietro l'ultimo cambio e si lancia il giro del timer
sovctl set DE >/dev/null  # stesso paese: resta de-2
sovctl rotation 1 >/dev/null
indietro() { python3 -c 'import json,sys; p=sys.argv[1]; s=json.load(open(p)); s["ultimo_cambio"]-=int(sys.argv[2]); json.dump(s,open(p,"w"))' "$D/uscite/stato.json" "$1"; }
indietro 30
sovctl tick >/dev/null
[ "$(vede)" = "203.0.113.12" ] || rosso "la rotazione e' scattata prima del minuto"
indietro 60
sovctl tick >/dev/null
[ "$(vede)" = "203.0.113.11" ] || rosso "dopo un minuto la rotazione non ha cambiato uscita"
sovctl rotation 0 >/dev/null
echo "OK: rotazione ogni minuto: prima del minuto resta 203.0.113.12, dopo passa a 203.0.113.11"

# 5. kill switch: l'uscita sparisce (wgx0 tolta), niente esce; ognuno dei due livelli basta da solo
ns usrv ip link del wgx0
non_esce "wgx0 tolta, kill switch intero"
ns usrv ip route del unreachable default metric 4294967295 table 51888
non_esce "solo la tabella nft del kill switch"
ns usrv ip route add unreachable default metric 4294967295 table 51888
ns usrv nft delete table inet sovereignvpn_uscita
non_esce "solo la rotta unreachable della tabella dedicata"
ns usrv ip route del unreachable default metric 4294967295 table 51888
[ "$(vede)" = "203.0.113.1" ] || rosso "controllo: tolti i due livelli il peer non esce dalla WAN, la prova non vedrebbe un ripiego"
echo "OK: wgx0 tolta = niente fuori; la tabella nft e la rotta unreachable bastano ciascuna da sola; tolte entrambe il sito vede 203.0.113.1 (la prova vede)"

# 6. riparazione dal timer, poi failover: l'uscita 2 muore, quella attiva diventa la 2 e il timer passa alla 1
# l'ultimo cambio ad adesso: la riparazione non deve dipendere da quanto e' durata la sezione 5 (oltre 180 s senza
# handshake il timer farebbe il failover; nella VM emulata, il 16/11, la 5 e' durata di piu' e la prova e' caduta)
python3 -c 'import json,sys,time; p=sys.argv[1]; s=json.load(open(p)); s["ultimo_cambio"]=int(time.time()); json.dump(s,open(p,"w"))' "$D/uscite/stato.json"
sovctl tick >/dev/null
[ "$(vede)" = "203.0.113.11" ] || rosso "il giro del timer non ha riparato l'uscita"
ns ux2 ip link set wge down
sovctl set de-2 >/dev/null && sovctl set DE >/dev/null  # de-2 attiva nel paese DE, morta: wgx0 nuova, mai un handshake
non_esce "uscita de-2 morta"
indietro 200
sovctl tick >/dev/null
[ "$(vede)" = "203.0.113.11" ] || rosso "il failover non e' passato all'uscita viva"
echo "OK: de-2 morta = niente fuori; dopo 3 minuti senza handshake il timer passa a de-1 (203.0.113.11)"

# 7. riavvio: tutto perso, il passo «uscita» di reconcile lo rifa' (prima dei peer)
ns usrv ip link del wgx0; ns usrv nft delete table inet sovereignvpn_uscita
ns usrv ip rule del iif wg0 lookup 51888 priority 5199; ns usrv ip rule del fwmark 0x5e48 lookup main priority 5198; ns usrv ip route flush table 51888
[ "$(vede)" = "203.0.113.1" ] || rosso "controllo: senza nessuna parte dell'uscita il peer dovrebbe uscire dal server"
ns usrv python3 -c 'import sys; from sovereignctl import configurazione, uscite; print(uscite.ripristina(configurazione.leggi(sys.argv[1]), cartella=sys.argv[2]))' "$CONFIG" "$D/uscite" >/dev/null
[ "$(vede)" = "203.0.113.11" ] || rosso "il passo di reconcile non ha rifatto l'uscita"
echo "OK: dopo il «riavvio» il passo uscita di reconcile rifa' kill switch, rotte e wgx0 (203.0.113.11)"

# 8. off: si torna al server, e non resta niente dell'uscita
sovctl set off >/dev/null
[ "$(vede)" = "203.0.113.1" ] || rosso "con l'uscita spenta il peer non esce dal server"
if ns usrv nft list table inet sovereignvpn_uscita >/dev/null 2>&1; then rosso "off lascia la tabella del kill switch"; fi
if ns usrv ip link show wgx0 >/dev/null 2>&1; then rosso "off lascia wgx0"; fi
[ -z "$(ns usrv ip rule show priority 5199)" ] || rosso "off lascia la regola dei peer"
echo "OK: exit set off: il peer esce dal server e dell'uscita non resta niente"
