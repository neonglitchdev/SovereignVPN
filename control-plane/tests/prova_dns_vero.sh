#!/usr/bin/env bash
# Prova di Unbound VERO (runner Linux con Docker e Internet): l'immagine nostra pin-nata per digest, la configurazione
# di `sovereignctl dns plan`. DNSSEC: un dominio firmato bene risolve col flag AD, uno firmato male da' SERVFAIL
# (FR-DNS-003); nei log del container nessun nome interrogato (FR-DNS-004). Dipende dalla rete del runner verso le
# radici e dai due domini di prova (isc.org firmato, dnssec-failed.org rotto apposta): e' dichiarato.
# Poi Pi-hole davanti a Unbound, raggiunto da un client WireGuard in un network namespace (serve root).
#   sudo bash control-plane/tests/prova_dns_vero.sh
set -Eeuo pipefail
contiene() { local t; t="$(cat)"; grep -q "$@" <<<"$t"; }  # legge tutto: un grep -q in una pipeline esce presto e,
# con pipefail, il SIGPIPE di chi scrive diventa un rosso finto, o un verde finto in un controllo negativo
IFS=$'\n\t'
for c in docker dig wg; do command -v "$c" >/dev/null || { echo "prova_dns_vero: serve $c"; exit 1; }; done
rosso() { echo "ROSSO: $*"; exit 1; }
D="$(mktemp -d)"
NOME=sovereignvpn-unbound-prova
PIHOLE=sovereignvpn-pihole-prova
trap 'docker rm -f "$NOME" "$PIHOLE" >/dev/null 2>&1 || true; ip link del wgdns0 2>/dev/null || true; ip link del vdns0 2>/dev/null || true; ip netns del dnscli 2>/dev/null || true; rm -rf "$D"' EXIT
cd "$(dirname "$0")/.."
docker build -q -t sovereignvpn-unbound:prova ../ops/dns/unbound >/dev/null
python3 -m sovereignctl dns plan > "$D/unbound.conf"
chmod 0644 "$D/unbound.conf"
docker run --rm -v "$D/unbound.conf:/etc/unbound/unbound.conf:ro" sovereignvpn-unbound:prova unbound-checkconf /etc/unbound/unbound.conf
sed 's/^  verbosity: 0$/  verbosity: nonumero/' "$D/unbound.conf" > "$D/rotta.conf"
if docker run --rm -v "$D/rotta.conf:/etc/unbound/unbound.conf:ro" sovereignvpn-unbound:prova unbound-checkconf /etc/unbound/unbound.conf >/dev/null 2>&1; then
  rosso "unbound-checkconf accetta una configurazione rotta: il controllo non vede"
fi
echo "OK: immagine costruita, configurazione accettata da unbound-checkconf, quella rotta rifiutata"
mapfile -t VINCOLI_UB < <(python3 -c 'from sovereignctl import dns; print("\n".join(dns.VINCOLI_UNBOUND))')
docker run -d --name "$NOME" --network host "${VINCOLI_UB[@]}" -v "$D/unbound.conf:/etc/unbound/unbound.conf:ro" sovereignvpn-unbound:prova >/dev/null
vincoli() { python3 -c 'import json,sys; from sovereignctl import audit, dns; print(json.dumps(audit.vincoli_mancanti(sys.argv[1], getattr(dns, sys.argv[2]))))' "$@"; }
[ "$(vincoli "$NOME" VINCOLI_UNBOUND)" = "[]" ] || rosso "Unbound acceso senza i vincoli dichiarati: $(vincoli "$NOME" VINCOLI_UNBOUND)"
chiedi() { dig +dnssec +timeout=5 +tries=2 @127.0.0.1 -p 5335 "$@"; }
for _ in $(seq 30); do chiedi . NS >/dev/null 2>&1 && break; sleep 1; done
BUONO="$(chiedi isc.org A)"
grep -q "status: NOERROR" <<<"$BUONO" || { echo "$BUONO"; rosso "isc.org non risolve"; }
grep -qE "flags:[^;]* ad[ ;]" <<<"$BUONO" || { echo "$BUONO"; rosso "isc.org risolve senza il flag AD: DNSSEC non validato"; }
ROTTO="$(chiedi dnssec-failed.org A || true)"
grep -q "status: SERVFAIL" <<<"$ROTTO" || { echo "$ROTTO"; rosso "dnssec-failed.org non da' SERVFAIL: la validazione DNSSEC non rifiuta"; }
echo "OK: DNSSEC, isc.org NOERROR col flag AD, dnssec-failed.org SERVFAIL"
LOG="$(docker logs "$NOME" 2>&1)"
if grep -qiE "isc\.org|dnssec-failed" <<<"$LOG"; then echo "$LOG"; rosso "un nome interrogato e' nei log del container"; fi
echo "OK: nei log del container ($(wc -l <<<"$LOG" | tr -d ' ') righe) nessun nome interrogato (FR-DNS-004)"

# Pi-hole davanti a Unbound [H23]: su un'interfaccia WireGuard di prova dell'host (wgdns0, 10.98.0.1), raggiunto da un
# client in un network namespace attraverso il tunnel; la «WAN» e' il veth 192.168.251.1, dove non deve rispondere.
[ "$(id -u)" -eq 0 ] || rosso "la parte di Pi-hole serve root (network namespace e WireGuard)"
ns() { ip netns exec dnscli "$@"; }
(umask 077; wg genkey > "$D/srv.key"; wg genkey > "$D/cli.key"; head -c 24 /dev/urandom | base64 > "$D/pw")
ip netns add dnscli
ip link add vdns0 type veth peer name vdns1 netns dnscli
ip address add 192.168.251.1/30 dev vdns0; ip link set vdns0 up
ns ip address add 192.168.251.2/30 dev vdns1; ns ip link set vdns1 up; ns ip link set lo up
ip link add wgdns0 type wireguard
wg set wgdns0 listen-port 51898 private-key "$D/srv.key" peer "$(wg pubkey < "$D/cli.key")" allowed-ips 10.98.0.2/32
python3 -c 'from sovereignctl import bootstrap, configurazione; bootstrap.interfaccia("wgdns0", "10.98.0.0/24", configurazione.SUBNET6)'  # IPv4 e ULA, come init [H38]
ns ip link add wgc type wireguard
ns wg set wgc private-key "$D/cli.key" peer "$(wg pubkey < "$D/srv.key")" endpoint 192.168.251.1:51898 allowed-ips 10.98.0.0/24
ns ip address add 10.98.0.2/32 dev wgc; ns ip link set wgc up; ns ip route add 10.98.0.0/24 dev wgc
python3 -m sovereignctl dns plan --servizio pihole --interfaccia wgdns0 --json > "$D/pihole.json"
IMMAGINE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["immagine"])' "$D/pihole.json")"
mapfile -t AMBIENTE < <(python3 -c 'import json,sys; [print(f"{k}={v}") for k, v in json.load(open(sys.argv[1]))["ambiente"].items()]' "$D/pihole.json")
ARGS=(); for e in "${AMBIENTE[@]}"; do ARGS+=(-e "$e"); done
mkdir -m 0755 "$D/liste"
docker run -d --name "$PIHOLE" --network host "${ARGS[@]}" -v "$D/pw:/run/secrets/pihole_webpasswd:ro" -v "$D/liste:/etc/pihole/sovereignvpn:ro" "$IMMAGINE" >/dev/null
chiedi_vpn() { ns dig +timeout=3 +tries=1 @10.98.0.1 "$@"; }
for _ in $(seq 90); do chiedi_vpn isc.org A 2>/dev/null | contiene "status: NOERROR" && break; sleep 1; done
BUONO="$(chiedi_vpn isc.org A || true)"
grep -q "status: NOERROR" <<<"$BUONO" || { echo "$BUONO"; docker logs "$PIHOLE" 2>&1 | tail -20; rosso "dal tunnel Pi-hole non risolve isc.org"; }
ROTTO="$(chiedi_vpn dnssec-failed.org A || true)"
grep -q "status: SERVFAIL" <<<"$ROTTO" || { echo "$ROTTO"; rosso "dnssec-failed.org attraverso Pi-hole non da' SERVFAIL"; }
echo "OK: dal tunnel Pi-hole risolve isc.org (via Unbound) e passa il SERVFAIL di dnssec-failed.org"
WAN="$(ns dig +timeout=2 +tries=1 @192.168.251.1 isc.org A 2>&1 || true)"
if grep -q "status: NOERROR" <<<"$WAN"; then echo "$WAN"; rosso "Pi-hole risponde anche sull'indirizzo «WAN»"; fi
echo "OK: sull'indirizzo «WAN» nessuna risposta DNS (listeningMode BIND su wgdns0)"
docker exec "$PIHOLE" pihole deny bloccato-prova.example >/dev/null
for _ in $(seq 10); do chiedi_vpn bloccato-prova.example A | contiene -E "^bloccato-prova\.example\..*0\.0\.0\.0|status: NXDOMAIN" && break; sleep 1; done
NEG="$(chiedi_vpn bloccato-prova.example A || true)"
grep -qE "^bloccato-prova\.example\..*0\.0\.0\.0|status: NXDOMAIN" <<<"$NEG" || { echo "$NEG"; rosso "un nome negato con pihole deny si risolve ancora"; }
echo "OK: un nome negato non si risolve, isc.org si' (FR-DNS-002)"
LOG="$(docker logs "$PIHOLE" 2>&1)"
if grep -qiE "isc\.org|dnssec-failed|bloccato-prova" <<<"$LOG"; then rosso "un nome interrogato e' nel log di Pi-hole"; fi
if grep -qiF "random password" <<<"$LOG" || contiene -F "$(cat "$D/pw")" <<<"$LOG"; then rosso "una password del pannello e' nel log"; fi
FILE_LOG="$(docker exec "$PIHOLE" sh -c 'cat /var/log/pihole/pihole.log 2>/dev/null' || true)"
if grep -qiE "isc\.org|dnssec-failed" <<<"$FILE_LOG"; then rosso "un nome interrogato e' in pihole.log"; fi
echo "OK: nessun nome interrogato nel log del container ne' in pihole.log, nessuna password nel log (FR-DNS-004, FR-OPS-002)"
# status chiede a Pi-hole dall'host stesso, sull'indirizzo di wg0: con listeningMode BIND deve rispondere anche cosi'
python3 -c 'import sys; from sovereignctl import stato; sys.exit(0 if stato._dns_risponde("10.98.0.1", 53) else 1)' \
  || rosso "dall'host Pi-hole non risponde sull'indirizzo di wgdns0: status lo vedrebbe GUASTO"
if python3 -c 'import sys; from sovereignctl import stato; sys.exit(0 if stato._dns_risponde("192.168.251.1", 53) else 1)'; then
  rosso "dall'host qualcuno risponde sull'indirizzo «WAN» porta 53"
fi
echo "OK: dall'host Pi-hole risponde sull'indirizzo di wgdns0 (come lo chiede status) e non su quello «WAN»"

# inventario delle porte (FR-NET-004, H26): con Unbound e Pi-hole accesi nessun ascolto fuori dal dichiarato; un secondo
# Unbound in ascolto su 0.0.0.0:5336 deve essere trovato
FUORI="$(python3 -c 'from sovereignctl import configurazione, runtime, stato; print(" ".join(stato.porte_fuori_inventario("10.98.0.1", str(runtime.indirizzo6(configurazione.SUBNET6, "10.98.0.1")))))')"
[ -z "$FUORI" ] || { ss -H -lntup | grep -E "unbound|pihole" || true; rosso "ascolti fuori inventario con il DNS acceso: $FUORI"; }
echo "INFO: ascolti di pihole-FTL sulla 53 (BIND li apre su ogni indirizzo di wgdns0, anche l'ULA [H38]): $(ss -H -lnup | awk '/pihole-FTL/ && $4 ~ /:53$/ {print $4}' | sort -u | tr '\n' ' ')"
python3 -m sovereignctl dns plan --porta 5336 | sed 's/127\.0\.0\.1@5336/0.0.0.0@5336/; s#access-control: 127.0.0.0/8 allow#access-control: 0.0.0.0/0 allow#' > "$D/largo.conf"
chmod 0644 "$D/largo.conf"
docker run -d --name "$NOME-largo" --network host -v "$D/largo.conf:/etc/unbound/unbound.conf:ro" sovereignvpn-unbound:prova >/dev/null
for _ in $(seq 20); do ss -H -lnup | contiene ":5336 " && break; sleep 1; done
FUORI="$(python3 -c 'from sovereignctl import configurazione, runtime, stato; print(" ".join(stato.porte_fuori_inventario("10.98.0.1", str(runtime.indirizzo6(configurazione.SUBNET6, "10.98.0.1")))))')"
LARGO="$(vincoli "$NOME-largo" VINCOLI_UNBOUND)"  # controllo negativo: senza vincoli il controllo deve vederli mancare
contiene -F '"read-only"' <<<"$LARGO" && contiene -F '"security-opt no-new-privileges"' <<<"$LARGO" || rosso "l'Unbound senza vincoli passa il controllo dei vincoli ($LARGO)"
docker rm -f "$NOME-largo" >/dev/null
grep -q "unbound 0.0.0.0:5336" <<<"$FUORI" || rosso "un Unbound su 0.0.0.0:5336 non e' stato trovato fuori inventario (trovato: «$FUORI»)"
echo "OK: inventario delle porte, nessun ascolto fuori dal dichiarato; un Unbound su 0.0.0.0:5336 viene trovato"

# liste di blocco versionate (FR-DNS-002/007, H27): la lista attiva blocca, una lista invalida non tocca quella attiva,
# la lista nuova sostituisce la vecchia, il rollback rimette la vecchia
bl() { python3 -m sovereignctl dns blocklist "$@" --cartella "$D/liste" --contenitore "$PIHOLE"; }
bloccato() { chiedi_vpn "$1" A | contiene -E "^$1\.[[:space:]].*0\.0\.0\.0"; }
aspetta() { for _ in $(seq 15); do if [ "$1" = si ]; then bloccato "$2" && return 0; else bloccato "$2" || return 0; fi; sleep 1; done; return 1; }
printf 'lista-prova.example\n# commento\n' > "$D/l1.txt"
printf 'altra-prova.example\n' > "$D/l2.txt"
printf 'lista-prova.example\nnon un dominio!\n' > "$D/rotta.txt"
R1="$(bl apply "$D/l1.txt" --sincronizza --json)"
[ "$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["pihole"]["domini_in_gravity"])' "$R1")" = "1" ] || { echo "$R1"; rosso "gravity non ha il dominio della lista"; }
aspetta si lista-prova.example || rosso "dopo apply la lista non blocca lista-prova.example"
set +e; bl apply "$D/rotta.txt" --sincronizza >/dev/null 2>&1; C=$?; set -e
[ "$C" -eq 2 ] || rosso "una lista invalida esce con $C, atteso 2"
bloccato lista-prova.example || rosso "dopo una lista invalida quella attiva non blocca piu'"
bl apply "$D/l2.txt" --sincronizza >/dev/null
aspetta si altra-prova.example || rosso "la lista nuova non blocca altra-prova.example"
aspetta no lista-prova.example || rosso "con la lista nuova lista-prova.example e' ancora bloccato"
bl rollback --sincronizza >/dev/null
aspetta si lista-prova.example || rosso "dopo il rollback lista-prova.example non e' bloccato"
aspetta no altra-prova.example || rosso "dopo il rollback altra-prova.example e' ancora bloccato"
echo "OK: liste di blocco, la attiva blocca, una invalida (2) lascia l'attiva, la nuova sostituisce, il rollback rimette la vecchia"

# permessi (FR-DNS-008, H28): lista-prova.example e' bloccato; un permesso per lo stesso nome segnala il conflitto e
# vince (antigravity di Pi-hole), il nome torna a risolversi senza 0.0.0.0
printf 'lista-prova.example\n' > "$D/p1.txt"
RP="$(python3 -m sovereignctl dns allowlist apply "$D/p1.txt" --cartella "$D/liste" --contenitore "$PIHOLE" --sincronizza --json)"
[ "$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["conflitti"])' "$RP")" = "['lista-prova.example']" ] || { echo "$RP"; rosso "il conflitto fra permesso e blocco non e' segnalato"; }
aspetta no lista-prova.example || rosso "con il permesso lista-prova.example e' ancora bloccato: il permesso non vince"
echo "OK: permessi, il conflitto con la lista di blocco e' segnalato e il permesso vince (lista-prova.example non piu' bloccato)"
