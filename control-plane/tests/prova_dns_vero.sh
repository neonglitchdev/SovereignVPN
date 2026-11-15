#!/usr/bin/env bash
# Prova di Unbound VERO (runner Linux con Docker e Internet): l'immagine nostra pin-nata per digest, la configurazione
# di `sovereignctl dns plan`. DNSSEC: un dominio firmato bene risolve col flag AD, uno firmato male da' SERVFAIL
# (FR-DNS-003); nei log del container nessun nome interrogato (FR-DNS-004). Dipende dalla rete del runner verso le
# radici e dai due domini di prova (isc.org firmato, dnssec-failed.org rotto apposta): e' dichiarato.
# Poi Pi-hole davanti a Unbound, raggiunto da un client WireGuard in un network namespace (serve root).
#   sudo bash control-plane/tests/prova_dns_vero.sh
set -Eeuo pipefail
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
docker run -d --name "$NOME" --network host -v "$D/unbound.conf:/etc/unbound/unbound.conf:ro" sovereignvpn-unbound:prova >/dev/null
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
ip address add 10.98.0.1/24 dev wgdns0; ip link set wgdns0 up
ns ip link add wgc type wireguard
ns wg set wgc private-key "$D/cli.key" peer "$(wg pubkey < "$D/srv.key")" endpoint 192.168.251.1:51898 allowed-ips 10.98.0.0/24
ns ip address add 10.98.0.2/32 dev wgc; ns ip link set wgc up; ns ip route add 10.98.0.0/24 dev wgc
python3 -m sovereignctl dns plan --servizio pihole --interfaccia wgdns0 --json > "$D/pihole.json"
IMMAGINE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["immagine"])' "$D/pihole.json")"
mapfile -t AMBIENTE < <(python3 -c 'import json,sys; [print(f"{k}={v}") for k, v in json.load(open(sys.argv[1]))["ambiente"].items()]' "$D/pihole.json")
ARGS=(); for e in "${AMBIENTE[@]}"; do ARGS+=(-e "$e"); done
docker run -d --name "$PIHOLE" --network host "${ARGS[@]}" -v "$D/pw:/run/secrets/pihole_webpasswd:ro" "$IMMAGINE" >/dev/null
chiedi_vpn() { ns dig +timeout=3 +tries=1 @10.98.0.1 "$@"; }
for _ in $(seq 90); do chiedi_vpn isc.org A 2>/dev/null | grep -q "status: NOERROR" && break; sleep 1; done
BUONO="$(chiedi_vpn isc.org A || true)"
grep -q "status: NOERROR" <<<"$BUONO" || { echo "$BUONO"; docker logs "$PIHOLE" 2>&1 | tail -20; rosso "dal tunnel Pi-hole non risolve isc.org"; }
ROTTO="$(chiedi_vpn dnssec-failed.org A || true)"
grep -q "status: SERVFAIL" <<<"$ROTTO" || { echo "$ROTTO"; rosso "dnssec-failed.org attraverso Pi-hole non da' SERVFAIL"; }
echo "OK: dal tunnel Pi-hole risolve isc.org (via Unbound) e passa il SERVFAIL di dnssec-failed.org"
WAN="$(ns dig +timeout=2 +tries=1 @192.168.251.1 isc.org A 2>&1 || true)"
if grep -q "status: NOERROR" <<<"$WAN"; then echo "$WAN"; rosso "Pi-hole risponde anche sull'indirizzo «WAN»"; fi
echo "OK: sull'indirizzo «WAN» nessuna risposta DNS (listeningMode BIND su wgdns0)"
docker exec "$PIHOLE" pihole deny bloccato-prova.example >/dev/null
for _ in $(seq 10); do chiedi_vpn bloccato-prova.example A | grep -qE "^bloccato-prova\.example\..*0\.0\.0\.0|status: NXDOMAIN" && break; sleep 1; done
NEG="$(chiedi_vpn bloccato-prova.example A || true)"
grep -qE "^bloccato-prova\.example\..*0\.0\.0\.0|status: NXDOMAIN" <<<"$NEG" || { echo "$NEG"; rosso "un nome negato con pihole deny si risolve ancora"; }
echo "OK: un nome negato non si risolve, isc.org si' (FR-DNS-002)"
LOG="$(docker logs "$PIHOLE" 2>&1)"
if grep -qiE "isc\.org|dnssec-failed|bloccato-prova" <<<"$LOG"; then rosso "un nome interrogato e' nel log di Pi-hole"; fi
if grep -qiF "random password" <<<"$LOG" || grep -qF "$(cat "$D/pw")" <<<"$LOG"; then rosso "una password del pannello e' nel log"; fi
FILE_LOG="$(docker exec "$PIHOLE" sh -c 'cat /var/log/pihole/pihole.log 2>/dev/null' || true)"
if grep -qiE "isc\.org|dnssec-failed" <<<"$FILE_LOG"; then rosso "un nome interrogato e' in pihole.log"; fi
echo "OK: nessun nome interrogato nel log del container ne' in pihole.log, nessuna password nel log (FR-DNS-004, FR-OPS-002)"
