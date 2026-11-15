#!/usr/bin/env bash
# Prova di Unbound VERO (runner Linux con Docker e Internet): l'immagine nostra pin-nata per digest, la configurazione
# di `sovereignctl dns plan`. DNSSEC: un dominio firmato bene risolve col flag AD, uno firmato male da' SERVFAIL
# (FR-DNS-003); nei log del container nessun nome interrogato (FR-DNS-004). Dipende dalla rete del runner verso le
# radici e dai due domini di prova (isc.org firmato, dnssec-failed.org rotto apposta): e' dichiarato.
#   bash control-plane/tests/prova_dns_vero.sh
set -Eeuo pipefail
IFS=$'\n\t'
for c in docker dig; do command -v "$c" >/dev/null || { echo "prova_dns_vero: serve $c"; exit 1; }; done
rosso() { echo "ROSSO: $*"; exit 1; }
D="$(mktemp -d)"
NOME=sovereignvpn-unbound-prova
trap 'docker rm -f "$NOME" >/dev/null 2>&1 || true; rm -rf "$D"' EXIT
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
