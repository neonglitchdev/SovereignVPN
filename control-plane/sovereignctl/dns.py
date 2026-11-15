"""DNS interno, primo pezzo: Unbound (FR-DNS-003, FR-DNS-004; cap. 6) [H22].

Unbound risolve ricorsivamente dalle radici e valida DNSSEC: nessuna forward-zone (cap. 6: «mai forwarder pubblici non
dichiarati»), trust anchor del pacchetto dns-root-data. Nessuna traccia delle query: verbosita' 0, log di query,
risposte, servfail e azioni locali spenti, niente statistiche, niente file di log (FR-DNS-004). Ascolta solo su
127.0.0.1: davanti, sulla VPN, ci sara' Pi-hole; dalla WAN non si raggiunge (cap. 6, interfacce DNS mai sulla WAN).
L'immagine e' nostra (ops/dns/unbound/Dockerfile): debian:12-slim pin-nata per digest (ANC-0319) col pacchetto Debian.
"""
import json, sys

PORTA_UNBOUND = 5335


def unbound_conf(porta=PORTA_UNBOUND):
    righe = ["# SovereignVPN 14.0.0 — Unbound, generato da `sovereignctl dns plan`; non modificare a mano",
             "server:",
             f"  interface: 127.0.0.1@{porta}",
             "  access-control: 0.0.0.0/0 refuse",
             "  access-control: 127.0.0.0/8 allow",
             "  do-ip4: yes", "  do-ip6: no", "  do-udp: yes", "  do-tcp: yes",
             '  username: "unbound"', '  chroot: ""',
             "  # ricorsione dalle radici, nessuna forward-zone (cap. 6); DNSSEC validato",
             '  trust-anchor-file: "/usr/share/dns/root.key"',
             "  harden-dnssec-stripped: yes", "  harden-glue: yes", "  qname-minimisation: yes",
             "  hide-identity: yes", "  hide-version: yes",
             "  # nessuna traccia delle query (FR-DNS-004)",
             "  verbosity: 0", "  log-queries: no", "  log-replies: no", "  log-servfail: no", "  log-local-actions: no",
             "  val-log-level: 0", "  use-syslog: no", '  logfile: ""', "  statistics-interval: 0", "  extended-statistics: no"]
    return "\n".join(righe) + "\n"


def aggiungi_parser(sotto, classe):
    dns = sotto.add_parser("dns", help="DNS interno: Unbound (FR-DNS-003/004)")
    az = dns.add_subparsers(dest="azione", required=True, parser_class=classe)
    pl = az.add_parser("plan", help="la configurazione di Unbound, solo testo")
    pl.add_argument("--porta", type=int, default=PORTA_UNBOUND)
    pl.add_argument("--json", action="store_true")


def esegui(a):
    if not 1024 <= a.porta <= 65535:
        print("sovereignctl: input non valido: --porta da 1024 a 65535 (le porte basse sono di Pi-hole)", file=sys.stderr)
        return 2
    testo = unbound_conf(a.porta)
    print(json.dumps({"unbound.conf": testo, "mutazioni_eseguite": 0}, ensure_ascii=False, indent=1) if a.json else testo, end="" if not a.json else "\n")
    return 0
