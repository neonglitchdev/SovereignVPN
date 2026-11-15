"""DNS interno, primo pezzo: Unbound (FR-DNS-003, FR-DNS-004; cap. 6) [H22].

Unbound risolve ricorsivamente dalle radici e valida DNSSEC: nessuna forward-zone (cap. 6: «mai forwarder pubblici non
dichiarati»), trust anchor del pacchetto dns-root-data. Nessuna traccia delle query: verbosita' 0, log di query,
risposte, servfail e azioni locali spenti, niente statistiche, niente file di log (FR-DNS-004). Ascolta solo su
127.0.0.1: davanti, sulla VPN, ci sara' Pi-hole; dalla WAN non si raggiunge (cap. 6, interfacce DNS mai sulla WAN).
L'immagine e' nostra (ops/dns/unbound/Dockerfile): debian:12-slim pin-nata per digest (ANC-0319) col pacchetto Debian.
"""
import json, os, secrets, sys

from .manifest import scrivi_testo

PORTA_UNBOUND = 5335
IMMAGINE_PIHOLE = "pihole/pihole:2026.10.1@sha256:30f803ad5dd60ff96cc0a63008a2e9271af481c1b0399a182192b2e91152c1f9"


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


def pihole_env(wg_if="wg0", porta_unbound=PORTA_UNBOUND):
    """Pi-hole 6 davanti a Unbound [H23]. Socket SOLO sull'indirizzo di wg0 (listeningMode BIND: nemmeno un ascolto sulla
    WAN, e nessuno scontro con systemd-resolved); unico upstream Unbound in locale (cap. 6: niente forwarder pubblici);
    nessuna query nel pihole.log ne' nel database, privacy al massimo nelle statistiche (FR-DNS-004, FR-DNS-009);
    pannello solo su 127.0.0.1 (ADR-006). La password del pannello la legge da un file segreto (WEBPASSWORD_FILE),
    altrimenti Pi-hole ne inventa una e la stampa nel log."""
    return {"TZ": "UTC",
            "FTLCONF_dns_upstreams": f"127.0.0.1#{porta_unbound}",
            "FTLCONF_dns_listeningMode": "BIND", "FTLCONF_dns_interface": wg_if,
            "FTLCONF_dns_queryLogging": "false", "FTLCONF_database_maxDBdays": "0", "FTLCONF_misc_privacylevel": "3",
            "FTLCONF_webserver_port": "127.0.0.1:8081o",
            "WEBPASSWORD_FILE": "pihole_webpasswd"}


CARTELLA_DNS = "/etc/sovereignvpn/dns"


def applica_file(cartella=None, wg_if="wg0"):
    """`dns apply` [H24]: i file che leggono le unita' systemd. unbound.conf 0644, pihole.env 0600; la password del
    pannello si genera una volta sola (secrets, aperta in esclusiva: mai sopra una esistente) e non si stampa mai."""
    cartella = cartella or CARTELLA_DNS
    os.makedirs(cartella, mode=0o700, exist_ok=True)
    os.chmod(cartella, 0o700)
    scrivi_testo(os.path.join(cartella, "unbound.conf"), unbound_conf(), 0o644)
    scrivi_testo(os.path.join(cartella, "pihole.env"), "".join(f"{k}={v}\n" for k, v in pihole_env(wg_if).items()), 0o600)
    segreto, generato = os.path.join(cartella, "pihole-web.secret"), False
    if not os.path.exists(segreto):
        fd = os.open(segreto, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, (secrets.token_urlsafe(24) + "\n").encode())
        finally:
            os.close(fd)
        generato = True
    return {"cartella": cartella, "file": ["unbound.conf", "pihole.env", "pihole-web.secret"], "password_generata": generato}


def aggiungi_parser(sotto, classe):
    dns = sotto.add_parser("dns", help="DNS interno: Unbound (FR-DNS-003/004)")
    az = dns.add_subparsers(dest="azione", required=True, parser_class=classe)
    pl = az.add_parser("plan", help="configurazione di Unbound o ambiente di Pi-hole, solo testo")
    pl.add_argument("--servizio", choices=("unbound", "pihole"), default="unbound")
    pl.add_argument("--porta", type=int, default=PORTA_UNBOUND, help="porta di Unbound su 127.0.0.1")
    pl.add_argument("--interfaccia", default="wg0", help="l'interfaccia WireGuard su cui ascolta Pi-hole")
    pl.add_argument("--json", action="store_true")
    ap = az.add_parser("apply", help="scrive i file di Unbound e Pi-hole che leggono le unita' systemd")
    ap.add_argument("--interfaccia", default="wg0")
    ap.add_argument("--cartella", help="di base /etc/sovereignvpn/dns (0700)")
    ap.add_argument("--json", action="store_true")


def esegui(a):
    if a.azione == "apply":
        from .configurazione import INTERFACCIA
        if not INTERFACCIA.match(a.interfaccia):
            print("sovereignctl: input non valido: --interfaccia: nome di interfaccia Linux di 1-15 caratteri", file=sys.stderr)
            return 2
        esito = applica_file(a.cartella, a.interfaccia)
        print(json.dumps(esito, ensure_ascii=False, indent=1) if a.json else
              f"File del DNS in {esito['cartella']}: unbound.conf (0644), pihole.env e pihole-web.secret (0600"
              + (", password generata ora, non si mostra)" if esito["password_generata"] else ", password gia' presente)"))
        return 0
    if not 1024 <= a.porta <= 65535:
        print("sovereignctl: input non valido: --porta da 1024 a 65535 (le porte basse sono di Pi-hole)", file=sys.stderr)
        return 2
    if a.servizio == "pihole":
        from .configurazione import INTERFACCIA
        if not INTERFACCIA.match(a.interfaccia):
            print("sovereignctl: input non valido: --interfaccia: nome di interfaccia Linux di 1-15 caratteri", file=sys.stderr)
            return 2
        env = pihole_env(a.interfaccia, a.porta)
        print(json.dumps({"immagine": IMMAGINE_PIHOLE, "ambiente": env, "mutazioni_eseguite": 0}, ensure_ascii=False, indent=1)
              if a.json else "".join(f"{k}={v}\n" for k, v in env.items()), end="" if not a.json else "\n")
        return 0
    testo = unbound_conf(a.porta)
    print(json.dumps({"unbound.conf": testo, "mutazioni_eseguite": 0}, ensure_ascii=False, indent=1) if a.json else testo, end="" if not a.json else "\n")
    return 0
