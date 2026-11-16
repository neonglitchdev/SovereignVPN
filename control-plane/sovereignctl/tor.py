"""Tor come tipo d'uscita (H52, in costruzione): la configurazione del demone Tor che fara' da uscita per i peer.

Primo pezzo: solo il testo di torrc, provato. Disegno (handoff del 16/11): il TCP dei peer (iif wg0) rediretto alla
TransPort, il DNS dei peer da Unbound alla DNSPort, l'UDP scartato, il kill switch di H48 invariato; rotazione con
NEWNYM sulla ControlSocket. Tutto ascolta solo su 127.0.0.1: nessuna porta di Tor e' raggiungibile da fuori.
"""
from .uscite import PAESE, UscitaNonValida

PORTA_TRANS = 9040
PORTA_DNS = 5353


def torrc(paese):
    """Il torrc per uscire da `paese` (ISO a due lettere). Solleva UscitaNonValida per un paese non valido."""
    if not PAESE.match(paese or ""):
        raise UscitaNonValida("paese: codice ISO di due lettere maiuscole (DE, NL, US...)")
    return "\n".join([
        f"# SovereignVPN — Tor come uscita da {paese}, generato da sovereignctl; non modificare a mano",
        "SocksPort 0",                                   # nessun proxy SOCKS: solo il traffico rediretto dei peer
        f"TransPort 127.0.0.1:{PORTA_TRANS}",
        f"DNSPort 127.0.0.1:{PORTA_DNS}",
        "AutomapHostsOnResolve 1",
        "VirtualAddrNetworkIPv4 10.192.0.0/10",
        f"ExitNodes {{{paese.lower()}}}",
        "StrictNodes 1",                                  # mai un'uscita fuori dal paese scelto
        "ClientUseIPv6 0",
        "ControlSocket /run/tor/control",
        "CookieAuthentication 1",
        "DataDirectory /var/lib/tor",
    ]) + "\n"
