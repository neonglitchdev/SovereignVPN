"""Sysctl dell'host (Slice B; ANC-0268, ANC-0186, FR-NET-006/007).

Tre valori soltanto, scritti in /etc/sysctl.d/90-sovereignvpn.conf (atomico) cosi' sopravvivono al riavvio (FR-NET-007):
- net.ipv4.ip_forward = 1: i peer escono dalla WAN attraverso il FORWARD del firewall (che e' il kill switch, ANC-0089);
- inoltro IPv6 spento su all e default: la 1.0 e' IPv4, l'inoltro IPv6 e' «disabilitato e verificato» (ANC-0186, T-013).
rp_filter NON si tocca: il documento lo vuole per scenario, mai globale (ANC-0124, ANC-0452).
Dopo la scrittura `sysctl -p <file>` e la rilettura di ogni valore; con --radice si scrive soltanto (prove, immagini).
"""
import os, subprocess

from . import registro
from .manifest import scrivi_testo

FILE = "etc/sysctl.d/90-sovereignvpn.conf"
VALORI = {"net.ipv4.ip_forward": "1", "net.ipv6.conf.all.forwarding": "0", "net.ipv6.conf.default.forwarding": "0"}


def componi():
    righe = ["# SovereignVPN 14.0.0 — scritto da sovereignctl host apply; non modificare a mano (FR-NET-007)",
             "# rp_filter non e' impostato qui: si decide per scenario (ANC-0124)"]
    return "\n".join(righe + [f"{k} = {v}" for k, v in VALORI.items()]) + "\n"


def _sysctl(*argomenti):
    p = subprocess.run(["sysctl", *argomenti], capture_output=True, text=True, timeout=15,
                       env={"PATH": os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"), "LC_ALL": "C"})
    return p.returncode, p.stdout, p.stderr


def applica(radice=""):
    percorso = os.path.join(radice or "/", FILE)
    os.makedirs(os.path.dirname(percorso), exist_ok=True)
    scrivi_testo(percorso, componi(), 0o644)
    if radice:
        return {"file": percorso, "attivato": False, "letti": {}, "verificato": None}
    codice, _, errore = _sysctl("-p", percorso)
    if codice != 0:
        raise RuntimeError(f"sysctl -p {percorso} non riuscito ({registro.redigi(errore.strip())[:200]})")
    letti = {}
    for chiave in VALORI:
        codice, uscita, _ = _sysctl("-n", chiave)
        letti[chiave] = uscita.strip() if codice == 0 else None
    return {"file": percorso, "attivato": True, "letti": letti, "verificato": letti == VALORI}
