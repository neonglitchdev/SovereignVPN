"""Uscite per paese (FR-NET-008, richiesta di Francesco del 15/11) [H48], primo pezzo: il pool delle uscite.

Un'uscita e' un file WireGuard del provider scelto (o di un VPS) con il suo paese (ISO 3166-1 alpha-2, da cui la
bandierina dell'app). Si accettano solo i campi WireGuard che servono a un'uscita; gli script (PreUp, PostUp, PreDown,
PostDown) si RIFIUTANO: un file di terzi eseguirebbe comandi come root sul server. Il pool sta in
/var/lib/sovereignvpn/uscite (0700), un file 0600 per uscita; la chiave privata dell'uscita resta li', mai a schermo.
Prossimi pezzi: interfaccia d'uscita con tabella e fwmark dedicati, kill switch (uscita giu' = niente fuori, mai la
WAN), rotazione statica o dinamica ogni N minuti, prova vera con due uscite finte e iperf3.
"""
import ipaddress, re

CARTELLA = "/var/lib/sovereignvpn/uscite"
PAESE = re.compile(r"^[A-Z]{2}$")
AMMESSI = {"Interface": {"PrivateKey", "Address", "DNS", "MTU"},
           "Peer": {"PublicKey", "PresharedKey", "Endpoint", "AllowedIPs", "PersistentKeepalive"}}
VIETATI = {"PreUp", "PostUp", "PreDown", "PostDown", "SaveConfig", "Table", "FwMark"}


class UscitaNonValida(ValueError):
    """Un file d'uscita rifiutato, col motivo (il valore di una chiave non si ripete mai)."""


def bandierina(paese):
    """«IT» -> la bandierina emoji (due simboli regionali): la mostra l'app accanto al nome del paese."""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in paese)


def leggi(testo, paese):
    """Il file WireGuard di un'uscita -> {paese, endpoint, indirizzi, chiave_pubblica}. Solleva UscitaNonValida."""
    if not PAESE.match(paese or ""):
        raise UscitaNonValida("paese: codice ISO di due lettere maiuscole (IT, DE, JP...)")
    sezione, campi = None, {"Interface": {}, "Peer": {}}
    for n, riga in enumerate(testo.splitlines(), 1):
        riga = riga.split("#", 1)[0].strip()
        if not riga:
            continue
        if riga.startswith("[") and riga.endswith("]"):
            sezione = riga[1:-1]
            if sezione not in campi or (sezione == "Peer" and campi["Peer"]):
                raise UscitaNonValida(f"riga {n}: sezione «{sezione}» non ammessa (un'Interface e un solo Peer)")
            continue
        chiave = riga.split("=", 1)[0].strip()
        if chiave in VIETATI:
            raise UscitaNonValida(f"riga {n}: «{chiave}» rifiutato: un'uscita non esegue comandi ne' cambia tabelle sul server")
        if sezione is None or chiave not in AMMESSI[sezione] or "=" not in riga:
            raise UscitaNonValida(f"riga {n}: campo «{chiave}» non ammesso in [{sezione}]")
        campi[sezione][chiave] = riga.split("=", 1)[1].strip()
    for s, k in (("Interface", "PrivateKey"), ("Interface", "Address"), ("Peer", "PublicKey"), ("Peer", "Endpoint")):
        if k not in campi[s]:
            raise UscitaNonValida(f"manca {k} in [{s}]")
    if "0.0.0.0/0" not in [x.strip() for x in campi["Peer"].get("AllowedIPs", "").split(",")]:
        raise UscitaNonValida("AllowedIPs del Peer deve contenere 0.0.0.0/0: e' l'uscita di tutto il traffico dei peer")
    indirizzi = [str(ipaddress.ip_interface(a.strip())) for a in campi["Interface"]["Address"].split(",")]
    return {"paese": paese, "bandierina": bandierina(paese), "endpoint": campi["Peer"]["Endpoint"],
            "indirizzi": indirizzi, "chiave_pubblica": campi["Peer"]["PublicKey"]}
