"""Riconciliazione dal registro al runtime WireGuard (Slice B; ANC-0276/0277/0280/0285/0288; FR-WG-001/002/003; FR-PEER-004).

Il registro e' la fonte. Nel runtime vanno i peer PENDING e ACTIVE, mai SUSPENDED, EXPIRED, REVOKED o ERROR. La
configurazione si applica con `wg syncconf <if> /dev/stdin`: la chiave privata del server passa da una pipe, mai da un
file temporaneo ne' dall'output. Poi `wg show <if> dump` si confronta peer per peer con l'atteso:
- coincide: saga APPLIED, PENDING -> ACTIVE; una revoca diventa completata solo qui (ANC-0288);
- non coincide: i PENDING vanno in ERROR e la saga in ROLLBACK_REQUIRED, codice 4 (ANC-0255, ANC-0280).
Un aggiornamento tocca solo le righe rimaste come lette (stato e saga uguali): un cambio arrivato nel frattempo non si
sovrascrive, resta in PENDING_APPLY per il giro dopo.
"""
import base64, binascii, os, stat, subprocess, time

from . import registro

NEL_RUNTIME = ("PENDING", "ACTIVE")
INTERFACCIA = "wg0"                                       # [H13]
CHIAVE_SERVER = "/etc/sovereignvpn/wg-server.key"         # [H13] la genera `init` con `wg genkey` (FR-WG-002)


class ChiaveEsposta(Exception):
    """Chiave del server leggibile da altri: security gate, codice 3."""


def _wg(*argomenti, ingresso=None):
    r = subprocess.run(["wg", *argomenti], input=ingresso, capture_output=True, text=True, timeout=15,
                       env={"PATH": os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"), "LC_ALL": "C"})
    return r.returncode, r.stdout, r.stderr


def leggi_chiave_server(percorso):
    try:
        modo = stat.S_IMODE(os.stat(percorso).st_mode)
    except FileNotFoundError:
        raise RuntimeError(f"chiave del server assente in {percorso}: la genera `init` con `wg genkey` (FR-WG-002)")
    if modo & 0o077:
        raise ChiaveEsposta(f"la chiave del server {percorso} ha permessi {oct(modo)}: servono 0600 (NFR-SEC-004)")
    with open(percorso, encoding="ascii") as f:
        chiave = f.read().strip()
    try:
        valida = len(base64.b64decode(chiave, validate=True)) == 32
    except (binascii.Error, ValueError):
        valida = False
    if not valida:
        raise RuntimeError(f"il file {percorso} non contiene una chiave WireGuard valida (il contenuto non si mostra)")
    return chiave


def configurazione(chiave_server, porta, peer):
    righe = ["[Interface]", f"PrivateKey = {chiave_server}", f"ListenPort = {porta}"]
    for p in peer:  # FR-WG-003: AllowedIPs precisa, una /32 per peer, uniche per vincolo del registro
        righe += ["", "[Peer]", f"PublicKey = {p['chiave_pubblica']}", f"AllowedIPs = {p['indirizzo']}/32"]
    return "\n".join(righe) + "\n"


def leggi_runtime(interfaccia):
    codice, uscita, errore = _wg("show", interfaccia, "dump")
    if codice != 0:
        raise RuntimeError(f"interfaccia {interfaccia} non leggibile ({registro.redigi(errore.strip())[:160]}): "
                           "va creata da `init` (ip link add ... type wireguard)")
    vivi = {}
    for riga in uscita.strip().splitlines()[1:]:  # la prima riga e' l'interfaccia, con la chiave privata: si salta
        campi = riga.split("\t")
        vivi[campi[0]] = campi[3]
    return vivi


def nel_runtime(righe):
    """Chiave pubblica -> AllowedIPs attesi nel runtime, da righe (chiave_pubblica, indirizzo, stato) del registro."""
    return {k: ind + "/32" for k, ind, stato in righe if stato in NEL_RUNTIME}


def riconcilia(archivio, interfaccia=INTERFACCIA, percorso_chiave=CHIAVE_SERVER, porta=51820):
    t0 = time.monotonic()
    chiave = leggi_chiave_server(percorso_chiave)
    letti = archivio.db.execute("SELECT id, chiave_pubblica, indirizzo, stato, saga FROM peer").fetchall()
    attesi_peer = [{"chiave_pubblica": k, "indirizzo": ind} for _, k, ind, stato, _ in letti if stato in NEL_RUNTIME]
    attesi = nel_runtime((k, ind, stato) for _, k, ind, stato, _ in letti)
    codice, _, errore = _wg("syncconf", interfaccia, "/dev/stdin", ingresso=configurazione(chiave, porta, attesi_peer))
    if codice != 0:  # niente applicato: la saga resta PENDING_APPLY e il giro si puo' ripetere
        raise RuntimeError(f"wg syncconf non riuscito su {interfaccia} ({registro.redigi(errore.strip())[:160]})")
    vivi = leggi_runtime(interfaccia)
    coincide = vivi == attesi
    aggiornati = 0
    with archivio.transazione() as c:
        for id_peer, _, _, stato, saga in letti:
            if saga != "PENDING_APPLY":
                continue
            if coincide:
                nuovo, nuova_saga = ("ACTIVE" if stato == "PENDING" else stato), "APPLIED"
            else:
                nuovo, nuova_saga = ("ERROR" if stato == "PENDING" else stato), "ROLLBACK_REQUIRED"
            fatto = c.execute("UPDATE peer SET stato = ?, saga = ? WHERE id = ? AND stato = ? AND saga = 'PENDING_APPLY'",
                              (nuovo, nuova_saga, id_peer, stato)).rowcount
            if fatto:
                aggiornati += 1
                archivio.audit(c, "peer.reconcile", "success" if coincide else "failure", id_peer,
                               "" if coincide else "runtime diverso dal registro dopo syncconf")
    return {"interfaccia": interfaccia, "attesi_nel_runtime": len(attesi), "trovati_nel_runtime": len(vivi),
            "coincide": coincide, "differenze": len(set(vivi.items()) ^ set(attesi.items())),
            "peer_aggiornati": aggiornati, "secondi": round(time.monotonic() - t0, 3)}
