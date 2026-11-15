"""`sovereignctl diagnostics collect [--extended --conferma]` (ANC-0254, ANC-0310-0312, FR-OPS-002, T-025) [H43].

Un archivio tar.gz per capire un guasto, senza segreti e senza dati di navigazione.
- minimal (di base): configurazione sanitizzata (endpoint, sorgenti SSH, hash del token, dominio TLS e destinatario
  del backup redatti), versioni, rapporto dell'audit (che contiene anche i controlli di status), conteggio dei peer
  per stato (ANC-0310: conteggi aggregati, mai nomi, chiavi o indirizzi), manifest con lo sha256 di ogni file;
- extended (solo con --conferma, ANC-0312): in piu' gli ultimi log delle unita' del prodotto e la tabella nft viva,
  redatti (chiavi, token, URL, IP pubblici, indirizzi della VPN); mai i log dei container DNS (le query), mai endpoint
  o handshake di WireGuard (ANC-0311).
Prima di scrivere, lo scan dei segreti sull'archivio intero (T-025): la chiave privata del server, una chiave WireGuard
in chiaro, una chiave PEM o un hash di token fermano tutto (security gate, codice 3, niente scritto). Il file e' 0600
in una cartella 0700; a schermo soltanto percorso e checksum.
"""
import datetime, hashlib, io, ipaddress, json, os, platform, sqlite3, sys, tarfile

from . import VERSIONE, audit, backup, peer, preflight, registro, runtime, stato

CARTELLA = "/var/lib/sovereignvpn/diagnostica"
REDATTI = ("endpoint", "admin_ssh_sources", "admin_token_hash", "tls_domain", "backup_recipient")
UNITA_LOG = ("sovereignvpn-reconcile.service", "sovereignvpn-expire.service", "sovereignvpn-unbound.service", "sovereignvpn-pihole.service")


class SegretoNelBundle(Exception):
    """Lo scan ha trovato un segreto nel bundle: security gate, codice 3."""


def _versioni():
    v = {"sovereignctl": VERSIONE, "python": platform.python_version(), "kernel": platform.release()}
    for nome, comando in (("wg", ("wg", "--version")), ("nft", ("nft", "--version")),
                          ("docker", ("docker", "version", "--format", "{{.Server.Version}}"))):
        codice, uscita = stato._leggi(*comando)
        v[nome] = uscita.strip().splitlines()[0][:80] if codice == 0 and uscita.strip() else "assente"
    return v


def _peer_per_stato(db):
    if not os.path.exists(db):
        return {}
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            return dict(con.execute("SELECT stato, count(*) FROM peer GROUP BY stato ORDER BY stato").fetchall())
        finally:
            con.close()
    except sqlite3.Error as e:
        return {"registro illeggibile": type(e).__name__}


def redigi_vpn(testo, cfg):
    """Gli indirizzi della VPN (IPv4 della subnet e ULA) diventano un segnaposto: ognuno identifica un dispositivo."""
    reti = (ipaddress.ip_network(cfg.get("subnet") or "10.66.0.0/24"), ipaddress.ip_network(cfg["subnet6"]))

    def sostituisci(m):
        try:
            a = ipaddress.ip_address(m.group(0))
        except ValueError:
            return m.group(0)
        return "[INDIRIZZO VPN]" if any(a.version == r.version and a in r for r in reti) else m.group(0)
    return registro._IP.sub(sostituisci, testo)


def _estesi(cfg):
    argomenti = [x for u in UNITA_LOG for x in ("-u", u)]
    codice, log = stato._leggi("journalctl", "--no-pager", "-q", "-o", "short-iso", "-n", "300", *argomenti)
    codice_t, tabella = stato._leggi("nft", "list", "table", "inet", "sovereignvpn")
    return {"log-unita.txt": log if codice == 0 else "journalctl non disponibile\n",
            "firewall.txt": tabella if codice_t == 0 else "tabella inet sovereignvpn non leggibile\n"}


def componi(cfg, db, esteso):
    """{nome: byte} del bundle, gia' redatti."""
    file = {"configurazione.json": {k: ("[REDATTO]" if k in REDATTI else v) for k, v in cfg.items()},
            "versioni.json": _versioni(), "audit.json": audit.esegui_controlli(cfg, db), "peer-per-stato.json": _peer_per_stato(db)}
    file = {n: json.dumps(v, ensure_ascii=False, indent=1, sort_keys=True) + "\n" for n, v in file.items()}
    if esteso:
        file.update(_estesi(cfg))
    return {n: redigi_vpn(registro.redigi(t), cfg).encode("utf-8") for n, t in file.items()}


def scansiona(file, chiave_server=None):
    """T-025: i nomi dei file che contengono un segreto. Non si fida della redazione: guarda il risultato."""
    colpevoli = []
    for nome, dati in file.items():
        t = dati.decode("utf-8", "replace")
        if (chiave_server and chiave_server in t) or any(r.search(t) for r in (registro._CHIAVE_WG, registro._PEM, registro._HASH)):
            colpevoli.append(nome)
    return sorted(colpevoli)


def raccogli(cfg, db, esteso=False, cartella=None, percorso_chiave=None):
    file = componi(cfg, db, esteso)
    try:
        chiave = runtime.leggi_chiave_server(percorso_chiave or runtime.CHIAVE_SERVER)
    except (RuntimeError, runtime.ChiaveEsposta, OSError):
        chiave = None  # senza la chiave lo scan guarda comunque la forma di ogni chiave WireGuard
    colpevoli = scansiona(file, chiave)
    if colpevoli:
        raise SegretoNelBundle(f"segreti trovati in {', '.join(colpevoli)}: niente scritto")
    adesso = datetime.datetime.now(datetime.timezone.utc)
    m = {"sovereignvpn": VERSIONE, "creato": adesso.isoformat(timespec="seconds").replace("+00:00", "Z"),
         "modalita": "extended" if esteso else "minimal",
         "file": [{"nome": n, "sha256": hashlib.sha256(b).hexdigest(), "byte": len(b)} for n, b in sorted(file.items())]}
    file["manifest-diagnostica.json"] = (json.dumps(m, ensure_ascii=False, indent=1) + "\n").encode("utf-8")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for nome, dati in sorted(file.items()):
            info = tarfile.TarInfo(nome)
            info.size, info.mode, info.mtime = len(dati), 0o600, int(adesso.timestamp())
            tar.addfile(info, io.BytesIO(dati))
    dati = buf.getvalue()
    cartella = cartella or CARTELLA
    os.makedirs(cartella, mode=0o700, exist_ok=True)
    os.chmod(cartella, 0o700)
    base = os.path.join(cartella, f"diagnostica-{adesso:%Y%m%dT%H%M%SZ}-{m['modalita']}")
    percorso, n = base + ".tar.gz", 1
    while os.path.exists(percorso):  # due raccolte nello stesso secondo: mai una sopra l'altra
        n += 1
        percorso = f"{base}-{n}.tar.gz"
    backup._scrivi(percorso, dati)  # atomico, 0600
    return {"percorso": percorso, "checksum": "sha256:" + hashlib.sha256(dati).hexdigest(), "modalita": m["modalita"],
            "file": len(file)}


def esegui(a):
    from . import configurazione
    if a.extended and not a.conferma:
        print("sovereignctl: input non valido: --extended aggiunge i log dell'host e vuole il consenso esplicito --conferma (ANC-0312)", file=sys.stderr)
        return 2
    try:
        cfg = configurazione.leggi(a.config)
        esito = raccogli(cfg, a.db, a.extended, a.out)
    except preflight.InputNonValido as e:
        print(f"sovereignctl: input non valido: {registro.redigi(e)}", file=sys.stderr)
        return 2
    except SegretoNelBundle as e:
        print(f"sovereignctl: security gate: {e}", file=sys.stderr)
        return 3
    except OSError as e:
        print(f"sovereignctl: errore della diagnostica ({type(e).__name__}): {registro.redigi(e)}", file=sys.stderr)
        return 1
    print(json.dumps(esito, ensure_ascii=False, indent=1) if a.json else
          f"Diagnostica {esito['modalita']} in {esito['percorso']} (0600), {esito['checksum']}, {esito['file']} file.")
    return 0
