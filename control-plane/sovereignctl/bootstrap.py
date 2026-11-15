"""`init --apply`: il bootstrap vero, nell'ordine del workflow 10.1 (ANC-0263-0270).

Si arriva qui solo col preflight tutto OK. Passi, ognuno idempotente: manifest (id dell'installazione conservato se
c'e'), chiave del server (solo se manca, `wg genkey`, file 0600 aperto in esclusiva, mai stampata, FR-WG-002),
interfaccia WireGuard col primo host della subnet, sysctl, firewall, riconciliazione. Il rapporto elenca i passi
fatti: un errore dopo almeno un passo esce col codice 4 (applicato in parte, serve recovery, ANC-0255), prima con 1.
`reconcile` (ripristina) rifa' a ogni avvio i passi di rete, col firewall per primo (FR-NET-007).
"""
import ipaddress, json, os, sqlite3, subprocess, uuid

from . import dns, firewall, host, manifest, peer, registro, runtime

MANIFEST = "/var/lib/sovereignvpn/manifest.json"


def _cmd(*argomenti, ingresso=None):
    p = subprocess.run(list(argomenti), input=ingresso, capture_output=True, text=True, timeout=30,
                       env={"PATH": os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"), "LC_ALL": "C"})
    if p.returncode != 0:
        raise RuntimeError(f"{argomenti[0]} {argomenti[1] if len(argomenti) > 1 else ''} non riuscito ({registro.redigi(p.stderr.strip())[:160]})")
    return p.stdout


def scrivi_manifest(fatti, percorso_config, percorso=None):
    percorso = percorso or MANIFEST  # letto ora, non alla definizione
    vecchio = None
    if os.path.exists(percorso):
        with open(percorso, encoding="utf-8") as f:
            vecchio = json.load(f).get("id_installazione")
    m = manifest.componi(fatti, percorso_config, id_installazione=vecchio or str(uuid.uuid4()), immagini=dns.immagini())
    os.makedirs(os.path.dirname(percorso), mode=0o700, exist_ok=True)
    manifest.scrivi(percorso, m)
    return m["id_installazione"]


def chiave_server(percorso=None):
    percorso = percorso or runtime.CHIAVE_SERVER
    if os.path.exists(percorso):
        return False
    os.makedirs(os.path.dirname(percorso), mode=0o700, exist_ok=True)
    chiave = _cmd("wg", "genkey")
    fd = os.open(percorso, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # esclusiva: mai sopra una chiave esistente
    try:
        os.write(fd, chiave.encode("ascii"))
    finally:
        os.close(fd)
    return True


def interfaccia(nome, rete, subnet6):
    rete = ipaddress.ip_network(rete)
    primo = next(rete.hosts())  # [H11] il primo host e' del server
    server = f"{primo}/{rete.prefixlen}"
    # [H38] anche un IPv6 ULA: e' la sorgente del rifiuto ICMPv6 e la rotta che lo riporta al peer nel tunnel
    server6 = f"{runtime.indirizzo6(subnet6, primo)}/{ipaddress.ip_network(subnet6).prefixlen}"
    try:
        _cmd("ip", "link", "show", nome)
    except RuntimeError:
        _cmd("ip", "link", "add", nome, "type", "wireguard")
    _cmd("ip", "address", "replace", server, "dev", nome)
    _cmd("sysctl", "-qw", f"net/ipv6/conf/{nome}/disable_ipv6=0")  # solo su wg0, anche dove l'host ha spento IPv6
    _cmd("ip", "address", "replace", server6, "dev", nome)
    _cmd("ip", "link", "set", nome, "up")
    return f"{server} {server6}"


def _verificato(passo, ok):
    if ok is not True:  # applicato ma diverso dallo stato dichiarato: come `host apply`, `firewall apply`, `peer reconcile`
        raise RuntimeError(f"{passo}: applicato, ma la verifica non coincide con lo stato dichiarato")
    return ok


def _sequenza(da_fare):
    """Esegue (passo, funzione) in ordine; al primo guasto si ferma e lo restituisce coi passi gia' fatti."""
    passi = []
    try:
        for nome, fare in da_fare:
            passi.append((nome, fare()))
    except Exception as e:  # noqa: BLE001 — qualunque guasto ferma la sequenza e si riporta coi passi gia' fatti
        return passi, e
    return passi, None


def _passi_di_rete(cfg, wan_if, wg_if, db):
    """I passi comuni a init e al ripristino. Un input non valido (WAN, sorgenti SSH, subnet) solleva InputNonValido
    QUI, prima di toccare l'host: le regole si compongono subito, e comporle non muta niente (ANC-0255: 2, non 4)."""
    rete, porta = cfg.get("subnet") or "10.66.0.0/24", cfg.get("wg_port", 51820)
    try:  # T-026 [H41]: registro illeggibile = firewall in recupero (nessun traffico dei peer), poi ci si ferma
        per_peer, recupero = (peer.limiti_rotte(db), peer.dns_liberi(db), peer.quote(db, firewall.quote_usate, salva=True)), False
    except sqlite3.Error:
        per_peer, recupero = ((), (), ()), True
    regole = firewall.componi(rete, wg_if, porta, wan_if, cfg.get("admin_port", 8443), cfg.get("ssh_port", 22), cfg.get("admin_ssh_sources"), cfg.get("mtu", 1420), cfg.get("dns_block_dot", True), *per_peer,
                              recupero=recupero)

    def _firewall():
        ok = _verificato("firewall", firewall.applica(regole)["verificato"])
        return "in recupero: registro dei peer illeggibile, nessun traffico dei peer (T-026)" if recupero else ok

    def _riconciliazione():
        if recupero:  # mai un peer dal registro rotto: si ferma qui, codice 4, e il runtime non si tocca
            raise RuntimeError("registro dei peer illeggibile (T-026): NEEDS_RECOVERY, serve `sovereignctl backup restore`")
        return _verificato("riconciliazione", runtime.riconcilia(peer.Archivio(db), wg_if, runtime.CHIAVE_SERVER, porta, cfg["subnet6"])["coincide"])
    return {
        "firewall": _firewall,
        "sysctl": lambda: _verificato("sysctl", host.applica()["verificato"]),
        "interfaccia": lambda: f"{wg_if} {interfaccia(wg_if, rete, cfg['subnet6'])}",
        "riconciliazione": _riconciliazione,
    }


def esegui(fatti, cfg, percorso_config, wan_if, wg_if="wg0", db=peer.DB_PREDEFINITO):
    """init --apply: restituisce (passi fatti, errore o None), nell'ordine del workflow 10.1."""
    rete = _passi_di_rete(cfg, wan_if, wg_if, db)
    return _sequenza([("manifest", lambda: scrivi_manifest(fatti, percorso_config)),
                      ("chiave del server", lambda: "generata" if chiave_server() else "gia' presente"),
                      *((n, rete[n]) for n in ("interfaccia", "sysctl", "firewall", "riconciliazione"))])


AL_RIAVVIO = ("firewall", "sysctl", "interfaccia", "riconciliazione")


def ripristina(cfg, wan_if, wg_if="wg0", db=peer.DB_PREDEFINITO):
    """`reconcile`, a ogni avvio (FR-NET-007): riporta l'host allo stato dichiarato. Il firewall per primo, prima che
    salga la rete. Niente preflight (al boot l'orologio puo' non essere sincronizzato e la porta e' gia' di wg0),
    niente manifest, e mai una chiave nuova: cambierebbe l'identita' del server, quindi chiave assente = errore."""
    rete = _passi_di_rete(cfg, wan_if, wg_if, db)
    return _sequenza([(n, rete[n]) for n in AL_RIAVVIO])
