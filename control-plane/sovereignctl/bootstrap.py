"""`init --apply`: il bootstrap vero, nell'ordine del workflow 10.1 (ANC-0263-0270).

Si arriva qui solo col preflight tutto OK. Passi, ognuno idempotente: manifest (id dell'installazione conservato se
c'e'), chiave del server (solo se manca, `wg genkey`, file 0600 aperto in esclusiva, mai stampata, FR-WG-002),
interfaccia WireGuard col primo host della subnet, sysctl, firewall, riconciliazione. Il rapporto elenca i passi
fatti: un errore dopo almeno un passo esce col codice 4 (applicato in parte, serve recovery, ANC-0255), prima con 1.
"""
import ipaddress, json, os, subprocess, uuid

from . import firewall, host, manifest, peer, registro, runtime

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
    m = manifest.componi(fatti, percorso_config, id_installazione=vecchio or str(uuid.uuid4()))
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


def interfaccia(nome, rete):
    rete = ipaddress.ip_network(rete)
    server = f"{next(rete.hosts())}/{rete.prefixlen}"  # [H11] il primo host e' del server
    try:
        _cmd("ip", "link", "show", nome)
    except RuntimeError:
        _cmd("ip", "link", "add", nome, "type", "wireguard")
    _cmd("ip", "address", "replace", server, "dev", nome)
    _cmd("ip", "link", "set", nome, "up")
    return server


def esegui(fatti, cfg, percorso_config, wan_if, wg_if="wg0", db=peer.DB_PREDEFINITO):
    """Restituisce (passi fatti, errore o None)."""
    rete = cfg.get("subnet") or "10.66.0.0/24"
    passi = []
    try:
        passi.append(("manifest", scrivi_manifest(fatti, percorso_config)))
        passi.append(("chiave del server", "generata" if chiave_server() else "gia' presente"))
        passi.append(("interfaccia", f"{wg_if} {interfaccia(wg_if, rete)}"))
        passi.append(("sysctl", host.applica()["verificato"]))
        passi.append(("firewall", firewall.applica(firewall.componi(rete, wg_if, cfg.get("wg_port", 51820), wan_if,
                                                                     cfg.get("admin_port", 8443), cfg.get("ssh_port", 22),
                                                                     cfg.get("admin_ssh_sources")))["verificato"]))
        esito = runtime.riconcilia(peer.Archivio(db), wg_if, runtime.CHIAVE_SERVER, cfg.get("wg_port", 51820))
        passi.append(("riconciliazione", esito["coincide"]))
    except Exception as e:  # noqa: BLE001 — qualunque guasto ferma la sequenza e si riporta coi passi gia' fatti
        return passi, e
    return passi, None
