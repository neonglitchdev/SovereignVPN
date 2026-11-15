"""`sovereignctl profile export <id> --conferma` (FR-PEER-007, FR-WG-004, FR-WG-005; ANC-0254) [H18].

Il profilo e' un file WireGuard full-tunnel: IPv4 0.0.0.0/0 nel tunnel, e anche ::/0, cosi' l'IPv6 non esce fuori dal
tunnel: nessun fallback non dichiarato. Il peer ha anche un IPv6 ULA nel tunnel [H38]: senza, il suo IPv6 partirebbe con
la sorgente nativa e WireGuard lo scarterebbe in silenzio sul server; con quello il server lo rifiuta subito con ICMPv6
admin-prohibited, e il sistema del dispositivo mette IPv4 davanti (RFC 6724). Segreti: nessuno, e il file lo dice in
testa. La chiave privata e' nata sul dispositivo [H2] e resta li': al suo posto c'e' un segnaposto da sostituire.
Il file si scrive 0600 in una cartella 0700, solo su richiesta e con --conferma; a schermo vanno percorso e checksum,
mai il contenuto, e nell'audit solo l'evento. Un peer revocato o scaduto non si esporta: serve un provisioning nuovo.
PersistentKeepalive e' spento salvo --keepalive (FR-WG-005).
"""
import hashlib, io, ipaddress, json, os, sys, tarfile

from . import VERSIONE, backup, configurazione, manifest, peer, registro, runtime
from .preflight import InputNonValido

CARTELLA = "/var/lib/sovereignvpn/export"
SEGNAPOSTO = "<CHIAVE_PRIVATA_DEL_DISPOSITIVO>"
LEGGIMI = """SovereignVPN {versione} — bundle di onboarding del peer {id} (FR-PEER-009) [H45]
Contenuto: {conf} (il profilo), manifest.json (sha256 di ogni file) e questo file. Nessun segreto, nessun altro peer.

1. Prima di importare: al posto di {segnaposto} va la chiave privata nata su questo dispositivo [H2].
2. Importare {conf} col client WireGuard ufficiale: Linux `wg-quick up`; macOS, iOS, Android, Windows «Importa da file».
3. Verificare: il tunnel si collega, il DNS e' quello del profilo; nel full-tunnel un sito IPv6 fallisce subito [H38].

Limiti, dichiarati (FR-APPLE-003, FR-APPLE-004):
- Il profilo non e' un kill switch di sistema: a tunnel spento il dispositivo esce dalla sua rete.
- «Connect On Demand» delle app Apple non e' Always-On VPN: Always-On vuole IKEv2 su dispositivi supervisionati via
  MDM, che la 1.0 non fornisce.
- La protezione dipende dal client, dalla versione del sistema e dalle sue impostazioni: il server non la impone.
"""


def componi(p, cfg, chiave_server_pubblica, keepalive=None):
    if keepalive is not None and not 1 <= keepalive <= 65535:
        raise InputNonValido("--keepalive: secondi da 1 a 65535; senza, resta spento (FR-WG-005)")
    rete = ipaddress.ip_network(cfg.get("subnet") or "10.66.0.0/24")
    dns = ", ".join(cfg.get("dns") or [str(next(rete.hosts()))])  # [H11] senza resolver dichiarati, il server
    endpoint = cfg["endpoint"]
    try:
        if ipaddress.ip_address(endpoint).version == 6:
            endpoint = f"[{endpoint}]"
    except ValueError:
        pass  # un nome host
    if p.get("rotte"):
        tipo, indirizzi = "split-tunnel verso le rotte del peer", f"{p['indirizzo']}/32"
        ipv6 = "fuori dal tunnel, come tutto cio' che non e' nelle rotte"
    else:
        tipo, indirizzi = "full-tunnel", f"{p['indirizzo']}/32, {runtime.indirizzo6(cfg['subnet6'], p['indirizzo'])}/128"
        ipv6 = "tutto nel tunnel, dove il server lo rifiuta subito (ICMPv6 admin-prohibited) [H38]"
    righe = [f"# SovereignVPN {VERSIONE} — profilo {tipo} del peer {p['id']} ({p['nome']})",
             "# SEGRETI: nessuno. La chiave privata e' nata sul dispositivo e resta li' [H2]:",
             f"# va scritta al posto di {SEGNAPOSTO} prima di importare il profilo.",
             f"# Scadenza: {p['scade'] or 'nessuna'} (UTC). IPv6: {ipv6} (FR-WG-004).",
             "", "[Interface]", f"PrivateKey = {SEGNAPOSTO}", f"Address = {indirizzi}", f"DNS = {dns}",
             f"MTU = {cfg.get('mtu', 1420)}",
             "", "[Peer]", f"PublicKey = {chiave_server_pubblica}", f"Endpoint = {endpoint}:{cfg.get('wg_port', 51820)}",
             "AllowedIPs = " + (", ".join(json.loads(p["rotte"]) + [str(rete)]) if p.get("rotte") else "0.0.0.0/0, ::/0")]
    if keepalive:
        righe.append(f"PersistentKeepalive = {keepalive}")
    return "\n".join(righe) + "\n"


def _bundle(p, testo):
    """FR-PEER-009 [H45]: tar.gz col solo profilo di questo peer, le istruzioni e il manifest con gli sha256."""
    conf = f"{p['id']}.conf"
    file = {conf: testo.encode(), "LEGGIMI.txt": LEGGIMI.format(versione=VERSIONE, id=p["id"], conf=conf, segnaposto=SEGNAPOSTO).encode()}
    m = {"peer": p["id"], "sovereignvpn": VERSIONE, "segreti": False,
         "file": [{"nome": n, "sha256": hashlib.sha256(b).hexdigest(), "byte": len(b)} for n, b in sorted(file.items())]}
    file["manifest.json"] = (json.dumps(m, ensure_ascii=False, indent=1) + "\n").encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for nome, dati in sorted(file.items()):
            info = tarfile.TarInfo(nome)
            info.size, info.mode = len(dati), 0o600
            tar.addfile(info, io.BytesIO(dati))
    return buf.getvalue(), len(file)


def esporta(archivio, id_peer, cfg, chiave_server, keepalive=None, cartella=None, bundle=False):
    cartella = cartella or CARTELLA
    p = archivio.mostra(id_peer)
    if p["stato"] in ("REVOKED", "EXPIRED"):
        raise InputNonValido(f"peer {p['stato']}: un profilo revocato o scaduto non si esporta, serve un provisioning nuovo")
    testo = componi(p, cfg, runtime.chiave_pubblica(chiave_server), keepalive)
    os.makedirs(cartella, mode=0o700, exist_ok=True)
    os.chmod(cartella, 0o700)
    if bundle:
        dati, n = _bundle(p, testo)
        percorso = os.path.join(cartella, f"{p['id']}.tar.gz")
        backup._scrivi(percorso, dati)  # atomico, 0600
        somma = hashlib.sha256(dati).hexdigest()
    else:
        percorso, n = os.path.join(cartella, f"{p['id']}.conf"), 1  # l'UUID, mai il nome, come percorso (ANC-0238)
        manifest.scrivi_testo(percorso, testo, 0o600)
        somma = hashlib.sha256(testo.encode()).hexdigest()
    with archivio.transazione() as c:
        archivio.audit(c, "profile.export", "success", p["id"])
    return {"peer": p["id"], "percorso": percorso, "checksum": "sha256:" + somma, "segreti": False, "keepalive": keepalive, "file": n}


def esegui(a):
    if not a.conferma:
        print("sovereignctl: input non valido: l'export di un profilo vuole --conferma (FR-PEER-007)", file=sys.stderr)
        return 2
    try:
        cfg = configurazione.leggi(a.config)
        if not os.path.exists(a.db):
            raise RuntimeError(f"registro dei peer assente in {a.db}")
        esito = esporta(peer.Archivio(a.db), a.id, cfg, a.server_key, a.keepalive, a.out, a.bundle)
    except InputNonValido as e:
        print(f"sovereignctl: input non valido: {registro.redigi(e)}", file=sys.stderr)
        return 2
    except runtime.ChiaveEsposta as e:
        print(f"sovereignctl: security gate: {registro.redigi(e)}", file=sys.stderr)
        return 3
    except (RuntimeError, OSError) as e:
        print(f"sovereignctl: errore ({type(e).__name__}): {registro.redigi(e)}", file=sys.stderr)
        return 1
    print(json.dumps(esito, ensure_ascii=False, indent=1) if a.json else
          f"Profilo scritto in {esito['percorso']} (0600), {esito['checksum']}. Segreti: nessuno; la chiave privata "
          f"va scritta sul dispositivo al posto di {SEGNAPOSTO}.")
    return 0
