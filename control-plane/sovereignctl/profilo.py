"""`sovereignctl profile export <id> --conferma` (FR-PEER-007, FR-WG-004, FR-WG-005; ANC-0254) [H18].

Il profilo e' un file WireGuard full-tunnel: IPv4 0.0.0.0/0 nel tunnel, e anche ::/0, cosi' l'IPv6 non esce fuori dal
tunnel (il server non lo inoltra, lo respinge): nessun fallback non dichiarato. Segreti: nessuno, e il file lo dice in
testa. La chiave privata e' nata sul dispositivo [H2] e resta li': al suo posto c'e' un segnaposto da sostituire.
Il file si scrive 0600 in una cartella 0700, solo su richiesta e con --conferma; a schermo vanno percorso e checksum,
mai il contenuto, e nell'audit solo l'evento. Un peer revocato o scaduto non si esporta: serve un provisioning nuovo.
PersistentKeepalive e' spento salvo --keepalive (FR-WG-005).
"""
import hashlib, ipaddress, json, os, sys

from . import VERSIONE, configurazione, manifest, peer, registro, runtime
from .preflight import InputNonValido

CARTELLA = "/var/lib/sovereignvpn/export"
SEGNAPOSTO = "<CHIAVE_PRIVATA_DEL_DISPOSITIVO>"


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
    tipo = "split-tunnel verso le rotte del peer" if p.get("rotte") else "full-tunnel"
    righe = [f"# SovereignVPN {VERSIONE} — profilo {tipo} del peer {p['id']} ({p['nome']})",
             "# SEGRETI: nessuno. La chiave privata e' nata sul dispositivo e resta li' [H2]:",
             f"# va scritta al posto di {SEGNAPOSTO} prima di importare il profilo.",
             f"# Scadenza: {p['scade'] or 'nessuna'} (UTC). IPv6: tutto nel tunnel, dove il server lo respinge (FR-WG-004).",
             "", "[Interface]", f"PrivateKey = {SEGNAPOSTO}", f"Address = {p['indirizzo']}/32", f"DNS = {dns}",
             f"MTU = {cfg.get('mtu', 1420)}",
             "", "[Peer]", f"PublicKey = {chiave_server_pubblica}", f"Endpoint = {endpoint}:{cfg.get('wg_port', 51820)}",
             "AllowedIPs = " + (", ".join(json.loads(p["rotte"]) + [str(rete)]) if p.get("rotte") else "0.0.0.0/0, ::/0")]
    if keepalive:
        righe.append(f"PersistentKeepalive = {keepalive}")
    return "\n".join(righe) + "\n"


def esporta(archivio, id_peer, cfg, chiave_server, keepalive=None, cartella=None):
    cartella = cartella or CARTELLA
    p = archivio.mostra(id_peer)
    if p["stato"] in ("REVOKED", "EXPIRED"):
        raise InputNonValido(f"peer {p['stato']}: un profilo revocato o scaduto non si esporta, serve un provisioning nuovo")
    testo = componi(p, cfg, runtime.chiave_pubblica(chiave_server), keepalive)
    os.makedirs(cartella, mode=0o700, exist_ok=True)
    os.chmod(cartella, 0o700)
    percorso = os.path.join(cartella, f"{p['id']}.conf")  # l'UUID, mai il nome, come percorso (ANC-0238)
    manifest.scrivi_testo(percorso, testo, 0o600)
    with archivio.transazione() as c:
        archivio.audit(c, "profile.export", "success", p["id"])
    return {"peer": p["id"], "percorso": percorso, "checksum": "sha256:" + hashlib.sha256(testo.encode()).hexdigest(),
            "segreti": False, "keepalive": keepalive}


def esegui(a):
    if not a.conferma:
        print("sovereignctl: input non valido: l'export di un profilo vuole --conferma (FR-PEER-007)", file=sys.stderr)
        return 2
    try:
        cfg = configurazione.leggi(a.config)
        if not os.path.exists(a.db):
            raise RuntimeError(f"registro dei peer assente in {a.db}")
        esito = esporta(peer.Archivio(a.db), a.id, cfg, a.server_key, a.keepalive, a.out)
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
