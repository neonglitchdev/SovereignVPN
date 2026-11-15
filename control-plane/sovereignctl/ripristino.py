"""`sovereignctl backup restore <file> --identity <chiave age> --conferma` (FR-OPS-003, ANC-0254) [H21].

Il restore e' una transazione, e un restore interrotto non deve lasciare un sistema che sembra sano ma e' incoerente:
1. preflight, senza toccare niente: si decifra in memoria con la chiave age data (che non sta sul server); nell'archivio
   si accettano solo i nomi attesi, mai un percorso; ogni file deve avere lo sha256 del BackupManifest; il registro si
   deve aprire. Un checksum diverso e' un security gate (3); un archivio malformato e' un input non valido (2);
2. lo stato corrente (i file che ci sono) si salva prima, cifrato verso lo stesso destinatario del backup;
3. i file si scrivono atomici coi loro permessi; i -wal e -shm del registro vecchio si tolgono prima (applicati al
   registro nuovo lo corromperebbero);
4. verifica finale: `reconcile` (firewall, sysctl, wg0, peer) e `status`. Se non e' tutto OK si rimettono i file di
   prima, si rifa' `reconcile` e si esce con 4.
"""
import hashlib, io, json, os, sqlite3, sys, tarfile

from . import backup, bootstrap, configurazione, manifest, peer, registro, runtime, stato
from .preflight import InputNonValido


class ChecksumDiverso(Exception):
    """Un file del backup non ha lo sha256 del suo manifest: security gate, codice 3."""


def _posti(percorso_config, db):
    """Nome nell'archivio -> (percorso sul server, permessi)."""
    return {"etc/sovereignvpn/server.toml": (percorso_config, 0o600),
            "etc/sovereignvpn/wg-server.key": (runtime.CHIAVE_SERVER, 0o600),
            "var/lib/sovereignvpn/manifest.json": (bootstrap.MANIFEST, 0o644),
            "var/lib/sovereignvpn/registro.sqlite3": (db, 0o600)}


def leggi(file_cifrato, identita, attesi):
    """Preflight: decifra in memoria, controlla nomi, checksum e registro. Restituisce (file, manifest del backup)."""
    try:
        chiaro = backup._age("-d", "-i", identita, file_cifrato)
    except backup.AgeFallito:
        raise InputNonValido("il backup non si decifra con questa chiave, o e' stato manomesso (age -d non riuscito)")
    try:
        with tarfile.open(fileobj=io.BytesIO(chiaro)) as tar:
            membri = tar.getmembers()
            estranei = [m.name for m in membri if m.name not in (*attesi, "backup-manifest.json") or not m.isfile()]
            if estranei:
                raise InputNonValido(f"archivio con voci inattese: {', '.join(sorted(estranei))[:200]}")
            file = {m.name: tar.extractfile(m).read() for m in membri}
    except tarfile.TarError as e:
        raise InputNonValido(f"archivio non leggibile ({e})")
    if "backup-manifest.json" not in file or sorted(set(file) - {"backup-manifest.json"}) != sorted(attesi):
        raise InputNonValido("archivio incompleto: mancano file o il BackupManifest")
    m = json.loads(file.pop("backup-manifest.json"))
    if m.get("schema") != backup.SCHEMA:
        raise InputNonValido(f"BackupManifest schema {m.get('schema')}, questo control plane legge lo schema {backup.SCHEMA}")
    dichiarati = {f["nome"]: f["sha256"] for f in m.get("file", [])}
    diversi = sorted(n for n, b in file.items() if dichiarati.get(n) != hashlib.sha256(b).hexdigest())
    if diversi:
        raise ChecksumDiverso(f"sha256 diverso dal manifest per: {', '.join(diversi)}")
    copia = sqlite3.connect(":memory:")
    try:
        copia.deserialize(file["var/lib/sovereignvpn/registro.sqlite3"])
        copia.execute("SELECT count(*) FROM peer").fetchone()
    except sqlite3.Error as e:
        raise InputNonValido(f"il registro nel backup non si apre ({e})")
    finally:
        copia.close()
    return file, m


def _scrivi(posti, file):
    for nome, dati in file.items():
        percorso, modo = posti[nome]
        os.makedirs(os.path.dirname(percorso), mode=0o700, exist_ok=True)
        if nome.endswith("registro.sqlite3"):
            for coda in ("-wal", "-shm"):  # del registro vecchio: sul nuovo lo corromperebbero
                if os.path.exists(percorso + coda):
                    os.unlink(percorso + coda)
        backup._scrivi(percorso, dati)
        os.chmod(percorso, modo)


def ripristina(file_cifrato, identita, percorso_config, wan_if=None, db=None, cartella=None):
    db = db or peer.DB_PREDEFINITO
    posti = _posti(percorso_config, db)
    file, m = leggi(file_cifrato, identita, posti)
    prima = {n: open(p, "rb").read() for n, (p, _) in posti.items() if os.path.exists(p)}
    salvato = None
    if prima:  # lo stato corrente, cifrato verso lo stesso destinatario, prima di toccare qualunque cosa
        salvato = backup.crea(percorso_config, m["destinatario"], cartella, db, presenti_soltanto=True)
    _scrivi(posti, file)
    cfg = configurazione.leggi(percorso_config)
    wan = wan_if or cfg.get("wan_interface")
    if not wan:
        raise InputNonValido("serve --wan-interface o wan_interface nella configurazione ripristinata")
    passi, errore = bootstrap.ripristina(cfg, wan)
    controlli, _ = stato.controlla(cfg, db)
    guasti = [c["nome"] for c in controlli if c["esito"] != "OK"]
    esito = {"backup": file_cifrato, "file": len(file), "stato_precedente": salvato and salvato["percorso"],
             "passi": [p for p, _ in passi], "errore": registro.redigi(errore) if errore else None, "guasti": guasti}
    if errore or guasti:
        if prima:  # si torna indietro: i file di prima e di nuovo reconcile
            _scrivi(posti, prima)
            bootstrap.ripristina(configurazione.leggi(percorso_config), wan)
        esito["tornato_indietro"] = bool(prima)
        return esito, 4
    return esito, 0


def esegui(a):
    if not a.conferma:
        print("sovereignctl: input non valido: il restore sovrascrive lo stato del server e vuole --conferma (FR-OPS-003)", file=sys.stderr)
        return 2
    try:
        esito, codice = ripristina(a.file, a.identity, a.config, a.wan_interface, a.db, a.out)
    except ChecksumDiverso as e:
        print(f"sovereignctl: security gate: {registro.redigi(e)}; niente toccato", file=sys.stderr)
        return 3
    except InputNonValido as e:
        print(f"sovereignctl: input non valido: {registro.redigi(e)}; niente toccato", file=sys.stderr)
        return 2
    except (RuntimeError, OSError, sqlite3.Error) as e:
        print(f"sovereignctl: errore del restore ({type(e).__name__}): {registro.redigi(e)}", file=sys.stderr)
        return 1
    print(json.dumps(esito, ensure_ascii=False, indent=1) if a.json else
          (f"Restore di {esito['file']} file da {esito['backup']}: verificato (reconcile e status tutti OK)."
           if codice == 0 else f"Restore NON verificato ({esito['errore'] or 'guasti: ' + ', '.join(esito['guasti'])}); "
           + ("rimesso lo stato di prima." if esito.get("tornato_indietro") else "nessuno stato di prima da rimettere."))
          + (f" Stato precedente salvato in {esito['stato_precedente']}." if esito["stato_precedente"] else ""))
    return codice
