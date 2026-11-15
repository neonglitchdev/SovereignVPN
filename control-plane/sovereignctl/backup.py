"""`sovereignctl backup create` (FR-OPS-001, ANC-0254; BackupManifest del cap. 8) [H20].

Cifratura con age (X25519) verso un destinatario dichiarato (`backup_recipient` nella configurazione, o --recipient):
una chiave PUBBLICA, cosi' la chiave per decifrare non sta sul server e il backup puo' uscire dall'host. Nessuna
primitiva crittografica nostra (FR-WG-002): il chiaro passa da una pipe ad `age`, mai su disco.
Dentro l'archivio: la configurazione, la chiave del server, il registro dei peer (copia coerente con l'API di backup
di SQLite, in memoria e senza file temporanei, con l'intestazione riportata da WAL a legacy), il manifest dell'installazione e il BackupManifest (schema, versione, ora UTC, file con
sha256 e byte, algoritmo, destinatario, istruzioni di restore). Fuori: profili esportati, file temporanei, log.
Accanto al .age si scrive il BackupManifest in chiaro (nomi e checksum, mai contenuti); a schermo percorso e checksum.
"""
import datetime, hashlib, io, json, os, sqlite3, subprocess, sys, tarfile, tempfile

from . import VERSIONE, bootstrap, configurazione, peer, registro, runtime
from .preflight import InputNonValido

CARTELLA = "/var/lib/sovereignvpn/backup"
SCHEMA = 1


class AgeFallito(RuntimeError):
    """age e' uscito con errore: chiave sbagliata, file manomesso o destinatario non valido."""


def _age(*argomenti, ingresso=None):
    try:
        p = subprocess.run(["age", *argomenti], input=ingresso, capture_output=True, timeout=120,
                           env={"PATH": os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"), "LC_ALL": "C"})
    except FileNotFoundError:
        raise RuntimeError("age non installato: serve per cifrare il backup (apt install age) [H20]")
    if p.returncode != 0:
        raise AgeFallito(f"age non riuscito ({registro.redigi(p.stderr.decode(errors='replace').strip())[:160]})")
    return p.stdout


def contenuti(percorso_config, db, presenti_soltanto=False):
    """Nome nell'archivio -> byte. Il registro come copia coerente, mai copiando il file aperto. Con
    `presenti_soltanto` (lo stato salvato prima di un restore) un file che manca si salta invece di fermare tutto."""
    file = {}
    for nome, percorso in (("etc/sovereignvpn/server.toml", percorso_config),
                           ("etc/sovereignvpn/wg-server.key", runtime.CHIAVE_SERVER),
                           ("var/lib/sovereignvpn/manifest.json", bootstrap.MANIFEST)):
        if presenti_soltanto and not os.path.exists(percorso):
            continue
        with open(percorso, "rb") as f:
            file[nome] = f.read()
    if not os.path.exists(db):
        if presenti_soltanto:
            return file
        raise RuntimeError(f"registro dei peer assente in {db}")
    src, mem = sqlite3.connect(f"file:{db}?mode=ro", uri=True), sqlite3.connect(":memory:")
    try:
        src.backup(mem)  # copia coerente attraverso il pager, transazioni ancora nel -wal comprese
        dati = bytearray(mem.serialize())
    finally:
        src.close(); mem.close()
    dati[18] = dati[19] = 1  # intestazione «legacy», non WAL: la copia si riapre ovunque; Archivio rimette il WAL
    file["var/lib/sovereignvpn/registro.sqlite3"] = bytes(dati)
    return file


def _scrivi(percorso, dati):
    cartella = os.path.dirname(percorso)
    fd, tmp = tempfile.mkstemp(prefix=".backup-", dir=cartella)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(dati)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, percorso)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def crea(percorso_config, destinatario, cartella=None, db=None, adesso=None, presenti_soltanto=False):
    cartella, db = cartella or CARTELLA, db or peer.DB_PREDEFINITO
    if not configurazione.DESTINATARIO_AGE.match(destinatario or ""):
        raise InputNonValido("--recipient: serve una chiave pubblica age (age1...), o backup_recipient nella configurazione [H20]")
    adesso = adesso or datetime.datetime.now(datetime.timezone.utc)
    file = contenuti(percorso_config, db, presenti_soltanto)
    m = {"schema": SCHEMA, "sovereignvpn": VERSIONE, "creato": adesso.isoformat(timespec="seconds").replace("+00:00", "Z"),
         "file": [{"nome": n, "sha256": hashlib.sha256(b).hexdigest(), "byte": len(b)} for n, b in sorted(file.items())],
         "cifratura": "age (X25519, ChaCha20-Poly1305)", "destinatario": destinatario,
         "istruzioni": "sovereignctl backup restore <file.tar.age> --identity <chiave privata age, tenuta fuori dal server>"}
    testo_m = json.dumps(m, ensure_ascii=False, indent=1, sort_keys=True) + "\n"
    if registro.redigi(testo_m) != testo_m:
        raise RuntimeError("il manifest del backup conterrebbe un segreto: non si scrive")
    archivio = io.BytesIO()
    with tarfile.open(fileobj=archivio, mode="w") as tar:
        for nome, dati in sorted(file.items()) + [("backup-manifest.json", testo_m.encode())]:
            info = tarfile.TarInfo(nome)
            info.size, info.mode, info.mtime = len(dati), 0o600, int(adesso.timestamp())
            tar.addfile(info, io.BytesIO(dati))
    cifrato = _age("-r", destinatario, ingresso=archivio.getvalue())
    os.makedirs(cartella, mode=0o700, exist_ok=True)
    os.chmod(cartella, 0o700)
    base = os.path.join(cartella, f"sovereignvpn-{adesso.strftime('%Y%m%dT%H%M%SZ')}")
    _scrivi(base + ".tar.age", cifrato)
    _scrivi(base + ".manifest.json", testo_m.encode())
    return {"percorso": base + ".tar.age", "checksum": "sha256:" + hashlib.sha256(cifrato).hexdigest(),
            "manifest": base + ".manifest.json", "file": len(file), "destinatario": destinatario}


def esegui(a):
    try:
        cfg = configurazione.leggi(a.config)
        esito = crea(a.config, a.recipient or cfg.get("backup_recipient"), a.out, a.db)
    except InputNonValido as e:
        print(f"sovereignctl: input non valido: {registro.redigi(e)}", file=sys.stderr)
        return 2
    except (RuntimeError, OSError, sqlite3.Error) as e:
        print(f"sovereignctl: errore del backup ({type(e).__name__}): {registro.redigi(e)}", file=sys.stderr)
        return 1
    print(json.dumps(esito, ensure_ascii=False, indent=1) if a.json else
          f"Backup cifrato in {esito['percorso']} (0600), {esito['checksum']}; {esito['file']} file, manifest in "
          f"{esito['manifest']}. Si decifra solo con la chiave privata di {esito['destinatario']}, che non sta qui.")
    return 0
