"""Manifest della release (FR-BOOT-002, ReleaseManifest ANC-0233) e sua scrittura atomica (ANC-0244, ANC-0344).

componi(...)  il manifest come dizionario; rifiuta tag mobili e digest malformati (NFR-SEC-002, ANC-0319) e tutto cio' che
              il redattore riconosce come segreto, URL o IP pubblico (FR-BOOT-002: «mai chiavi o token»)
scrivi(...)   file temporaneo nella stessa cartella, flush, fsync, os.replace, fsync della cartella. Lo chiama solo
              `init` vero: `init --check` mostra l'anteprima e non scrive.
"""
import hashlib, json, os, re, tempfile

from . import VERSIONE
from .configurazione import VERSIONE_SCHEMA
from .registro import redigi

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class ManifestNonValido(ValueError):
    pass


def componi(fatti, percorso_config=None, id_installazione=None, immagini=()):
    elenco = []
    for img in immagini:  # le immagini arrivano con la Slice B (compose); qui la regola del pin per digest
        nome, digest = img.get("nome", ""), img.get("digest", "")
        if not DIGEST.match(digest):
            raise ManifestNonValido(f"immagine {nome or '?'}: serve un digest sha256:<64 esadecimali>, non un tag (NFR-SEC-002)")
        if nome.endswith(":latest"):
            raise ManifestNonValido(f"immagine {nome}: tag mobile «latest» vietato (ANC-0319)")
        elenco.append({"nome": nome, "digest": digest})
    checksum = None
    if percorso_config:
        with open(percorso_config, "rb") as f:
            checksum = "sha256:" + hashlib.sha256(f.read()).hexdigest()
    m = {"sovereignvpn": VERSIONE,
         "id_installazione": id_installazione or "generato da init: UUID casuale, non sensibile",
         "os": " ".join(fatti["os"]).strip(), "kernel": fatti["kernel"],
         "componenti": {"docker": fatti["docker"], "compose": fatti["compose"]},
         "immagini": elenco, "schema_configurazione": VERSIONE_SCHEMA,
         "checksum_configurazione": checksum, "stato_migrazione": "nessuna"}
    testo = json.dumps(m, ensure_ascii=False, sort_keys=True)
    if redigi(testo) != testo:
        raise ManifestNonValido("il manifest conterrebbe un segreto, un URL o un IP pubblico: non si compone (FR-BOOT-002)")
    return m


def scrivi(percorso, manifest):
    return scrivi_testo(percorso, json.dumps(manifest, ensure_ascii=False, indent=1, sort_keys=True) + "\n")


def scrivi_testo(percorso, testo, modo=0o644):
    """Scrittura atomica di un testo (ANC-0244, ANC-0344): la usano il manifest e i file di sistema."""
    cartella = os.path.dirname(os.path.abspath(percorso))
    fd, tmp = tempfile.mkstemp(prefix=".manifest-", dir=cartella)  # stessa filesystem: os.replace e' atomico
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(testo)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, modo)
        os.replace(tmp, percorso)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    d = os.open(cartella, os.O_RDONLY)
    try:
        os.fsync(d)
    finally:
        os.close(d)
    return percorso
