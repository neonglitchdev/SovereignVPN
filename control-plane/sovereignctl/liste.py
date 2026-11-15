"""Liste di blocco del DNS (FR-DNS-002, FR-DNS-007) [H27].

Una lista e' un file locale di domini, versionato col suo sha256, non un URL che cambia da solo. `dns blocklist apply`
la valida PRIMA di attivarla (un dominio per riga, nomi host veri, niente indirizzi IP): una lista invalida non entra
e quella attiva resta operativa. L'attivazione e' atomica (un link simbolico rinominato sopra il vecchio) e la
precedente resta per `dns blocklist rollback`. Pi-hole la legge come adlist file:// e la ricompila con gravity
(`--sincronizza`). In stato.json versione, sha256, numero di domini e ora: mai una query (FR-DNS-009).
"""
import collections, datetime, hashlib, ipaddress, json, os, subprocess, sys

from . import dns, registro
from .configurazione import NOME_HOST
from .manifest import scrivi_testo
from .preflight import InputNonValido

DENTRO_PIHOLE = "/etc/pihole/sovereignvpn"  # dove l'unita' di Pi-hole monta la cartella delle liste, in sola lettura
CONTENITORE = "sovereignvpn-pihole"


def cartella_predefinita():
    return os.path.join(dns.CARTELLA_DNS, "liste")


def valida(testo):
    """(domini unici ordinati, errori, doppioni). Commenti con #, righe vuote ammesse."""
    domini, errori = [], []
    for n, riga in enumerate(testo.splitlines(), 1):
        r = riga.split("#", 1)[0].strip().lower().rstrip(".")
        if not r:
            continue
        try:
            ipaddress.ip_address(r)
            errori.append(f"riga {n}: «{r[:60]}» e' un indirizzo IP, non un dominio")
            continue
        except ValueError:
            pass
        if "." not in r or not NOME_HOST.match(r):
            errori.append(f"riga {n}: «{r[:60]}» non e' un nome di dominio")
        else:
            domini.append(r)
    doppioni = sorted(d for d, c in collections.Counter(domini).items() if c > 1)
    return sorted(set(domini)), errori, doppioni


def _stato(cartella):
    try:
        with open(os.path.join(cartella, "stato.json"), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _attiva(cartella, nome, stato):
    link = os.path.join(cartella, "attiva.txt")
    if os.path.lexists(link + ".nuovo"):
        os.unlink(link + ".nuovo")
    os.symlink(nome, link + ".nuovo")  # relativo: si risolve anche dentro il container
    os.replace(link + ".nuovo", link)  # atomico: in ogni istante attiva.txt e' la lista vecchia o la nuova
    scrivi_testo(os.path.join(cartella, "stato.json"), json.dumps(stato, ensure_ascii=False, indent=1) + "\n", 0o644)
    return stato


def applica(file, cartella=None, adesso=None):
    cartella = cartella or cartella_predefinita()
    with open(file, encoding="utf-8") as f:
        testo = f.read(50 * 1024 * 1024)
    domini, errori, doppioni = valida(testo)
    if errori or not domini:
        raise InputNonValido("lista non attivata, resta quella di prima: " + ("; ".join(errori[:5]) if errori else "nessun dominio")
                             + (f" (e altri {len(errori) - 5})" if len(errori) > 5 else ""))
    corpo = "".join(d + "\n" for d in domini)
    sha = hashlib.sha256(corpo.encode()).hexdigest()
    os.makedirs(cartella, mode=0o755, exist_ok=True)  # liste non segrete: le legge l'utente di Pi-hole nel container
    nome = f"lista-{sha[:16]}.txt"
    scrivi_testo(os.path.join(cartella, nome), corpo, 0o644)
    prima = _stato(cartella)
    adesso = adesso or datetime.datetime.now(datetime.timezone.utc)
    return _attiva(cartella, nome, {"attiva": nome, "sha256": sha, "domini": len(domini), "doppioni_tolti": len(doppioni),
                                     "attivata": adesso.isoformat(timespec="seconds").replace("+00:00", "Z"),
                                     "precedente": prima.get("attiva") if prima.get("attiva") != nome else prima.get("precedente"),
                                     "precedente_stato": {k: prima.get(k) for k in ("attiva", "sha256", "domini", "attivata")} if prima else None})


def rollback(cartella=None):
    cartella = cartella or cartella_predefinita()
    prima = _stato(cartella)
    vecchio = prima.get("precedente_stato") or {}
    if not vecchio.get("attiva") or not os.path.exists(os.path.join(cartella, vecchio["attiva"])):
        raise InputNonValido("nessuna lista precedente a cui tornare")
    return _attiva(cartella, vecchio["attiva"], {**vecchio, "doppioni_tolti": None, "precedente": prima.get("attiva"),
                                                 "precedente_stato": {k: prima.get(k) for k in ("attiva", "sha256", "domini", "attivata")}})


def _docker(*argomenti):
    p = subprocess.run(["docker", *argomenti], capture_output=True, text=True, timeout=600,
                       env={"PATH": os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"), "LC_ALL": "C"})
    if p.returncode != 0:
        raise RuntimeError(f"docker {argomenti[0]} non riuscito ({registro.redigi(p.stderr.strip())[:200]})")
    return p.stdout


def sincronizza(contenitore=CONTENITORE):
    """Registra in Pi-hole l'adlist della lista attiva (una volta) e ricompila gravity; restituisce numero e stato."""
    indirizzo = f"file://{DENTRO_PIHOLE}/attiva.txt"
    _docker("exec", contenitore, "pihole-FTL", "sqlite3", "/etc/pihole/gravity.db",
            f"INSERT OR IGNORE INTO adlist (address, enabled, comment) VALUES ('{indirizzo}', 1, 'sovereignvpn');")
    _docker("exec", contenitore, "pihole", "-g")
    riga = _docker("exec", contenitore, "pihole-FTL", "sqlite3", "/etc/pihole/gravity.db",
                   f"SELECT number, status FROM adlist WHERE address = '{indirizzo}';").strip()
    numero, _, stato = riga.partition("|")
    return {"adlist": indirizzo, "domini_in_gravity": int(numero or 0), "stato_pihole": int(stato or 0)}


def aggiungi_parser(az, classe):
    bl = az.add_parser("blocklist", help="liste di blocco versionate: apply, rollback, status (FR-DNS-002/007)")
    ba = bl.add_subparsers(dest="lista", required=True, parser_class=classe)
    ap = ba.add_parser("apply"); ap.add_argument("file")
    ba.add_parser("rollback")
    ba.add_parser("status")
    for s in (ap, ba.choices["rollback"], ba.choices["status"]):
        s.add_argument("--cartella"); s.add_argument("--json", action="store_true")
    for s in (ap, ba.choices["rollback"]):
        s.add_argument("--sincronizza", action="store_true", help="registra l'adlist in Pi-hole e ricompila gravity")
        s.add_argument("--contenitore", default=CONTENITORE)


def esegui(a):
    try:
        if a.lista == "status":
            esito = _stato(a.cartella or cartella_predefinita()) or {"attiva": None}
        else:
            esito = applica(a.file, a.cartella) if a.lista == "apply" else rollback(a.cartella)
            if a.sincronizza:
                esito = {**esito, "pihole": sincronizza(a.contenitore)}
    except InputNonValido as e:
        print(f"sovereignctl: input non valido: {registro.redigi(e)}", file=sys.stderr)
        return 2
    except (RuntimeError, OSError) as e:
        print(f"sovereignctl: errore delle liste ({type(e).__name__}): {registro.redigi(e)}", file=sys.stderr)
        return 1
    print(json.dumps(esito, ensure_ascii=False, indent=1) if a.json else
          f"Lista attiva: {esito.get('attiva')} ({esito.get('domini')} domini, sha256 {str(esito.get('sha256'))[:16]}..., "
          f"attivata {esito.get('attivata')}); precedente: {esito.get('precedente')}")
    return 0
