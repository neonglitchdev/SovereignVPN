"""Registro dei peer (Slice B, primo pezzo; ANC-0347): modello, macchina a stati, archivio SQLite, comandi `peer`.

Due dimensioni [H1]: lo STATO del peer (i sei di FR-PEER-003) e lo stato della SAGA che porta il registro nel runtime
WireGuard (ANC-0244: PENDING_APPLY, APPLIED, ROLLBACK_REQUIRED, ERROR). Ogni comando che cambia stato lascia la saga in
PENDING_APPLY: la applichera' la riconciliazione col runtime (pezzo successivo). Una revoca e' completata solo con
REVOKED + APPLIED (ANC-0288). Chiave privata del peer mai sul server [H2]: si registra solo la pubblica (ANC-0148).
Archivio: SQLite, BEGIN IMMEDIATE, vincoli univoci su nome, chiave e indirizzo (ANC-0244, FR-PEER-001), schema versionato
(ANC-0242), file 0600. Ogni cambio e ogni rifiuto di transizione lascia un evento di audit (FR-PEER-003, ANC-0232).
"""
import base64, binascii, datetime, ipaddress, json, os, sqlite3, sys, unicodedata, uuid

from . import preflight, registro
from .preflight import InputNonValido

VERSIONE_SCHEMA_DB = 4
# Migrazioni esplicite (cap. 8): da versione -> istruzioni per passare alla successiva; prima si salva il registro.
MIGRAZIONI = {1: ["ALTER TABLE peer ADD COLUMN rotte TEXT"],
              2: ["ALTER TABLE peer ADD COLUMN politica_dns TEXT"],
              3: ["ALTER TABLE peer ADD COLUMN quota_byte INTEGER", "ALTER TABLE peer ADD COLUMN quota_usati INTEGER"]}  # 3 -> 4: quota [H35]  # 2 -> 3: DNS per peer, NULL = interno  # 1 -> 2: rotte per peer (FR-PEER-008), NULL = full-tunnel
DB_PREDEFINITO = "/var/lib/sovereignvpn/registro.sqlite3"   # [H12] la cartella 0700 la crea l'installer
TTL_MASSIMO_GIORNI = 365                                    # [H10] ANC-0240 vuole un massimo configurabile
STATI = ("PENDING", "ACTIVE", "SUSPENDED", "EXPIRED", "REVOKED", "ERROR")   # FR-PEER-003, per intero
TRANSIZIONI = {  # (stato, azione) -> nuovo stato; tutto il resto e' respinto. REVOKED non ha uscite (FR-PEER-006).
    ("PENDING", "revoke"): "REVOKED", ("ACTIVE", "suspend"): "SUSPENDED", ("ACTIVE", "revoke"): "REVOKED",
    ("SUSPENDED", "resume"): "ACTIVE", ("SUSPENDED", "revoke"): "REVOKED", ("EXPIRED", "revoke"): "REVOKED",
    ("ERROR", "revoke"): "REVOKED",
    # FR-PEER-005: «expire» la fa solo il tempo (peer expire-sweep), mai un comando sul singolo peer; da EXPIRED
    # si esce solo con revoke: il peer scaduto non si riattiva, serve un provisioning nuovo (workflow 10).
    ("PENDING", "expire"): "EXPIRED", ("ACTIVE", "expire"): "EXPIRED", ("SUSPENDED", "expire"): "EXPIRED",
    ("ERROR", "expire"): "EXPIRED",
}


class Conflitto(InputNonValido):
    """Nome, chiave o indirizzo gia' presenti, o transizione non valida: codice 2 (ANC-0255), col motivo."""


def ora():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def normalizza_nome(nome):
    """ANC-0238: nome normalizzato (NFC, spazi compressi, confronto senza maiuscole), mai usato come percorso."""
    n = " ".join(unicodedata.normalize("NFC", str(nome)).split())
    if not 1 <= len(n) <= 64:
        raise InputNonValido("--name: da 1 a 64 caratteri")
    if any(c in n for c in "/\\\0") or n in (".", "..") or not all(c.isalnum() or c in " -_." for c in n):
        raise InputNonValido("--name: solo lettere, cifre, spazio, trattino, trattino basso e punto")
    return n, n.casefold()


def valida_chiave(chiave):
    try:
        grezza = base64.b64decode(chiave, validate=True)
    except (binascii.Error, ValueError, TypeError):
        raise InputNonValido("--public-key: non e' base64")
    if len(grezza) != 32 or base64.b64encode(grezza).decode() != chiave:
        raise InputNonValido("--public-key: una chiave pubblica WireGuard e' di 32 byte in base64 (44 caratteri)")
    return chiave


def dns_liberi(db):
    """FR-PEER-008 [H34]: gli indirizzi dei peer non revocati con DNS libero; registro di schema vecchio = nessuno."""
    if not os.path.exists(db):
        return []
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        return [r[0] for r in con.execute("SELECT indirizzo FROM peer WHERE politica_dns = 'libero' AND stato != 'REVOKED' ORDER BY indirizzo")]
    except sqlite3.OperationalError:
        return []
    finally:
        con.close()


def limiti_rotte(db):
    """FR-PEER-008 [H33]: (indirizzo, rotte) dei peer non revocati che hanno rotte, in sola lettura; il firewall li
    applica. Registro assente o di schema 1 (senza la colonna) = nessun limite."""
    if not os.path.exists(db):
        return []
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        righe = con.execute("SELECT indirizzo, rotte FROM peer WHERE rotte IS NOT NULL AND stato != 'REVOKED' ORDER BY indirizzo").fetchall()
    except sqlite3.OperationalError:
        return []
    finally:
        con.close()
    return [(ind, json.loads(r)) for ind, r in righe]


class Archivio:
    def __init__(self, percorso):
        self.percorso = percorso
        nuovo = not os.path.exists(percorso)
        if nuovo:  # creato 0600 prima che sqlite ci scriva (NFR-SEC-004)
            os.close(os.open(percorso, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        self.db = sqlite3.connect(percorso, timeout=30, isolation_level=None)
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.execute("PRAGMA journal_mode = WAL")
        if not nuovo:
            self._migra()
        with self.transazione() as c:
            c.execute("CREATE TABLE IF NOT EXISTS schema (versione INTEGER NOT NULL)")
            v = c.execute("SELECT versione FROM schema").fetchone()
            if v is None:
                c.execute("INSERT INTO schema VALUES (?)", (VERSIONE_SCHEMA_DB,))
                c.execute("""CREATE TABLE peer (
                    id TEXT PRIMARY KEY, nome TEXT NOT NULL, nome_chiave TEXT NOT NULL UNIQUE,
                    chiave_pubblica TEXT NOT NULL UNIQUE, indirizzo TEXT NOT NULL UNIQUE,
                    stato TEXT NOT NULL CHECK (stato IN ('PENDING','ACTIVE','SUSPENDED','EXPIRED','REVOKED','ERROR')),
                    saga TEXT NOT NULL CHECK (saga IN ('PENDING_APPLY','APPLIED','ROLLBACK_REQUIRED','ERROR')),
                    creato TEXT NOT NULL, scade TEXT, revocato TEXT, sospeso TEXT, rotte TEXT, politica_dns TEXT, quota_byte INTEGER, quota_usati INTEGER)""")
                c.execute("CREATE TABLE id_usati (id TEXT PRIMARY KEY)")  # ANC-0237: un UUID non si riusa mai
                c.execute("CREATE TABLE audit (n INTEGER PRIMARY KEY AUTOINCREMENT, evento TEXT NOT NULL)")
            elif v[0] != VERSIONE_SCHEMA_DB:
                raise RuntimeError(f"schema del registro {v[0]}, questo sovereignctl conosce il {VERSIONE_SCHEMA_DB}: serve una migrazione")

    def _migra(self):
        """Porta un registro di schema vecchio al corrente, un passo alla volta; prima una copia coerente 0600 accanto."""
        try:
            v = self.db.execute("SELECT versione FROM schema").fetchone()
        except sqlite3.OperationalError:
            return  # registro vuoto (creato altrove e mai inizializzato): ci pensa il ramo «nuovo»
        if v is None or v[0] >= VERSIONE_SCHEMA_DB:
            return
        copia = f"{self.percorso}.schema{v[0]}.bak"
        if not os.path.exists(copia):
            os.close(os.open(copia, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
            dest = sqlite3.connect(copia)
            try:
                self.db.backup(dest)  # copia coerente, WAL compreso, prima di toccare lo schema
            finally:
                dest.close()
        with self.transazione() as c:
            for da in range(v[0], VERSIONE_SCHEMA_DB):
                for istruzione in MIGRAZIONI[da]:
                    c.execute(istruzione)
            c.execute("UPDATE schema SET versione = ?", (VERSIONE_SCHEMA_DB,))
            self.audit(c, "registro.migrate", "success", motivo=f"schema {v[0]} -> {VERSIONE_SCHEMA_DB}, copia in {os.path.basename(copia)}")

    class _T:
        def __init__(self, db): self.db = db
        def __enter__(self):
            self.db.execute("BEGIN IMMEDIATE")  # un solo scrittore: l'allocazione non duplica (FR-PEER-001)
            return self.db
        def __exit__(self, tipo, *_):
            self.db.execute("COMMIT" if tipo is None else "ROLLBACK")
            return False

    def transazione(self):
        return self._T(self.db)

    def audit(self, c, azione, esito, bersaglio=None, motivo=""):
        c.execute("INSERT INTO audit (evento) VALUES (?)", (registro.evento_audit(
            actor="sovereignctl", action=azione, target=bersaglio, outcome=esito, reason=motivo),))

    @staticmethod
    def valida_rotte(testo, rete):
        """FR-PEER-008, FR-WG-007 [H32]: «CIDR,CIDR» -> lista canonica; reti IPv4, al massimo 32, nessuna sovrapposta
        alla subnet VPN (la VPN entra sempre nel profilo), niente 0.0.0.0/0 (quello e' il full-tunnel: si omette)."""
        if testo is None:
            return None
        rotte = []
        for pezzo in [x.strip() for x in testo.split(",") if x.strip()]:
            try:
                r = ipaddress.ip_network(pezzo)
            except ValueError:
                raise InputNonValido(f"--routes: «{pezzo}» non e' un CIDR canonico")
            if r.version != 4 or r.prefixlen == 0 or r.overlaps(ipaddress.ip_network(rete)):
                raise InputNonValido(f"--routes: «{pezzo}» deve essere una rete IPv4 non 0.0.0.0/0 e fuori dalla subnet VPN {rete}")
            rotte.append(str(r))
        if not 1 <= len(rotte) <= 32:
            raise InputNonValido("--routes: da 1 a 32 reti")
        return sorted(set(rotte))

    def aggiungi(self, nome, chiave, rete, ttl_giorni=None, rotte=None, politica_dns=None, quota_mb=None):
        nome, nome_chiave = normalizza_nome(nome)
        chiave = valida_chiave(chiave)
        rotte = self.valida_rotte(rotte, rete)
        if quota_mb is not None and not 1 <= quota_mb <= 10_000_000:
            raise InputNonValido("--quota-mb: da 1 a 10.000.000 MB (FR-PEER-008) [H35]")
        if politica_dns not in (None, "interno", "libero"):
            raise InputNonValido("--dns-policy: interno (di base, solo il resolver interno) o libero (anche DNS esterni) [H34]")
        if ttl_giorni is not None and not 1 <= ttl_giorni <= TTL_MASSIMO_GIORNI:
            raise InputNonValido(f"--ttl-days: da 1 a {TTL_MASSIMO_GIORNI} [H10]")
        rete = ipaddress.ip_network(rete)
        rifiuto = None  # un rifiuto si registra (COMMIT del solo evento di audit) e si solleva dopo la transazione
        with self.transazione() as c:
            occupati = {r[0] for r in c.execute("SELECT indirizzo FROM peer")}
            host = list(rete.hosts())[1:]  # [H11] il primo host e' del server
            libero = next((str(h) for h in host if str(h) not in occupati), None)
            if c.execute("SELECT 1 FROM peer WHERE nome_chiave = ?", (nome_chiave,)).fetchone():
                rifiuto = Conflitto(f"--name: «{nome}» e' gia' in uso")
            elif c.execute("SELECT 1 FROM peer WHERE chiave_pubblica = ?", (chiave,)).fetchone():
                rifiuto = Conflitto("--public-key: chiave gia' registrata; una chiave revocata non torna (FR-PEER-006)")
            elif libero is None:
                rifiuto = Conflitto(f"subnet {rete} esaurita (SUBNET_EXHAUSTED, ANC-0261)")
            if rifiuto:
                self.audit(c, "peer.add", "denied", motivo=str(rifiuto).split(":")[0])
        if rifiuto:
            raise rifiuto
        with self.transazione() as c:
            occupati = {r[0] for r in c.execute("SELECT indirizzo FROM peer")}  # riletto dentro la transazione che scrive
            libero = next((str(h) for h in host if str(h) not in occupati), None)
            if libero is None:
                raise Conflitto(f"subnet {rete} esaurita (SUBNET_EXHAUSTED, ANC-0261)")
            nuovo = str(uuid.uuid4())
            adesso = datetime.datetime.now(datetime.timezone.utc)
            scade = None if ttl_giorni is None else (adesso + datetime.timedelta(days=ttl_giorni)).isoformat(timespec="seconds").replace("+00:00", "Z")
            c.execute("INSERT INTO id_usati VALUES (?)", (nuovo,))
            c.execute("INSERT INTO peer (id, nome, nome_chiave, chiave_pubblica, indirizzo, stato, saga, creato, scade, rotte, politica_dns, quota_byte) "
                      "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                      (nuovo, nome, nome_chiave, chiave, libero, "PENDING", "PENDING_APPLY", ora(), scade,
                       json.dumps(rotte) if rotte else None, politica_dns if politica_dns == "libero" else None,
                       quota_mb * 1024 * 1024 if quota_mb else None))
            self.audit(c, "peer.add", "success", nuovo)
        return self.mostra(nuovo)

    def scadi(self, adesso=None):
        """FR-PEER-005: i peer col TTL passato vanno in EXPIRED, saga PENDING_APPLY (dal runtime li toglie la
        riconciliazione). Legge solo `scade`, in UTC: nessun timer in memoria, si puo' rifare dopo un riavvio e una
        seconda volta non cambia niente. `adesso` lo passano solo le prove (orologio controllato), mai la CLI."""
        adesso = adesso or ora()
        with self.transazione() as c:
            con_ttl = [(i, s) for i, s in c.execute("SELECT id, stato FROM peer WHERE scade IS NOT NULL AND stato != 'EXPIRED'")]
            scaduti = 0
            for i, s in c.execute("SELECT id, stato FROM peer WHERE scade IS NOT NULL AND scade <= ?", (adesso,)).fetchall():
                nuovo = TRANSIZIONI.get((s, "expire"))
                if nuovo:
                    c.execute("UPDATE peer SET stato = ?, saga = 'PENDING_APPLY' WHERE id = ?", (nuovo, i))
                    self.audit(c, "peer.expire", "success", i)
                    scaduti += 1
        return {"scaduti": scaduti, "con_ttl": sum(1 for _, s in con_ttl if (s, "expire") in TRANSIZIONI),
                "controllato_alle": adesso}

    def elenco(self):
        cur = self.db.execute("SELECT id, nome, indirizzo, stato, saga, creato, scade FROM peer ORDER BY creato, nome")
        return [dict(zip(("id", "nome", "indirizzo", "stato", "saga", "creato", "scade"), r)) for r in cur]

    def mostra(self, id_peer):
        try:
            id_peer = str(uuid.UUID(id_peer))
        except (ValueError, TypeError):
            raise InputNonValido("id: serve l'UUID del peer")
        cur = self.db.execute("SELECT * FROM peer WHERE id = ?", (id_peer,))
        r = cur.fetchone()
        if r is None:
            raise InputNonValido(f"id: nessun peer {id_peer} (PEER_NOT_FOUND)")
        d = dict(zip([x[0] for x in cur.description], r))
        d.pop("nome_chiave")
        d["chiave_privata_sul_server"] = False  # [H2]: non esiste, quindi non si puo' mostrare (ANC-0246)
        return d

    def transizione(self, id_peer, azione):
        p = self.mostra(id_peer)
        with self.transazione() as c:
            stato = c.execute("SELECT stato FROM peer WHERE id = ?", (p["id"],)).fetchone()[0]
            nuovo = TRANSIZIONI.get((stato, azione))
            if nuovo is None:  # respinta E registrata (FR-PEER-003): il COMMIT tiene l'evento, l'errore esce dopo
                self.audit(c, f"peer.{azione}", "denied", p["id"], f"transizione non valida da {stato}")
        if nuovo is None:
            raise Conflitto(f"{azione}: non si puo' da {stato}" + (" (la revoca e' irreversibile, FR-PEER-006)" if stato == "REVOKED" else ""))
        with self.transazione() as c:
            if c.execute("SELECT stato FROM peer WHERE id = ?", (p["id"],)).fetchone()[0] != stato:
                raise Conflitto(f"{azione}: lo stato e' cambiato nel frattempo, riprovare (CONFLICT)")
            campi = {"REVOKED": ", revocato = ?", "SUSPENDED": ", sospeso = ?"}.get(nuovo, "")
            valori = (nuovo, "PENDING_APPLY") + ((ora(),) if campi else ()) + (p["id"],)
            c.execute(f"UPDATE peer SET stato = ?, saga = ?{campi} WHERE id = ?", valori)
            self.audit(c, f"peer.{azione}", "success", p["id"])
        return self.mostra(p["id"])


def aggiungi_parser_firewall(sotto, classe):
    fw = sotto.add_parser("firewall", help="firewall di base nftables (ADR-005)")
    az = fw.add_subparsers(dest="azione", required=True, parser_class=classe)
    for nome in ("plan", "apply"):
        s = az.add_parser(nome)
        s.add_argument("--config", required=True); s.add_argument("--wan-interface"); s.add_argument("--wg-interface", default="wg0")
        s.add_argument("--db", default=DB_PREDEFINITO, help="registro: le rotte dei peer diventano regole (FR-PEER-008)")
        s.add_argument("--json", action="store_true")


def esegui_firewall(a):
    from . import configurazione, firewall
    try:
        cfg = configurazione.leggi(a.config)
        ruleset = firewall.componi(cfg.get("subnet") or preflight.CANDIDATE_VPN[0], a.wg_interface, cfg.get("wg_port", 51820),
                                   a.wan_interface or cfg.get("wan_interface"), cfg.get("admin_port", 8443),
                                   cfg["ssh_port"], cfg["admin_ssh_sources"], cfg.get("mtu", 1420),
                                   cfg.get("dns_block_dot", True), limiti_rotte(a.db), dns_liberi(a.db))
        if a.azione == "plan":  # solo testo: niente nft, niente host toccato
            print(json.dumps({"ruleset": ruleset, "mutazioni_eseguite": 0}, ensure_ascii=False, indent=1) if a.json else ruleset, end="" if not a.json else "\n")
            return 0
        esito = firewall.applica(ruleset)
    except InputNonValido as e:
        print(f"sovereignctl: input non valido: {registro.redigi(e)}", file=sys.stderr)
        return 2
    except (RuntimeError, OSError) as e:
        print(f"sovereignctl: errore del firewall: {registro.redigi(e)}", file=sys.stderr)
        return 1
    print(json.dumps(esito, ensure_ascii=False, indent=1) if a.json else
          f"Firewall applicato: tabella {esito['tabella']}, {esito['regole']} regole, policy {esito['catene']}")
    return 0 if esito["verificato"] else 4


def aggiungi_parser_host(sotto, classe):
    h = sotto.add_parser("host", help="sysctl dell'host (inoltro IPv4 acceso, IPv6 spento)")
    az = h.add_subparsers(dest="azione", required=True, parser_class=classe)
    for nome in ("plan", "apply"):
        s = az.add_parser(nome)
        s.add_argument("--radice", default=""); s.add_argument("--json", action="store_true")


def esegui_host(a):
    from . import host
    if a.azione == "plan":
        print(json.dumps({"file": "/" + host.FILE, "contenuto": host.componi(), "mutazioni_eseguite": 0}, ensure_ascii=False, indent=1)
              if a.json else host.componi(), end="" if not a.json else "\n")
        return 0
    if a.radice and not os.path.isdir(a.radice):
        print(f"sovereignctl: input non valido: --radice: la cartella «{a.radice}» non esiste", file=sys.stderr)
        return 2
    try:
        esito = host.applica(a.radice)
    except (RuntimeError, OSError) as e:
        print(f"sovereignctl: errore dei sysctl: {registro.redigi(e)}", file=sys.stderr)
        return 1
    print(json.dumps(esito, ensure_ascii=False, indent=1) if a.json else
          f"Sysctl scritti in {esito['file']}" + (f"; attivati e riletti: {esito['letti']}" if esito["attivato"] else "; non attivati (radice di prova)"))
    return 4 if esito["verificato"] is False else 0


def aggiungi_parser(sotto, classe):
    peer = sotto.add_parser("peer", help="registro dei peer")
    az = peer.add_subparsers(dest="azione", required=True, parser_class=classe)
    for nome in ("add", "list", "show", "suspend", "resume", "revoke", "reconcile", "expire-sweep"):
        s = az.add_parser(nome)
        s.add_argument("--db", default=DB_PREDEFINITO)
        s.add_argument("--json", action="store_true")
        if nome == "add":
            s.add_argument("--name", required=True); s.add_argument("--public-key", required=True)
            s.add_argument("--ttl-days", type=int); s.add_argument("--config")
            s.add_argument("--quota-mb", type=int, help="traffico massimo del peer in MB; oltre, fermo (FR-PEER-008)")
            s.add_argument("--dns-policy", choices=("interno", "libero"), help="interno (di base) o libero: DNS esterni ammessi per questo peer (FR-PEER-008)")
            s.add_argument("--routes", help="split tunnel: CIDR,CIDR verso cui il peer esce (FR-PEER-008); senza, full-tunnel")
        if nome in ("show", "suspend", "resume", "revoke"):
            s.add_argument("id")
        if nome == "reconcile":  # dal registro al runtime WireGuard (ANC-0276/0277)
            s.add_argument("--interface", default="wg0"); s.add_argument("--server-key", default="/etc/sovereignvpn/wg-server.key")
            s.add_argument("--port", type=int, default=51820)


def esegui(a):
    try:
        archivio = Archivio(a.db)
        if a.azione == "add":
            from . import configurazione
            cfg = configurazione.leggi(a.config) if a.config else {}
            rete = cfg.get("subnet") or preflight.CANDIDATE_VPN[0]  # [H6] senza configurazione, la prima candidata
            esito = archivio.aggiungi(a.name, a.public_key, rete, a.ttl_days, a.routes, a.dns_policy, a.quota_mb)
        elif a.azione == "reconcile":
            from . import runtime
            try:
                esito = runtime.riconcilia(archivio, a.interface, a.server_key, a.port)
            except runtime.ChiaveEsposta as e:
                print(f"sovereignctl: security gate: {registro.redigi(e)}", file=sys.stderr)
                return 3
            if a.json:
                print(json.dumps(esito, ensure_ascii=False, indent=1))
            else:
                print(f"Riconciliazione su {esito['interfaccia']}: attesi {esito['attesi_nel_runtime']}, trovati {esito['trovati_nel_runtime']}, "
                      f"differenze {esito['differenze']}; peer aggiornati {esito['peer_aggiornati']} in {esito['secondi']} s")
                if not esito["coincide"]:
                    print("  Il runtime non coincide col registro: i peer in attesa sono in ERROR, saga ROLLBACK_REQUIRED (ANC-0280).")
            return 0 if esito["coincide"] else 4  # ANC-0255: 4 = applicato in parte, serve recovery
        elif a.azione == "expire-sweep":  # conteggio sintetico (ANC-0254): niente nomi, niente chiavi
            esito = archivio.scadi()
            print(json.dumps(esito, ensure_ascii=False, indent=1) if a.json else
                  f"Scadenze: {esito['scaduti']} peer scaduti su {esito['con_ttl']} col TTL ancora in corso "
                  f"(controllo delle {esito['controllato_alle']} UTC); dal runtime li toglie la riconciliazione.")
            return 0
        elif a.azione == "list":
            esito = archivio.elenco()
        elif a.azione == "show":
            esito = archivio.mostra(a.id)
        else:
            esito = archivio.transizione(a.id, a.azione)
    except InputNonValido as e:
        print(f"sovereignctl: input non valido: {registro.redigi(e)}", file=sys.stderr)
        return 2
    except (sqlite3.Error, OSError, RuntimeError) as e:
        print(f"sovereignctl: errore del registro ({type(e).__name__}): {registro.redigi(e)}", file=sys.stderr)
        return 1
    if a.json:
        print(json.dumps(esito, ensure_ascii=False, indent=1))
    elif isinstance(esito, list):
        print(f"Peer nel registro: {len(esito)}")
        for p in esito:
            print(f"  {p['id']}  {p['nome']:<20} {p['indirizzo']:<15} {p['stato']:<9} saga {p['saga']}" + (f"  scade {p['scade']}" if p["scade"] else ""))
    else:
        print(f"{esito['id']}  {esito['nome']}  {esito['indirizzo']}  stato {esito['stato']}, saga {esito['saga']}")
        if esito["saga"] == "PENDING_APPLY":
            print("  Il registro e' aggiornato; il runtime WireGuard no: lo allinea la riconciliazione (ANC-0244, ANC-0288).")
    return 0
