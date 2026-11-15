"""Prove del registro dei peer (FR-PEER-001/002/003/006, ANC-0237/0238/0244/0288, H1, H2).
Uso, da control-plane/: python3 -m unittest discover -s tests"""
import base64, datetime, json, os, pathlib, sqlite3, stat, subprocess, sys, tempfile, unittest

from sovereignctl import peer
from test_preflight import esegui

QUI = pathlib.Path(__file__).resolve().parents[1]


def chiave():
    return base64.b64encode(os.urandom(32)).decode()


class Base(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory(prefix="registro-")
        self.db = os.path.join(self._t.name, "registro.sqlite3")

    def tearDown(self):
        self._t.cleanup()

    def cli(self, *argomenti):
        return esegui(["peer", *argomenti[:1], "--db", self.db, *argomenti[1:]])

    def add(self, nome, k=None, *extra):
        codice, out, err = self.cli("add", "--name", nome, "--public-key", k or chiave(), "--json", *extra)
        return codice, (json.loads(out) if codice == 0 else None), err

    def audit(self):
        db = sqlite3.connect(self.db)
        return [json.loads(r[0]) for r in db.execute("SELECT evento FROM audit ORDER BY n")]

    def forza(self, id_peer, stato):  # simula la riconciliazione, che arriva nel pezzo successivo
        db = sqlite3.connect(self.db)
        db.execute("UPDATE peer SET stato = ?, saga = 'APPLIED' WHERE id = ?", (stato, id_peer)); db.commit()


class Aggiunta(Base):
    def test_primo_peer_dopo_il_server_pending_e_saga_da_applicare(self):
        codice, p, err = self.add("Telefono")
        self.assertEqual(codice, 0, err)
        self.assertEqual((p["indirizzo"], p["stato"], p["saga"]), ("10.66.0.2", "PENDING", "PENDING_APPLY"))
        self.assertFalse(p["chiave_privata_sul_server"])
        self.assertEqual(self.add("Portatile")[1]["indirizzo"], "10.66.0.3")
        self.assertEqual(stat.S_IMODE(os.stat(self.db).st_mode), 0o600)

    def test_nome_duplicato_anche_con_maiuscole_e_spazi(self):
        self.add("Telefono di casa")
        codice, _, err = self.add("  telefono   DI casa ")
        self.assertEqual(codice, 2)
        self.assertIn("gia' in uso", err)
        self.assertEqual(self.audit()[-1]["outcome"], "denied")

    def test_chiave_duplicata(self):
        k = chiave(); self.add("uno", k)
        codice, _, err = self.add("due", k)
        self.assertEqual(codice, 2)
        self.assertIn("--public-key", err)

    def test_chiavi_non_valide(self):
        for k in ("non-base64!!", base64.b64encode(os.urandom(31)).decode(), base64.b64encode(os.urandom(33)).decode()):
            with self.subTest(k=k):
                codice, _, err = self.add(f"p{len(k)}", k)
                self.assertEqual(codice, 2)
                self.assertIn("--public-key", err)

    def test_nomi_non_validi(self):
        for nome in ("", "../etc/passwd", "a/b", "x" * 65, "nome;rm"):
            with self.subTest(nome=nome):
                self.assertEqual(self.add(nome)[0], 2)

    def test_ttl(self):
        self.assertEqual(self.add("zero", None, "--ttl-days", "0")[0], 2)
        self.assertEqual(self.add("troppo", None, "--ttl-days", "366")[0], 2)
        codice, p, _ = self.add("trenta", None, "--ttl-days", "30")
        self.assertEqual(codice, 0)
        self.assertTrue(p["scade"].endswith("Z"))

    def test_subnet_esaurita(self):
        cfg = os.path.join(self._t.name, "server.toml")
        pathlib.Path(cfg).write_text('schema_version = 1\nendpoint = "vpn.example.org"\nsubnet = "10.70.0.0/29"\n')
        indirizzi = [self.add(f"p{i}", None, "--config", cfg)[1]["indirizzo"] for i in range(5)]
        self.assertEqual(indirizzi, [f"10.70.0.{i}" for i in range(2, 7)])
        codice, _, err = self.add("sesto", None, "--config", cfg)
        self.assertEqual(codice, 2)
        self.assertIn("SUBNET_EXHAUSTED", err)

    def test_allocazione_concorrente_non_duplica(self):
        """FR-PEER-001: 12 processi nello stesso istante, 12 indirizzi diversi."""
        self.add("primo")  # crea lo schema prima della corsa
        processi = [subprocess.Popen([sys.executable, "-m", "sovereignctl", "peer", "add", "--db", self.db, "--name", f"corsa{i}",
                                      "--public-key", chiave(), "--json"], cwd=QUI, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    for i in range(12)]
        esiti = [(p.wait(timeout=60), p.stdout.read(), p.stderr.read()) for p in processi]
        self.assertEqual([c for c, _, _ in esiti], [0] * 12, [e for _, _, e in esiti if e])
        indirizzi = [json.loads(o)["indirizzo"] for _, o, _ in esiti]
        self.assertEqual(len(set(indirizzi)), 12)


# L'oracolo della matrice, scritto dai requisiti e NON preso dal codice: FR-PEER-006 (sospensione reversibile, revoca
# irreversibile), H1 (nessun REVOKED_PENDING). Le transizioni verso ACTIVE/ERROR/EXPIRED le fa la riconciliazione.
ATTESE = {("PENDING", "revoke"): "REVOKED", ("ACTIVE", "suspend"): "SUSPENDED", ("ACTIVE", "revoke"): "REVOKED",
          ("SUSPENDED", "resume"): "ACTIVE", ("SUSPENDED", "revoke"): "REVOKED", ("EXPIRED", "revoke"): "REVOKED",
          ("ERROR", "revoke"): "REVOKED"}


class Stati(Base):
    def test_matrice_completa_delle_transizioni(self):
        """Ogni (stato, azione) fuori da TRANSIZIONI e' respinta e lascia un evento denied; quelle dentro passano."""
        for stato in peer.STATI:
            for azione in ("suspend", "resume", "revoke"):
                with self.subTest(stato=stato, azione=azione):
                    _, p, _ = self.add(f"{stato}-{azione}")
                    self.forza(p["id"], stato)
                    codice, out, err = self.cli(azione, p["id"], "--json")
                    atteso = ATTESE.get((stato, azione))
                    if atteso:
                        self.assertEqual(codice, 0, err)
                        self.assertEqual((json.loads(out)["stato"], json.loads(out)["saga"]), (atteso, "PENDING_APPLY"))
                    else:
                        self.assertEqual(codice, 2)
                        self.assertEqual(self.audit()[-1]["outcome"], "denied")

    def test_revoca_irreversibile_e_non_completata_finche_non_applicata(self):
        _, p, _ = self.add("da revocare")
        self.forza(p["id"], "ACTIVE")
        codice, out, _ = self.cli("revoke", p["id"], "--json")
        r = json.loads(out)
        self.assertEqual((r["stato"], r["saga"]), ("REVOKED", "PENDING_APPLY"))  # ANC-0288: non ancora completata
        self.assertTrue(r["revocato"].endswith("Z"))
        for azione in ("resume", "suspend", "revoke"):
            codice, _, err = self.cli(azione, p["id"])
            self.assertEqual(codice, 2)
        self.assertIn("irreversibile", err)

    def test_sospensione_reversibile(self):
        _, p, _ = self.add("sospendibile")
        self.forza(p["id"], "ACTIVE")
        self.assertEqual(json.loads(self.cli("suspend", p["id"], "--json")[1])["stato"], "SUSPENDED")
        self.assertEqual(json.loads(self.cli("resume", p["id"], "--json")[1])["stato"], "ACTIVE")


class Lettura(Base):
    def test_show_e_list_senza_segreti_e_id_sbagliati(self):
        _, p, _ = self.add("telefono")
        codice, out, _ = self.cli("list", "--json")
        self.assertEqual(codice, 0)
        self.assertNotIn("chiave_pubblica", json.loads(out)[0])  # metadati non sensibili (ANC-0254)
        self.assertEqual(self.cli("show", "non-un-uuid")[0], 2)
        codice, _, err = self.cli("show", "00000000-0000-4000-8000-000000000000")
        self.assertEqual(codice, 2)
        self.assertIn("PEER_NOT_FOUND", err)

    def test_audit_coi_campi_di_ANC_0232_e_id_registrati(self):
        _, p, _ = self.add("telefono")
        e = self.audit()[-1]
        self.assertEqual(set(e), {"id", "timestamp", "actor", "action", "target", "outcome", "request_id", "reason"})
        self.assertEqual((e["action"], e["target"], e["outcome"]), ("peer.add", p["id"], "success"))
        db = sqlite3.connect(self.db)
        self.assertEqual(db.execute("SELECT count(*) FROM id_usati WHERE id = ?", (p["id"],)).fetchone()[0], 1)

    def test_schema_sconosciuto_esce_con_1(self):
        self.add("telefono")
        db = sqlite3.connect(self.db); db.execute("UPDATE schema SET versione = 99"); db.commit()
        codice, _, err = self.cli("list")
        self.assertEqual(codice, 1)
        self.assertIn("migrazione", err)


class Scadenze(Base):
    """FR-PEER-005 con l'orologio controllato: `scadi` riceve l'istante dalle prove; il comando no (un --now sulla riga
    di comando permetterebbe di spostare l'orologio indietro e non far scadere nessuno)."""
    MAI = "2999-01-01T00:00:00Z"

    def test_scade_all_istante_giusto_e_una_volta_sola(self):
        _, p, _ = self.add("ospite", None, "--ttl-days", "1")
        s = p["scade"]
        un_secondo_prima = (datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
                            - datetime.timedelta(seconds=1)).isoformat(timespec="seconds").replace("+00:00", "Z")
        a = peer.Archivio(self.db)
        self.assertEqual(a.scadi(un_secondo_prima), {"scaduti": 0, "con_ttl": 1, "controllato_alle": un_secondo_prima})
        self.assertEqual(a.mostra(p["id"])["stato"], "PENDING")
        self.assertEqual(a.scadi(s), {"scaduti": 1, "con_ttl": 1, "controllato_alle": s})
        q = a.mostra(p["id"])
        self.assertEqual((q["stato"], q["saga"]), ("EXPIRED", "PENDING_APPLY"))
        self.assertEqual(a.scadi(s)["scaduti"], 0)  # idempotente: rifarla dopo un riavvio non cambia niente
        e = self.audit()[-1]
        self.assertEqual((e["action"], e["outcome"], e["target"]), ("peer.expire", "success", p["id"]))

    def test_scaduto_non_si_riattiva_ma_si_revoca(self):
        _, p, _ = self.add("ospite", None, "--ttl-days", "1")
        self.forza(p["id"], "SUSPENDED")
        peer.Archivio(self.db).scadi(self.MAI)
        self.assertEqual(self.cli("resume", p["id"])[0], 2)
        codice, out, err = self.cli("revoke", p["id"], "--json")
        self.assertEqual(codice, 0, err)
        self.assertEqual(json.loads(out)["stato"], "REVOKED")

    def test_revocati_e_senza_ttl_non_scadono(self):
        _, r, _ = self.add("revocato", None, "--ttl-days", "1")
        self.forza(r["id"], "REVOKED")
        self.add("fisso")
        _, a, _ = self.add("attivo", None, "--ttl-days", "1")
        self.forza(a["id"], "ACTIVE")
        self.assertEqual(peer.Archivio(self.db).scadi(self.MAI)["scaduti"], 1)
        stati = {x["nome"]: x["stato"] for x in peer.Archivio(self.db).elenco()}
        self.assertEqual(stati, {"revocato": "REVOKED", "fisso": "PENDING", "attivo": "EXPIRED"})

    def test_il_comando_usa_l_orologio_vero_e_non_ne_accetta_un_altro(self):
        self.add("ospite", None, "--ttl-days", "1")
        codice, out, err = self.cli("expire-sweep", "--json")
        self.assertEqual(codice, 0, err)
        r = json.loads(out)
        self.assertEqual((r["scaduti"], r["con_ttl"]), (0, 1))  # scade fra un giorno: adesso no
        with self.assertRaises(SystemExit) as uscita:
            self.cli("expire-sweep", "--now", self.MAI)
        self.assertEqual(uscita.exception.code, 2)



class Migrazione(Base):
    """Cap. 8: schema versionato, migrazione esplicita, copia del registro prima di toccarlo."""
    V1 = ["CREATE TABLE schema (versione INTEGER NOT NULL)", "INSERT INTO schema VALUES (1)",
          """CREATE TABLE peer (id TEXT PRIMARY KEY, nome TEXT NOT NULL, nome_chiave TEXT NOT NULL UNIQUE,
             chiave_pubblica TEXT NOT NULL UNIQUE, indirizzo TEXT NOT NULL UNIQUE, stato TEXT NOT NULL, saga TEXT NOT NULL,
             creato TEXT NOT NULL, scade TEXT, revocato TEXT, sospeso TEXT)""",
          "CREATE TABLE id_usati (id TEXT PRIMARY KEY)", "CREATE TABLE audit (n INTEGER PRIMARY KEY AUTOINCREMENT, evento TEXT NOT NULL)",
          "INSERT INTO peer VALUES ('3f2a7d9e-0000-4000-8000-000000000001', 'vecchio', 'vecchio', 'K', '10.66.0.2', 'ACTIVE', 'APPLIED', '2026-11-01T00:00:00Z', NULL, NULL, NULL)"]

    def test_registro_nuovo_e_gia_alla_versione_2(self):
        peer.Archivio(self.db).db.close()
        db = sqlite3.connect(self.db)
        self.assertEqual(db.execute("SELECT versione FROM schema").fetchone()[0], peer.VERSIONE_SCHEMA_DB)
        self.assertIn("rotte", [r[1] for r in db.execute("PRAGMA table_info(peer)")])
        self.assertFalse(os.path.exists(self.db + ".schema1.bak"))

    def test_da_1_a_2_con_copia_prima_e_peer_intatti(self):
        db = sqlite3.connect(self.db)
        for s in self.V1:
            db.execute(s)
        db.commit(); db.close()
        a = peer.Archivio(self.db)
        p = a.mostra("3f2a7d9e-0000-4000-8000-000000000001")
        self.assertEqual((p["nome"], p["stato"], p["rotte"]), ("vecchio", "ACTIVE", None))
        self.assertEqual(a.db.execute("SELECT versione FROM schema").fetchone()[0], peer.VERSIONE_SCHEMA_DB)
        self.assertIsNone(p["politica_dns"])  # tutti i passi applicati, fino all'ultimo
        copia = self.db + ".schema1.bak"
        self.assertEqual(oct(os.stat(copia).st_mode & 0o777), "0o600")
        vecchia = sqlite3.connect(copia)
        self.assertEqual((vecchia.execute("SELECT versione FROM schema").fetchone()[0],
                          vecchia.execute("SELECT nome FROM peer").fetchone()[0]), (1, "vecchio"))
        self.assertNotIn("rotte", [r[1] for r in vecchia.execute("PRAGMA table_info(peer)")])
        self.assertEqual(self.audit()[-1]["action"], "registro.migrate")
        a.db.close()
        peer.Archivio(self.db).db.close()  # riaprire non rifa' niente
        self.assertEqual(sum(1 for e in self.audit() if e["action"] == "registro.migrate"), 1)

    def test_schema_piu_nuovo_rifiutato(self):
        peer.Archivio(self.db).db.close()
        db = sqlite3.connect(self.db); db.execute("UPDATE schema SET versione = ?", (peer.VERSIONE_SCHEMA_DB + 1,)); db.commit(); db.close()
        with self.assertRaises(RuntimeError):
            peer.Archivio(self.db)


class Rotte(Base):
    """FR-PEER-008 / FR-WG-007: rotte per peer validate e salvate; senza, full-tunnel."""
    def test_rotte_canoniche_salvate_e_quelle_sbagliate_rifiutate(self):
        codice, p, err = self.add("ufficio", None, "--routes", "192.168.10.0/24, 172.16.0.0/16,192.168.10.0/24")
        self.assertEqual(codice, 0, err)
        self.assertEqual(json.loads(p["rotte"]), ["172.16.0.0/16", "192.168.10.0/24"])
        self.assertIsNone(self.add("tutto")[1]["rotte"])
        self.assertEqual(peer.limiti_rotte(self.db), [(p["indirizzo"], ["172.16.0.0/16", "192.168.10.0/24"])])
        self.forza(p["id"], "REVOKED")
        self.assertEqual(peer.limiti_rotte(self.db), [])  # un revocato non ha piu' regole
        self.assertEqual(peer.limiti_rotte(self.db + ".assente"), [])
        for sbagliate in ("10.66.0.0/25", "0.0.0.0/0", "192.168.1.1/24", "fd00::/64", "non-una-rete",
                          ",".join(f"10.{i}.0.0/16" for i in range(100, 133))):
            with self.subTest(sbagliate=sbagliate[:30]):
                self.assertEqual(self.add("x" + str(abs(hash(sbagliate)) % 1000), None, "--routes", sbagliate)[0], 2)



class PoliticaDns(Base):
    def test_interno_di_base_libero_letto_dal_firewall_e_il_resto_rifiutato(self):
        _, p, _ = self.add("libero", None, "--dns-policy", "libero")
        _, q, _ = self.add("interno", None, "--dns-policy", "interno")
        self.assertEqual((p["politica_dns"], q["politica_dns"]), ("libero", None))
        self.assertEqual(peer.dns_liberi(self.db), [p["indirizzo"]])
        self.forza(p["id"], "REVOKED")
        self.assertEqual(peer.dns_liberi(self.db), [])
        with self.assertRaises(SystemExit):
            self.add("altro", None, "--dns-policy", "tutto")
        with self.assertRaises(peer.InputNonValido):  # anche chi chiama l'Archivio senza la CLI
            peer.Archivio(self.db).aggiungi("diretto", chiave(), "10.66.0.0/24", politica_dns="tutto")


class Quota(Base):
    def test_byte_usati_presi_al_massimo_e_salvati(self):
        _, p, _ = self.add("limitato", None, "--quota-mb", "1")
        self.assertEqual(peer.quote(self.db), [(p["indirizzo"], 1048576, 0)])
        self.assertEqual(peer.quote(self.db, {p["indirizzo"]: 500}, salva=True), [(p["indirizzo"], 1048576, 500)])
        self.assertEqual(peer.quote(self.db, {p["indirizzo"]: 100}), [(p["indirizzo"], 1048576, 500)])  # mai indietro
        self.assertEqual(self.add("troppo", None, "--quota-mb", "0")[0], 2)

if __name__ == "__main__":
    unittest.main()
