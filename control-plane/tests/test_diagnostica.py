"""Prove di `sovereignctl diagnostics collect` (ANC-0310-0312, FR-OPS-002, T-025) [H43], con audit e comandi
dell'host sostituiti. Uso, da control-plane/: python3 -m unittest discover -s tests"""
import base64, io, json, os, pathlib, sqlite3, stat, tarfile, tempfile, unittest
from unittest import mock

from sovereignctl import diagnostica, peer, registro, stato
from test_configurazione import ESEMPIO
from test_preflight import esegui

PRIVATA = base64.b64encode(b"s" * 32).decode()
CHIAVE_PEER = base64.b64encode(os.urandom(32)).decode()
GIORNALE = (f"2026-11-15T18:00:00+0000 sovereignctl[1]: syncconf wg0, chiave {CHIAVE_PEER}, peer 10.66.0.7 da 8.8.8.8\n"
            "2026-11-15T18:00:01+0000 sovereignctl[1]: scaricata https://example.org/lista token=abc123segreto\n")
TABELLA = 'table inet sovereignvpn {\n chain forward {\n  iifname "wg0" ip saddr 10.66.0.7 ip daddr != { 10.66.0.0/24 } drop\n }\n}\n'


class Diagnostica(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory(); t = pathlib.Path(self._t.name)
        self.out, self.db, self.chiave = t / "diagnostica", str(t / "registro.sqlite3"), t / "wg-server.key"
        self.chiave.write_text(PRIVATA + "\n"); self.chiave.chmod(0o600)
        a = peer.Archivio(self.db)
        for nome in ("telefono di Anna", "portatile"):
            a.aggiungi(nome, base64.b64encode(os.urandom(32)).decode(), "10.66.0.0/24")
        a.db.close()
        self.risposte = {("wg", "--version"): (0, "wireguard-tools v1.0.20210914\n"), ("nft", "--version"): (0, "nftables v1.0.9\n"),
                         ("docker", "version", "--format", "{{.Server.Version}}"): (0, "27.3.1\n"),
                         ("nft", "list", "table", "inet", "sovereignvpn"): (0, TABELLA)}
        self.patch = [mock.patch.object(diagnostica.stato, "_leggi", lambda *a, **k: self.risposte.get(a, (0, GIORNALE) if a[0] == "journalctl" else (1, ""))),
                      mock.patch.object(diagnostica.audit, "esegui_controlli", lambda cfg, db: [{"id": "AUD-01", "stato": "PASS", "evidenza": "release 14.0.0"}]),
                      mock.patch.object(diagnostica.runtime, "CHIAVE_SERVER", str(self.chiave))]
        for p in self.patch:
            p.start()

    def tearDown(self):
        for p in self.patch:
            p.stop()
        self._t.cleanup()

    def raccogli(self, *extra):
        return esegui(["diagnostics", "collect", "--config", str(ESEMPIO), "--db", self.db, "--out", str(self.out), *extra])

    def apri(self):
        (archivio,) = self.out.iterdir()
        with tarfile.open(archivio) as tar:
            return archivio, {m.name: tar.extractfile(m).read().decode() for m in tar.getmembers()}

    def test_minimal_sanitizzato_0600_e_a_schermo_solo_percorso_e_checksum(self):
        codice, out, err = self.raccogli("--json")
        self.assertEqual(codice, 0, err)
        archivio, file = self.apri()
        r = json.loads(out)
        self.assertEqual(set(r), {"percorso", "checksum", "modalita", "file"})
        self.assertEqual((r["percorso"], r["modalita"]), (str(archivio), "minimal"))
        self.assertEqual((stat.S_IMODE(archivio.stat().st_mode), stat.S_IMODE(self.out.stat().st_mode)), (0o600, 0o700))
        import hashlib
        self.assertEqual(r["checksum"], "sha256:" + hashlib.sha256(archivio.read_bytes()).hexdigest())
        self.assertEqual(set(file), {"configurazione.json", "versioni.json", "audit.json", "peer-per-stato.json", "manifest-diagnostica.json"})
        cfg = json.loads(file["configurazione.json"])
        self.assertEqual((cfg["endpoint"], cfg["admin_ssh_sources"]), ("[REDATTO]", "[REDATTO]"))
        self.assertEqual(cfg["mtu"], 1420)
        self.assertEqual(json.loads(file["peer-per-stato.json"]), {"PENDING": 2})  # conteggi, mai nomi
        tutto = "".join(file.values())
        for vietato in ("vpn.example.org", "198.51.100", "Anna", "portatile", PRIVATA, "journalctl"):
            self.assertNotIn(vietato, tutto)
        manifest = json.loads(file["manifest-diagnostica.json"])
        self.assertEqual({f["nome"] for f in manifest["file"]}, set(file) - {"manifest-diagnostica.json"})

    def test_extended_senza_conferma_esce_con_2_e_non_scrive(self):
        codice, _, err = self.raccogli("--extended")
        self.assertEqual(codice, 2)
        self.assertIn("--conferma", err)
        self.assertFalse(self.out.exists())

    def test_extended_redige_chiavi_ip_url_token_e_indirizzi_vpn(self):
        codice, _, err = self.raccogli("--extended", "--conferma")
        self.assertEqual(codice, 0, err)
        _, file = self.apri()
        self.assertIn("log-unita.txt", file)
        log, tabella = file["log-unita.txt"], file["firewall.txt"]
        for vietato in (CHIAVE_PEER, "8.8.8.8", "10.66.0.7", "https://example.org", "abc123segreto"):
            self.assertNotIn(vietato, log + tabella)
        self.assertIn("[INDIRIZZO VPN]", tabella)
        self.assertIn("syncconf wg0", log)  # il resto del log resta leggibile

    def test_lo_scan_ferma_un_segreto_sfuggito_alla_redazione(self):
        """T-025: se la redazione si rompe, lo scan sul risultato ferma tutto (3) e non scrive niente."""
        with mock.patch.object(diagnostica.registro, "redigi", lambda t: str(t)), \
                mock.patch.object(diagnostica.audit, "esegui_controlli", lambda cfg, db: [{"evidenza": f"chiave {PRIVATA}"}]):
            codice, _, err = self.raccogli()
        self.assertEqual(codice, 3)
        self.assertIn("audit.json", err)
        self.assertNotIn(PRIVATA, err)
        self.assertFalse(self.out.exists() and any(self.out.iterdir()))

    def test_due_raccolte_nello_stesso_secondo_non_si_sovrascrivono(self):
        istante = diagnostica.datetime.datetime(2026, 11, 15, 18, 0, 0, tzinfo=diagnostica.datetime.timezone.utc)
        orologio = mock.Mock(wraps=diagnostica.datetime.datetime); orologio.now = lambda tz=None: istante
        with mock.patch.object(diagnostica.datetime, "datetime", orologio):
            self.assertEqual(self.raccogli()[0], 0)
            self.assertEqual(self.raccogli()[0], 0)
        self.assertEqual(sorted(p.name for p in self.out.iterdir()),
                         ["diagnostica-20261115T180000Z-minimal-2.tar.gz", "diagnostica-20261115T180000Z-minimal.tar.gz"])

    def test_scansiona(self):
        self.assertEqual(diagnostica.scansiona({"a": f"x {CHIAVE_PEER} y".encode(), "b": b"sha256:" + b"ab" * 32}), ["a"])
        self.assertEqual(diagnostica.scansiona({"c": b"scrypt$abcdefghijklmnopqrstuvwxyz"}), ["c"])
        self.assertEqual(diagnostica.scansiona({"d": PRIVATA[:20].encode()}, chiave_server=PRIVATA), [])
        self.assertEqual(diagnostica.scansiona({"e": b"ok"}), [])

    def test_registro_corrotto_conteggio_dichiarato(self):
        pathlib.Path(self.db).write_bytes(os.urandom(4096))
        codice, _, err = self.raccogli()
        self.assertEqual(codice, 0, err)
        _, file = self.apri()
        self.assertEqual(json.loads(file["peer-per-stato.json"]), {"registro illeggibile": "DatabaseError"})


if __name__ == "__main__":
    unittest.main()
