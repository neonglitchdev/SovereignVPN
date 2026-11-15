"""Prove di `sovereignctl profile export` (FR-PEER-007, FR-WG-004, FR-WG-005) con `wg pubkey` sostituito.
Uso, da control-plane/: python3 -m unittest discover -s tests"""
import base64, hashlib, json, os, pathlib, sqlite3, stat, tempfile, unittest
from unittest import mock

from sovereignctl import peer, profilo
from test_configurazione import ESEMPIO
from test_preflight import esegui

PRIVATA = base64.b64encode(b"s" * 32).decode()
PUB = base64.b64encode(b"p" * 32).decode()


class Export(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory(); t = pathlib.Path(self._t.name)
        self.chiave, self.db, self.out = t / "wg-server.key", str(t / "registro.sqlite3"), t / "export"
        self.chiave.write_text(PRIVATA + "\n"); self.chiave.chmod(0o600)
        a = peer.Archivio(self.db)
        self.p = a.aggiungi("telefono di Anna", base64.b64encode(os.urandom(32)).decode(), "10.66.0.0/24")
        a.db.close()
        self.patch = mock.patch.object(profilo.runtime, "_wg", self.wg)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self._t.cleanup()

    def wg(self, *argomenti, ingresso=None):
        self.assertEqual((argomenti, ingresso), (("pubkey",), PRIVATA + "\n"))  # la privata solo su stdin
        return 0, PUB + "\n", ""

    def export(self, *extra, id_peer=None, config=ESEMPIO):
        return esegui(["profile", "export", id_peer or self.p["id"], "--config", str(config), "--db", self.db,
                       "--server-key", str(self.chiave), "--out", str(self.out), *extra])

    def stato(self, s):
        db = sqlite3.connect(self.db); db.execute("UPDATE peer SET stato = ?", (s,)); db.commit(); db.close()

    def test_full_tunnel_senza_segreti_0600_e_a_schermo_solo_percorso_e_checksum(self):
        codice, out, err = self.export("--conferma", "--json")
        self.assertEqual(codice, 0, err)
        r = json.loads(out)
        f = pathlib.Path(r["percorso"])
        self.assertEqual((f.parent, f.name), (self.out, f"{self.p['id']}.conf"))
        self.assertEqual((stat.S_IMODE(f.stat().st_mode), stat.S_IMODE(self.out.stat().st_mode)), (0o600, 0o700))
        testo = f.read_text()
        self.assertEqual(r["checksum"], "sha256:" + hashlib.sha256(testo.encode()).hexdigest())
        righe = testo.splitlines()
        for attesa in ("PrivateKey = <CHIAVE_PRIVATA_DEL_DISPOSITIVO>", "Address = 10.66.0.2/32", "DNS = 10.66.0.1",
                       "MTU = 1420", f"PublicKey = {PUB}", "Endpoint = vpn.example.org:51820", "AllowedIPs = 0.0.0.0/0, ::/0"):
            self.assertIn(attesa, righe)
        self.assertTrue(righe[1].startswith("# SEGRETI: nessuno"))
        self.assertFalse(any(x.startswith("PersistentKeepalive") for x in righe))  # FR-WG-005: di base spento
        self.assertNotIn(PRIVATA, testo + out + err)
        self.assertNotIn("AllowedIPs", out + err)  # il contenuto non va a schermo
        e = [json.loads(x[0]) for x in sqlite3.connect(self.db).execute("SELECT evento FROM audit ORDER BY n")][-1]
        self.assertEqual((e["action"], e["target"]), ("profile.export", self.p["id"]))

    def test_senza_conferma_niente(self):
        codice, _, err = self.export()
        self.assertEqual(codice, 2)
        self.assertIn("--conferma", err)
        self.assertFalse(self.out.exists())

    def test_revocato_e_scaduto_non_si_esportano(self):
        for s in ("REVOKED", "EXPIRED"):
            with self.subTest(s):
                self.stato(s)
                self.assertEqual(self.export("--conferma")[0], 2)
                self.assertFalse(self.out.exists())

    def test_keepalive_solo_se_chiesto_e_nei_limiti(self):
        self.assertEqual(self.export("--conferma", "--keepalive", "25")[0], 0)
        self.assertIn("PersistentKeepalive = 25", (self.out / f"{self.p['id']}.conf").read_text().splitlines())
        self.assertEqual(self.export("--conferma", "--keepalive", "0")[0], 2)

    def test_endpoint_ipv6_fra_parentesi(self):
        config = pathlib.Path(self._t.name) / "server.toml"
        config.write_text(ESEMPIO.read_text().replace('endpoint = "vpn.example.org"', 'endpoint = "2001:db8::1"'))
        self.assertEqual(self.export("--conferma", config=config)[0], 0)
        self.assertIn("Endpoint = [2001:db8::1]:51820", (self.out / f"{self.p['id']}.conf").read_text().splitlines())

    def test_chiave_del_server_leggibile_da_altri_esce_con_3(self):
        self.chiave.chmod(0o644)
        self.assertEqual(self.export("--conferma")[0], 3)
        self.assertFalse(self.out.exists())



class SplitTunnel(unittest.TestCase):
    def test_con_le_rotte_il_profilo_e_split_tunnel_con_la_vpn(self):
        p = {"id": "x", "nome": "ufficio", "indirizzo": "10.66.0.2", "scade": None, "rotte": '["192.168.10.0/24"]'}
        righe = profilo.componi(p, {"endpoint": "vpn.example.org"}, PUB).splitlines()
        self.assertIn("AllowedIPs = 192.168.10.0/24, 10.66.0.0/24", righe)
        self.assertIn("split-tunnel", righe[0])
        righe = profilo.componi({**p, "rotte": None}, {"endpoint": "vpn.example.org"}, PUB).splitlines()
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", righe)


if __name__ == "__main__":
    unittest.main()
