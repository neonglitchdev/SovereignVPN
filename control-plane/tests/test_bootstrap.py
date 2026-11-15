"""Prove di `init --apply` (ANC-0263-0270, ANC-0255, FR-WG-002) con tutto cio' che tocca l'host sostituito.
Uso, da control-plane/: python3 -m unittest discover -s tests"""
import base64, json, os, pathlib, stat, tempfile, unittest
from unittest import mock

from sovereignctl import bootstrap, preflight
from test_configurazione import ESEMPIO
from test_preflight import BUONI, con, esegui

CHIAVE = base64.b64encode(b"k" * 32).decode()
ORDINE = ["manifest", "chiave del server", "interfaccia", "sysctl", "firewall", "riconciliazione"]


class Apply(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory(); t = pathlib.Path(self._t.name)
        self.chiave, self.manifest = t / "etc/wg-server.key", t / "var/manifest.json"
        self.patch = [mock.patch.object(bootstrap, "MANIFEST", str(self.manifest)),
                      mock.patch.object(bootstrap.runtime, "CHIAVE_SERVER", str(self.chiave)),
                      mock.patch.object(bootstrap, "_cmd", self.cmd),
                      mock.patch.object(bootstrap.host, "applica", lambda: {"verificato": True}),
                      mock.patch.object(bootstrap.firewall, "applica", lambda r: {"verificato": True}),
                      mock.patch.object(bootstrap.runtime, "riconcilia", lambda *a, **k: {"coincide": True}),
                      mock.patch.object(bootstrap.peer, "Archivio", lambda db: None)]
        for p in self.patch:
            p.start()
        self.comandi = []

    def tearDown(self):
        for p in self.patch:
            p.stop()
        self._t.cleanup()

    def cmd(self, *a, ingresso=None):
        self.comandi.append(a)
        if a[:3] == ("ip", "link", "show"):
            raise RuntimeError("ip link show non riuscito")  # interfaccia assente: va creata
        return CHIAVE + "\n" if a == ("wg", "genkey") else ""

    def apply(self, *extra, fatti=BUONI):
        return esegui(["init", "--apply", "--config", str(ESEMPIO), "--wan-interface", "ens3", "--json", *extra], fatti)

    def test_passi_nell_ordine_del_workflow(self):
        codice, out, err = self.apply()
        self.assertEqual(codice, 0, err)
        r = json.loads(out)
        self.assertEqual([p["passo"] for p in r["passi"]], ORDINE)
        self.assertIn(("ip", "link", "add", "wg0", "type", "wireguard"), self.comandi)
        self.assertIn(("ip", "address", "replace", "10.66.0.1/24", "dev", "wg0"), self.comandi)

    def test_chiave_0600_mai_stampata_e_mai_sovrascritta(self):
        codice, out, err = self.apply()
        self.assertEqual(codice, 0, err)
        self.assertEqual(stat.S_IMODE(self.chiave.stat().st_mode), 0o600)
        self.assertEqual(self.chiave.read_text().strip(), CHIAVE)
        self.assertNotIn(CHIAVE, out + err)
        self.chiave.write_text("chiave-di-prima\n")
        self.apply()
        self.assertEqual(self.chiave.read_text(), "chiave-di-prima\n")
        self.assertEqual(sum(1 for c in self.comandi if c == ("wg", "genkey")), 1)

    def test_id_dell_installazione_conservato(self):
        self.apply(); primo = json.loads(self.manifest.read_text())["id_installazione"]
        self.apply(); secondo = json.loads(self.manifest.read_text())["id_installazione"]
        self.assertEqual(primo, secondo)

    def test_preflight_fallito_non_tocca_niente(self):
        codice, _, err = self.apply(fatti=con(os=("ubuntu", "22.04")))
        self.assertEqual(codice, 1)
        self.assertEqual(self.comandi, [])
        self.assertFalse(self.manifest.exists())

    def test_senza_wan_esce_con_2(self):
        codice, _, err = esegui(["init", "--apply", "--config", str(ESEMPIO)], BUONI)
        self.assertEqual(codice, 2)
        self.assertIn("--wan-interface", err)

    def test_wan_non_valida_esce_con_2_senza_toccare_niente(self):
        codice, _, err = self.apply_wan("ens3;drop")
        self.assertEqual(codice, 2, err)
        self.assertIn("--wan-interface", err)
        self.assertEqual(self.comandi, [])
        self.assertFalse(self.manifest.exists())
        self.assertFalse(self.chiave.exists())

    def apply_wan(self, wan):
        return esegui(["init", "--apply", "--config", str(ESEMPIO), "--wan-interface", wan], BUONI)

    def test_errore_a_meta_esce_con_4_e_dice_i_passi_fatti(self):
        with mock.patch.object(bootstrap.firewall, "applica", side_effect=RuntimeError("nft -f non riuscito")):
            codice, out, _ = self.apply()
        self.assertEqual(codice, 4)
        r = json.loads(out)
        self.assertEqual([p["passo"] for p in r["passi"]], ORDINE[:4])
        self.assertIn("nft -f", r["errore"])

    def test_check_e_apply_insieme_rifiutati(self):
        import contextlib, io
        from sovereignctl import __main__ as cli
        with self.assertRaises(SystemExit) as e, contextlib.redirect_stderr(io.StringIO()):
            cli.main(["init", "--check", "--apply"])
        self.assertEqual(e.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
