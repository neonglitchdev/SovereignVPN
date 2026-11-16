"""Prove di `init --apply` (ANC-0263-0270, ANC-0255, FR-WG-002) con tutto cio' che tocca l'host sostituito.
Uso, da control-plane/: python3 -m unittest discover -s tests"""
import base64, contextlib, io, json, os, pathlib, stat, tempfile, unittest
from unittest import mock

from sovereignctl import __main__ as cli, bootstrap, preflight
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
        # [H38] IPv6 acceso solo su wg0, poi l'ULA del server: il prefisso piu' i 32 bit di 10.66.0.1
        acceso = self.comandi.index(("sysctl", "-qw", "net/ipv6/conf/wg0/disable_ipv6=0"))
        self.assertLess(acceso, self.comandi.index(("ip", "address", "replace", "fdd3:5205:9303::a42:1/64", "dev", "wg0")))

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

    def test_il_manifest_porta_le_immagini_col_digest(self):
        self.apply()
        m = json.loads(self.manifest.read_text())
        self.assertEqual(m["immagini"], bootstrap.dns.immagini())
        self.assertTrue(all(i["digest"].startswith("sha256:") and len(i["digest"]) == 71 for i in m["immagini"]))
        self.assertEqual(len(m["immagini"]), 2)

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

    def test_senza_subnet_nel_file_esce_con_2_senza_toccare_niente(self):
        senza = pathlib.Path(tempfile.mkdtemp()) / "server.toml"
        testo = ESEMPIO.read_text()
        self.assertIn('subnet = "10.66.0.0/24"', testo)
        senza.write_text(testo.replace('subnet = "10.66.0.0/24"', ""))
        for cfg, extra in ((senza, []), (ESEMPIO, ["--subnet", "10.70.0.0/24"])):
            with self.subTest(cfg=cfg.name, extra=extra):
                codice, _, err = esegui(["init", "--apply", "--config", str(cfg), "--wan-interface", "ens3", *extra], BUONI)
                self.assertEqual(codice, 2, err)
                self.assertIn("subnet = ", err)
                self.assertEqual(self.comandi, [])
                self.assertFalse(self.manifest.exists())

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

    def test_verifica_che_non_torna_esce_con_4(self):
        casi = [("sysctl", bootstrap.host, "applica", lambda: {"verificato": False}),
                ("firewall", bootstrap.firewall, "applica", lambda r: {"verificato": False}),
                ("riconciliazione", bootstrap.runtime, "riconcilia", lambda *a, **k: {"coincide": False})]
        for passo, modulo, nome, finto in casi:
            with self.subTest(passo), mock.patch.object(modulo, nome, finto):
                codice, out, _ = self.apply()
                self.assertEqual(codice, 4)
                r = json.loads(out)
                self.assertEqual([p["passo"] for p in r["passi"]], ORDINE[:ORDINE.index(passo)])
                self.assertIn(passo, r["errore"])

    def test_check_e_apply_insieme_rifiutati(self):
        import contextlib, io
        from sovereignctl import __main__ as cli
        with self.assertRaises(SystemExit) as e, contextlib.redirect_stderr(io.StringIO()):
            cli.main(["init", "--check", "--apply"])
        self.assertEqual(e.exception.code, 2)


    def test_chiave_esposta_esce_con_3(self):
        with mock.patch.object(bootstrap.runtime, "riconcilia", side_effect=bootstrap.runtime.ChiaveEsposta("permessi 0o644")):
            codice, _, _ = self.apply()
        self.assertEqual(codice, 3)


class Riavvio(unittest.TestCase):
    """`reconcile` a ogni avvio (FR-NET-007): firewall per primo, mai il preflight, mai una chiave o un manifest nuovi."""
    setUp, tearDown, cmd = Apply.setUp, Apply.tearDown, Apply.cmd

    def rec(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch.object(preflight, "raccogli", side_effect=AssertionError("preflight al riavvio")):
            codice = cli.main(["reconcile", "--config", str(ESEMPIO), *argv])
        return codice, out.getvalue(), err.getvalue()

    def test_firewall_per_primo_niente_chiave_ne_manifest(self):
        codice, out, err = self.rec("--wan-interface", "ens3", "--json")
        self.assertEqual(codice, 0, err)
        self.assertEqual([p["passo"] for p in json.loads(out)["passi"]], ["firewall", "sysctl", "interfaccia", "uscita", "riconciliazione"])
        self.assertNotIn(("wg", "genkey"), self.comandi)
        self.assertFalse(self.chiave.exists())
        self.assertFalse(self.manifest.exists())

    def test_senza_wan_esce_con_2_senza_toccare_niente(self):
        codice, _, err = self.rec()
        self.assertEqual(codice, 2)
        self.assertIn("wan_interface", err)
        self.assertEqual(self.comandi, [])

    def test_chiave_assente_esce_con_4_senza_generarla(self):
        with mock.patch.object(bootstrap.runtime, "riconcilia", side_effect=RuntimeError("chiave del server assente")):
            codice, out, _ = self.rec("--wan-interface", "ens3", "--json")
        self.assertEqual(codice, 4)
        self.assertEqual([p["passo"] for p in json.loads(out)["passi"]], ["firewall", "sysctl", "interfaccia", "uscita"])
        self.assertNotIn(("wg", "genkey"), self.comandi)

    def test_registro_illeggibile_firewall_in_recupero_e_si_ferma(self):
        """T-026 [H41]: col registro corrotto il firewall sale lo stesso ma chiuso ai peer, il runtime non si tocca, codice 4."""
        rotto = pathlib.Path(self._t.name) / "registro.sqlite3"
        rotto.write_bytes(os.urandom(4096))
        applicate = []
        with mock.patch.object(bootstrap.firewall, "applica", lambda r: applicate.append(r) or {"verificato": True}), \
                mock.patch.object(bootstrap.runtime, "riconcilia", side_effect=AssertionError("riconciliazione da un registro rotto")):
            passi, errore = bootstrap.ripristina({"admin_ssh_sources": ["198.51.100.0/24"], "subnet6": "fd00::/64"}, "ens3", db=str(rotto))
        self.assertEqual([p for p, _ in passi], ["firewall", "sysctl", "interfaccia", "uscita"])
        self.assertIn("in recupero", passi[0][1])
        self.assertIn("NEEDS_RECOVERY", str(errore))
        righe = [x.strip() for x in applicate[0].splitlines()]
        avanti = righe.index("type filter hook forward priority filter; policy drop;")
        self.assertEqual(righe[avanti + 1:avanti + 3], ['iifname "wg0" drop', 'oifname "wg0" drop'])  # prima di ogni accept

    def test_registro_leggibile_nessun_recupero(self):
        applicate = []
        with mock.patch.object(bootstrap.firewall, "applica", lambda r: applicate.append(r) or {"verificato": True}):
            passi, errore = bootstrap.ripristina({"admin_ssh_sources": ["198.51.100.0/24"], "subnet6": "fd00::/64"}, "ens3",
                                                 db=str(pathlib.Path(self._t.name) / "assente.sqlite3"))
        self.assertIsNone(errore)
        self.assertEqual(passi[0], ("firewall", True))
        self.assertNotIn('iifname "wg0" drop', [x.strip() for x in applicate[0].splitlines()])

    def test_chiave_esposta_esce_con_3(self):
        with mock.patch.object(bootstrap.runtime, "riconcilia", side_effect=bootstrap.runtime.ChiaveEsposta("permessi 0o644")):
            codice, _, _ = self.rec("--wan-interface", "ens3")
        self.assertEqual(codice, 3)


if __name__ == "__main__":
    unittest.main()
