"""Prove della riconciliazione registro -> runtime WireGuard, con un `wg` finto (tests/wg_finto.py).
La prova con il `wg` vero e un'interfaccia vera gira sul runner Linux: tests/prova_wg_vero.sh.
Uso, da control-plane/: python3 -m unittest discover -s tests"""
import base64, json, os, pathlib, sqlite3, stat, sys, tempfile, unittest
from unittest import mock

from test_peer import Base, chiave

FINTO = pathlib.Path(__file__).resolve().parent / "wg_finto.py"


class Riconciliazione(Base):
    def setUp(self):
        super().setUp()
        t = pathlib.Path(self._t.name)
        bin_ = t / "bin"; bin_.mkdir()
        self.stato, self.reg, self.modo = t / "wg-stato.json", t / "wg-registro.txt", t / "wg-modo.txt"
        (bin_ / "wg").write_text(f"#!/bin/sh\nWG_FINTO_STATO='{self.stato}' WG_FINTO_REGISTRO='{self.reg}' WG_FINTO_MODO_FILE='{self.modo}' "
                                 f"exec {sys.executable} {FINTO} \"$@\"\n"); (bin_ / "wg").chmod(0o755)
        self.chiave_server = base64.b64encode(os.urandom(32)).decode()
        self.file_chiave = t / "wg-server.key"
        self.file_chiave.write_text(self.chiave_server + "\n"); self.file_chiave.chmod(0o600)
        self.env = mock.patch.dict(os.environ, {"PATH": f"{bin_}:{os.environ['PATH']}"})
        self.env.start()

    def tearDown(self):
        self.env.stop(); super().tearDown()

    def riconcilia(self, *extra):
        return self.cli("reconcile", "--server-key", str(self.file_chiave), "--json", *extra)

    def righe(self):
        db = sqlite3.connect(self.db)
        return {r[0]: (r[1], r[2]) for r in db.execute("SELECT nome, stato, saga FROM peer")}

    def test_i_pending_diventano_active_e_la_chiave_passa_solo_dalla_pipe(self):
        k1, k2 = chiave(), chiave()
        self.add("telefono", k1); self.add("portatile", k2)
        codice, out, err = self.riconcilia()
        self.assertEqual(codice, 0, err)
        r = json.loads(out)
        self.assertEqual((r["coincide"], r["attesi_nel_runtime"], r["peer_aggiornati"]), (True, 2, 2))
        self.assertEqual(set(self.righe().values()), {("ACTIVE", "APPLIED")})
        s = json.loads(self.stato.read_text())
        self.assertEqual(s["argomenti"], ["syncconf", "wg0", "/dev/stdin"])
        self.assertTrue(s["chiave_privata_da_stdin"])
        self.assertEqual(s["peer"], {k1: "10.66.0.2/32", k2: "10.66.0.3/32"})
        self.assertNotIn(self.chiave_server, out + err)
        self.assertNotIn(self.chiave_server, self.reg.read_text())  # mai fra gli argomenti di wg

    def test_sospeso_e_revocato_escono_dal_runtime_e_la_revoca_si_completa(self):
        _, a, _ = self.add("da sospendere"); _, b, _ = self.add("da revocare"); self.add("resta")
        self.assertEqual(self.riconcilia()[0], 0)
        self.cli("suspend", a["id"]); self.cli("revoke", b["id"])
        self.assertEqual(self.righe()["da revocare"], ("REVOKED", "PENDING_APPLY"))  # ANC-0288: non ancora completata
        codice, out, err = self.riconcilia()
        self.assertEqual(codice, 0, err)
        self.assertEqual(self.righe()["da sospendere"], ("SUSPENDED", "APPLIED"))
        self.assertEqual(self.righe()["da revocare"], ("REVOKED", "APPLIED"))
        self.assertEqual(len(json.loads(self.stato.read_text())["peer"]), 1)

    def test_runtime_diverso_porta_in_error_con_codice_4(self):
        self.add("uno"); self.add("due")
        self.modo.write_text("perde-un-peer")
        codice, out, _ = self.riconcilia()
        self.assertEqual(codice, 4)
        self.assertEqual(json.loads(out)["differenze"], 1)
        self.assertEqual(set(self.righe().values()), {("ERROR", "ROLLBACK_REQUIRED")})  # ANC-0280: nessuno resta ACTIVE
        self.assertEqual(self.audit()[-1]["outcome"], "failure")

    def test_syncconf_rifiutato_non_cambia_niente(self):
        self.add("uno")
        self.modo.write_text("syncconf-fallisce")
        codice, _, err = self.riconcilia()
        self.assertEqual(codice, 1)
        self.assertIn("syncconf", err)
        self.assertEqual(self.righe()["uno"], ("PENDING", "PENDING_APPLY"))

    def test_interfaccia_assente(self):
        self.add("uno")
        self.modo.write_text("interfaccia-assente")
        codice, _, err = self.riconcilia()
        self.assertEqual(codice, 1)
        self.assertIn("wg0", err)

    def test_chiave_del_server_esposta_e_security_gate(self):
        self.add("uno")
        self.file_chiave.chmod(0o644)
        codice, _, err = self.riconcilia()
        self.assertEqual(codice, 3)
        self.assertIn("0600", err)
        self.assertFalse(self.stato.exists())  # niente applicato

    def test_chiave_del_server_assente_o_rovinata_senza_mostrarla(self):
        self.add("uno")
        self.assertEqual(self.cli("reconcile", "--server-key", "/non/esiste.key")[0], 1)
        self.file_chiave.write_text("non-una-chiave-segreta-xyz"); self.file_chiave.chmod(0o600)
        codice, _, err = self.riconcilia()
        self.assertEqual(codice, 1)
        self.assertNotIn("non-una-chiave-segreta-xyz", err)

    def test_un_cambio_arrivato_dopo_la_lettura_non_si_sovrascrive(self):
        """Il peer revocato DURANTE il giro resta in PENDING_APPLY per il giro dopo: niente revoca dichiarata a vuoto."""
        _, p, _ = self.add("uno")
        from sovereignctl import runtime
        leggi = runtime.leggi_runtime

        def con_revoca_in_mezzo(interfaccia):
            db = sqlite3.connect(self.db)
            db.execute("UPDATE peer SET stato = 'REVOKED', saga = 'PENDING_APPLY' WHERE id = ?", (p["id"],)); db.commit()
            return leggi(interfaccia)

        with mock.patch.object(runtime, "leggi_runtime", con_revoca_in_mezzo):
            codice, _, err = self.riconcilia()
        self.assertEqual(codice, 0, err)
        self.assertEqual(self.righe()["uno"], ("REVOKED", "PENDING_APPLY"))


if __name__ == "__main__":
    unittest.main()
