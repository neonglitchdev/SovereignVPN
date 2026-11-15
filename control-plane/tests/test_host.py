"""Prove dei sysctl dell'host (ANC-0124, ANC-0186, FR-NET-007). L'attivazione vera e' in tests/prova_sysctl_vero.sh.
Uso, da control-plane/: python3 -m unittest discover -s tests"""
import json, os, pathlib, stat, tempfile, unittest
from unittest import mock

from sovereignctl import host
from test_preflight import esegui


class Sysctl(unittest.TestCase):
    def test_tre_valori_e_niente_rp_filter(self):
        testo = host.componi()
        righe = [r for r in testo.splitlines() if r and not r.startswith("#")]
        self.assertEqual(righe, ["net.ipv4.ip_forward = 1", "net.ipv6.conf.all.forwarding = 0", "net.ipv6.conf.default.forwarding = 0"])
        self.assertFalse(any("rp_filter" in r for r in righe))  # ANC-0124: mai globale

    def test_plan_non_scrive_e_non_chiama_sysctl(self):
        with mock.patch.object(host, "_sysctl", side_effect=AssertionError("sysctl chiamato da plan")), \
             mock.patch.object(host, "scrivi_testo", side_effect=AssertionError("scrittura da plan")):
            codice, out, err = esegui(["host", "plan", "--json"])
        self.assertEqual(codice, 0, err)
        self.assertEqual(json.loads(out)["mutazioni_eseguite"], 0)

    def test_apply_con_radice_scrive_atomico_e_non_attiva(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(host, "_sysctl", side_effect=AssertionError("attivato sotto radice")):
            codice, out, err = esegui(["host", "apply", "--radice", d, "--json"])
            self.assertEqual(codice, 0, err)
            f = pathlib.Path(d) / host.FILE
            self.assertEqual(f.read_text(), host.componi())
            self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o644)
            self.assertEqual(sorted(os.listdir(f.parent)), ["90-sovereignvpn.conf"])  # nessun temporaneo avanzato
            self.assertFalse(json.loads(out)["attivato"])

    def test_valore_riletto_diverso_esce_con_4(self):
        def sysctl(*a):  # -p riesce, ma rileggendo ip_forward e' ancora 0
            return (0, "", "") if a[0] == "-p" else (0, "0\n", "")
        with mock.patch.object(host, "_sysctl", sysctl), mock.patch.object(host, "scrivi_testo", lambda *a, **k: None), \
             mock.patch.object(host.os, "makedirs", lambda *a, **k: None):
            codice, out, _ = esegui(["host", "apply", "--json"])
        self.assertEqual(codice, 4)
        self.assertFalse(json.loads(out)["verificato"])

    def test_radice_inesistente(self):
        self.assertEqual(esegui(["host", "apply", "--radice", "/non/esiste/davvero"])[0], 2)


if __name__ == "__main__":
    unittest.main()
