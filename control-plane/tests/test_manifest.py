"""Prove del manifest della release (FR-BOOT-002, ANC-0233) e della scrittura atomica (ANC-0244, ANC-0344).
Uso, da control-plane/: python3 -m unittest discover -s tests"""
import hashlib, json, os, pathlib, tempfile, unittest
from unittest import mock

from sovereignctl import manifest, preflight
from test_configurazione import ESEMPIO
from test_preflight import BUONI, con, esegui

DIGEST = "sha256:" + "a" * 64


class Componi(unittest.TestCase):
    def test_campi_di_ANC_0233_e_checksum_vero_della_configurazione(self):
        m = manifest.componi(BUONI, str(ESEMPIO), immagini=[{"nome": "ghcr.io/sovereign/wg", "digest": DIGEST}])
        self.assertEqual(set(m), {"sovereignvpn", "id_installazione", "os", "kernel", "componenti", "immagini",
                                  "schema_configurazione", "checksum_configurazione", "stato_migrazione"})
        self.assertEqual(m["checksum_configurazione"], "sha256:" + hashlib.sha256(ESEMPIO.read_bytes()).hexdigest())
        self.assertEqual(m["os"], "debian 12")

    def test_tag_mobile_e_digest_malformato_rifiutati(self):
        for img in ({"nome": "pihole/pihole:latest", "digest": DIGEST}, {"nome": "unbound", "digest": "sha256:corto"},
                    {"nome": "wg", "digest": ""}):
            with self.subTest(img=img), self.assertRaises(manifest.ManifestNonValido):
                manifest.componi(BUONI, immagini=[img])

    def test_un_segreto_o_un_url_non_entra_nel_manifest(self):
        with self.assertRaises(manifest.ManifestNonValido):
            manifest.componi(BUONI, immagini=[{"nome": "https://utente:password@registro.example/wg", "digest": DIGEST}])
        with self.assertRaises(manifest.ManifestNonValido):
            manifest.componi(con(kernel="6.1 token=abc123segreto"))  # gitleaks:allow — segreto finto di prova (T-025)


class Scrivi(unittest.TestCase):
    def test_scrive_e_non_lascia_temporanei(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "manifest.json")
            manifest.scrivi(p, {"a": 1})
            self.assertEqual(json.loads(pathlib.Path(p).read_text()), {"a": 1})
            self.assertEqual(os.listdir(d), ["manifest.json"])
            self.assertEqual(os.stat(p).st_mode & 0o777, 0o644)

    def test_se_la_sostituzione_fallisce_l_originale_resta_intatto(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "manifest.json")
            manifest.scrivi(p, {"versione": "vecchia"})
            with mock.patch("os.replace", side_effect=OSError("disco pieno")), self.assertRaises(OSError):
                manifest.scrivi(p, {"versione": "nuova"})
            self.assertEqual(json.loads(pathlib.Path(p).read_text()), {"versione": "vecchia"})
            self.assertEqual(os.listdir(d), ["manifest.json"])


class Anteprima(unittest.TestCase):
    def test_check_mostra_il_manifest_senza_scriverlo(self):
        codice, out, err = esegui(["init", "--check", "--config", str(ESEMPIO), "--json"], BUONI)
        self.assertEqual(codice, 0, err)
        r = json.loads(out)
        self.assertEqual(r["mutazioni_eseguite"], 0)
        self.assertTrue(r["manifest_anteprima"]["checksum_configurazione"].startswith("sha256:"))

    def test_check_con_prerequisiti_falliti_non_mostra_il_manifest(self):
        codice, out, _ = esegui(["init", "--check", "--json"], con(os=("ubuntu", "22.04")))
        self.assertEqual(codice, 1)
        self.assertNotIn("manifest_anteprima", json.loads(out))

    def test_security_gate_esce_con_3(self):
        codice, _, err = esegui(["init", "--check"], con(kernel="6.1 password=hunter2segreto"))
        self.assertEqual(codice, 3)
        self.assertIn("security gate", err)
        self.assertNotIn("hunter2segreto", err)


if __name__ == "__main__":
    unittest.main()
