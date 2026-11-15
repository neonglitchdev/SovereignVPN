"""Prove delle liste di blocco (FR-DNS-002/007, H27) con docker sostituito; Pi-hole vero in prova_dns_vero.sh.
Uso, da control-plane/: python3 -m unittest discover -s tests"""
import json, os, pathlib, tempfile, unittest
from unittest import mock

from sovereignctl import liste
from sovereignctl.preflight import InputNonValido
from test_preflight import esegui


class Liste(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory(); self.t = pathlib.Path(self._t.name); self.cartella = self.t / "liste"

    def tearDown(self):
        self._t.cleanup()

    def file(self, nome, testo):
        f = self.t / nome; f.write_text(testo); return str(f)

    def attiva(self):
        return os.readlink(self.cartella / "attiva.txt")

    def test_validazione(self):
        domini, errori, doppioni = liste.valida("Ads.Example.\n# commento\n\nads.example\ntrack.example # dopo\n1.2.3.4\nnon valido\nlocalhost\n")
        self.assertEqual(domini, ["ads.example", "track.example"])
        self.assertEqual(doppioni, ["ads.example"])
        self.assertEqual([e.split(":")[0] for e in errori], ["riga 6", "riga 7", "riga 8"])
        self.assertIn("indirizzo IP", errori[0])

    def test_versioni_attivazione_atomica_e_rollback(self):
        s1 = liste.applica(self.file("l1.txt", "uno.example\n"), str(self.cartella))
        self.assertEqual((self.attiva(), s1["domini"], s1["precedente"]), (s1["attiva"], 1, None))
        self.assertEqual((self.cartella / s1["attiva"]).read_text(), "uno.example\n")
        s2 = liste.applica(self.file("l2.txt", "due.example\ntre.example\n"), str(self.cartella))
        self.assertEqual((self.attiva(), s2["precedente"], s2["domini"]), (s2["attiva"], s1["attiva"], 2))
        r = liste.rollback(str(self.cartella))
        self.assertEqual((self.attiva(), r["sha256"], r["precedente"]), (s1["attiva"], s1["sha256"], s2["attiva"]))
        self.assertEqual(json.loads((self.cartella / "stato.json").read_text())["attiva"], s1["attiva"])

    def test_lista_invalida_non_cambia_niente(self):
        s1 = liste.applica(self.file("l1.txt", "uno.example\n"), str(self.cartella))
        prima = sorted(os.listdir(self.cartella))
        codice, _, err = esegui(["dns", "blocklist", "apply", self.file("rotta.txt", "uno.example\nnon un dominio!\n"),
                                 "--cartella", str(self.cartella)])
        self.assertEqual(codice, 2)
        self.assertIn("resta quella di prima", err)
        self.assertEqual((self.attiva(), sorted(os.listdir(self.cartella))), (s1["attiva"], prima))
        with self.assertRaises(InputNonValido):
            liste.applica(self.file("vuota.txt", "# solo commenti\n"), str(self.cartella))

    def test_rollback_senza_precedente(self):
        liste.applica(self.file("l1.txt", "uno.example\n"), str(self.cartella))
        self.assertEqual(esegui(["dns", "blocklist", "rollback", "--cartella", str(self.cartella)])[0], 2)

    def test_sincronizza_registra_l_adlist_e_ricompila(self):
        chiamate = []
        def docker(*a):
            chiamate.append(a)
            return "1|1\n" if "SELECT" in a[-1] else ""
        with mock.patch.object(liste, "_docker", docker):
            r = liste.sincronizza("pihole-prova")
        self.assertEqual(r, {"adlist": "file:///etc/pihole/sovereignvpn/attiva.txt", "domini_in_gravity": 1, "stato_pihole": 1})
        self.assertIn("INSERT OR IGNORE INTO adlist", chiamate[0][-1])
        self.assertEqual(chiamate[1], ("exec", "pihole-prova", "pihole", "-g"))


if __name__ == "__main__":
    unittest.main()
