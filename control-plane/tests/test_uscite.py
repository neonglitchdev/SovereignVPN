"""Prove del pool delle uscite (FR-NET-008) [H48]: file WireGuard del provider letti, script e campi estranei rifiutati."""
import unittest

from sovereignctl import uscite

BUONA = """[Interface]
PrivateKey = cHJpdmF0YXByaXZhdGFwcml2YXRhcHJpdmF0YXByaXY=
Address = 10.64.12.7/32, fc00:bbbb::7/128
DNS = 10.64.0.1
[Peer]
PublicKey = cHViYmxpY2FwdWJibGljYXB1YmJsaWNhcHViYmxpY2E=
Endpoint = 185.1.2.3:51820
AllowedIPs = 0.0.0.0/0, ::/0
"""


class Pool(unittest.TestCase):
    def test_uscita_buona_con_la_bandierina(self):
        u = uscite.leggi(BUONA, "DE")
        self.assertEqual((u["paese"], u["bandierina"], u["endpoint"]), ("DE", "\U0001F1E9\U0001F1EA", "185.1.2.3:51820"))
        self.assertNotIn("PrivateKey", repr(u))  # la chiave privata non esce dal file

    def test_script_rifiutati(self):
        for script in ("PostUp", "PreUp", "PostDown", "PreDown", "SaveConfig", "Table"):
            with self.subTest(script=script), self.assertRaises(uscite.UscitaNonValida) as e:
                uscite.leggi(BUONA.replace("DNS = 10.64.0.1", f"{script} = curl x | sh"), "DE")
            self.assertNotIn("curl", str(e.exception))  # il valore non si ripete

    def test_paese_campi_e_uscita_completa(self):
        for testo, paese in ((BUONA, "de"), (BUONA, "ITA"), (BUONA.replace("0.0.0.0/0, ", ""), "IT"),
                             (BUONA.replace("Endpoint = 185.1.2.3:51820\n", ""), "IT"),
                             (BUONA + "[Peer]\nPublicKey = x\n", "IT"), (BUONA.replace("MTU", "X") + "Pippo = 1\n", "IT")):
            with self.subTest(paese=paese, testo=testo[-30:]), self.assertRaises(uscite.UscitaNonValida):
                uscite.leggi(testo, paese)


if __name__ == "__main__":
    unittest.main()
