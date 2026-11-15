"""Prove del logging sanitizzato (ANC-0059, ANC-0232, ANC-0239, FR-OPS-002, NFR-SEC-004/005).
Uso, da control-plane/: python3 -m unittest discover -s tests"""
import datetime, io, json, logging, unittest, uuid

from sovereignctl.registro import FiltroSanitizza, evento_audit, redigi

CHIAVE = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="   # forma di una chiave WireGuard (32 byte base64), di prova
PEM = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"


class Redazione(unittest.TestCase):
    def assert_tolto(self, testo, segreto):
        r = redigi(testo)
        self.assertNotIn(segreto, r)
        self.assertIn("REDATT", r)

    def test_chiave_wireguard(self):
        self.assert_tolto(f"peer creato con chiave {CHIAVE} su wg0", CHIAVE)

    def test_chiave_pem(self):
        self.assert_tolto(f"letto:\n{PEM}\nfine", "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC")

    def test_portatore(self):
        self.assert_tolto("Authorization: Bearer eyJhbGciOi.eyJzdWIiOi.SflKxwRJSM", "eyJhbGciOi.eyJzdWIiOi.SflKxwRJSM")

    def test_campi_segreti_in_varie_forme(self):
        for testo, segreto in [("token=SuperSegreto99", "SuperSegreto99"), ("password: hunter2-lungo", "hunter2-lungo"),
                               ('{"private_key": "abc-def-123"}', "abc-def-123"), ("PresharedKey = qwerty-uiop", "qwerty-uiop"),
                               ("admin_token_hash=scrypt$abcdefghij1234567890", "abcdefghij1234567890"),
                               ("api-key: k-998877", "k-998877")]:
            with self.subTest(testo=testo):
                self.assert_tolto(testo, segreto)

    def test_url_e_ip_pubblici(self):
        self.assert_tolto("il client ha chiesto https://esempio.it/percorso?q=1", "esempio.it")
        self.assert_tolto("handshake da 8.8.4.4 alle 10:00", "8.8.4.4")
        self.assert_tolto("handshake da 2001:4860:4860::8888", "2001:4860:4860::8888")

    def test_il_testo_normale_resta_com_era(self):
        """Il caso innocuo: una redazione che cancella tutto passerebbe le prove sopra e renderebbe i log inutili."""
        for testo in ["SovereignVPN 14.0.0 — init --check", "porta UDP 51820 libera", "peer 10.66.0.2 su wg0, MTU 1420",
                      "vedi ANC-0255 e FR-BOOT-003", "rete fd42:6a5f:1::/64", "ora 2026-11-15T10:00:00Z",
                      "controlli eseguiti: 11 su 11", "LAN 192.168.1.0/24"]:
            with self.subTest(testo=testo):
                self.assertEqual(redigi(testo), testo)


class Filtro(unittest.TestCase):
    def test_gli_argomenti_del_logging_vengono_redatti(self):
        uscita = io.StringIO()
        h = logging.StreamHandler(uscita); h.addFilter(FiltroSanitizza())
        log = logging.getLogger("prova-registro"); log.handlers = [h]; log.propagate = False; log.setLevel(logging.INFO)
        log.info("peer %s con chiave %s da %s", "casa", CHIAVE, "8.8.8.8")
        self.assertNotIn(CHIAVE, uscita.getvalue())
        self.assertNotIn("8.8.8.8", uscita.getvalue())
        self.assertIn("peer casa con chiave [CHIAVE REDATTA]", uscita.getvalue())

    def test_una_traccia_non_porta_fuori_il_segreto(self):
        uscita = io.StringIO()
        h = logging.StreamHandler(uscita); h.addFilter(FiltroSanitizza())
        log = logging.getLogger("prova-traccia"); log.handlers = [h]; log.propagate = False
        try:
            raise ValueError(f"chiave {CHIAVE} non valida")
        except ValueError:
            log.exception("sincronizzazione fallita")
        self.assertNotIn(CHIAVE, uscita.getvalue())
        self.assertIn("[ValueError]", uscita.getvalue())


class Audit(unittest.TestCase):
    def test_campi_ammessi_ora_utc_motivo_redatto(self):
        bersaglio = uuid.uuid4()
        e = json.loads(evento_audit(actor="owner", action="peer.revoke", target=bersaglio, outcome="success",
                                    reason=f"revocato, la chiave {CHIAVE} era esposta"))
        self.assertEqual(set(e), {"id", "timestamp", "actor", "action", "target", "outcome", "request_id", "reason"})
        self.assertTrue(e["timestamp"].endswith("Z"))
        datetime.datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00"))
        self.assertEqual(e["target"], str(bersaglio))
        self.assertNotIn(CHIAVE, e["reason"])

    def test_un_campo_vietato_e_rifiutato(self):
        for campo in ("url", "query", "client_ip", "payload", "private_key", "token"):
            with self.subTest(campo=campo), self.assertRaises(TypeError):
                evento_audit(actor="owner", action="peer.add", outcome="success", **{campo: "x"})

    def test_il_bersaglio_e_un_uuid_non_un_nome(self):
        with self.assertRaises(ValueError):
            evento_audit(actor="owner", action="peer.add", target="../../etc/passwd", outcome="success")

    def test_esito_fuori_elenco(self):
        with self.assertRaises(ValueError):
            evento_audit(actor="owner", action="peer.add", outcome="forse")


if __name__ == "__main__":
    unittest.main()
