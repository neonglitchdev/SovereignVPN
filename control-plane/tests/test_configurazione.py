"""Prove dello schema della configurazione v1 (FR-BOOT-003, ANC-0230, ANC-0236-0242).
Uso, da control-plane/: python3 -m unittest discover -s tests"""
import json, pathlib, tempfile, unittest
from unittest import mock

from sovereignctl import preflight
from test_preflight import BUONI, esegui

ESEMPIO = pathlib.Path(__file__).resolve().parents[2] / "config" / "examples" / "server.toml"
BASE = 'schema_version = 1\nendpoint = "vpn.example.org"\n'


def con_file(testo, *opzioni):
    with tempfile.TemporaryDirectory() as d:
        f = pathlib.Path(d) / "server.toml"
        f.write_text(testo, encoding="utf-8")
        return esegui(["init", "--check", "--config", str(f), *opzioni], BUONI)


class Esempio(unittest.TestCase):
    def test_l_esempio_della_repo_e_valido(self):
        codice, out, err = esegui(["init", "--check", "--config", str(ESEMPIO)], BUONI)
        self.assertEqual(codice, 0, err)
        self.assertIn("Configurazione:", out)
        self.assertIn("endpoint vpn.example.org, MTU 1420", out)

    def test_la_riga_di_comando_sovrascrive_il_file(self):
        codice, out, err = con_file(BASE + "wg_port = 51000\n", "--wg-port", "52000", "--json")
        self.assertEqual(codice, 0, err)
        self.assertIn("udp/52000", out)
        self.assertNotIn("udp/51000", out)

    def test_il_rapporto_non_mostra_l_hash_del_token(self):
        h = "scrypt$" + "a" * 40
        codice, out, err = con_file(BASE + f'admin_token_hash = "{h}"\n', "--json")
        self.assertEqual(codice, 0, err)
        self.assertEqual(json.loads(out)["configurazione"]["admin_token_hash"], "impostato")
        self.assertNotIn(h, out)


class Rifiuti(unittest.TestCase):
    """Codice 2, il campo nominato, nessuna raccolta sull'host."""

    def rifiuto(self, testo, campo, *opzioni):
        with mock.patch.object(preflight, "raccogli", side_effect=AssertionError("raccolta con input non valido")):
            with tempfile.TemporaryDirectory() as d:
                f = pathlib.Path(d) / "server.toml"
                f.write_text(testo, encoding="utf-8")
                codice, _, err = esegui(["init", "--check", "--config", str(f), *opzioni])
        self.assertEqual(codice, 2, err)
        self.assertIn(campo, err)
        return err

    def test_versione_dello_schema_mancante(self):
        self.rifiuto('endpoint = "vpn.example.org"\n', "config.schema_version")

    def test_endpoint_mancante(self):
        self.rifiuto("schema_version = 1\n", "config.endpoint")

    def test_endpoint_non_valido(self):
        self.rifiuto('schema_version = 1\nendpoint = "non valido!"\n', "config.endpoint")

    def test_campo_sconosciuto(self):
        self.rifiuto(BASE + "colore = 3\n", "config.colore")

    def test_porta_dal_file_fuori_intervallo(self):
        self.rifiuto(BASE + "wg_port = 0\n", "config.wg_port")

    def test_subnet_dal_file_non_canonica(self):
        self.rifiuto(BASE + 'subnet = "10.66.0.5/24"\n', "config.subnet")

    def test_subnet6_non_ula(self):
        self.rifiuto(BASE + 'subnet6 = "2001:db8::/64"\n', "config.subnet6")

    def test_subnet6_dove_non_ci_stanno_i_32_bit_dell_ipv4(self):
        self.rifiuto(BASE + 'subnet6 = "fd00::/112"\n', "config.subnet6")

    def test_subnet6_di_base_ula_con_id_casuale(self):
        """[H38] Senza subnet6, una ULA fd00::/8 (ID globale casuale, RFC 4193) /64; con subnet6, quella."""
        import ipaddress
        from sovereignctl import configurazione
        base = configurazione.valida({"schema_version": 1, "endpoint": "vpn.example.org"})["subnet6"]
        self.assertEqual(base, configurazione.SUBNET6)
        self.assertTrue(ipaddress.ip_network(base).subnet_of(ipaddress.ip_network("fd00::/8")))
        self.assertEqual(ipaddress.ip_network(base).prefixlen, 64)
        dichiarata = configurazione.valida({"schema_version": 1, "endpoint": "vpn.example.org", "subnet6": "fd00:1:2::/96"})
        self.assertEqual(dichiarata["subnet6"], "fd00:1:2::/96")

    def test_mtu_jumbo(self):
        self.rifiuto(BASE + "mtu = 9000\n", "config.mtu")

    def test_dns_non_ip(self):
        self.rifiuto(BASE + 'dns = ["resolver.local"]\n', "config.dns[0]")

    def test_interfaccia_troppo_lunga(self):
        self.rifiuto(BASE + 'wan_interface = "interfaccialunghissima0"\n', "config.wan_interface")

    def test_firewall_iptables(self):
        self.rifiuto(BASE + 'firewall_profile = "iptables"\n', "config.firewall_profile")

    def test_servizio_opzionale_acceso(self):
        self.rifiuto(BASE + "[flags]\ntor = true\n", "config.flags.tor")

    def test_sorgenti_ssh_non_canoniche(self):
        self.rifiuto(BASE + 'admin_ssh_sources = ["198.51.100.7/24"]\n', "config.admin_ssh_sources[0]")

    def test_porta_ssh_fuori_intervallo(self):
        self.rifiuto(BASE + "ssh_port = 0\n", "config.ssh_port")

    def test_toml_rotto(self):
        self.rifiuto("schema_version = \n", "--config")

    def test_file_mancante(self):
        with mock.patch.object(preflight, "raccogli", side_effect=AssertionError):
            codice, _, err = esegui(["init", "--check", "--config", "/non/esiste/server.toml"])
        self.assertEqual(codice, 2)
        self.assertIn("--config", err)

    def test_token_in_chiaro_rifiutato_senza_mostrarlo(self):
        segreto = "SegretoMoltoRiconoscibile-7f3a9"
        err = self.rifiuto(BASE + f'admin_token = "{segreto}"\n', "config.admin_token")
        self.assertNotIn(segreto, err)

    def test_lo_schema_da_solo_non_ripete_il_segreto(self):
        """Il primo strato, senza la CLI che redige davanti: un guasto qui non deve restare coperto dal secondo."""
        from sovereignctl import configurazione
        segreto = "SegretoMoltoRiconoscibile-7f3a9"
        with self.assertRaises(preflight.InputNonValido) as e:
            configurazione.valida({"schema_version": 1, "endpoint": "vpn.example.org", "admin_token": segreto})
        self.assertIn("config.admin_token", str(e.exception))
        self.assertNotIn(segreto, str(e.exception))

    def test_hash_malformato_non_ripete_il_valore(self):
        valore = "plaintext-che-non-e-un-hash-91c2"
        err = self.rifiuto(BASE + f'admin_token_hash = "{valore}"\n', "config.admin_token_hash")
        self.assertNotIn(valore, err)

    def test_controllo_negativo_il_cercatore_vede_un_segreto_stampato(self):
        """La prova «il valore non compare» deve saper dire no: un errore che lo stampa viene preso."""
        segreto = "SegretoMoltoRiconoscibile-7f3a9"
        stampato = f"sovereignctl: input non valido: config.admin_token: {segreto}"
        self.assertIn(segreto, stampato)



class BloccoDot(unittest.TestCase):
    def test_dns_block_dot_solo_vero_o_falso(self):
        import tomllib
        from sovereignctl import configurazione
        base = tomllib.loads(ESEMPIO.read_text())
        self.assertIs(configurazione.valida({**base, "dns_block_dot": False})["dns_block_dot"], False)
        with self.assertRaises(Exception):
            configurazione.valida({**base, "dns_block_dot": "no"})

if __name__ == "__main__":
    unittest.main()
