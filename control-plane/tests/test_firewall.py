"""Prove del firewall di base (ANC-0181-0187, FR-NET-001/002/003, FR-DNS-005, T-013, ADR-005/006).
Qui il testo del ruleset e l'ordine delle regole; l'applicazione vera e' in tests/prova_nft_vero.sh (runner Linux).
Uso, da control-plane/: python3 -m unittest discover -s tests"""
import json, pathlib, tempfile, unittest
from unittest import mock

from sovereignctl import firewall
from sovereignctl.preflight import InputNonValido
from test_configurazione import ESEMPIO
from test_preflight import esegui

BASE = dict(subnet="10.66.0.0/24", wg_if="wg0", wg_port=51820, wan_if="ens3", admin_port=8443, ssh_port=22,
            ssh_sorgenti=["198.51.100.0/24", "2001:db8:1::/48"])


def righe(**cambi):
    return [r.strip() for r in firewall.componi(**{**BASE, **cambi}).splitlines()]


class Ruleset(unittest.TestCase):
    def test_policy_drop_su_input_e_forward_e_batch_atomico(self):
        r = righe()
        self.assertEqual(r[:3], ["table inet sovereignvpn", "delete table inet sovereignvpn", "table inet sovereignvpn {"])
        self.assertEqual(sum("policy drop;" in x for x in r), 2)

    def test_ssh_solo_dalle_sorgenti_dichiarate(self):
        r = righe()
        self.assertIn("ip saddr { 198.51.100.0/24 } tcp dport 22 accept", r)
        self.assertIn("ip6 saddr { 2001:db8:1::/48 } tcp dport 22 accept", r)
        self.assertFalse(any("0.0.0.0/0" in x for x in r))

    def test_senza_sorgenti_ssh_non_si_compone(self):
        with self.assertRaises(InputNonValido) as e:
            firewall.componi(**{**BASE, "ssh_sorgenti": []})
        self.assertIn("admin_ssh_sources", str(e.exception))

    def test_amministrazione_e_dns_solo_dalla_vpn(self):
        r = righe()
        self.assertIn('iifname "wg0" ip saddr 10.66.0.0/24 tcp dport 8443 accept', r)
        self.assertFalse(any("dport 8443" in x and "wg0" not in x for x in r))

    def test_mss_solo_sui_syn_fra_wg0_e_wan_e_prima_di_established(self):
        """FR-WG-006: verso la WAN la MSS del peer scende a MTU - 40 solo se piu' alta; verso il peer rt mtu (wg0)."""
        r = righe()
        verso_wan = 'iifname "wg0" oifname "ens3" tcp flags syn / syn,rst tcp option maxseg size > 1380 tcp option maxseg size set 1380'
        verso_peer = 'iifname "ens3" oifname "wg0" tcp flags syn / syn,rst tcp option maxseg size set rt mtu'
        stabilite = r.index("ct state established,related accept", r.index("chain forward {"))
        self.assertLess(r.index(verso_wan), stabilite)
        self.assertLess(r.index(verso_peer), stabilite)
        self.assertIn('iifname "wg0" oifname "ens3" tcp flags syn / syn,rst tcp option maxseg size > 1240 tcp option maxseg size set 1240',
                      righe(mtu=1280))  # segue la MTU della configurazione

    def test_dot_bloccato_di_base_e_disattivabile(self):
        """FR-DNS-006: reject su TCP 853 dai peer, prima dell'uscita verso la WAN; con dns_block_dot = false non c'e'."""
        r = righe()
        dot = 'iifname "wg0" tcp dport 853 reject with tcp reset'
        self.assertLess(r.index(dot), r.index('iifname "wg0" ip saddr 10.66.0.0/24 oifname "ens3" accept'))
        self.assertNotIn(dot, righe(blocca_dot=False))
        sorgente = (pathlib.Path(firewall.__file__)).read_text()
        self.assertIn("NON ferma ogni DNS cifrato", sorgente)  # la nota di FR-DNS-006 accanto alla regola

    def test_un_peer_con_rotte_esce_solo_verso_le_rotte_e_la_vpn(self):
        r = righe(limiti=[("10.66.0.5", ["192.168.10.0/24", "172.16.0.0/16"])])
        regola = 'iifname "wg0" ip saddr 10.66.0.5 ip daddr != { 10.66.0.0/24, 192.168.10.0/24, 172.16.0.0/16 } drop'
        self.assertLess(r.index(regola), r.index('iifname "wg0" ip saddr 10.66.0.0/24 oifname "ens3" accept'))
        self.assertFalse(any("ip daddr !=" in x for x in righe()))  # senza limiti, nessuna regola per peer

    def test_dns_libero_per_peer_prima_del_blocco(self):
        r = righe(dns_liberi=["10.66.0.7"])
        eccezione = 'iifname "wg0" ip saddr 10.66.0.7 meta l4proto { tcp, udp } th dport 53 accept'
        self.assertLess(r.index(eccezione), r.index('iifname "wg0" meta l4proto { tcp, udp } th dport 53 drop'))
        self.assertFalse(any("ip saddr 10.66.0.7" in x for x in righe()))

    def test_ordine_del_forward(self):
        """Isolamento fra peer e DNS esterno bloccati PRIMA dell'uscita verso la WAN: dopo non servirebbero a niente."""
        r = righe()
        uscita = r.index('iifname "wg0" ip saddr 10.66.0.0/24 oifname "ens3" accept')
        self.assertLess(r.index('iifname "wg0" oifname "wg0" drop'), uscita)
        self.assertLess(r.index('iifname "wg0" meta l4proto { tcp, udp } th dport 53 drop'), uscita)
        self.assertLess(r.index('iifname "wg0" meta nfproto ipv6 reject with icmpv6 type admin-prohibited'), uscita)

    def test_masquerade_verso_la_wan(self):
        self.assertIn('ip saddr 10.66.0.0/24 oifname "ens3" masquerade', righe())

    def test_input_non_validi(self):
        for cambi, voce in (({"wan_if": None}, "--wan-interface"), ({"wan_if": "eth0; drop"}, "--wan-interface"),
                            ({"wg_if": "x" * 16}, "--wg-interface"), ({"subnet": "8.8.8.0/24"}, "subnet"),
                            ({"subnet": "10.66.0.1/24"}, "subnet"), ({"ssh_sorgenti": ["10.0.0.1/8"]}, "admin_ssh_sources[0]")):
            with self.subTest(cambi=cambi), self.assertRaises(InputNonValido) as e:
                firewall.componi(**{**BASE, **cambi})
            self.assertIn(voce, str(e.exception))


class Comandi(unittest.TestCase):
    def test_plan_non_tocca_nft(self):
        with mock.patch.object(firewall, "_nft", side_effect=AssertionError("nft chiamato da plan")):
            codice, out, err = esegui(["firewall", "plan", "--config", str(ESEMPIO), "--wan-interface", "ens3", "--json"])
        self.assertEqual(codice, 0, err)
        r = json.loads(out)
        self.assertEqual(r["mutazioni_eseguite"], 0)
        self.assertIn("policy drop", r["ruleset"])

    def test_config_senza_sorgenti_ssh_esce_con_2(self):
        with tempfile.TemporaryDirectory() as d:
            f = pathlib.Path(d) / "s.toml"
            f.write_text('schema_version = 1\nendpoint = "vpn.example.org"\n')
            codice, _, err = esegui(["firewall", "plan", "--config", str(f), "--wan-interface", "ens3"])
        self.assertEqual(codice, 2)
        self.assertIn("admin_ssh_sources", err)

    def test_controllo_rifiutato_non_applica(self):
        chiamate = []

        def nft(*argomenti, ingresso=None):
            chiamate.append(argomenti)
            return (1, "", "Error: syntax error") if argomenti[0] == "-c" else (0, "", "")
        with mock.patch.object(firewall, "_nft", nft), self.assertRaises(RuntimeError):
            firewall.applica("table inet sovereignvpn { rotto }")
        self.assertEqual(chiamate, [("-c", "-f", "-")])  # dopo il rifiuto, nessun nft -f


if __name__ == "__main__":
    unittest.main()
