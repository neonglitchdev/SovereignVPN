"""Prove di `sovereignctl init --check` (FR-BOOT-001/003/004, T-003, T-004, codici di uscita ANC-0255).
Uso, da control-plane/: python3 -m unittest discover -s tests"""
import builtins, contextlib, io, json, os, shutil, subprocess, unittest
from unittest import mock

from sovereignctl import __main__ as cli, preflight

BUONI = {"os": ("debian", "12"), "architettura": "x86_64", "kernel": "6.1.0-26-amd64", "docker": "27.3.1",
         "compose": "2.29.7", "wireguard": True, "disco_libero": 40 * 1024 ** 3, "ntp": True,
         "porte_libere": {"udp/51820": True, "tcp/8443": True}, "reti_host": ["192.168.1.0/24", "172.17.0.0/16"],
         "installato": False, "porta_di_wg0": None, "ascolto_53": []}


def esegui(argv, fatti=None):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        if fatti is None:
            codice = cli.main(argv)
        else:
            with mock.patch.object(preflight, "raccogli", lambda imp: fatti):
                codice = cli.main(argv)
    return codice, out.getvalue(), err.getvalue()


def con(**cambi):
    f = dict(BUONI); f.update(cambi); return f


class Preflight(unittest.TestCase):
    def test_host_conforme_esce_0_col_piano(self):
        codice, out, _ = esegui(["init", "--check"], BUONI)
        self.assertEqual(codice, 0)
        self.assertIn("Controlli eseguiti: 12 su 12; superati: 12; falliti: 0", out)
        self.assertIn("Piano (da approvare", out)
        self.assertIn("10.66.0.0/24", out)

    def test_sistema_non_supportato_fallisce_col_rimedio(self):
        codice, out, _ = esegui(["init", "--check"], con(os=("ubuntu", "22.04")))
        self.assertEqual(codice, 1)
        self.assertIn("[FALLITO] Sistema operativo: ubuntu 22.04", out)
        self.assertIn("Debian 12 o Ubuntu 24.04", out)
        self.assertIn("Piano non generato", out)

    def test_T003_subnet_in_conflitto_con_la_lan(self):
        codice, out, _ = esegui(["init", "--check", "--subnet", "192.168.1.0/24"], BUONI)
        self.assertEqual(codice, 1)
        self.assertIn("collide con 192.168.1.0/24", out)

    def test_T004_porta_admin_occupata(self):
        codice, out, _ = esegui(["init", "--check"], con(porte_libere={"udp/51820": True, "tcp/8443": False}))
        self.assertEqual(codice, 1)
        self.assertIn("[FALLITO] Porta TCP 8443: gia' in uso", out)

    def test_ipam_salta_le_reti_occupate(self):
        codice, out, _ = esegui(["init", "--check", "--json"], con(reti_host=["10.66.0.0/16"]))
        self.assertEqual(codice, 0)
        self.assertIn("10.67.0.0/24", out)
        self.assertIn('"mutazioni_eseguite": 0', out)

    def test_zero_reti_lette_non_e_nessuna_collisione(self):
        codice, out, _ = esegui(["init", "--check"], con(reti_host=[]))
        self.assertEqual(codice, 1)
        self.assertIn("nessuna rete dell'host letta", out)

    def test_kernel_vecchio(self):
        codice, out, _ = esegui(["init", "--check"], con(kernel="5.4.0-150-generic"))
        self.assertEqual(codice, 1)
        self.assertIn("[FALLITO] Kernel: 5.4.0-150-generic", out)


class InputNonValido(unittest.TestCase):
    """Codice 2, la voce sbagliata nominata, e nessuna raccolta: niente tocca l'host (FR-BOOT-003)."""

    def assert_rifiuto(self, argv, voce):
        with mock.patch.object(preflight, "raccogli", side_effect=AssertionError("raccolta con input non valido")):
            codice, _, err = esegui(argv)
        self.assertEqual(codice, 2)
        self.assertIn(voce, err)

    def test_porta_fuori_intervallo(self):
        self.assert_rifiuto(["init", "--check", "--wg-port", "70000"], "--wg-port")

    def test_porta_non_numerica(self):
        self.assert_rifiuto(["init", "--check", "--admin-port", "abc"], "--admin-port")

    def test_cidr_non_canonico(self):
        self.assert_rifiuto(["init", "--check", "--subnet", "10.8.0.1/24"], "--subnet")

    def test_subnet_pubblica(self):
        self.assert_rifiuto(["init", "--check", "--subnet", "8.8.8.0/24"], "--subnet")

    def test_porte_uguali(self):
        self.assert_rifiuto(["init", "--check", "--wg-port", "8443"], "--admin-port")

    def test_senza_check(self):
        with self.assertRaises(SystemExit) as e, contextlib.redirect_stderr(io.StringIO()) as err:
            cli.main(["init"])
        self.assertEqual(e.exception.code, 2)
        self.assertIn("--check", err.getvalue())


class DryRun(unittest.TestCase):
    """FR-BOOT-004: la raccolta VERA gira sull'host di prova; ogni scrittura e ogni comando che muta sono intercettati."""

    MUTANTI = {"nft", "iptables", "ip6tables", "sysctl", "systemctl", "wg", "wg-quick", "modprobe", "ufw"}

    def muta(self, args):
        """Un comando che puo' mutare. `wg show` legge soltanto: e' l'unico `wg` ammesso (la porta di wg0)."""
        if args[:2] == ["wg", "show"] or tuple(args[:2]) == ("wg", "show"):
            return False
        return os.path.basename(args[0]) in self.MUTANTI or list(args[:2]) in (["ip", "link"], ["ip", "route"]) and len(args) > 2 and args[2] in ("add", "del", "set", "replace")

    def test_il_divieto_vede_ancora_i_comandi_che_mutano(self):  # controllo negativo della guardia qui sopra
        for args in (["wg", "set", "wg0", "listen-port", "1"], ["wg", "setconf", "wg0", "/dev/stdin"], ["nft", "-f", "-"],
                     ["ip", "link", "add", "wg0", "type", "wireguard"]):
            self.assertTrue(self.muta(args), args)
        self.assertFalse(self.muta(["wg", "show", "wg0", "listen-port"]))

    def test_nessuna_mutazione(self):
        tentativi = []
        apri = builtins.open
        esegui_vero = subprocess.run

        def open_solo_lettura(f, mode="r", *a, **k):
            if any(c in mode for c in "wax+"):
                tentativi.append(("open", f, mode)); raise PermissionError("scrittura vietata nel dry-run")
            return apri(f, mode, *a, **k)

        def run_controllato(args, *a, **k):
            if self.muta(args):
                tentativi.append(("comando", args)); raise PermissionError("comando che muta, vietato nel dry-run")
            return esegui_vero(args, *a, **k)

        def vietato(nome):
            def f(*a, **k):
                tentativi.append((nome, a)); raise PermissionError(f"{nome} vietato nel dry-run")
            return f

        with mock.patch("builtins.open", open_solo_lettura), mock.patch("subprocess.run", run_controllato), \
             mock.patch("os.replace", vietato("os.replace")), mock.patch("os.rename", vietato("os.rename")), \
             mock.patch("os.mkdir", vietato("os.mkdir")), mock.patch("os.makedirs", vietato("os.makedirs")), \
             mock.patch("os.remove", vietato("os.remove")), mock.patch("shutil.rmtree", vietato("shutil.rmtree")):
            codice, out, err = esegui(["init", "--check", "--json"])
        self.assertEqual(tentativi, [])
        self.assertIn(codice, (0, 1), err)
        self.assertIn('"mutazioni_eseguite": 0', out)

    def test_la_trappola_prende_una_scrittura(self):
        """Controllo negativo: lo stesso intercettore deve accorgersi di una scrittura vera."""
        tentativi = []
        apri = builtins.open

        def open_solo_lettura(f, mode="r", *a, **k):
            if any(c in mode for c in "wax+"):
                tentativi.append(f); raise PermissionError
            return apri(f, mode, *a, **k)

        with mock.patch("builtins.open", open_solo_lettura), \
             mock.patch.object(preflight, "raccogli", lambda imp: (open("/tmp/sovereign-prova-negativa", "w"), BUONI)[1]):
            with self.assertRaises(PermissionError):
                preflight.raccogli({})
        self.assertEqual(tentativi, ["/tmp/sovereign-prova-negativa"])


class Loopback53(unittest.TestCase):
    """[H49] 127.0.0.1:53 deve essere libera, o del Pi-hole di questa installazione: un altro resolver fa cadere Pi-hole."""
    def esito(self, **cambi):
        return {c["id"]: c for c in preflight.valuta(con(**cambi), preflight.leggi_impostazioni())[0]}["dns-loopback"]

    def test_libera_o_nostra(self):
        self.assertEqual(self.esito(ascolto_53=[])["esito"], "OK")
        self.assertEqual(self.esito(ascolto_53=["pihole-FTL"], installato=True)["esito"], "OK")

    def test_occupata_da_altri_o_non_verificabile(self):
        for cambi in ({"ascolto_53": ["dnsmasq"]}, {"ascolto_53": ["pihole-FTL"], "installato": False},
                      {"ascolto_53": ["dnsmasq", "pihole-FTL"], "installato": True}, {"ascolto_53": None}):
            with self.subTest(**cambi):
                c = self.esito(**cambi)
                self.assertEqual(c["esito"], "FALLITO"); self.assertIn("except-interface=lo", c["rimedio"])
        self.assertIn("dnsmasq", self.esito(ascolto_53=["dnsmasq"])["dettaglio"])

    def test_si_legge_da_ss(self):
        ss = ("udp   UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:((\"systemd-resolve\",pid=1,fd=13))\n"
              "udp   UNCONN 0 0 127.0.0.1:53 0.0.0.0:* users:((\"dnsmasq\",pid=2,fd=6))\n"
              "tcp   LISTEN 0 32 127.0.0.1:53 0.0.0.0:* users:((\"dnsmasq\",pid=2,fd=7))\n"
              "udp   UNCONN 0 0 10.66.0.1:53 0.0.0.0:* users:((\"pihole-FTL\",pid=3,fd=21))")
        with mock.patch.object(preflight, "_comando", lambda *a, **k: (0, ss)):
            self.assertEqual(preflight._ascolto_53_loopback(), ["dnsmasq"])  # resolved su 127.0.0.53 non conta
        with mock.patch.object(preflight, "_comando", lambda *a, **k: (0, ss.replace("127.0.0.1:53", "127.0.0.1:5353"))):
            self.assertEqual(preflight._ascolto_53_loopback(), [])
        with mock.patch.object(preflight, "_comando", lambda *a, **k: (None, "")):
            self.assertIsNone(preflight._ascolto_53_loopback())


class Reinstallazione(unittest.TestCase):
    """Su un host gia' installato (manifest presente) la porta e la rete di wg0 sono sue, non un conflitto."""
    def esiti(self, **cambi):
        return {c["id"]: c for c in preflight.valuta(con(**cambi), preflight.leggi_impostazioni())[0]}

    def test_la_porta_di_wg0_su_un_host_installato_e_ok(self):
        c = self.esiti(porte_libere={"udp/51820": False, "tcp/8443": True}, installato=True, porta_di_wg0=51820)["porta-udp-51820"]
        self.assertEqual(c["esito"], "OK")
        self.assertIn("wg0", c["dettaglio"])

    def test_porta_occupata_resta_fallita_se_non_e_di_questa_installazione(self):
        for cambi in ({"installato": False, "porta_di_wg0": 51820}, {"installato": True, "porta_di_wg0": 51821},
                      {"installato": True, "porta_di_wg0": None}):
            with self.subTest(**cambi):
                c = self.esiti(porte_libere={"udp/51820": False, "tcp/8443": True}, **cambi)["porta-udp-51820"]
                self.assertEqual(c["esito"], "FALLITO")

    def test_la_tcp_occupata_resta_fallita_anche_su_un_host_installato(self):
        c = self.esiti(porte_libere={"udp/51820": True, "tcp/8443": False}, installato=True, porta_di_wg0=8443)["porta-tcp-8443"]
        self.assertEqual(c["esito"], "FALLITO")

    def test_la_rete_di_wg0_si_esclude_solo_se_chiesto(self):
        ip = json.dumps([{"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]},
                         {"ifname": "wg0", "addr_info": [{"family": "inet", "local": "10.66.0.1", "prefixlen": 24}]},
                         {"ifname": "eth0", "addr_info": [{"family": "inet", "local": "192.168.1.10", "prefixlen": 24}]}])
        finto = lambda *a, **k: (0, ip) if a == ("ip", "-j", "addr") else (1, "")
        with mock.patch.object(preflight, "_comando", finto):
            self.assertEqual(preflight._reti_host(escludi="wg0"), ["127.0.0.0/8", "192.168.1.0/24"])
            self.assertIn("10.66.0.0/24", preflight._reti_host())  # senza esclusione la rete di wg0 c'e'


if __name__ == "__main__":
    unittest.main()
