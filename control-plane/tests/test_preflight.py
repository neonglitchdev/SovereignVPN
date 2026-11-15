"""Prove di `sovereignctl init --check` (FR-BOOT-001/003/004, T-003, T-004, codici di uscita ANC-0255).
Uso, da control-plane/: python3 -m unittest discover -s tests"""
import builtins, contextlib, io, os, shutil, subprocess, unittest
from unittest import mock

from sovereignctl import __main__ as cli, preflight

BUONI = {"os": ("debian", "12"), "architettura": "x86_64", "kernel": "6.1.0-26-amd64", "docker": "27.3.1",
         "compose": "2.29.7", "wireguard": True, "disco_libero": 40 * 1024 ** 3, "ntp": True,
         "porte_libere": {"udp/51820": True, "tcp/8443": True}, "reti_host": ["192.168.1.0/24", "172.17.0.0/16"]}


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
        self.assertIn("Controlli eseguiti: 11 su 11; superati: 11; falliti: 0", out)
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

    def test_nessuna_mutazione(self):
        tentativi = []
        apri = builtins.open
        esegui_vero = subprocess.run

        def open_solo_lettura(f, mode="r", *a, **k):
            if any(c in mode for c in "wax+"):
                tentativi.append(("open", f, mode)); raise PermissionError("scrittura vietata nel dry-run")
            return apri(f, mode, *a, **k)

        def run_controllato(args, *a, **k):
            if os.path.basename(args[0]) in self.MUTANTI or args[:2] in (["ip", "link"], ["ip", "route"]) and len(args) > 2 and args[2] in ("add", "del", "set", "replace"):
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


if __name__ == "__main__":
    unittest.main()
