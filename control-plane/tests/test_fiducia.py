"""Prova della riga «nessuna telemetria, per costruzione» di docs/decisions/fiducia.md (NFR-SEC-006) [H46]: nessun modulo
del control plane importa librerie di rete; `socket` solo in stato.py (domande DNS ai resolver locali), in preflight.py
(un bind locale per sapere se una porta e' libera) e in uscite.py (il nome di un'uscita al resolver del server, H50).
Uso, da control-plane/: python3 -m unittest discover -s tests"""
import ast, pathlib, tempfile, unittest

CARTELLA = pathlib.Path(__file__).resolve().parents[1] / "sovereignctl"
VIETATI = {"urllib", "http", "requests", "httpx", "smtplib", "ftplib", "telnetlib", "xmlrpc", "asyncio"}
SOCKET_AMMESSO = {"stato.py", "preflight.py", "uscite.py"}  # status: domande DNS in locale; preflight: un bind per sapere
# se la porta e' libera; uscite: il nome dell'uscita all'import e al failover (H50, dichiarato in docs/decisions/fiducia.md)


def importati(file):
    albero = ast.parse(file.read_text(encoding="utf-8"))
    nomi = set()
    for n in ast.walk(albero):
        if isinstance(n, ast.Import):
            nomi |= {a.name.split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom) and n.module and n.level == 0:
            nomi.add(n.module.split(".")[0])
    return nomi


def violazioni(cartella):
    v = []
    for f in sorted(cartella.glob("*.py")):
        imp = importati(f)
        v += [f"{f.name}: {x}" for x in sorted(imp & VIETATI)]
        if "socket" in imp and f.name not in SOCKET_AMMESSO:
            v.append(f"{f.name}: socket")
    return v


class NessunaRete(unittest.TestCase):
    def test_nessuna_libreria_di_rete_e_socket_solo_nello_status(self):
        file = list(CARTELLA.glob("*.py"))
        self.assertGreater(len(file), 10)  # la cartella giusta, non una vuota
        self.assertEqual(violazioni(CARTELLA), [])

    def test_la_prova_vede_un_import_vietato(self):
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "spia.py").write_text("import urllib.request\nfrom http import client\nimport socket\n")
            self.assertEqual(violazioni(pathlib.Path(d)), ["spia.py: http", "spia.py: urllib", "spia.py: socket"])


if __name__ == "__main__":
    unittest.main()
