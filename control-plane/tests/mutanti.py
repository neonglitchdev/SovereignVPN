#!/usr/bin/env python3
"""Banco dei mutanti del control plane: le prove valgono solo se un guasto vero le fa diventare rosse
e un cambiamento innocuo le lascia verdi.
Uso, da control-plane/: python3 tests/mutanti.py      (esce 0 solo se tutti i guasti sono presi e tutti gli innocui sopravvivono)

Ogni mutante gira su una copia in una cartella temporanea propria, tolta alla fine. Il codice di uscita di unittest
si controlla: 0 = verde, 1 = prove rosse; qualunque altro valore e' un guasto dello strumento e ferma il banco.
"""
import pathlib, shutil, subprocess, sys, tempfile

QUI = pathlib.Path(__file__).resolve().parents[1]  # control-plane/
GUASTI = {  # devono essere PRESI: almeno una prova rossa
    "il controllo del sistema dice sempre OK": ("preflight.py", "(sist, ver) in SISTEMI, f\"{sist} {ver}\"", "True, f\"{sist} {ver}\""),
    "nessun controllo dell'intervallo della porta": ("preflight.py", "if not 1 <= n <= 65535:", "if False:"),
    "IPAM che ignora le collisioni": ("preflight.py", "return str(rete), [str(o) for o in occupate if o.overlaps(rete)]", "return str(rete), []"),
    "il preflight scrive un file": ("preflight.py", "    os_rel = {}\n", "    os_rel = {}\n    open('/tmp/sovereign-mutante', 'w').close()\n"),
    "zero reti lette passa come nessuna collisione": ("preflight.py", "    if not fatti[\"reti_host\"]:", "    if False:"),
    "chiavi sconosciute accettate": ("configurazione.py", "sconosciuti = sorted(set(dati) - CAMPI)", "sconosciuti = []"),
    "il segreto finisce nell'errore": ("configurazione.py", "raise _errore(k, \"un segreto in chiaro", "raise _errore(k, f\"{dati[k]} un segreto in chiaro"),
    "MTU senza limiti": ("configurazione.py", "not 1280 <= mtu <= 1500", "False"),
    "la CLI ignora il file di configurazione": ("__main__.py", "if da_cli is None and campo in cfg:", "if False:"),
}
INNOCUI = {  # devono SOPRAVVIVERE: stesso comportamento, prove verdi
    "un rimedio detto con altre parole": ("preflight.py", "\"Liberare spazio: servono almeno", "\"Fare spazio: servono almeno"),
    "una variabile locale rinominata": ("preflight.py", "    gib = fatti[\"disco_libero\"] / 1024 ** 3\n", "    giga = fatti[\"disco_libero\"] / 1024 ** 3\n    gib = giga\n"),
}


def prova(file, da, a):
    with tempfile.TemporaryDirectory(prefix="mutante-") as t:
        copia = pathlib.Path(t) / "control-plane"
        shutil.copytree(QUI, copia, ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(QUI.parent / "config", pathlib.Path(t) / "config")
        f = copia / "sovereignctl" / file
        testo = f.read_text(encoding="utf-8")
        if testo.count(da) != 1:
            sys.exit(f"GUASTO DEL BANCO: punto di mutazione non univoco in {file}: {da[:60]!r}")
        f.write_text(testo.replace(da, a), encoding="utf-8")
        r = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests"], cwd=copia, capture_output=True, text=True)
        if r.returncode not in (0, 1):
            sys.exit(f"GUASTO DEL BANCO: unittest e' uscito con {r.returncode}\n{r.stderr[-800:]}")
        rosse = [l.split("(")[0].split(": ", 1)[-1].strip() for l in r.stderr.splitlines() if l.startswith(("FAIL:", "ERROR:"))]
        return r.returncode, rosse


if __name__ == "__main__":
    base, rosse = prova("__init__.py", "VERSIONE", "VERSIONE")  # nessun cambiamento: la suite di partenza dev'essere verde
    if base != 0:
        sys.exit(f"GUASTO DEL BANCO: la suite senza mutazioni e' rossa ({', '.join(rosse)})")
    presi = 0
    for nome, (file, da, a) in GUASTI.items():
        codice, rosse = prova(file, da, a)
        presi += codice == 1
        print(f"{'PRESO      ' if codice == 1 else 'SFUGGITO   '} {nome}: {len(rosse)} prove rosse — {', '.join(rosse)[:150]}")
    vivi = 0
    for nome, (file, da, a) in INNOCUI.items():
        codice, rosse = prova(file, da, a)
        vivi += codice == 0
        print(f"{'SOPRAVVIVE ' if codice == 0 else 'UCCISO     '} {nome} (innocuo){': ' + ', '.join(rosse) if rosse else ''}")
    print(f"guasti presi: {presi} su {len(GUASTI)}; innocui sopravvissuti: {vivi} su {len(INNOCUI)}")
    sys.exit(0 if presi == len(GUASTI) and vivi == len(INNOCUI) else 1)
