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
    "le chiavi WireGuard non vengono redatte": ("registro.py", "    t = _CHIAVE_WG.sub(\"[CHIAVE REDATTA]\", t)\n", ""),
    "il filtro lascia passare gli argomenti": ("registro.py", "        record.msg = redigi(record.getMessage())\n        record.args = ()\n", ""),
    "il manifest accetta segreti e URL": ("manifest.py", "    if redigi(testo) != testo:", "    if False:"),
    "il manifest accetta il tag latest": ("manifest.py", "        if nome.endswith(\":latest\"):", "        if False:"),
    "scrittura diretta sul file vero, non atomica": ("manifest.py", "fd, tmp = tempfile.mkstemp(prefix=\".manifest-\", dir=cartella)", "fd, tmp = os.open(percorso, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644), percorso"),
    "il dry-run dell'installer muta": ("ops/install.sh", 'if [ "$DRY" -eq 1 ]; then', "if false; then"),
    "l'installer ignora il lucchetto": ("ops/install.sh", 'mkdir "$LUCCHETTO" 2>/dev/null ||', 'mkdir -p "$LUCCHETTO" 2>/dev/null ||'),
    "configurazione leggibile da tutti": ("ops/install.sh", 'chmod 0700 "$ETC" "$VAR"', 'chmod 0755 "$ETC" "$VAR"'),
    "input non valido dell'installer esce con 1": ("ops/install.sh", 'echo "install.sh: input non valido: $1" >&2; exit 2; }', 'echo "install.sh: input non valido: $1" >&2; exit 1; }'),
    "la revoca torna indietro": ("peer.py", '    ("ERROR", "revoke"): "REVOKED",\n', '    ("ERROR", "revoke"): "REVOKED", ("REVOKED", "resume"): "ACTIVE",\n'),
    "nomi confrontati con le maiuscole": ("peer.py", "return n, n.casefold()", "return n, n"),
    "chiave di lunghezza qualunque": ("peer.py", "if len(grezza) != 32 or ", "if False or "),
    "il server perde il suo indirizzo": ("peer.py", "host = list(rete.hosts())[1:]", "host = list(rete.hosts())"),
    "transizione respinta senza audit": ("peer.py", 'self.audit(c, f"peer.{azione}", "denied", p["id"], f"transizione non valida da {stato}")', "pass"),
    "il sospeso resta nel runtime": ("runtime.py", 'NEL_RUNTIME = ("PENDING", "ACTIVE")', 'NEL_RUNTIME = ("PENDING", "ACTIVE", "SUSPENDED")'),
    "chiave del server leggibile accettata": ("runtime.py", "    if modo & 0o077:", "    if False:"),
    "nessuna verifica del runtime": ("runtime.py", "coincide = vivi == attesi", "coincide = True"),
    "un cambio nel frattempo sovrascritto": ("runtime.py", "AND stato = ? AND saga = 'PENDING_APPLY'", "AND ? IS NOT NULL"),
    "redazione per eccesso: anche gli IP privati": ("registro.py", "if ipaddress.ip_address(m.group(0)).is_global else", "if True else"),
}
INNOCUI = {  # devono SOPRAVVIVERE: stesso comportamento, prove verdi
    "un rimedio detto con altre parole": ("preflight.py", "\"Liberare spazio: servono almeno", "\"Fare spazio: servono almeno"),
    "un segnaposto detto con altre parole": ("registro.py", "\"[URL REDATTO]\"", "\"[INDIRIZZO WEB REDATTO]\""),
    "un messaggio dell'installer detto con altre parole": ("ops/install.sh", "Prossimo passo:", "Passo successivo:"),
    "un messaggio del registro detto con altre parole": ("peer.py", "riprovare (CONFLICT)", "ritentare (CONFLICT)"),
    "un messaggio della riconciliazione detto con altre parole": ("runtime.py", "va creata da `init`", "la crea `init`"),
    "una variabile locale rinominata": ("preflight.py", "    gib = fatti[\"disco_libero\"] / 1024 ** 3\n", "    giga = fatti[\"disco_libero\"] / 1024 ** 3\n    gib = giga\n"),
}


def prova(file, da, a):
    with tempfile.TemporaryDirectory(prefix="mutante-") as t:
        repo = pathlib.Path(t) / "repo"  # tutta la repo senza .git: i mutanti possono toccare anche ops/ e config/
        shutil.copytree(QUI.parent, repo, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        copia = repo / "control-plane"
        f = repo / file if "/" in file else copia / "sovereignctl" / file
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
