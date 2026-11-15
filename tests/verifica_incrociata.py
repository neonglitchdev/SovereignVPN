#!/usr/bin/env python3
"""Verifica indipendente dei due lotti della verifica incrociata (scritta dopo che i lettori hanno finito).
Uso: verifica_lotti.py <progetto> <lotto-1.md> <lotto-2.md>"""
import collections, pathlib, re, sys
P = pathlib.Path(sys.argv[1]); lotti = [pathlib.Path(x) for x in sys.argv[2:]]
blocchi = {}
for f in sorted((P / "corpus").glob("*.md")):
    pz = re.split(r"<!-- (ANC-\d{4}) -->", f.read_text(encoding="utf-8"))
    for i in range(1, len(pz), 2):
        blocchi[pz[i]] = pz[i + 1]
n = lambda s: " ".join(re.sub(r"[^\w]+", " ", s).lower().split())
registro = {}
for r in (P / "docs/lettore-nuovo-1.md").read_text(encoding="utf-8").splitlines():
    m = re.match(r"^\|\s*(\d+)\s*\|\s*(ANC-\d{4})\s*\|", r)
    if m: registro[int(m.group(1))] = m.group(2)
ATTESI = [list(range(1, 27)), [x for x in range(27, 53) if x not in (28, 36, 38)]]

def esamina(testo):
    righe, errori = [], []
    for r in testo.splitlines():
        if not re.match(r"^\|\s*\d+\s*\|", r): continue
        c = [x.strip() for x in r.strip().strip("|").split("|")]
        num, anc, esito, prova, cit = int(c[0]), c[1], c[2].lower(), c[3], c[4]
        righe.append((num, esito))
        if registro.get(num) != anc: errori.append(f"riga {num}: ancora {anc}, nel registro {registro.get(num)}")
        if esito.startswith("aperta"):
            continue
        anc_prova = re.findall(r"ANC-\d{4}", prova)
        citazioni = re.findall(r"«([^«»]+)»", cit)
        if not anc_prova or not citazioni:
            errori.append(f"riga {num}: esito «{esito}» senza ancora o senza citazione"); continue
        for q in citazioni:
            if not any(a in blocchi and n(q) in n(blocchi[a]) for a in anc_prova):
                errori.append(f"riga {num}: citazione non ritrovata nelle ancore {anc_prova}: «{q[:70]}»")
    return righe, errori

totale = collections.Counter(); tutti_errori = []
for i, f in enumerate(lotti):
    testo = f.read_text(encoding="utf-8")
    righe, errori = esamina(testo)
    nums = [x for x, _ in righe]
    if sorted(nums) != ATTESI[i]: errori.append(f"{f.name}: righe {sorted(set(ATTESI[i]) - set(nums))} mancanti, {sorted(set(nums) - set(ATTESI[i]))} in piu'")
    conto = collections.Counter("chiusa" if e.startswith("chiusa") else "parziale" if e.startswith("parziale") else "aperta" for _, e in righe)
    totale += conto
    print(f"{f.name}: righe {len(righe)} su {len(ATTESI[i])}; chiuse {conto['chiusa']}, parziali {conto['parziale']}, aperte {conto['aperta']}; errori {len(errori)}")
    tutti_errori += errori
for e in tutti_errori: print("  ERRORE:", e)
print(f"TOTALE: {sum(totale.values())} righe su 49; chiuse {totale['chiusa']}, parziali {totale['parziale']}, aperte {totale['aperta']}")
# controllo negativo: una citazione alterata in una riga non aperta deve essere presa
t = lotti[0].read_text(encoding="utf-8")
m = re.search(r"^\|\s*\d+\s*\|[^|]*\|\s*(chiusa|parziale)[^|]*\|[^|]*\|[^«]*«([^«»]+)»", t, re.M)
mut = t.replace("«" + m.group(2) + "»", "«" + m.group(2) + " parolainventatissima»", 1)
_, e2 = esamina(mut)
print("controllo negativo (citazione alterata):", "PRESO" if len(e2) > len(esamina(t)[1]) else "NON PRESO — verifica cieca")
sys.exit(0 if not tutti_errori else 1)
