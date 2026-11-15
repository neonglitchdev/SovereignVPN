#!/usr/bin/env python3
"""Verifica indipendente della verifica incrociata delle 49 ambiguita', letta dal registro (docs/lettore-nuovo-1.md).
Uso: python3 tests/verifica_incrociata.py <progetto>"""
import collections, pathlib, re, sys
P = pathlib.Path(sys.argv[1])
blocchi = {}
for f in sorted((P / "corpus").glob("*.md")):
    pz = re.split(r"<!-- (ANC-\d{4}) -->", f.read_text(encoding="utf-8"))
    for i in range(1, len(pz), 2):
        blocchi[pz[i]] = pz[i + 1]
n = lambda s: " ".join(re.sub(r"[^\w]+", " ", s).lower().split())
registro = {}
DOC = (P / "docs/lettore-nuovo-1.md").read_text(encoding="utf-8")
for r in DOC.split("## Registro delle ambiguità", 1)[-1].split("\n## ", 1)[0].splitlines():
    m = re.match(r"^\|\s*(\d+)\s*\|\s*(ANC-\d{4})\s*\|", r)
    if m: registro[int(m.group(1))] = m.group(2)
ATTESI = [x for x in range(1, 53) if x not in (28, 36, 38)]
SEZIONE = DOC.split("## Verifica incrociata delle altre 49", 1)[-1].split("\n## ", 1)[0]

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

righe, tutti_errori = esamina(SEZIONE)
nums = sorted(x for x, _ in righe)
if nums != ATTESI: tutti_errori.append(f"righe mancanti {sorted(set(ATTESI) - set(nums))}, in piu' {sorted(set(nums) - set(ATTESI))}")
totale = collections.Counter("chiusa" if e.startswith("chiusa") else "parziale" if e.startswith("parziale") else "aperta" for _, e in righe)
for e in tutti_errori: print("  ERRORE:", e)
print(f"righe esaminate: {len(righe)} su {len(ATTESI)}; chiuse {totale['chiusa']}, parziali {totale['parziale']}, aperte {totale['aperta']}")
# controllo negativo: una citazione alterata in una riga non aperta deve essere presa
t = SEZIONE
m = re.search(r"^\|\s*\d+\s*\|[^|]*\|\s*(chiusa|parziale)[^|]*\|[^|]*\|[^«]*«([^«»]+)»", t, re.M)
mut = t.replace("«" + m.group(2) + "»", "«" + m.group(2) + " parolainventatissima»", 1)
_, e2 = esamina(mut)
print("controllo negativo (citazione alterata):", "PRESO" if len(e2) > len(esamina(t)[1]) else "NON PRESO — verifica cieca")
sys.exit(0 if not tutti_errori else 1)
