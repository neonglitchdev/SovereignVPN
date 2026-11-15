#!/usr/bin/env python3
"""Verifica indipendente del rapporto del lettore (la sua copia l'ha riscritta lui). Ogni riga del registro: ancora vera,
file giusto, citazione dentro il blocco di quell'ancora. Controlli negativi: ancora inventata, frase inventata, e un
mutante del rapporto con una citazione alterata devono risultare ROSSI.  Uso: verifica_mia.py <progetto> <rapporto>"""
import pathlib, re, sys
P, R = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
blocchi = {}
for f in sorted((P / "corpus").glob("*.md")):
    pezzi = re.split(r"<!-- (ANC-\d{4}) -->", f.read_text(encoding="utf-8"))
    for i in range(1, len(pezzi), 2):
        blocchi[pezzi[i]] = (f.name, pezzi[i + 1])
n = lambda s: " ".join(re.sub(r"[^\w]+", " ", s.replace("\\|", "|")).lower().split())

def esamina(testo):
    righe = [r for r in testo.splitlines() if re.match(r"^\|\s*\d+\s*\|", r)]
    cattive = []
    for r in righe:
        c = [x.strip() for x in re.split(r"(?<!\\)\|", r.strip())[1:-1]]
        anc, fil, cit = c[1], c[2], c[3].strip("«»\"“” ")
        b = blocchi.get(anc)
        if not b or b[0] != fil or not n(cit) or n(cit) not in n(b[1]):
            cattive.append((c[0], anc, cit[:80]))
    return righe, cattive

testo = R.read_text(encoding="utf-8")
righe, cattive = esamina(testo)
print(f"righe del registro: {len(righe)}; citazioni ritrovate nel blocco della loro ancora e nel file giusto: {len(righe) - len(cattive)} su {len(righe)}")
for x in cattive: print("  ROSSA:", x)
# controlli negativi
assert "ANC-9999" not in blocchi
prima = righe[0]
mut = testo.replace(prima, re.sub(r"(\|\s*\d+\s*\|[^|]*\|[^|]*\|\s*«?)(\w+)", r"\1parolainventata", prima, count=1))
_, c2 = esamina(mut)
print("mutante (una citazione alterata):", "PRESO" if len(c2) == len(cattive) + 1 else "NON PRESO — verifica cieca")
sys.exit(0 if righe and not cattive and len(c2) == len(cattive) + 1 else 1)
