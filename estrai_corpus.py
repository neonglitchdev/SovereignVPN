#!/usr/bin/env python3
# estrai_corpus.py v2 — corpus ancorato da un .docx. Stdlib sola, mai pandoc in lettura.
# Ricomposto il 15/11 dalla chat con Atlante: testa della v2 delle 09:23 (troncata), coda della v1 delle 08:01
# (con `righe, primo = [...]` corretto in `righe = [...]`, che faceva cadere la v1), cancello dell'impronta delle 08:05.
import json, re, sys, zipfile, hashlib, xml.etree.ElementTree as ET
from pathlib import Path
VERSIONE_GENERATORE = 2  # v2: impronta di sorgente e regole nel profilo
W = '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'
APPENDICE = re.compile(r'(?i)^\s*appendice\s+\d+\.[0-9a-z]')
def testo(el): return ''.join(t.text or '' for t in el.iter(W + 't'))
def norm(s): return ''.join(s.replace('\\', '').split()).lower()
def blocchi_di(el):
    for e in el:  # paragrafi e tabelle in ordine documento, scendendo nei content control
        if e.tag == W + 'p': yield ('p', e)
        elif e.tag == W + 'tbl': yield ('tbl', e)
        elif e.tag == W + 'sdt':
            c = e.find(W + 'sdtContent')
            yield from blocchi_di(c if c is not None else e)
def livello(p):
    pPr = p.find(W + 'pPr')
    if pPr is None: return 0
    st = pPr.find(W + 'pStyle')
    v = (st.get(W + 'val') or '') if st is not None else ''
    if v == 'Title': return 1
    m = re.fullmatch(r'Heading(\d)', v)
    return int(m.group(1)) if m else 0
def gfm(righe):
    ncol = max(len(r) for r in righe)
    c = lambda s: s.replace('|', '\\|').replace('\n', ' ') or '—'
    out = ['| ' + ' | '.join(c(x) for x in righe[0] + ['—'] * (ncol - len(righe[0]))) + ' |',
           '|' + '---|' * ncol]
    for r in righe[1:]:
        out.append('| ' + ' | '.join(c(x) for x in r + ['—'] * (ncol - len(r))) + ' |')
    return out
def slug(t): return re.sub(r'[^a-z0-9]+', '-', t.lower())[:40].strip('-') or 'capitolo'
def impronta(b): return hashlib.sha256(b).hexdigest()[:16]
def main(src, outdir):
    out = Path(outdir); out.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(src) as z: xml = z.read('word/document.xml')
    root = ET.fromstring(xml); body = root.find(W + 'body')
    prof = {'tabelle': len(root.findall('.//' + W + 'tbl')),
            'celle': len(root.findall('.//' + W + 'tc')),
            'celle_unite': len(root.findall('.//' + W + 'gridSpan')) + len(root.findall('.//' + W + 'vMerge')),
            'sdt': len(root.findall('.//' + W + 'sdt')),
            'tabelle_annidate': sum(len(t.findall('.//' + W + 'tbl')) for t in body.findall(W + 'tbl'))}
    prof['generatore'] = {'versione': VERSIONE_GENERATORE,
                          'impronta_script': impronta(Path(__file__).read_bytes()),
                          'impronta_document_xml': impronta(xml),
                          'sorgente': Path(src).name}
    # cancello che morde: definizione cambiata e numero no → rosso
    p = out / 'profilo.json'
    if p.exists():
        g = json.loads(p.read_text(encoding='utf-8')).get('generatore', {})
        if g.get('impronta_script') != prof['generatore']['impronta_script'] \
           and g.get('versione') == VERSIONE_GENERATORE:
            sys.exit('ROSSO: lo script è cambiato ma VERSIONE_GENERATORE no — alza il numero')
    seq = []  # ('h', livello, testo) | ('p', 0, testo) | ('tbl', righe_di_celle)
    for tipo, el in blocchi_di(body):
        if tipo == 'p':
            t = testo(el).strip()
            if not t: continue
            lvl = livello(el)
            if lvl and lvl <= 3: seq.append(('h', lvl, t))
            elif APPENDICE.match(t): seq.append(('h', 1, t))
            else: seq.append(('p', 0, t))
        else:
            righe = [[testo(tc).strip() for tc in tr.findall(W + 'tc')] for tr in el.findall(W + 'tr')]
            if righe: seq.append(('tbl', righe))
    docx_txt = norm(testo(body))
    blocchi_txt = norm(''.join(b[2] if b[0] != 'tbl' else ''.join(''.join(r) for r in b[1]) for b in seq))
    assert blocchi_txt == docx_txt, f'testo perso: docx={len(docx_txt)} blocchi={len(blocchi_txt)}'
    cap, cur = [], ['(apertura)', []]
    cap.append(cur)
    for b in seq:
        if b[0] == 'h' and b[1] == 1: cur = [b[2], []]; cap.append(cur)
        else: cur[1].append(b)
    indice, n = [], 0
    for i, (tit, bl) in enumerate(cap):
        nome = f'{i:02d}-{slug(tit)}.md'; righe = ['# ' + tit, '']
        for b in bl:
            n += 1; anc = f'ANC-{n:04d}'; riga = len(righe) + 1
            righe.append(f'<!-- {anc} -->')
            if b[0] == 'tbl':
                righe.extend(gfm(b[1]))
                if prof['celle_unite']: righe.append('<!-- celle unite: verificare -->')
                t0 = next((x for r in b[1] for x in r if x), '')
                indice.append({'ancora': anc, 'file': nome, 'riga': riga, 'tipo': 'tbl', 'testo': t0[:80]})
            else:
                righe.append(('#' * b[1] + ' ' + b[2]) if b[0] == 'h' else b[2])
                indice.append({'ancora': anc, 'file': nome, 'riga': riga,
                               'tipo': f'h{b[1]}' if b[0] == 'h' else 'p', 'testo': b[2][:80]})
        (out / nome).write_text('\n'.join(righe) + '\n', encoding='utf-8')
    cache, presenti = {}, 0
    for v in indice:
        t = norm(v['testo'])
        if not t: presenti += 1; continue
        txt = cache.setdefault(v['file'], (out / v['file']).read_text(encoding='utf-8'))
        presenti += (t in norm(txt))
    prof.update({'capitoli': len(cap), 'blocchi': len(indice), 'presenti_nel_corpus': presenti})
    (out / 'indice.json').write_text(json.dumps(indice, ensure_ascii=False, indent=1), encoding='utf-8')
    p.write_text(json.dumps(prof, ensure_ascii=False, indent=1), encoding='utf-8')
    print(f"PROFILO  tabelle={prof['tabelle']} (annidate {prof['tabelle_annidate']})  celle={prof['celle']}  "
          f"celle_unite={prof['celle_unite']}  sdt={prof['sdt']}")
    print(f"CORPUS   capitoli={len(cap)}  blocchi={len(indice)}  presenti={presenti}/{len(indice)}")
    print(f"TESTO    assert superato: nessun carattere perso")
    print(f"OUTPUT   {out}/  (indice.json, profilo.json, {len(cap)} .md)")
    if prof['celle_unite'] or prof['tabelle_annidate']:
        print('ATTENZIONE: celle unite/annidate > 0 → le tabelle marcate vanno rivedute prima della resa')
if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
