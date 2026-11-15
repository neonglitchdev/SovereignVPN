# tests/prova_corpus.py — copertura sana = verde; estrattore stropiato = rosso obbligatorio
# I file di prova vivono in una cartella temporanea propria, tolta alla fine (niente /tmp fissi, niente prova.docx nella repo).
import sys, tempfile; from pathlib import Path
sys.path.insert(0, '.')
import estrai_corpus as ec, fabbrica_docx as fd
with tempfile.TemporaryDirectory(prefix='prova-corpus-') as cartella:
    t = Path(cartella); docx = str(t / 'prova.docx')
    attese = fd.fabbrica(docx)
    out = t / 'sano'; ec.main(docx, str(out))
    md = ''.join(f.read_text() for f in out.glob('*.md'))
    mancanti = [f for f in attese if f not in md]
    assert not mancanti, f'controprova: mancano {mancanti}'
    def cieca(el):  # mutazione: non discende più nei w:sdt
        for e in el:
            if e.tag == ec.W+'p': yield ('p', e)
            elif e.tag == ec.W+'tbl': yield ('tbl', e)
    ec.blocchi_di = cieca
    rotto = False
    try:
        ec.main(docx, str(t / 'rotto'))
        md2 = ''.join(f.read_text() for f in (t / 'rotto').glob('*.md'))
        rotto = attese[2] not in md2
    except AssertionError:
        rotto = True
    assert rotto, 'CIECO: la mutazione non fa dire rosso al controllo'
print('OK: copertura sana verde, mutazione sdt rossa — il controllo vede.')
