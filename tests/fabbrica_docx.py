# tests/fabbrica_docx.py — docx minimo con contenuto noto: uno zip con solo document.xml
import zipfile
NS = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'
FRASI = [('titolo', 'SOVEREIGNVPN prova'),
         ('p', "Frase nell'apertura, con l'apostrofo."),
         ('sdt', 'Frase dentro un content control.'),
         ('p', 'Frase dopo il content control.')]
TABELLA = [['Campo', 'Valore'], ['Nome', 'prova']]
def p(t, stile=None):
    s = f'<w:pPr><w:pStyle w:val="{stile}"/></w:pPr>' if stile else ''
    return f'<w:p>{s}<w:r><w:t xml:space="preserve">{t}</w:t></w:r></w:p>'
def fabbrica(percorso='prova.docx'):
    pezzi = [p(t, s) if s != 'sdt' else
             f'<w:sdt><w:sdtPr/><w:sdtContent>{p(t)}</w:sdtContent></w:sdt>' for s, t in FRASI]
    riga = ''.join(f'<w:tc>{p(c)}</w:tc>' for c in TABELLA[0])
    xml = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           f'<w:document xmlns:w="{NS}"><w:body>{"".join(pezzi)}'
           f'<w:tbl><w:tr>{riga}</w:tr></w:tbl><w:sectPr/></w:body></w:document>')
    with zipfile.ZipFile(percorso, 'w') as z: z.writestr('word/document.xml', xml)
    return [t for _, t in FRASI] + TABELLA[0]
