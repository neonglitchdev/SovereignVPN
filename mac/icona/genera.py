#!/usr/bin/env python3
"""Rigenera mac/AppIcon.icns da mac/icona/logo.svg: le 10 misure dell'iconset di macOS rese da Chromium (Playwright),
poi `iconutil`. Si lancia solo quando il logo cambia; build.sh usa l'.icns gia' pronto.
Uso: python3 mac/icona/genera.py"""
import pathlib, subprocess, tempfile
from playwright.sync_api import sync_playwright

QUI = pathlib.Path(__file__).resolve().parent
SVG = (QUI / "logo.svg").read_text()
MISURE = [(16, 1), (16, 2), (32, 1), (32, 2), (128, 1), (128, 2), (256, 1), (256, 2), (512, 1), (512, 2)]

with tempfile.TemporaryDirectory() as t:
    iconset = pathlib.Path(t) / "AppIcon.iconset"
    iconset.mkdir()
    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page()
        for punti, scala in MISURE:
            n = punti * scala
            pg.set_viewport_size({"width": n, "height": n})
            pg.set_content('<html><body style="margin:0;background:transparent">'
                           + SVG.replace("<svg ", '<svg width="%d" height="%d" ' % (n, n), 1) + "</body></html>")
            nome = "icon_%dx%d%s.png" % (punti, punti, "@2x" if scala == 2 else "")
            pg.screenshot(path=str(iconset / nome), omit_background=True)
        b.close()
    subprocess.run(["iconutil", "-c", "icns", str(iconset), "-o", str(QUI.parent / "AppIcon.icns")], check=True)
print("scritta", QUI.parent / "AppIcon.icns")
