#!/usr/bin/env bash
# Prova del backup VERO (runner Linux, root) con age vero (FR-OPS-001, H20): sull'installazione lasciata da
# prova_init_vero.sh. La chiave privata age resta fuori dal «server» (in una cartella temporanea della prova): il
# backup si decifra solo con lei, non con un'altra chiave, e non se il file e' manomesso; dentro ci sono gli stessi
# byte dei file vivi (il registro con le stesse righe), e accanto un manifest senza segreti.
#   sudo bash control-plane/tests/prova_init_vero.sh && sudo bash control-plane/tests/prova_backup_vero.sh
set -Eeuo pipefail
IFS=$'\n\t'
[ "$(id -u)" -eq 0 ] || { echo "prova_backup_vero: serve root"; exit 1; }
for c in age age-keygen tar; do command -v "$c" >/dev/null || { echo "prova_backup_vero: serve $c"; exit 1; }; done
rosso() { echo "ROSSO: $*"; exit 1; }
CHIAVE=/etc/sovereignvpn/wg-server.key
REGISTRO=/var/lib/sovereignvpn/registro.sqlite3
for f in "$CHIAVE" "$REGISTRO" /var/lib/sovereignvpn/manifest.json /etc/sovereignvpn/server.toml; do
  [ -f "$f" ] || rosso "manca $f: prima prova_init_vero.sh"
done
D="$(mktemp -d)"
trap 'rm -rf "$D"' EXIT
cd "$(dirname "$0")/.."
age-keygen -o "$D/identita.txt" 2>/dev/null
DEST="$(age-keygen -y "$D/identita.txt")"
R="$(python3 -m sovereignctl backup create --config /etc/sovereignvpn/server.toml --recipient "$DEST" --out "$D/backup" --json)"
FILE="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["percorso"])' "$R")"
MAN="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["manifest"])' "$R")"
[ "$(stat -c '%a %a' "$FILE" "$MAN")" = "600 600" ] || rosso "backup o manifest non 0600"
[ "$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["checksum"])' "$R")" = "sha256:$(sha256sum "$FILE" | cut -d' ' -f1)" ] || rosso "checksum stampato diverso dal file"
if grep -qF "$(cat "$CHIAVE")" "$MAN" - <<<"$R"; then rosso "la chiave del server e' nel manifest o a schermo"; fi
if grep -qaF "$(cat "$CHIAVE")" "$FILE"; then rosso "la chiave del server si legge in chiaro nel file cifrato"; fi
echo "OK: backup cifrato verso $DEST, 0600, checksum giusto, nessun segreto in chiaro"

# si decifra con la chiave giusta, e dentro ci sono gli stessi byte dei file vivi
age -d -i "$D/identita.txt" -o "$D/archivio.tar" "$FILE"
mkdir "$D/dentro"
tar -xf "$D/archivio.tar" -C "$D/dentro"
for f in etc/sovereignvpn/server.toml etc/sovereignvpn/wg-server.key var/lib/sovereignvpn/manifest.json; do
  cmp -s "$D/dentro/$f" "/$f" || rosso "$f nel backup diverso dal file vivo"
done
python3 - "$REGISTRO" "$D/dentro/var/lib/sovereignvpn/registro.sqlite3" "$D/dentro/backup-manifest.json" <<'PY'
import hashlib, json, pathlib, sqlite3, sys
vivo, copia, manifest = sys.argv[1:]
righe = lambda p: sorted(sqlite3.connect(f"file:{p}?mode=ro", uri=True).execute("SELECT id, chiave_pubblica, indirizzo, stato FROM peer"))
a, b = righe(vivo), righe(copia)
if not a or a != b:
    sys.exit(f"ROSSO: registro nel backup diverso dal vivo ({len(b)} righe contro {len(a)})")
m = json.loads(pathlib.Path(manifest).read_text())
base = pathlib.Path(copia).parents[3]
for f in m["file"]:
    if hashlib.sha256((base / f["nome"]).read_bytes()).hexdigest() != f["sha256"]:
        sys.exit(f"ROSSO: sha256 di {f['nome']} diverso dal manifest")
print(f"OK: decifrato con la chiave giusta: {len(m['file'])} file su {len(m['file'])} col checksum del manifest, registro con {len(a)} peer come il vivo")
PY

# e solo con quella: un'altra chiave e un file manomesso non si decifrano
age-keygen -o "$D/altra.txt" 2>/dev/null
if age -d -i "$D/altra.txt" -o /dev/null "$FILE" 2>/dev/null; then rosso "il backup si decifra con un'altra chiave"; fi
cp "$FILE" "$D/manomesso.age"
python3 - "$D/manomesso.age" <<'PY'
import sys
b = bytearray(open(sys.argv[1], "rb").read()); b[-10] ^= 0x01; open(sys.argv[1], "wb").write(b)
PY
if age -d -i "$D/identita.txt" -o /dev/null "$D/manomesso.age" 2>/dev/null; then rosso "un backup manomesso si decifra lo stesso"; fi
echo "OK: un'altra chiave non decifra, un byte cambiato rende il backup illeggibile"
