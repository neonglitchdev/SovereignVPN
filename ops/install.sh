#!/usr/bin/env bash
# install.sh — installa il control plane di SovereignVPN (Slice A, ANC-0346) seguendo ANC-0342:
# set -Eeuo pipefail, IFS controllato, trap d'errore sanitizzato, pulizia e lucchetto, --dry-run, prerequisiti
# controllati, idempotente, errore di validazione (2) distinto da errore runtime (1). Non stampa mai chiavi o token.
#
#   sudo ops/install.sh [--dry-run]          installa sotto /
#   ops/install.sh --radice DIR [--dry-run]  installa sotto DIR (prove, immagini, chroot)
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

DRY=0
RADICE=""
LUCCHETTO=""
pulizia() { [ -n "$LUCCHETTO" ] && rmdir "$LUCCHETTO" 2>/dev/null || true; }
trap pulizia EXIT
trap 'echo "install.sh: errore runtime alla riga $LINENO; nessun valore stampato, nessun passo successivo eseguito" >&2' ERR
invalido() { echo "install.sh: input non valido: $1" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --radice) [ $# -ge 2 ] || invalido "--radice senza cartella"; RADICE="$2"; shift ;;
    -h|--help) sed -n '2,7p' "$0"; exit 0 ;;
    *) invalido "opzione sconosciuta «${1}»" ;;
  esac
  shift
done
if [ -n "$RADICE" ]; then
  [ -d "$RADICE" ] || invalido "--radice: la cartella «${RADICE}» non esiste"
  RADICE="$(cd "$RADICE" && pwd)"
fi

SORGENTE="$(cd "$(dirname "$0")/.." && pwd)/control-plane/sovereignctl"
SORGENTE_UNITA="$(cd "$(dirname "$0")" && pwd)/systemd/sovereignvpn-reconcile.service"
OPT="$RADICE/opt/sovereignvpn"
ETC="$RADICE/etc/sovereignvpn"
VAR="$RADICE/var/lib/sovereignvpn"
BIN="$RADICE/usr/local/bin"
UNITA="$RADICE/etc/systemd/system/sovereignvpn-reconcile.service"

# prerequisiti (errori runtime: codice 1)
[ -f "$SORGENTE/__main__.py" ] || { echo "install.sh: sorgente del control plane mancante in $SORGENTE" >&2; exit 1; }
[ -f "$SORGENTE_UNITA" ] || { echo "install.sh: unita' systemd mancante in $SORGENTE_UNITA" >&2; exit 1; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
  || { echo "install.sh: serve Python 3.11 o successivo (ANC-0334)" >&2; exit 1; }
if [ -z "$RADICE" ] && [ "$DRY" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
  echo "install.sh: per installare sotto / serve root; per vedere il piano: --dry-run" >&2; exit 1
fi

PASSI=(
  "copiare il control plane in $OPT/sovereignctl (0755), sostituendo per rinomina la versione precedente"
  "creare $ETC (0700) per la configurazione"
  "creare $VAR (0700) per lo stato e il manifest"
  "scrivere il comando $BIN/sovereignctl (0755)"
  "installare l'unita' $UNITA (0644) e, sul sistema vero, abilitarla: a ogni avvio \`sovereignctl reconcile\`, solo dopo init --apply (FR-NET-007)"
)
if [ "$DRY" -eq 1 ]; then
  echo "install.sh --dry-run: nessuna mutazione. Piano:"
  n=1; for p in "${PASSI[@]}"; do echo "  $n. $p"; n=$((n + 1)); done
  exit 0
fi

mkdir -p "$RADICE/opt"
LUCCHETTO="$RADICE/opt/.sovereignvpn-install.lock"
mkdir "$LUCCHETTO" 2>/dev/null || { LUCCHETTO=""; echo "install.sh: un'altra installazione e' in corso (lucchetto presente)" >&2; exit 1; }

# 1. control plane: copia accanto, poi rinomina (mai una cartella a meta')
install -d -m 0755 "$OPT"
rm -rf "$OPT/sovereignctl.nuovo" "$OPT/sovereignctl.vecchio"
cp -R "$SORGENTE" "$OPT/sovereignctl.nuovo"
find "$OPT/sovereignctl.nuovo" -name __pycache__ -type d -prune -exec rm -rf {} +
chmod -R u=rwX,go=rX "$OPT/sovereignctl.nuovo"
[ -d "$OPT/sovereignctl" ] && mv "$OPT/sovereignctl" "$OPT/sovereignctl.vecchio"
mv "$OPT/sovereignctl.nuovo" "$OPT/sovereignctl"
rm -rf "$OPT/sovereignctl.vecchio"

# 2-3. configurazione e stato, solo il proprietario
install -d -m 0700 "$ETC" "$VAR"
chmod 0700 "$ETC" "$VAR"

# 4. comando: scritto accanto e rinominato
install -d -m 0755 "$BIN"
TMP="$BIN/.sovereignctl.nuovo"
printf '#!/bin/sh\nexec python3 -I -c '\''import sys; sys.path.insert(0, "%s"); from sovereignctl.__main__ import main; sys.exit(main())'\'' "$@"\n' "$OPT" > "$TMP"
chmod 0755 "$TMP"
mv "$TMP" "$BIN/sovereignctl"

# 5. unita' del ripristino al riavvio: scritta accanto e rinominata; abilitata solo dove systemd e' davvero in funzione
install -d -m 0755 "$(dirname "$UNITA")"
install -m 0644 "$SORGENTE_UNITA" "$UNITA.nuovo"
mv "$UNITA.nuovo" "$UNITA"
if [ -z "$RADICE" ] && [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  systemctl enable --quiet sovereignvpn-reconcile.service
fi

echo "install.sh: installato. Control plane in $OPT, configurazione in $ETC, stato in $VAR."
echo "Prossimo passo: sovereignctl init --check --config $ETC/server.toml"
