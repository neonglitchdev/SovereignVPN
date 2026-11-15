#!/usr/bin/env bash
# install.sh — installa il control plane di SovereignVPN (Slice A, ANC-0346) seguendo ANC-0342:
# set -Eeuo pipefail, IFS controllato, trap d'errore sanitizzato, pulizia e lucchetto, --dry-run, prerequisiti
# controllati, idempotente, errore di validazione (2) distinto da errore runtime (1). Non stampa mai chiavi o token.
#
#   sudo ops/install.sh [--dry-run]          installa sotto /
#   ops/install.sh --radice DIR [--dry-run]  installa sotto DIR (prove, immagini, chroot)
#   sudo ops/install.sh --rollback [--dry-run]  torna alla release installata prima di questa (FR-OPS-005)
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

DRY=0
INDIETRO=0
RADICE=""
LUCCHETTO=""
pulizia() { [ -n "$LUCCHETTO" ] && rmdir "$LUCCHETTO" 2>/dev/null || true; }
trap pulizia EXIT
trap 'echo "install.sh: errore runtime alla riga $LINENO; nessun valore stampato, nessun passo successivo eseguito" >&2' ERR
invalido() { echo "install.sh: input non valido: $1" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --rollback) INDIETRO=1 ;;
    --radice) [ $# -ge 2 ] || invalido "--radice senza cartella"; RADICE="$2"; shift ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) invalido "opzione sconosciuta «${1}»" ;;
  esac
  shift
done
if [ -n "$RADICE" ]; then
  [ -d "$RADICE" ] || invalido "--radice: la cartella «${RADICE}» non esiste"
  RADICE="$(cd "$RADICE" && pwd)"
fi

SORGENTE="$(cd "$(dirname "$0")/.." && pwd)/control-plane/sovereignctl"
SORGENTE_UNITA="$(cd "$(dirname "$0")" && pwd)/systemd"
SORGENTE_DNS="$(cd "$(dirname "$0")" && pwd)/dns"
UNITA_NOMI=(sovereignvpn-reconcile.service sovereignvpn-expire.service sovereignvpn-expire.timer
            sovereignvpn-unbound.service sovereignvpn-pihole.service)
OPT="$RADICE/opt/sovereignvpn"
ETC="$RADICE/etc/sovereignvpn"
VAR="$RADICE/var/lib/sovereignvpn"
BIN="$RADICE/usr/local/bin"
UNITA="$RADICE/etc/systemd/system"

# prerequisiti (errori runtime: codice 1)
[ -f "$SORGENTE/__main__.py" ] || { echo "install.sh: sorgente del control plane mancante in $SORGENTE" >&2; exit 1; }
for u in "${UNITA_NOMI[@]}"; do
  [ -f "$SORGENTE_UNITA/$u" ] || { echo "install.sh: unita' systemd mancante: $SORGENTE_UNITA/$u" >&2; exit 1; }
done
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
  || { echo "install.sh: serve Python 3.11 o successivo (ANC-0334)" >&2; exit 1; }
if [ -z "$RADICE" ] && [ "$DRY" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
  echo "install.sh: per installare sotto / serve root; per vedere il piano: --dry-run" >&2; exit 1
fi

if [ "$INDIETRO" -eq 1 ]; then  # FR-OPS-005 [H29]: torna all'ultima release installata prima di questa
  [ -d "$OPT/sovereignctl.precedente/" ] && [ -f "$OPT/sovereignctl.precedente/__main__.py" ] \
    || { echo "install.sh: nessuna release precedente in $OPT/sovereignctl.precedente: niente da fare" >&2; exit 1; }
  if [ "$DRY" = 1 ]; then
    echo "install.sh --rollback --dry-run: nessuna mutazione. Piano: scambiare $OPT/sovereignctl con $OPT/sovereignctl.precedente"
    exit 0
  fi
  mkdir "$RADICE/opt/.sovereignvpn-install.lock" 2>/dev/null || { echo "install.sh: un'altra installazione e' in corso (lucchetto presente)" >&2; exit 1; }
  LUCCHETTO="$RADICE/opt/.sovereignvpn-install.lock"
  rm -rf "$OPT/sovereignctl.scambio"
  mv "$OPT/sovereignctl" "$OPT/sovereignctl.scambio"  # shortcut: per un istante la cartella manca; mv --exchange vuole coreutils 9.5
  mv "$OPT/sovereignctl.precedente" "$OPT/sovereignctl"
  mv "$OPT/sovereignctl.scambio" "$OPT/sovereignctl.precedente"
  echo "install.sh: tornato alla release precedente; quella lasciata e' in $OPT/sovereignctl.precedente (un secondo --rollback la rimette)."
  echo "Prossimo passo: sovereignctl reconcile --config $ETC/server.toml"
  exit 0
fi

PASSI=(
  "copiare il control plane in $OPT/sovereignctl (0755) per rinomina, tenendo la release di prima per --rollback"
  "creare $ETC (0700) per la configurazione"
  "creare $VAR (0700) per lo stato e il manifest"
  "scrivere il comando $BIN/sovereignctl (0755)"
  "installare le unita' systemd in $UNITA (0644) e, sul sistema vero, abilitarle: \`sovereignctl reconcile\` a ogni avvio (FR-NET-007), scadenze dei peer ogni minuto (FR-PEER-005); partono solo dopo init --apply"
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
rm -rf "$OPT/sovereignctl.nuovo"
cp -R "$SORGENTE" "$OPT/sovereignctl.nuovo"
find "$OPT/sovereignctl.nuovo" -name __pycache__ -type d -prune -exec rm -rf {} +
chmod -R u=rwX,go=rX "$OPT/sovereignctl.nuovo"
if [ -d "$OPT/sovereignctl" ]; then  # la release di prima resta, per --rollback (FR-OPS-005)
  rm -rf "$OPT/sovereignctl.precedente"
  mv "$OPT/sovereignctl" "$OPT/sovereignctl.precedente"
fi
mv "$OPT/sovereignctl.nuovo" "$OPT/sovereignctl"

# 2-3. configurazione e stato, solo il proprietario
install -d -m 0700 "$ETC" "$VAR"
chmod 0700 "$ETC" "$VAR"

# 4. comando: scritto accanto e rinominato
install -d -m 0755 "$BIN"
TMP="$BIN/.sovereignctl.nuovo"
printf '#!/bin/sh\nexec python3 -I -c '\''import sys; sys.path.insert(0, "%s"); from sovereignctl.__main__ import main; sys.exit(main())'\'' "$@"\n' "$OPT" > "$TMP"
chmod 0755 "$TMP"
mv "$TMP" "$BIN/sovereignctl"

# 5. unita' systemd: ognuna scritta accanto e rinominata; abilitate solo dove systemd e' davvero in funzione
install -d -m 0755 "$UNITA"
for u in "${UNITA_NOMI[@]}"; do
  install -m 0644 "$SORGENTE_UNITA/$u" "$UNITA/$u.nuovo"
  mv "$UNITA/$u.nuovo" "$UNITA/$u"
done
if [ -z "$RADICE" ] && [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  systemctl enable --quiet sovereignvpn-reconcile.service sovereignvpn-expire.timer sovereignvpn-unbound.service sovereignvpn-pihole.service
fi

# 6. immagine di Unbound, costruita dalla base pin-nata per digest (Pi-hole si scarica per digest al primo avvio)
if [ -z "$RADICE" ] && command -v docker >/dev/null 2>&1; then
  docker build -q -t sovereignvpn-unbound:14.0.0 "$SORGENTE_DNS/unbound" >/dev/null
fi

echo "install.sh: installato. Control plane in $OPT, configurazione in $ETC, stato in $VAR."
echo "Prossimo passo: sovereignctl init --check --config $ETC/server.toml"
