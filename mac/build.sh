#!/usr/bin/env bash
# Costruisce «SovereignVPN.app» per questo Mac: swiftc dei Command Line Tools, sorgenti del server nelle Resources,
# firma ad-hoc (la notarizzazione vuole un Apple Developer ID a pagamento: al primo avvio, tasto destro > Apri).
#   bash mac/build.sh [cartella di uscita, di base mac/build]
set -Eeuo pipefail
QUI="$(cd "$(dirname "$0")" && pwd)"; RADICE="$(cd "$QUI/.." && pwd)"
OUT="${1:-$QUI/build}"; APP="$OUT/SovereignVPN.app"
rm -rf "$APP"; mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/sovereignvpn"
swiftc -O -swift-version 5 -parse-as-library -target arm64-apple-macosx14.0 -o "$APP/Contents/MacOS/SovereignVPN" "$QUI"/Sources/*.swift
for d in ops control-plane/sovereignctl config/examples mac/prepara-server.sh; do
  mkdir -p "$APP/Contents/Resources/sovereignvpn/$(dirname "$d")"; cp -R "$RADICE/$d" "$APP/Contents/Resources/sovereignvpn/$d"
done
find "$APP" -name __pycache__ -type d -prune -exec rm -rf {} +
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
 <key>CFBundleName</key><string>SovereignVPN</string>
 <key>CFBundleDisplayName</key><string>SovereignVPN</string>
 <key>CFBundleIdentifier</key><string>it.sovereignvpn.mac</string>
 <key>CFBundleVersion</key><string>14.0.0</string>
 <key>CFBundleShortVersionString</key><string>14.0.0</string>
 <key>CFBundleExecutable</key><string>SovereignVPN</string>
 <key>CFBundlePackageType</key><string>APPL</string>
 <key>LSMinimumSystemVersion</key><string>14.0</string>
 <key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
codesign -s - --force --deep "$APP"
codesign --verify --deep --strict "$APP" && echo "costruita e firmata (ad-hoc): $APP"
