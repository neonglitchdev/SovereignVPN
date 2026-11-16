#!/usr/bin/env bash
# Il QR dei dispositivi [H51]: si compila QR.swift con la prova e si rilegge il QR col rilevatore di macOS.
set -Eeuo pipefail
QUI="$(cd "$(dirname "$0")" && pwd)"; D="$(mktemp -d)"; trap 'rm -rf "$D"' EXIT
swiftc -swift-version 5 -parse-as-library -o "$D/prova" "$QUI/Sources/QR.swift" "$QUI/Prove/ProvaQR.swift"
"$D/prova"
