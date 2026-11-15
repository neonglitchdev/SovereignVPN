# 13. Deployment, ambienti e supply chain

<!-- ANC-0313 -->
## 13.1 Ambienti
<!-- ANC-0314 -->
DEV: VM locale, dati sintetici, nessun segreto reale.
<!-- ANC-0315 -->
CI: test unitari, static analysis, schema check, secret scan, build immagine, SBOM, vulnerability scan.
<!-- ANC-0316 -->
STAGING: VM disposable con rete simulata e client di test.
<!-- ANC-0317 -->
PRODUCTION: host gestito dall'owner, release pin-nata, backup prima di ogni update, accesso SSH ristretto.
<!-- ANC-0318 -->
## 13.2 Dipendenze e immagini
<!-- ANC-0319 -->
Ogni immagine deve essere pin-nata a digest nel manifest di release. I tag mobili (latest) sono vietati per il deployment production. Aggiornare una dipendenza richiede changelog, valutazione CVE, test di compatibilità e rollback. Le release devono generare SBOM e attestazione/checksum degli artefatti.
<!-- ANC-0320 -->
## 13.3 Hardening host
<!-- ANC-0321 -->
SSH key-only, root login disabilitato ove possibile, MFA/out-of-band se disponibile.
<!-- ANC-0322 -->
Aggiornamenti security del sistema operativo pianificati.
<!-- ANC-0323 -->
Firewall host e Docker integrati e testati.
<!-- ANC-0324 -->
Swap cifrato o disabilitato secondo capacità host e threat model; core dump disabilitati per processi sensibili dove compatibile.
<!-- ANC-0325 -->
NTP/chrony per timestamp e TTL.
<!-- ANC-0326 -->
Accesso al socket Docker trattato come root-equivalent.
<!-- ANC-0327 -->
Directory dati con owner/permessi minimi; backup cifrato fuori host.
<!-- ANC-0328 -->
Provider snapshots e serial console documentati come trust boundary.
<!-- ANC-0329 -->
## 13.4 Cloud free tier
<!-- ANC-0330 -->
La documentazione Oracle Cloud o di altri provider deve essere un deployment guide non una promessa di disponibilità gratuita permanente. Quote, regioni, requisiti carta, regole di rete, policy e prezzi possono cambiare. Il deployment deve funzionare anche su un host Linux generico.
