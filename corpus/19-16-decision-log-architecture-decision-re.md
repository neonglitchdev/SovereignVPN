# 16. Decision log / Architecture Decision Records

<!-- ANC-0355 -->
## ADR-001 — WireGuard come protocollo core
<!-- ANC-0356 -->
Decisione: WireGuard è il protocollo standard del MVP.
<!-- ANC-0357 -->
Motivo: implementazione moderna, configurazione relativamente semplice, integrazione kernel e tooling diffuso.
<!-- ANC-0358 -->
Conseguenza: UDP deve essere raggiungibile per il percorso standard; trasporti alternativi sono un layer opzionale.
<!-- ANC-0359 -->
## ADR-002 — PSK come defense-in-depth, non PQC completa
<!-- ANC-0360 -->
Decisione: PSK WireGuard opzionale/abilitabile per peer e ruotabile.
<!-- ANC-0361 -->
Motivo: aggiunge un segreto simmetrico al handshake; non elimina la dipendenza da Curve25519.
<!-- ANC-0362 -->
Conseguenza: il marketing e la documentazione non usano “quantum-proof”.
<!-- ANC-0363 -->
## ADR-003 — Privacy-Minimized come default
<!-- ANC-0364 -->
Decisione: persistere i metadati indispensabili al funzionamento, non query DNS o cronologia.
<!-- ANC-0365 -->
Motivo: un sistema che deve sopravvivere ai reboot ha bisogno di configurazioni e identità; la promessa RAM-only assoluta è incompatibile con molti requisiti di gestione.
<!-- ANC-0366 -->
Conseguenza: retention e storage sono espliciti e auditabili.
<!-- ANC-0367 -->
## ADR-004 — IPv6 esplicito
<!-- ANC-0368 -->
Decisione: supportare IPv6 integralmente oppure disabilitare/filtrare il percorso in modo verificato.
<!-- ANC-0369 -->
Motivo: una regola isolata su ip6tables può non coprire tutti i namespace e tutti i percorsi.
<!-- ANC-0370 -->
Conseguenza: i test dual-stack sono P0.
<!-- ANC-0371 -->
## ADR-005 — Firewall backend singolo per installazione
<!-- ANC-0372 -->
Decisione: backend nftables preferito; iptables compatibility mode separato.
<!-- ANC-0373 -->
Motivo: ridurre conflitti di ordering e di ownership con Docker e strumenti host.
<!-- ANC-0374 -->
Conseguenza: nessuna miscela casuale fra iptables legacy, iptables-nft e nft native rules.
<!-- ANC-0375 -->
## ADR-006 — API e dashboard non pubbliche
<!-- ANC-0376 -->
Decisione: control plane disabilitato per default e local/VPN-only.
<!-- ANC-0377 -->
Motivo: superficie d'attacco e segreti di provisioning.
<!-- ANC-0378 -->
Conseguenza: l'amministrazione remota usa un canale VPN admin o un reverse proxy specificamente configurato.
<!-- ANC-0379 -->
## ADR-007 — Funzioni avanzate feature-gated
<!-- ANC-0380 -->
Decisione: Tor, stealth, UDP2raw e multi-hop non sono requisiti MVP.
<!-- ANC-0381 -->
Motivo: maggiore complessità di routing, fallback e test, non necessaria al valore primario.
<!-- ANC-0382 -->
Conseguenza: ogni feature ha owner, compatibilità, kill switch e gate.
