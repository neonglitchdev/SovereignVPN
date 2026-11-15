# 3. Ambito e roadmap di prodotto

<!-- ANC-0085 -->
## 3.1 MVP — Release 1.0
<!-- ANC-0086 -->
Installazione su singolo host Debian 12 o Ubuntu 24.04 LTS, architettura amd64. ARM64 è un target di compatibilità da validare separatamente.
<!-- ANC-0087 -->
WireGuard server e provisioning peer.
<!-- ANC-0088 -->
Full-tunnel IPv4 con policy firewall fail-closed.
<!-- ANC-0089 -->
Kill switch lato host per il forwarding dei peer; profili client che dichiarano solo ciò che il client supporta.
<!-- ANC-0090 -->
DNS interno Pi-hole + Unbound ricorsivo, query logging disabilitato per default.
<!-- ANC-0091 -->
Isolamento peer-to-peer.
<!-- ANC-0092 -->
CLI per init, add, list, show, revoke, expire-sweep, rotate-psk, export, backup, restore e audit.
<!-- ANC-0093 -->
Registro peer con storage atomico e backup cifrato.
<!-- ANC-0094 -->
API locale amministrativa opzionale, disattivata di default e protetta da autenticazione.
<!-- ANC-0095 -->
Test automatici di leak DNS/IPv4/IPv6, firewall, esposizione porte e lifecycle.
<!-- ANC-0096 -->
Aggiornamento controllato, rollback e documentazione di incident response.
<!-- ANC-0097 -->
## 3.2 Release 1.x — Hardening e user experience
<!-- ANC-0098 -->
Dashboard web locale con RBAC e sessioni sicure.
<!-- ANC-0099 -->
Profili split-tunnel e home-LAN con validazione dei CIDR e prevenzione di route overlap.
<!-- ANC-0100 -->
QR code per onboarding controllato e bundle client.
<!-- ANC-0101 -->
Profili Apple WireGuard importabili; documentazione separata per distribuzione MDM e per le capacità Always On native Apple.
<!-- ANC-0102 -->
Guest peer con TTL e policy di rinnovo.
<!-- ANC-0103 -->
Backup/restore assistito e recovery drills.
<!-- ANC-0104 -->
## 3.3 Release 2.x — Funzioni opzionali ad alto rischio
<!-- ANC-0105 -->
Wstunnel/WSS come trasporto alternativo, con benchmark e test di compatibilità tramite reti di prova autorizzate.
<!-- ANC-0106 -->
Tor per destinazioni onion, inizialmente tramite proxy esplicito; trasparenza TCP solo dopo threat model e leak tests.
<!-- ANC-0107 -->
Multi-hop per un sottoinsieme di peer, con policy routing e kill switch egress.
<!-- ANC-0108 -->
UDP2raw/FakeTCP come esperimento opzionale e non supportato in produzione finché non siano verificati manutenzione, sicurezza crittografica, compatibilità kernel e robustezza dei fallback.
<!-- ANC-0109 -->
IPv6 full support end-to-end, se non già realizzato nel MVP.
<!-- ANC-0110 -->
## 3.4 Criteri di esclusione dal rilascio
<!-- ANC-0111 -->
Una feature deve restare disabilitata o essere rimossa dalla release se: non esiste un maintainer responsabile; la dipendenza non ha una release riproducibile; non è disponibile una suite di test negativa; la policy di fallback può causare traffico fuori tunnel; il comportamento non è documentabile; o l'audit non riesce a distinguere feature disattivata, degradato e operativo.
