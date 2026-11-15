# 17. Open questions da chiudere prima del design freeze

<!-- ANC-0383 -->
1. Qual è il target reale: uso personale/familiare, piccolo team o installazione multi-tenant? Il modello RBAC e le responsabilità operative cambiano sensibilmente.
<!-- ANC-0384 -->
2. Si vuole conservare la private key del peer sul server per rigenerare tutti i profili, oppure generarla lato client e conservare solo la public key? La seconda opzione riduce il materiale segreto sul server ma cambia l'onboarding.
<!-- ANC-0385 -->
3. Il target primario resta Debian 12/Ubuntu 24.04 amd64 o ARM64 deve entrare nel MVP?
<!-- ANC-0386 -->
4. L'accesso LAN deve essere un profilo standard o una capability abilitata per singolo peer e singolo CIDR?
<!-- ANC-0387 -->
5. Il pannello web è davvero necessario nella prima release, o la CLI è sufficiente per ridurre superficie d'attacco?
<!-- ANC-0388 -->
6. Quale threat model è prioritario: Wi-Fi ostile, provider cloud, peer malevolo, censura/DPI o privacy DNS? Non esiste una singola architettura ottimale per tutti.
<!-- ANC-0389 -->
7. Il multi-hop deve usare un secondo host sotto controllo dello stesso owner o un provider terzo? Il trust model è diverso.
<!-- ANC-0390 -->
8. Qual è la politica di retention richiesta per audit amministrativo: 0, 7, 30 o 90 giorni?
<!-- ANC-0391 -->
9. Quali client e versioni OS saranno realmente testati e supportati nella matrice release?
<!-- ANC-0392 -->
10. Quale budget minimo di risorse/throughput è necessario per la macchina target?
<!-- ANC-0393 -->
In assenza di risposta, la baseline di prodotto assume uso personale/piccolo team, un solo host, CLI-first, Debian/Ubuntu amd64, nessun log di navigazione, audit amministrativo di 30 giorni, e optional services disabilitati.
