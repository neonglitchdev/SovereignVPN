# 5. Requisiti non funzionali

<!-- ANC-0139 -->
## 5.1 Sicurezza
<!-- ANC-0140 -->
NFR-SEC-001: ogni processo/container opera con privilegi minimi; NET_ADMIN e SYS_MODULE sono assegnati solo dove inevitabili e documentati.
<!-- ANC-0141 -->
NFR-SEC-002: immagini container sono pin-nate per digest, con SBOM e scansione CVE per ogni release.
<!-- ANC-0142 -->
NFR-SEC-003: filesystem read-only, no-new-privileges, capability drop, seccomp e AppArmor sono applicati per servizio quando compatibili.
<!-- ANC-0143 -->
NFR-SEC-004: segreti con permessi minimi (0600 o secret store), rotazione e zero output involontario.
<!-- ANC-0144 -->
NFR-SEC-005: operazioni critiche hanno audit event sanitizzati (chi, cosa, quando, esito), senza query DNS, URL, IP sorgente utente o payload.
<!-- ANC-0145 -->
NFR-SEC-006: threat model aggiornato a ogni feature che introduce nuovo trust boundary o nuovo egress.
<!-- ANC-0146 -->
NFR-SEC-007: dipendenze crittografiche custom sono vietate.
<!-- ANC-0147 -->
## 5.2 Privacy e conservazione dati
<!-- ANC-0148 -->
| Dato | Scopo | Persistenza | Retention predefinita | Note |
|---|---|---|---|---|
| Chiave privata server | Identità endpoint | Cifrata a riposo / secret file protetto | Finché server è attivo | Necessaria al funzionamento; backup cifrato |
| Chiave privata peer | Provisioning/export e gestione | Solo se il prodotto la conserva; preferire generazione lato client quando fattibile | Finché richiesta dal modello operativo | Opzione export one-time da valutare |
| Public key peer | Autenticazione WireGuard | Persistente | Finché peer attivo o retention amministrativa | Non è un segreto |
| IP VPN peer e nome | Routing e amministrazione | Persistente | Fino a revoca + retention minima | Non collegare a cronologia di navigazione |
| Data creazione/scadenza | Lifecycle | Persistente | Fino a cancellazione amministrativa | Necessaria al TTL |
| DNS query/domain | Nessuna nel modello privacy-first | Non persistente | 0 | In RAM per il tempo di elaborazione è inevitabile |
| IP sorgente pubblico/handshake timestamp | Operatività protocollo | Runtime/kernel; non in log app | Nessuna retention applicativa | Alcuni dati esistono temporaneamente nello stack kernel/WireGuard |
| Audit event amministrativo | Accountability | Persistente con rotazione | Configurabile, default 30 giorni | Senza dati navigazione o segreti |
| Metriche aggregate | Health/performance | Persistenza opzionale | Configurabile, default 7 giorni | Niente cardinalità per peer se non necessario |
| Log sistema/host/provider | Troubleshooting | Fuori dal pieno controllo del prodotto | Dipende da host/cloud | Dichiarare la responsabilità e indicare hardening host |
<!-- ANC-0149 -->
Il sistema deve documentare anche swap, hibernation, core dump, journald, Docker logging driver, backup del provider e snapshot VM. L'opzione tmpfs non azzera automaticamente tutti questi canali.
<!-- ANC-0150 -->
## 5.3 Disponibilità e recuperabilità
<!-- ANC-0151 -->
NFR-AVL-001: il servizio deve ripartire automaticamente dopo reboot host, rispettando l'ordine di avvio e le dipendenze.
<!-- ANC-0152 -->
NFR-AVL-002: health check distinguono processo attivo da servizio realmente funzionante (DNS response, WireGuard interface, firewall ruleset).
<!-- ANC-0153 -->
NFR-AVL-003: target iniziale di recovery time objective (RTO) documentato: 30 minuti su host singolo con backup valido; target recovery point objective (RPO): ultimo backup riuscito. Valori da validare con prove reali.
<!-- ANC-0154 -->
NFR-AVL-004: nessun update automatico non controllato delle immagini in produzione; il deploy usa release note e rollback.
<!-- ANC-0155 -->
## 5.4 Performance
<!-- ANC-0156 -->
I numeri di throughput/latency non sono promesse universali. La piattaforma deve fornire un benchmark ripetibile che riporti CPU, RAM, NIC, MTU, kernel, provider, RTT, packet loss, cipher suite, numero peer e qdisc.
<!-- ANC-0157 -->
| Metrica | Obiettivo iniziale | Metodo |
|---|---|---|
| Handshake WireGuard | p95 < 3 s su rete nominale dopo richiesta di connessione | Test automatizzato con client di riferimento |
| Revoca peer | <= 5 s dal commit | Test di raggiungibilità prima/dopo revoca |
| DNS interno | p95 < 100 ms per cache hit su host di riferimento | dig batch con query sintetiche |
| Overhead CPU | Baseline e curva per throughput | iperf3 + metriche sistema |
| Packet loss | Non introdurre perdita aggiuntiva misurabile rispetto al baseline oltre la soglia concordata | Test su rete controllata |
| Reconnect | Stato ristabilito entro 15 s su perdita breve, target da validare | Network impairment test |
<!-- ANC-0158 -->
## 5.5 Compatibilità
<!-- ANC-0159 -->
Host MVP: Debian 12 e Ubuntu 24.04 LTS amd64.
<!-- ANC-0160 -->
Container runtime: Docker Engine e Docker Compose plugin nelle versioni minime dichiarate nella release.
<!-- ANC-0161 -->
Client: WireGuard ufficiale su Windows, macOS, iOS, Android e Linux; ogni piattaforma deve avere test d'importazione separati.
<!-- ANC-0162 -->
ARM64: supporto dichiarato solo per immagini, kernel e test CI che lo coprono.
<!-- ANC-0163 -->
Kernel: versione minima dichiarata e verificata per WireGuard kernel module o userspace fallback, con impatto performance esplicitato.
<!-- ANC-0164 -->
## 5.6 Usabilità e accessibilità
<!-- ANC-0165 -->
CLI con help, esempi, errori azionabili e codici exit stabili. Dashboard con layout responsive, focus keyboard, contrasto adeguato, etichette leggibili e nessuna informazione critica comunicata solo tramite colore. Ogni azione distruttiva richiede conferma e mostra l'impatto.
