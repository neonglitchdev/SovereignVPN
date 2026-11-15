# 4. Requisiti funzionali

<!-- ANC-0112 -->
I requisiti usano gli identificativi FR-*. “MUST” indica un vincolo di rilascio; “SHOULD” una scelta fortemente raccomandata; “MAY” una capacità opzionale.
<!-- ANC-0113 -->
## 4.1 Bootstrap e configurazione
<!-- ANC-0114 -->
| ID | Priorità | Requisito | Criterio di accettazione |
|---|---|---|---|
| FR-BOOT-001 | P0 | Il bootstrap verifica OS, kernel, architettura, Docker/Compose, capacità kernel WireGuard, spazio disco, sincronizzazione oraria e porte disponibili. | Se un prerequisito fallisce, non applica mutazioni e restituisce un report con remediation. |
| FR-BOOT-002 | P0 | Ogni installazione genera un identificativo locale non sensibile e un manifest delle versioni. | Il manifest include versioni e digest immagini, mai chiavi o token. |
| FR-BOOT-003 | P0 | Le impostazioni obbligatorie sono validate contro schema e CIDR/IPAM prima del deploy. | Input invalido produce exit code 2 e nessun cambio di stato. |
| FR-BOOT-004 | P0 | Il bootstrap supporta dry-run e piano delle mutazioni. | Dry-run non modifica filesystem, firewall o servizi. |
| FR-BOOT-005 | P1 | Il bootstrap può applicare una configurazione di rete con rollback. | Un errore in qualsiasi step ripristina la configurazione precedente o entra in stato NEEDS_RECOVERY. |
<!-- ANC-0115 -->
## 4.2 Identità, peer e lifecycle
<!-- ANC-0116 -->
| ID | Priorità | Requisito | Criterio di accettazione |
|---|---|---|---|
| FR-PEER-001 | P0 | Creare peer con nome univoco, chiave, indirizzo assegnato, data creazione e stato. | Collisioni nome/IP sono rifiutate; allocazione concorrente non duplica indirizzi. |
| FR-PEER-002 | P0 | Ogni peer ha un identificatore stabile UUID e un nome visualizzato separato. | Rinominare il display name non cambia l'identità crittografica. |
| FR-PEER-003 | P0 | Supportare stati PENDING, ACTIVE, SUSPENDED, EXPIRED, REVOKED, ERROR. | Le transizioni non valide vengono respinte e registrate come evento amministrativo sanitizzato. |
| FR-PEER-004 | P0 | Revoca effettiva entro 5 secondi dal commit locale, in condizioni operative nominali. | Dopo revoca, nuovo traffico del peer non raggiunge Internet né reti interne; il test usa handshake e ping controllati. |
| FR-PEER-005 | P0 | Peer con TTL sono disattivati automaticamente alla scadenza. | Test con clock controllato conferma la transizione; watchdog riprende dopo reboot. |
| FR-PEER-006 | P0 | Sospensione reversibile, revoca irreversibile per la stessa chiave. | Una chiave revocata non può essere riattivata; serve una nuova identità. |
| FR-PEER-007 | P0 | L'esportazione di un profilo mostra chiaramente se contiene segreti e richiede autorizzazione esplicita. | Gli export vengono generati su richiesta e non inseriti in log o backup non cifrati. |
| FR-PEER-008 | P1 | Supportare limiti per peer: DNS policy, allowed routes, multi-hop eligibility, scadenza e quota opzionale. | Le policy sono validate e applicate a routing/firewall, non solo memorizzate nel database. |
| FR-PEER-009 | P1 | Il bundle di onboarding include solo i profili abilitati per il peer. | Ogni file ha checksum e manifest; il bundle non include chiavi di altri peer. |
<!-- ANC-0117 -->
## 4.3 WireGuard e profili di routing
<!-- ANC-0118 -->
| ID | Priorità | Requisito | Criterio di accettazione |
|---|---|---|---|
| FR-WG-001 | P0 | Utilizzare WireGuard kernel-space quando disponibile e supportato dal sistema. | wg show e test end-to-end confermano interfaccia, peer e handshake. |
| FR-WG-002 | P0 | Generare chiavi con wg o librerie/strumenti riconosciuti; mai implementare primitive crittografiche custom. | Chiavi valide, permessi minimi, nessun secret in stdout o debug log. |
| FR-WG-003 | P0 | Ogni peer ha una AllowedIPs precisa e non sovrapposta, salvo eccezioni documentate. | La validazione impedisce sovrapposizioni accidentali e route hijacking tra peer. |
| FR-WG-004 | P0 | Il profilo full-tunnel instrada IPv4 0.0.0.0/0 nel tunnel e definisce policy IPv6 esplicita. | Test IPv4/IPv6 confermano assenza di fallback non dichiarato. |
| FR-WG-005 | P0 | Supportare PersistentKeepalive configurabile per peer, con default disattivato salvo necessità NAT documentata. | Il sistema non impone keepalive a tutti i peer senza motivazione. |
| FR-WG-006 | P0 | Applicare TCP MSS clamping solo dove serve, con test MTU/PMTUD. | Test su MTU ridotta e path IPv4/IPv6 dimostrano assenza di black-hole PMTU. |
| FR-WG-007 | P1 | Supportare profili split tunnel e LAN con route esplicite. | I CIDR LAN sono approvati, esclusioni sono visibili e conflitti sono bloccati. |
| FR-WG-008 | P1 | Esportare configurazioni compatibili con client WireGuard ufficiali. | Ogni piattaforma target supera test import/connect/disconnect e verifica DNS. |
<!-- ANC-0119 -->
## 4.4 DNS, filtering e risoluzione ricorsiva
<!-- ANC-0120 -->
| ID | Priorità | Requisito | Criterio di accettazione |
|---|---|---|---|
| FR-DNS-001 | P0 | I peer usano il resolver interno assegnato dal profilo. | Il test DNS verifica resolver, risposta e routing attraverso il tunnel. |
| FR-DNS-002 | P0 | Pi-hole applica liste di blocco configurate e versionate. | Il report indica ultima sincronizzazione, numero fonti e stato aggiornamento, senza salvare query utente. |
| FR-DNS-003 | P0 | Unbound esegue risoluzione ricorsiva e validazione DNSSEC. | Test positivo DNSSEC risolve; test negativo DNSSEC viene rifiutato. |
| FR-DNS-004 | P0 | Query logging è disabilitato per default in Pi-hole e Unbound; i livelli privacy sono verificati in config runtime. | Il test cerca query log e database persistenti e fallisce se contengono domini/client. |
| FR-DNS-005 | P0 | DNS UDP/TCP 53 non autorizzato in uscita dai peer viene intercettato o bloccato secondo la policy. | Testa resolver hardcoded IPv4/IPv6 e verifica che non esca traffico DNS diretto. |
| FR-DNS-006 | P0 | DoT TCP/853 può essere bloccato; la UI deve chiarire che il blocco non neutralizza ogni DNS cifrato. | La documentazione e l'audit non descrivono TCP/853 reject come blocco universale DoH/DoQ. |
| FR-DNS-007 | P1 | Aggiornamenti blocklist sono atomici, con snapshot precedente e rollback. | Se la nuova lista è invalida, la lista attiva precedente resta operativa. |
| FR-DNS-008 | P1 | Allowlist e blocklist locali hanno precedenza dichiarata e testata. | Regole duplicate o in conflitto generano diagnostica. |
| FR-DNS-009 | P1 | Le query DNS non sono esposte in dashboard, API o metriche. | Un audit API e dei dati persistenti non rileva domini visitati o IP client associati a query. |
<!-- ANC-0121 -->
Limite funzionale: bloccare TCP/853 impedisce solo il DoT su quella porta. DoH può viaggiare su HTTPS/TCP 443 o HTTP/3/QUIC UDP 443; bloccare tutto il DoH in modo affidabile senza inspection, gestione endpoint o allowlist restrittive non è un requisito realistico universale. Il prodotto può offrire blocklist di endpoint DoH noti e policy DNS, ma deve descriverle come mitigazioni parziali.
<!-- ANC-0122 -->
## 4.5 Firewall, routing e isolamento
<!-- ANC-0123 -->
| ID | Priorità | Requisito | Criterio di accettazione |
|---|---|---|---|
| FR-NET-001 | P0 | Il forwarding dei peer è deny-by-default e abilita solo i flussi esplicitamente previsti. | Testa ingressi non autorizzati, egress e traffico laterale. |
| FR-NET-002 | P0 | Isolamento peer-to-peer attivo di default. | Un peer non può raggiungere l'IP VPN di un altro peer. |
| FR-NET-003 | P0 | DNS verso resolver interni è consentito; DNS esterno è gestito dalla policy. | Test UDP e TCP 53 su destinazioni esterne. |
| FR-NET-004 | P0 | Le porte pubblicate dai container sono dichiarate in un port inventory e verificate dal firewall host. | Test esterno da rete distinta conferma che solo le porte approvate sono raggiungibili. |
| FR-NET-005 | P0 | La policy firewall Docker è trattata separatamente dalle regole UFW/INPUT. | Audit verifica chain DOCKER-USER o equivalente backend supportato e port publishing. |
| FR-NET-006 | P0 | La configurazione IPv6 è coerente su host, bridge, container, forwarding e client. | Non esistono percorsi IPv6 non coperti dalla policy. |
| FR-NET-007 | P0 | Routing e firewall devono sopravvivere a restart di container, Docker e host. | Test reboot + reconcile conferma stato dichiarato. |
| FR-NET-008 | P1 | Configurazioni multi-hop usano tabelle dedicate, mark riservati, regole di ritorno e test di failover. | Caduta dell'egress hop non produce fallback verso WAN diretta. |
| FR-NET-009 | P1 | Le eccezioni LAN sono limitate a CIDR specifici e non consentono route generiche. | Scanner route e test di accesso confermano solo gli host autorizzati. |
<!-- ANC-0124 -->
Nota architetturale: rp_filter=1 non è imposto globalmente come requisito assoluto. Il reverse-path filtering strict può scartare pacchetti in scenari di routing asimmetrico o policy routing. La configurazione deve essere selezionata per interfaccia e validata; per i percorsi asimmetrici si valuta modalità loose e/o src_valid_mark in modo documentato. [R4]
<!-- ANC-0125 -->
## 4.6 Stealth e trasporti alternativi
<!-- ANC-0126 -->
| ID | Priorità | Requisito | Criterio di accettazione |
|---|---|---|---|
| FR-STEALTH-001 | P2 | Wstunnel trasporta il traffico previsto su WebSocket protetto da TLS, se abilitato. | Test connessione, certificato, autenticazione, throughput e reconnect su reti di test autorizzate. |
| FR-STEALTH-002 | P2 | Path/credential di accesso sono ad alta entropia e ruotabili; non sono hardcoded nel repository. | Secret scan e test di rotazione passano. |
| FR-STEALTH-003 | P2 | Il sistema rileva e comunica handshake TLS falliti, proxy incompatibili e degrado. | UI/CLI distingue CONNECTED, DEGRADED, BLOCKED, FAILED. |
| FR-STEALTH-004 | P2 | UDP2raw è un adapter sperimentale isolato, disattivato per default. | Release note dichiara compatibilità testata e rischio; nessun claim di DPI bypass universale. |
<!-- ANC-0127 -->
Wstunnel supporta più modalità e trasporti, ma il comportamento dipende dalla versione, dal reverse proxy, dal percorso di rete e dal tipo di firewall. La configurazione va pin-nata e testata; il fatto che un traffico usi TLS/WebSocket non lo rende indistinguibile da ogni altro traffico HTTPS. [R8]
<!-- ANC-0128 -->
## 4.7 Tor e destinazioni onion
<!-- ANC-0129 -->
| ID | Priorità | Requisito | Criterio di accettazione |
|---|---|---|---|
| FR-TOR-001 | P2 | Tor è opzionale e isolato in un servizio con egress policy dedicata. | Se disabilitato, nessun listener o route Tor è attivo. |
| FR-TOR-002 | P2 | La prima modalità supportata è proxy esplicito SOCKS/DNS per client o applicazioni configurate. | Test onion passa solo attraverso Tor e nessun DNS onion raggiunge il resolver clearnet. |
| FR-TOR-003 | P2 | La modalità transparent proxy è separata, con TransPort, DNSPort e virtual address mapping documentati. | Testa TCP, DNS, IPv4 virtual mapping, exclusion di traffico del processo Tor e leak. |
| FR-TOR-004 | P2 | L'UI avvisa che l'instradamento Tor modifica latenza, compatibilità e modello di fiducia. | L'utente deve scegliere il profilo in modo esplicito. |
<!-- ANC-0130 -->
Tor DNSPort ha limiti di tipi di query e AutomapHostsOnResolve crea indirizzi virtuali per nomi come .onion; il solo inoltro condizionale DNS a una porta non realizza automaticamente un proxy trasparente TCP completo. [R9]
<!-- ANC-0131 -->
## 4.8 Apple e client mobili
<!-- ANC-0132 -->
| ID | Priorità | Requisito | Criterio di accettazione |
|---|---|---|---|
| FR-APPLE-001 | P1 | Generare configurazioni WireGuard importabili su iOS/macOS, con istruzioni corrette e versionate. | Import da client WireGuard ufficiale e connessione testata. |
| FR-APPLE-002 | P1 | La generazione di .mobileconfig è limitata a payload e use case Apple effettivamente supportati. | Validazione plist, schema e test su dispositivi compatibili o ambiente MDM. |
| FR-APPLE-003 | P1 | Il prodotto non etichetta On Demand come Always-On VPN o come kill switch di sistema. | Copy, documentazione e UI distinguono Connect On Demand, Always On IKEv2 supervisionato e WireGuard Packet Tunnel. |
| FR-APPLE-004 | P1 | Le istruzioni specificano i limiti di enforcement per dispositivo, versione OS, supervisione e MDM. | Checklist di rilascio per ogni piattaforma Apple. |
<!-- ANC-0133 -->
Apple documenta Always On VPN come capability IKEv2 con requisito di supervisione; On Demand è una famiglia distinta di regole per attivare una VPN in base alle condizioni. Non si deve generare un profilo WireGuard fingendo che com.wireguard.ios sia un protocollo VPN nativo equivalente al payload Always On IKEv2. [R5][R6]
<!-- ANC-0134 -->
## 4.9 Control plane, API e dashboard
<!-- ANC-0135 -->
| ID | Priorità | Requisito | Criterio di accettazione |
|---|---|---|---|
| FR-CTRL-001 | P0 | La CLI è l'interfaccia amministrativa primaria dell'MVP. | Ogni operazione critica è documentata e disponibile da CLI. |
| FR-CTRL-002 | P0 | L'API è disabilitata per default e ascolta solo su loopback o interfaccia VPN admin. | Scan esterno e scan LAN non autorizzato non raggiungono API/pannello. |
| FR-CTRL-003 | P0 | Tutti gli endpoint modificativi richiedono autenticazione e autorizzazione server-side. | Test senza token, token errato, ruolo insufficiente e replay. |
| FR-CTRL-004 | P0 | Le operazioni API sono validate, idempotenti dove possibile e protette da rate limiting. | Request schema invalidi non producono side effects. |
| FR-CTRL-005 | P1 | Dashboard web utilizza CSRF protection, CSP, cookie sicuri se session-based, e controllo Origin. | Suite web security e test CSRF passano. |
| FR-CTRL-006 | P1 | Gli export ZIP sono costruiti in memoria o in area temporanea protetta e rimossi in modo sicuro al termine. | Nessuna copia accessibile a utenti non autorizzati; dimensione e path sono validati. |
| FR-CTRL-007 | P1 | L'API espone solo telemetria operativa aggregata e non query DNS/cronologia. | Schema API non contiene campi query, hostname visitato o payload. |
<!-- ANC-0136 -->
Per la dashboard, Python http.server può essere usato solo come server locale minimale dopo hardening e test; non è da considerare automaticamente un server Internet-facing production-grade. Il bind locale/VPN-only resta requisito, con reverse proxy TLS raccomandato quando il pannello viene esposto a più operatori.
<!-- ANC-0137 -->
## 4.10 Backup, restore, aggiornamenti e recovery
<!-- ANC-0138 -->
| ID | Priorità | Requisito | Criterio di accettazione |
|---|---|---|---|
| FR-OPS-001 | P0 | Backup cifrato di configurazioni e materiale necessario al recovery, con manifest e checksum. | Backup non contiene file temporanei o query log; decrypt/restore è testato. |
| FR-OPS-002 | P0 | Chiavi e segreti sono esclusi da Git, console, crash report e log. | Secret scanning automatico sul repository e sui bundle. |
| FR-OPS-003 | P0 | Restore è una transazione con preflight, backup dello stato corrente e verifica finale. | Restore interrotto non lascia un sistema apparentemente healthy ma incoerente. |
| FR-OPS-004 | P0 | Aggiornamenti immagine sono pin-nati a digest e promossi dopo test. | La release installata è riproducibile dal manifest. |
| FR-OPS-005 | P0 | Il sistema supporta rollback all'ultima release nota funzionante. | Test upgrade/rollback su VM pulita e VM con dati. |
| FR-OPS-006 | P1 | Watchdog controlla servizi, scadenze peer, DNS, tunnel e firewall. | Il watchdog non modifica segreti o policy senza un piano di reconcile. |
| FR-OPS-007 | P1 | L'uninstall rimuove solo le risorse create dal prodotto e richiede conferma per dati persistenti. | Test conserva o cancella dati secondo una scelta esplicita. |
