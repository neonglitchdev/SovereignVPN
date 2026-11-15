# SovereignVPN: lettura del documento da un ingegnere nuovo

Documento letto: PRD + RFC SovereignVPN 14.0.0 (15 novembre 2026), corpus di 25 file Markdown in `corpus/`. Lettore: un ingegnere che non conosce il prodotto e ha solo il documento. Non ho aperto altri file del progetto.

## Capitoli letti: 25 su 25

1. 00-apertura.md (quasi vuoto: contiene solo il titolo «(apertura)»)
2. 01-sovereignvpn.md
3. 02-indice.md
4. 03-0-executive-summary.md
5. 04-1-visione-problema-e-posizionamento.md
6. 05-2-utenti-ruoli-e-casi-d-uso.md
7. 06-3-ambito-e-roadmap-di-prodotto.md
8. 07-4-requisiti-funzionali.md
9. 08-5-requisiti-non-funzionali.md
10. 09-6-architettura-logica.md
11. 10-7-sicurezza-e-threat-model.md
12. 11-8-modello-dati-e-segreti.md
13. 12-9-api-e-cli-contract.md
14. 13-10-workflow-end-to-end.md
15. 14-11-piano-di-test-e-criteri-di-accettazio.md
16. 15-12-observability-senza-profilazione.md
17. 16-13-deployment-ambienti-e-supply-chain.md
18. 17-14-organizzazione-del-repository-e-piano.md
19. 18-15-rischi-dipendenze-e-mitigazioni.md
20. 19-16-decision-log-architecture-decision-re.md
21. 20-17-open-questions-da-chiudere-prima-del.md
22. 21-18-definition-of-done-e-release-gate.md
23. 22-19-glossario.md
24. 23-20-riferimenti-tecnici-primari.md
25. 24-21-sintesi-delle-modifiche-rispetto-a-rf.md

I file `indice.json` e `profilo.json` non sono file `.md` e non li ho aperti.

## Da dove partirei

Solo per i capitoli che descrivono qualcosa da costruire. Le ancore citate sono quelle del capitolo indicato.

- **05-2 Utenti, ruoli e casi d'uso** (ANC-0084). Costruirei per primo il controllo di autorizzazione lato server: una tabella ruolo-permesso (Owner, Operator, Auditor, Peer) applicata da un unico punto a ogni endpoint, con test negativi per ruolo insufficiente e per token errato. Il documento chiede che la sicurezza non stia nell'interfaccia.
- **06-3 Ambito e roadmap di prodotto** (ANC-0086, ANC-0110). Il primo passo è il rifiuto di tutto ciò che non è Debian 12 o Ubuntu 24.04 amd64, dentro il preflight. Tor, multi-hop, Wstunnel e UDP2raw restano fuori finché non hanno un gate proprio (ANC-0110).
- **07-4 Requisiti funzionali** (ANC-0116, ANC-0118). Costruirei il registro dei peer con UUID stabile, nome separato e transizioni di stato validate, con comandi `peer add`, `peer list` e `peer show`. Subito dopo, la validazione di AllowedIPs non sovrapposti (FR-WG-003), perché le route sovrapposte sono un rischio di sicurezza.
- **08-5 Requisiti non funzionali** (ANC-0152). Il primo componente sono gli health check che distinguono un processo attivo da un servizio funzionante: risposta DNS, interfaccia WireGuard, ruleset firewall. Si espongono in `sovereignctl status`. Il benchmark ripetibile (ANC-0156) viene dopo.
- **09-6 Architettura logica** (ANC-0187, ANC-0180). Costruirei un applicatore di ruleset firewall transazionale, con batch atomico e rollback. Va scritto solo dopo aver scelto il backend firewall (ANC-0180), altrimenti si costruisce su due ipotesi.
- **10-7 Sicurezza e threat model** (ANC-0221, ANC-0059). Il primo controllo è la redazione e lo scanning di log, output diagnostici e bundle contro chiavi e token. Il documento lo impone (ANC-0059) e lo rende verificabile (ANC-0221).
- **11-8 Modello dati e segreti** (ANC-0242, ANC-0244). Costruirei lo storage del registro su SQLite con transazioni `BEGIN IMMEDIATE`, vincoli di unicità e schema versionato con backup prima di ogni migrazione. Poi il processo di riconciliazione per la saga di stato (ANC-0244).
- **12-9 API e CLI contract** (ANC-0252, ANC-0255). Lo scheletro di `sovereignctl` viene prima dell'API: cinque codici di uscita (0-4), output sanitizzato e test dei codici, che il documento considera parte del contratto (ANC-0255).
- **13-10 Workflow end-to-end** (ANC-0275, ANC-0280). Il primo workflow da implementare è l'onboarding di un peer come transizione di stato con rollback: scrittura in PENDING_APPLY, sincronizzazione, verifica, poi ACTIVE oppure ERROR. Prima va però deciso chi conserva la chiave privata (ANC-0274).
- **14-11 Piano di test** (ANC-0309). Costruirei il banco dei leak DNS in network namespace, con due punti di osservazione, client e server (ANC-0309). Copre T-009 e T-010 ed è la prova che il prodotto dichiara di avere.
- **15-12 Observability senza profilazione** (ANC-0310). Un endpoint di metriche aggregate, solo conteggi e stato di interfaccia, con un test che fallisce se nel payload compaiono domini o IP di client.
- **16-13 Deployment, ambienti e supply chain** (ANC-0319). Il manifest di release con digest delle immagini, e un controllo in CI che rifiuti i tag mobili come `latest` (ANC-0319).
- **17-14 Organizzazione del repository e piano** (ANC-0346, ANC-0332). Costruirei la Slice A, cioè preflight, manifest, schema della configurazione, logging sanitizzato e installer in dry-run (ANC-0346), dentro la struttura di cartelle prevista (ANC-0332).
- **21-18 Definition of Done e release gate** (ANC-0405). Una checklist eseguibile che restituisce PASS o FAIL per ogni voce di ANC-0405, da far girare prima di ogni rilascio.

## Registro delle ambiguità

Ogni citazione è copiata senza modifiche dal blocco che segue l'ancora indicata.

| n. | ancora | file | citazione esatta | perché non basta per implementare | domanda da chiudere |
|---|---|---|---|---|---|
| 1 | ANC-0039 | 03-0-executive-summary.md | I log di sistema sono minimizzati e sottoposti a retention configurabile. | Il valore non è scritto: senza un default la retention non si può né implementare né testare. Il punto 5.2 la lascia a «Dipende da host/cloud». | Quanti giorni di retention per i log di sistema, di default, e chi li cancella? |
| 2 | ANC-0045 | 03-0-executive-summary.md | supporto completo end-to-end oppure blocco verificato | La 1.0 prevede il full tunnel IPv4 (3.1), ma non dice se IPv6 viene supportato o bloccato. La 3.3 rimanda a «IPv6 full support end-to-end, se non già realizzato nel MVP». | Nella 1.0 IPv6 è supporto completo o blocco verificato? Se è blocco, con quale test? |
| 3 | ANC-0047 | 03-0-executive-summary.md | L'accesso remoto richiede VPN amministrativa o un canale out-of-band protetto. | Non è scritto quale VPN amministrativa usare, né come si crea il primo accesso quando il pannello non esiste ancora. «Canale out-of-band protetto» non è definito. | Come si crea la VPN amministrativa nella 1.0, e quale canale out-of-band è ammesso? |
| 4 | ANC-0079 | 05-2-utenti-ruoli-e-casi-d-uso.md | una durata massima, una data di scadenza visibile e revoca immediata | «Durata massima» non ha un numero. «Revoca immediata» non è misurata: FR-PEER-004 dà 5 secondi per ogni peer, senza riferimento all'ospite. | Quale durata massima per l'ospite, in ore o giorni? «Immediata» vuol dire entro 5 secondi? |
| 5 | ANC-0083 | 05-2-utenti-ruoli-e-casi-d-uso.md | Creare, elencare, sospendere, revocare peer | Nella matrice l'Operator può revocare senza condizioni. In 9.2 la DELETE è concessa a «Owner o Operator con policy». La «policy» non è definita in nessun punto. | L'Operator può revocare ogni peer, o solo con una policy? Quale policy, e dove è scritta? |
| 6 | ANC-0083 | 05-2-utenti-ruoli-e-casi-d-uso.md | Non legge private key già create | L'Operator non legge le chiavi, ma può esportare un profilo (9.2: «Owner/Operator con step-up»), e FR-PEER-007 dice che l'export può contenere segreti. Divieto e permesso non sono coordinati. | L'export richiesto dall'Operator può contenere la private key? Sì o no? |
| 7 | ANC-0083 | 05-2-utenti-ruoli-e-casi-d-uso.md | consultare scadenza/stato condiviso | Il peer deve sapere quando scade il profilo (2.2: «capire lo stato e sapere quando il profilo scade»), ma non ha accesso al control plane, e nessun endpoint dell'API 9.2 è per il peer. | Attraverso quale canale il peer legge il proprio stato, senza accesso al control plane? |
| 8 | ANC-0086 | 06-3-ambito-e-roadmap-di-prodotto.md | ARM64 è un target di compatibilità da validare separatamente. | Il capitolo 5.5 dice che il supporto ARM64 è «supporto dichiarato solo per immagini, kernel e test CI che lo coprono», e la domanda 3 lo lascia aperto. «Da validare» non dice se ARM64 entra nella 1.0. | ARM64 entra nella 1.0? Se no, quali test CI lo escludono in modo esplicito? |
| 9 | ANC-0089 | 06-3-ambito-e-roadmap-di-prodotto.md | Kill switch lato host per il forwarding dei peer | Il kill switch è descritto solo lato host, per il forwarding. Per il client, che non deve avere «fallback silenzioso verso Internet diretto» (1.3), non c'è un comportamento definito. | Il client deve bloccare il traffico quando il tunnel cade? Con quale mezzo: il profilo WireGuard o un firewall locale? |
| 10 | ANC-0092 | 06-3-ambito-e-roadmap-di-prodotto.md | CLI per init, add, list, show, revoke, expire-sweep, rotate-psk, export, backup, restore e audit. | La lista non coincide con 9.1: lì i nomi sono «peer add» e «psk rotate», compaiono «suspend», «status» e «diagnostics collect», e «resume» non è in nessuna delle due liste. | Quale lista vale per la 1.0? Quali nomi di comando sono definitivi? |
| 11 | ANC-0116 | 07-4-requisiti-funzionali.md | in condizioni operative nominali | Il requisito dice «Revoca effettiva entro 5 secondi dal commit locale». «Condizioni operative nominali» non è definito, e il tempo non dice se include il sync di WireGuard e la verifica che la chiave sia sparita (10.3). | Quali condizioni sono nominali? Il tempo di 5 secondi include il sync e la verifica in WireGuard? |
| 12 | ANC-0116 | 07-4-requisiti-funzionali.md | scadenza e quota opzionale | «Quota» non ha unità: numero di peer, byte, banda? Il capitolo 10.2 parla di «quota subnet», con un altro significato. | Quota in quale unità, e chi la applica? |
| 13 | ANC-0116 | 07-4-requisiti-funzionali.md | Peer con TTL sono disattivati automaticamente alla scadenza. | Il requisito è P0, quindi entra nella 1.0. Ma la 3.2 (release 1.x) mette «Guest peer con TTL e policy di rinnovo» dopo la 1.0, e la policy di rinnovo non è definita. | Il TTL è nella 1.0 o nella 1.x? Quale regola di rinnovo? |
| 14 | ANC-0120 | 07-4-requisiti-funzionali.md | Pi-hole applica liste di blocco configurate e versionate. | Non è scritto quali liste siano di default, chi le configura, né ogni quanto si sincronizzano. FR-DNS-002 chiede l'«ultima sincronizzazione» senza un intervallo. | Quali liste sono di default, e con quale frequenza si aggiornano? |
| 15 | ANC-0120 | 07-4-requisiti-funzionali.md | i livelli privacy sono verificati in config runtime | Il requisito non fissa il livello di privacy di Pi-hole. Il riferimento R7 (file 23) cita il livello «anonymous», ma il requisito non lo impone. | Quale livello privacy è obbligatorio, e quale test lo verifica? |
| 16 | ANC-0120 | 07-4-requisiti-funzionali.md | DoT TCP/853 può essere bloccato | Un P0 con «può» non impone nulla: ogni esito è accettabile, quindi il requisito non si può dichiarare verificato. | Il blocco di TCP/853 è obbligatorio nella 1.0? Se sì, il «può» va tolto. |
| 17 | ANC-0124 | 07-4-requisiti-funzionali.md | si valuta modalità loose e/o src_valid_mark in modo documentato | La nota lascia la scelta aperta: per rp_filter per interfaccia non c'è un default. Il rischio 15 dice «Config per interfaccia», senza un valore. | Qual è il valore di default di rp_filter per interfaccia nella 1.0? |
| 18 | ANC-0135 | 07-4-requisiti-funzionali.md | Ogni operazione critica è documentata e disponibile da CLI. | «Operazione critica» non ha un elenco. L'API 9.2 espone POST /peers/{uuid}/resume, che 9.1 non contiene. | Il resume è un'operazione critica? Se sì, va aggiunto alla CLI in 9.1. |
| 19 | ANC-0138 | 07-4-requisiti-funzionali.md | Il watchdog non modifica segreti o policy senza un piano di reconcile. | «Piano di reconcile» non è definito: non si sa che cosa contenga, chi lo approvi, o quale comando lo produca. | Che cos'è un piano di reconcile, chi lo approva, e con quale comando si applica? |
| 20 | ANC-0141 | 08-5-requisiti-non-funzionali.md | con SBOM e scansione CVE per ogni release | Non è scritta nessuna soglia: non si sa quale severità CVE blocca la release, né chi decide un'eccezione. | Quale severità CVE blocca una release, e chi autorizza un'eccezione? |
| 21 | ANC-0148 | 08-5-requisiti-non-funzionali.md | Finché richiesta dal modello operativo | La retention della chiave privata del peer dipende da un modello non ancora scelto (domanda 2, file 20). Non è una durata verificabile. | Il server conserva la chiave privata del peer? Sì o no, e per quanto tempo? |
| 22 | ANC-0153 | 08-5-requisiti-non-funzionali.md | target recovery point objective (RPO): ultimo backup riuscito | Il RPO dipende dalla frequenza dei backup, e la frequenza non è scritta. Il backup è un comando manuale (`backup create`) e, prima degli update, un passo di 13.1. | Con quale frequenza si fanno i backup automatici, e quanto vale il RPO in ore? |
| 23 | ANC-0157 | 08-5-requisiti-non-funzionali.md | oltre la soglia concordata | Il criterio di packet loss non ha un numero: la soglia non è scritta, né è detto con chi va concordata. | Quale percentuale di perdita aggiuntiva è accettabile, e chi la concorda? |
| 24 | ANC-0157 | 08-5-requisiti-non-funzionali.md | Stato ristabilito entro 15 s su perdita breve, target da validare | Il valore è dichiarato come target da validare, quindi il test non ha un criterio di superamento definitivo. | Quale valore, validato come, vale come superamento del test di reconnect? |
| 25 | ANC-0157 | 08-5-requisiti-non-funzionali.md | p95 < 100 ms per cache hit su host di riferimento | L'host di riferimento non è descritto: CPU, RAM, rete e carico non sono indicati, quindi il dato non è ripetibile. | Quale hardware è l'host di riferimento per il benchmark DNS? |
| 26 | ANC-0163 | 08-5-requisiti-non-funzionali.md | versione minima dichiarata e verificata | Non c'è nessun numero di versione del kernel. Il preflight di FR-BOOT-001 dovrebbe confrontare la capacità kernel con una soglia che non esiste. | Qual è la versione minima del kernel per WireGuard, e vale anche per il fallback userspace? |
| 27 | ANC-0174 | 09-6-architettura-logica.md | La specifica finale di deployment deve utilizzare un IPAM configurabile | Non c'è una subnet VPN di default né una dimensione del pool. Senza questi dati non si può scrivere il controllo di collisione di T-003, né far scattare SUBNET_EXHAUSTED (9.3). | Quale subnet VPN di default, e quanti peer al massimo per subnet? |
| 28 | ANC-0180 | 09-6-architettura-logica.md | Il prodotto deve scegliere un backend firewall primario per release | La scelta è rinviata alla release. nftables è «consigliato» in 6.5 e «preferito» in ADR-005 e 14.1, mentre iptables-nft compare solo «con compatibilità testata». | Il backend della 1.0 è nftables senza alternative? Se sì, iptables-nft esce dal MVP? |
| 29 | ANC-0221 | 10-7-sicurezza-e-threat-model.md | Pin digest, SBOM, scansione, release signature | Non è scritto chi firma, con quale strumento, né dove sta la chiave di firma. Il capitolo 13.2 parla di «attestazione/checksum», che è un'altra cosa. | Con quale strumento si firmano le release, e dove vive la chiave privata di firma? |
| 30 | ANC-0240 | 11-8-modello-dati-e-segreti.md | TTL minimo/massimo configurabile e limite massimo per guest. | Non ci sono numeri: non si sa se il TTL minimo è di un'ora o di un secondo, né quale sia il limite per guest. | Quali sono TTL minimo, massimo e limite per guest, in ore o giorni? |
| 31 | ANC-0247 | 11-8-modello-dati-e-segreti.md | Il token admin viene verificato con funzione constant-time | Il RBAC di 2.5 ha tre ruoli amministrativi, ma il modello parla di un solo «token admin». Non è scritto come un token porti un ruolo. | Un token per ruolo, o un solo token? Come si lega il ruolo alla credenziale? |
| 32 | ANC-0248 | 11-8-modello-dati-e-segreti.md | Backup cifrati con algoritmo autenticato e derivazione chiave robusta | Non sono nominati l'algoritmo, la funzione di derivazione né i parametri. «Robusta» non è misurabile. | Quale algoritmo e quale funzione di derivazione, con quali parametri iniziali? |
| 33 | ANC-0249 | 11-8-modello-dati-e-segreti.md | La password di backup non deve essere conservata nello stesso backup. | Non è scritto dove sta la password né cosa succede se si perde: un backup cifrato senza password non si restaura, e FR-OPS-001 chiede un restore provato. | Dove si conserva la password di backup, e come si recupera se si perde? |
| 34 | ANC-0258 | 12-9-api-e-cli-contract.md | Owner/Operator con step-up | «Step-up» non è definito né nel glossario né altrove: non si sa quale verifica aggiuntiva richieda. | Che cosa è lo step-up (quale verifica), e come si implementa? |
| 35 | ANC-0259 | 12-9-api-e-cli-contract.md | le operazioni distruttive devono richiedere conferma logica | «Conferma logica» non è un meccanismo: non è scritto se è un campo del corpo, un header o un secondo passo. | Qual è la forma della conferma di un'operazione distruttiva nell'API? |
| 36 | ANC-0274 | 13-10-workflow-end-to-end.md | Genera o riceve le chiavi secondo il modello scelto. | Il modello non è stato scelto (domanda 2, file 20). Generare la chiave sul server o sul client cambia PeerRecord e l'onboarding. | Il server conserva la private key del peer? Il modello va deciso prima dello schema PeerRecord. |
| 37 | ANC-0280 | 13-10-workflow-end-to-end.md | rollback o stato ERROR con recovery path | Non è deciso quando si fa rollback e quando si va in ERROR, né come si esce da ERROR. | Quando il passo 5 o 6 fallisce, si fa rollback o si va in ERROR? Chi decide? |
| 38 | ANC-0283 | 13-10-workflow-end-to-end.md | Peer transita a REVOKED_PENDING | REVOKED_PENDING non è tra i sei stati di FR-PEER-003 (PENDING, ACTIVE, SUSPENDED, EXPIRED, REVOKED, ERROR), né lo è PENDING_APPLY usato in 10.2. | Quali sono tutti gli stati del peer, e quali transizioni sono ammesse fra loro? |
| 39 | ANC-0287 | 13-10-workflow-end-to-end.md | Eventuale export/backup viene invalidato dove applicabile. | «Dove applicabile» non dice quando. Un export già consegnato fuori dal server non si invalida dal server, e il documento non lo dichiara. | Quali export e backup si invalidano, e come, quando il file è già fuori dal server? |
| 40 | ANC-0290 | 13-10-workflow-end-to-end.md | finestra di transizione controllata | Non c'è una durata. Il timeout di 8.4 non ha valore, quindi non si sa quando la rotazione si ferma o torna indietro. | Quanto dura la finestra di transizione, e cosa succede allo scadere? |
| 41 | ANC-0300 | 13-10-workflow-end-to-end.md | marcare NEEDS_RECOVERY e bloccare ulteriori mutazioni | Non c'è una via d'uscita da NEEDS_RECOVERY: nessun comando e nessuna condizione. Il termine non è nel glossario. | Quale comando o condizione riporta il sistema da NEEDS_RECOVERY a operativo, e chi lo autorizza? |
| 42 | ANC-0303 | 14-11-piano-di-test-e-criteri-di-accettazio.md | Query intercettata/bloccata secondo policy | Il test accetta due esiti diversi: intercettata oppure bloccata. Così non distingue una policy dall'altra, e «policy» non è definita. | Qual è l'esito atteso: intercettata o bloccata? Il test deve accettarne solo uno? |
| 43 | ANC-0303 | 14-11-piano-di-test-e-criteri-di-accettazio.md | Bloccato se policy DoT attiva | Il flag della «policy DoT» non è definito nei requisiti e non ha un default. Il test T-011 non sa che cosa verificare. | Qual è il flag che attiva la policy DoT, e qual è il suo default? |
| 44 | ANC-0303 | 14-11-piano-di-test-e-criteri-di-accettazio.md | Security audit 24+ controlli | I controlli non sono elencati. Il file 21 parla di «lista fissa di 24 controlli» e di audit «estendibile»: senza la lista, il risultato non è ripetibile. | Quali sono i 24 controlli, con ID e severità? |
| 45 | ANC-0311 | 15-12-observability-senza-profilazione.md | La dashboard può mostrare online/offline in forma effimera | Il concetto di «online» non ha soglia: non si sa quanti secondi senza handshake fanno passare un peer a offline. | Qual è la soglia di online e offline, e vale anche per la CLI? |
| 46 | ANC-0338 | 17-14-organizzazione-del-repository-e-piano.md | Pi-hole e Unbound con versioni pin-nate | Non sono indicate versioni né digest: chi implementa non sa quale versione pinnare. | Quali versioni di Pi-hole, Unbound, WireGuard e Docker sono pinnate per la 1.0? |
| 47 | ANC-0360 | 19-16-decision-log-architecture-decision-re.md | PSK WireGuard opzionale/abilitabile per peer e ruotabile | Il capitolo 7.5 chiede una «PSK addizionale per peer» come requisito, 0.2 dice che la PSK è «supportata», e l'ADR dice «opzionale». Il default non è scritto. | La PSK è attiva su ogni peer per default, o è opzionale? Quale default? |
| 48 | ANC-0383 | 20-17-open-questions-da-chiudere-prima-del.md | Qual è il target reale: uso personale/familiare, piccolo team o installazione multi-tenant? | Domanda aperta. La baseline (ANC-0393) assume uso personale o piccolo team, ma il modello RBAC e le responsabilità cambiano con il target. | Il target è uso personale, piccolo team o multi-tenant? Si conferma la baseline? |
| 49 | ANC-0391 | 20-17-open-questions-da-chiudere-prima-del.md | Quali client e versioni OS saranno realmente testati e supportati nella matrice release? | Il capitolo 5.5 elenca cinque piattaforme client (Windows, macOS, iOS, Android, Linux) senza versioni. FR-WG-008 chiede test per «ogni piattaforma target», senza dire quali. | Quali versioni di Windows, macOS, iOS, Android e Linux entrano nella matrice? |
| 50 | ANC-0392 | 20-17-open-questions-da-chiudere-prima-del.md | Quale budget minimo di risorse/throughput è necessario per la macchina target? | Non c'è nessun minimo di CPU, RAM, disco o throughput. FR-BOOT-001 controlla lo spazio disco, ma senza soglia. | Qual è il minimo di CPU, RAM, disco e throughput per la macchina target? |
| 51 | ANC-0395 | 21-18-definition-of-done-e-release-gate.md | esplicitamente esclusi dal perimetro con approvazione | Non è scritto chi approva l'esclusione di un requisito P0: l'owner, il product, la sicurezza? | Chi approva l'esclusione di un P0 dal perimetro? |
| 52 | ANC-0398 | 21-18-definition-of-done-e-release-gate.md | Il security audit non presenta FAIL P0. | La DoD blocca solo il FAIL di un P0: un P0 in WARN o SKIPPED passa. Il capitolo 11.3 però dice che SKIPPED non conta come PASS, e i due testi non coincidono. | Un P0 in WARN o SKIPPED blocca la release? Sì o no? |

Totale ambiguità: 52

Per capitolo (file):

- 03-0-executive-summary.md: 3
- 05-2-utenti-ruoli-e-casi-d-uso.md: 4
- 06-3-ambito-e-roadmap-di-prodotto.md: 3
- 07-4-requisiti-funzionali.md: 9
- 08-5-requisiti-non-funzionali.md: 7
- 09-6-architettura-logica.md: 2
- 10-7-sicurezza-e-threat-model.md: 1
- 11-8-modello-dati-e-segreti.md: 4
- 12-9-api-e-cli-contract.md: 2
- 13-10-workflow-end-to-end.md: 6
- 14-11-piano-di-test-e-criteri-di-accettazio.md: 3
- 15-12-observability-senza-profilazione.md: 1
- 17-14-organizzazione-del-repository-e-piano.md: 1
- 19-16-decision-log-architecture-decision-re.md: 1
- 20-17-open-questions-da-chiudere-prima-del.md: 3
- 21-18-definition-of-done-e-release-gate.md: 2

Nessuna ambiguità contata nei capitoli 00, 01, 02, 04, 16, 18, 22, 23, 24.

## Prima mossa

Comincerei dalla Slice A (ANC-0346) con il solo preflight e il dry-run di `sovereignctl init --check`: legge OS, architettura, Docker, spazio disco, orologio e porte, produce un piano senza mutazioni, e con un input non valido esce con exit code 2 senza cambiare stato (ANC-0114, ANC-0263, ANC-0265). È il primo pezzo che non dipende dal modello di chiavi (riga 36) né dal backend firewall (riga 28), e si può verificare da solo. Resta un buco: la versione minima del kernel (riga 26). La tengo come assunzione dichiarata nel preflight, da chiudere con il primo test su Debian 12. Lo scelgo perché il documento vuole che ogni slice sia una release candidate installabile (ANC-0353), e il preflight è la porta d'ingresso di tutte le altre.
