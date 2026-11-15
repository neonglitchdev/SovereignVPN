# 0. Executive summary

<!-- ANC-0029 -->
SovereignVPN è una piattaforma VPN self-hosted, orientata alla privacy e alla gestione autonoma, che combina WireGuard come data plane, servizi DNS con filtraggio, un control plane leggero per la gestione dei peer, automazione operativa e profili di connessione opzionali. Il prodotto deve essere installabile su un singolo host Linux supportato e deve consentire a un amministratore di creare, distribuire, sospendere, revocare e far scadere identità VPN senza dover modificare manualmente decine di file o regole di rete.
<!-- ANC-0030 -->
La proposta non è quella di replicare in ogni dettaglio un servizio VPN commerciale con una singola installazione self-hosted. SovereignVPN non controlla la rete di uscita dell'host, il provider cloud, l'ISP, la giurisdizione, la qualità del peering o la sicurezza del dispositivo client. Il prodotto offre invece un piano di controllo trasparente e verificabile sopra componenti open source, con configurazioni conservative, test automatici e limiti dichiarati.
<!-- ANC-0031 -->
Il successo del prodotto dipende da cinque risultati:
<!-- ANC-0032 -->
1. Connessione affidabile: un peer autorizzato raggiunge l'endpoint configurato, instrada il traffico secondo il profilo selezionato e non aggira il kill switch di rete previsto in caso di guasto.
<!-- ANC-0033 -->
2. Gestione semplice e sicura: onboarding, esportazione, rotazione, scadenza e revoca sono operazioni ripetibili, autorizzate, tracciabili senza registrare cronologie di navigazione e recuperabili dopo errori.
<!-- ANC-0034 -->
3. Privacy verificabile: il sistema minimizza i dati raccolti, disabilita la registrazione delle query DNS e del traffico applicativo per impostazione predefinita e documenta con precisione i dati inevitabilmente presenti su host, kernel, provider e client.
<!-- ANC-0035 -->
4. Difesa in profondità: firewall, isolamento dei servizi, gestione dei segreti, aggiornamenti e test di leak sono progettati come un sistema unico, non come una lista di comandi indipendenti.
<!-- ANC-0036 -->
5. Evoluzione controllata: funzioni avanzate come stealth, Tor e multi-hop sono opzionali, isolate, osservabili e rilasciate soltanto dopo il superamento di gate di sicurezza e compatibilità.
<!-- ANC-0037 -->
## 0.1 Decisione di prodotto fondamentale
<!-- ANC-0038 -->
Il termine RAM-only Zero-Log viene sostituito da due modalità esplicite:
<!-- ANC-0039 -->
Privacy-Minimized (default): nessun log applicativo di query DNS, URL, payload o cronologia di navigazione; persistenza dei soli dati operativi indispensabili, come configurazione del server, chiavi del server, registro peer e metadati di scadenza, protetti a riposo. I log di sistema sono minimizzati e sottoposti a retention configurabile.
<!-- ANC-0040 -->
Ephemeral Runtime (optional): dove supportato, le informazioni di sessione e le statistiche transitorie risiedono in RAM/tmpfs; al riavvio possono essere perse. La modalità non promette che il provider cloud, il kernel, l'hypervisor, lo swap, i crash dump o il dispositivo client non conservino informazioni.
<!-- ANC-0041 -->
Nessuna modalità è definita “provably zero-log” in senso assoluto. Ogni dichiarazione pubblica deve corrispondere a una matrice dati/persistenza e a una suite di test.
<!-- ANC-0042 -->
## 0.2 Decisioni architetturali iniziali
<!-- ANC-0043 -->
WireGuard è il solo protocollo VPN standard del MVP.
<!-- ANC-0044 -->
La PSK WireGuard è supportata come livello simmetrico aggiuntivo, con rotazione; non viene descritta come sostituto di un key exchange post-quantum standardizzato.
<!-- ANC-0045 -->
IPv4 è supportato nel MVP. IPv6 viene gestito esplicitamente: supporto completo end-to-end oppure blocco verificato, mai un “drop IPv6” parziale che lasci percorsi alternativi.
<!-- ANC-0046 -->
Il control plane è separato dal data plane e non deve poter leggere il traffico degli utenti.
<!-- ANC-0047 -->
Le porte amministrative non sono pubblicate su interfacce pubbliche. L'accesso remoto richiede VPN amministrativa o un canale out-of-band protetto.
<!-- ANC-0048 -->
DNS filtering e risoluzione ricorsiva sono componenti separati e testabili; Unbound non è un “upstream esterno”, ma effettua query ricorsive verso root, TLD e authoritative server.
<!-- ANC-0049 -->
Stealth, Tor e multi-hop non sono requisiti di rilascio MVP; sono capability successive con flag disattivati per default.
