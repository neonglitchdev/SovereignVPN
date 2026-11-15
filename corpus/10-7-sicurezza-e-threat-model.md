# 7. Sicurezza e threat model

<!-- ANC-0196 -->
## 7.1 Asset da proteggere
<!-- ANC-0197 -->
Private key server e peer.
<!-- ANC-0198 -->
PSK WireGuard.
<!-- ANC-0199 -->
Token/API credential e certificati TLS.
<!-- ANC-0200 -->
Registro peer, subnet e policy di accesso.
<!-- ANC-0201 -->
Integrità delle regole firewall e del routing.
<!-- ANC-0202 -->
Disponibilità di tunnel, DNS e control plane.
<!-- ANC-0203 -->
Metadati amministrativi e informazioni di rete dell'host.
<!-- ANC-0204 -->
## 7.2 Avversari e capacità considerate
<!-- ANC-0205 -->
1. Attaccante su Wi-Fi pubblico che osserva, blocca o altera traffico.
<!-- ANC-0206 -->
2. Host remoto che effettua scansioni delle porte pubbliche.
<!-- ANC-0207 -->
3. Peer legittimo ma malevolo che tenta lateral movement o abuso delle route.
<!-- ANC-0208 -->
4. Attaccante che ottiene credenziali amministrative.
<!-- ANC-0209 -->
5. Compromissione di container o dipendenza di terze parti.
<!-- ANC-0210 -->
6. Provider cloud/ISP con visibilità sul traffico in ingresso/uscita e sui metadati di rete.
<!-- ANC-0211 -->
7. Utente con accesso root all'host o al client.
<!-- ANC-0212 -->
## 7.3 Minacce non risolte dal prodotto
<!-- ANC-0213 -->
Endpoint client compromesso o keylogger.
<!-- ANC-0214 -->
Analisi di timing/volume e correlazione globale del traffico.
<!-- ANC-0215 -->
Provider cloud che effettua snapshot o ha accesso al layer hypervisor.
<!-- ANC-0216 -->
Malware con privilegi locali sul server.
<!-- ANC-0217 -->
Server di destinazione che identifica l'utente tramite account, cookie o fingerprint.
<!-- ANC-0218 -->
Restrizioni legali o richieste del provider/giurisdizione.
<!-- ANC-0219 -->
Traffic confirmation da avversari con osservazione di entrambi i lati della rete.
<!-- ANC-0220 -->
## 7.4 Controlli richiesti
<!-- ANC-0221 -->
| Minaccia | Controllo | Test |
|---|---|---|
| Accesso peer non autorizzato | Chiavi WireGuard uniche, revoca e registry coerente | Tentativo con chiave revocata |
| Lateral movement tra peer | Isolamento inter-peer e firewall forward deny-by-default | Ping/scan peer-to-peer fallisce |
| DNS leak | DNS interno, policy UDP/TCP 53, test IPv4/IPv6 | Resolver hardcoded e packet capture |
| IPv6 leak | Supporto IPv6 end-to-end o drop verificato | Test dual-stack e route leak |
| Esposizione admin | Bind loopback/VPN-only, firewall, auth e RBAC | Scan WAN/LAN e test auth |
| Supply chain | Pin digest, SBOM, scansione, release signature | Verifica manifest e firma |
| Credential leakage | Secret scanning, redaction, permessi minimi | Test log, shell history, bundle e CI |
| Docker port bypass | Policy firewall dedicata e port inventory | Scan da host/rete esterna |
| Routing loop o leak multi-hop | Mark/tabelle dedicate, kill switch e failure injection | Spegnimento egress hop |
| DNS logging | Pi-hole privacy level/queryLogging off, Unbound no query log | Ispezione file, DB e volume |
<!-- ANC-0222 -->
## 7.5 Crittografia e post-quantum
<!-- ANC-0223 -->
WireGuard utilizza Noise_IK e Curve25519 per il proprio handshake e consente una PSK simmetrica addizionale mescolata nel processo crittografico. Il progetto ufficiale descrive questa PSK come un livello simmetrico utile anche in ottica di post-quantum resistance. [R1]
<!-- ANC-0224 -->
La specifica deve però evitare la formula “post-quantum VPN completa”. La PSK non sostituisce un key exchange post-quantum standardizzato e non rende Curve25519 post-quantum. Il requisito corretto è: PSK addizionale per peer, generata con CSPRNG e scambiata tramite canale sicuro, con rotazione e revoca automatizzabili. Eventuali suite ibride PQC dovranno essere valutate come protocollo separato, con standard, implementazioni e interoperabilità documentati.
<!-- ANC-0225 -->
La generazione di chiavi utilizza wg genkey, wg pubkey e wg genpsk o strumenti equivalenti ufficiali; la documentazione WireGuard descrive il flusso di generazione. [R2]
<!-- ANC-0226 -->
## 7.6 Zero-Log: formulazione verificabile
<!-- ANC-0227 -->
La dichiarazione ammessa è: “SovereignVPN non registra intenzionalmente query DNS, URL o payload applicativi nel control plane; la configurazione predefinita minimizza i log dei resolver e dei servizi. Alcuni metadati operativi esistono temporaneamente nel kernel e sull'host; provider e client restano fuori dal controllo completo del prodotto.”
<!-- ANC-0228 -->
La parola “provable” può essere usata soltanto per singoli test circoscritti, ad esempio: “il test verifica che il database Pi-hole non contenga query DNS durante lo scenario X”, non per una promessa assoluta sull'intera infrastruttura.
