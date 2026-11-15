# 6. Architettura logica

<!-- ANC-0166 -->
## 6.1 Separazione dei piani
<!-- ANC-0167 -->
Data plane — WireGuard, interfacce, routing, NAT, firewall, MTU e qdisc. È il percorso dei pacchetti degli utenti; deve funzionare indipendentemente dalla dashboard.
<!-- ANC-0168 -->
Control plane — CLI/API, validazione, registro peer, lifecycle, generazione profili, applicazione atomica della configurazione e audit amministrativo. Non deve ispezionare il payload applicativo.
<!-- ANC-0169 -->
DNS plane — Pi-hole per policy/filtraggio e Unbound per risoluzione ricorsiva/DNSSEC. Le interfacce DNS non sono esposte su WAN.
<!-- ANC-0170 -->
Operations plane — watchdog, update manager, backup/restore, security audit, health check e report. I controlli operativi devono essere non invasivi e non registrare cronologie.
<!-- ANC-0171 -->
Optional service plane — Wstunnel, Tor, multi-hop ed eventuale adapter UDP2raw. Ogni servizio ha rete e policy egress separate e può essere spento senza compromettere il core VPN.
<!-- ANC-0172 -->
## 6.2 Topologia di riferimento
<!-- ANC-0173 -->
INTERNET / RETI OSTILI                              |              +---------------+----------------+              |                                |          UDP 51820                         TCP 443 (opz.)          WireGuard                         WSS ingress              |                                |+-------------v--------------------------------v-------------+| HOST LINUX                                                   ||                                                               ||  Firewall host + Docker firewall integration                 ||  sysctl / routing tables / conntrack / qdisc                  ||                                                               ||  +-------------------- sovereign_net ---------------------+   ||  |                                                       |   ||  |  WireGuard data plane                                 |   ||  |  wg0: VPN client subnet                                |   ||  |       |                                               |   ||  |       +----> Policy firewall / NAT / routing          |   ||  |       |                                               |   ||  |  DNS plane                                            |   ||  |  Pi-hole ---> Unbound ---> Root/TLD/Authoritative DNS |   ||  |                                                       |   ||  |  Control plane (loopback/VPN admin only)              |   ||  |  CLI / API / registry / profile exporter             |   ||  |                                                       |   ||  |  Optional isolated services: WSS / Tor / egress hop  |   ||  +-------------------------------------------------------+   ||                                                               ||  Persistent encrypted config + backup                         ||  Volatile runtime state (tmpfs where appropriate)             |+---------------------------------------------------------------+
<!-- ANC-0174 -->
Gli indirizzi IP e le subnet del diagramma sono esempi logici. La specifica finale di deployment deve utilizzare un IPAM configurabile, controllare collisioni con LAN/VPC e generare una matrice delle route. Non si deve assumere che eth0 sia sempre l'interfaccia WAN: il bootstrap deve rilevare la route predefinita o richiedere una configurazione esplicita.
<!-- ANC-0175 -->
## 6.3 Ownership dei componenti
<!-- ANC-0176 -->
| Componente | Responsabilità | Non deve fare |
|---|---|---|
| Host kernel | WireGuard, routing, conntrack, netfilter/nftables, qdisc | Registrare query o contenuti applicativi per conto del prodotto |
| Docker Engine | Isolamento e networking container | Essere trattato come neutrale rispetto al firewall host |
| WireGuard service | Terminare tunnel e applicare peer config | Esporre pannello admin o gestire utenti web |
| Pi-hole | Bloccare/consentire risoluzioni secondo policy | Esporre query log al control plane |
| Unbound | Risolvere ricorsivamente e validare DNSSEC | Usare forwarder pubblici non dichiarati |
| Control plane | Validare e orchestrare configurazioni | Fare packet inspection o raccogliere URL |
| Wstunnel | Trasporto WSS opzionale | Essere necessario al funzionamento core |
| Tor | Proxy anonimo opzionale | Diventare fallback invisibile del traffico clearnet |
| Watchdog | Riconciliare stato dichiarato e stato reale | Aggirare policy o riattivare peer revocati |
<!-- ANC-0177 -->
## 6.4 Network namespace e IPAM
<!-- ANC-0178 -->
La release deve descrivere per ogni servizio: network namespace, indirizzo, listener, porte container, porte host pubblicate, ingress consentiti, egress consentito, capability Linux e volumi. La subnet Docker non deve collidere con VPN subnet, LAN, VPC, subnet Tor virtuale o reti sovrapposte del client. Il sistema deve calcolare i CIDR e rifiutare overlap non gestiti.
<!-- ANC-0179 -->
## 6.5 Firewall architecture
<!-- ANC-0180 -->
Il prodotto deve scegliere un backend firewall primario per release (nftables consigliato per nuova implementazione, oppure iptables-nft con compatibilità testata) ed evitare di mischiare regole native e legacy senza una matrice di compatibilità.
<!-- ANC-0181 -->
Policy minima concettuale:
<!-- ANC-0182 -->
INPUT: drop default; consentire loopback, established/related, SSH amministrativo da sorgenti autorizzate e porte VPN pubbliche configurate.
<!-- ANC-0183 -->
FORWARD: drop default; consentire solo peer VPN verso WAN/DNS e verso LAN se esplicitamente abilitata; drop peer-to-peer; consentire return traffic stateful.
<!-- ANC-0184 -->
OUTPUT: consentire traffico host necessario; opzionalmente limitare egress per servizi isolati.
<!-- ANC-0185 -->
Docker: port publishing verificato anche nel percorso di forwarding e nella chain di user policy dedicata.
<!-- ANC-0186 -->
IPv6: stessa postura di sicurezza di IPv4, oppure disabilitazione completa e verificata dell'inoltro IPv6 secondo un modello documentato.
<!-- ANC-0187 -->
Le regole devono essere applicate come ruleset transazionale, preferibilmente con nftables batch atomico. Se resta iptables, la sequenza deve verificare lo stato e applicare rollback. “Comando idempotente” non significa soltanto usare -C || -A: occorre anche evitare duplicati, gestire ordering, rimozione, restore e conflitti con Docker/UFW.
<!-- ANC-0188 -->
## 6.6 Routing e QoS
<!-- ANC-0189 -->
FQ_CODEL è una disciplina di fair queueing e gestione delle code; non configura da sola un limite di banda della WAN. CAKE può essere più appropriato quando si conosce la banda effettiva del collo di bottiglia e si vuole shaping. La qdisc deve essere applicata all'interfaccia e alla direzione in cui si verifica il collo di bottiglia, con test misurabili. Un fq_codel applicato soltanto a wg0 non dimostra che il bufferbloat della coda WAN sia stato risolto.
<!-- ANC-0190 -->
Il benchmark deve confrontare baseline, FQ_CODEL e CAKE (se abilitato) utilizzando carico controllato, misure di latenza sotto saturazione e throughput. La configurazione scelta non deve essere hardcoded come universale.
<!-- ANC-0191 -->
## 6.7 DNS resolution path
<!-- ANC-0192 -->
VPN client   |   | DNS UDP/TCP 53   vPi-hole (policy + cache + blocklists)   |   | recursive query   vUnbound (DNSSEC validation + cache)   |   +--> Root server --> TLD server --> Authoritative server
<!-- ANC-0193 -->
Il resolver ricorsivo contatta server DNS autoritativi della gerarchia pubblica; pertanto “nessun upstream provider configurato” non significa “nessuna query esce dal server”. Il threat model deve considerare quali domini sono visibili ai resolver autoritativi lungo la catena e al provider di rete. QNAME minimisation riduce la quantità di nome trasmessa ai livelli superiori, ma non rende la risoluzione invisibile.
<!-- ANC-0194 -->
## 6.8 Multi-hop architecture (futura)
<!-- ANC-0195 -->
Ogni peer abilitato al multi-hop deve essere marcato in modo non ambiguo. Il policy routing deve instradare il traffico verso wg-egress e applicare un blocco esplicito se l'egress hop non è disponibile. Il traffico di bootstrap del tunnel egress deve essere esente dal routing ricorsivo. Le regole di ritorno, conntrack, rp_filter, MTU e DNS devono essere testate con failure injection. L'uso di fwmark 0x5182 è un esempio, non un valore globale riservato: mark, tabelle e priorità devono essere allocate da un registry interno e controllate contro conflitti host.
