# 11. Piano di test e criteri di accettazione

<!-- ANC-0301 -->
Il rilascio non è approvato sulla base della sola compilazione dei file. Ogni feature deve superare test unitari, integrazione, end-to-end, security e failure injection.
<!-- ANC-0302 -->
## 11.1 Gate P0
<!-- ANC-0303 -->
| ID test | Scenario | Risultato atteso |
|---|---|---|
| T-001 | Installazione su Debian 12 pulito | Bootstrap e health check PASS |
| T-002 | Installazione su Ubuntu 24.04 pulito | Bootstrap e health check PASS |
| T-003 | CIDR VPN in conflitto con LAN | Preflight FAIL senza mutazioni |
| T-004 | Porta admin già in uso | Preflight segnala conflitto e non espone endpoint alternativo in pubblico |
| T-005 | Creazione concorrente peer | Nessun IP/UUID duplicato |
| T-006 | Revoca peer con tunnel attivo | Peer perde connettività autorizzata entro 5 s |
| T-007 | Peer-to-peer | Connessione tra peer bloccata |
| T-008 | Full tunnel IPv4 | IP egress coincide con host VPN e non con rete locale client |
| T-009 | DNS hardcoded 8.8.8.8 UDP | Query intercettata/bloccata secondo policy; nessun leak |
| T-010 | DNS hardcoded TCP 53 | Nessun bypass non autorizzato |
| T-011 | DoT TCP 853 | Bloccato se policy DoT attiva |
| T-012 | DoH su 443 | Documentato come limite; nessun claim di blocco universale |
| T-013 | Client IPv6 con server IPv4-only | Nessun IPv6 leak; traffico IPv6 fallisce in modo esplicito |
| T-014 | Query logging Pi-hole | Nessun dominio/peer query persistito |
| T-015 | Log Unbound | Nessuna query applicativa registrata |
| T-016 | Porta DNS container esposta accidentalmente | Security audit FAIL |
| T-017 | Docker port publishing + UFW | Porta non autorizzata bloccata da policy corretta |
| T-018 | Restart Docker | Regole di sicurezza restano valide |
| T-019 | Reboot host | Tunnel/DNS/firewall ripristinati in ordine |
| T-020 | Restore backup | Peer/config ricostruiti e audit PASS |
| T-021 | Backup senza password | Restore rifiutato senza corruzione |
| T-022 | Token admin errato | 401/403 e rate limit; nessuna informazione sensibile |
| T-023 | API da WAN | Non raggiungibile |
| T-024 | API role escalation | Operazione vietata |
| T-025 | Secret scan repository e bundle | Nessun segreto reale o chiave di test non marcata |
| T-026 | Registro corrotto | Startup si ferma in stato recovery, non inventa peer |
| T-027 | Apply firewall fallisce | Rollback o NEEDS_RECOVERY, mai falso PASS |
| T-028 | Clock skew / TTL | Scadenza calcolata UTC e comportamento documentato |
| T-029 | Kernel senza supporto richiesto | Preflight blocca o usa fallback dichiarato |
| T-030 | Security audit 24+ controlli | Esito riproducibile, dettagli per PASS/WARN/FAIL |
<!-- ANC-0304 -->
## 11.2 Gate P1/P2
<!-- ANC-0305 -->
| ID test | Scenario | Risultato atteso |
|---|---|---|
| T-101 | Import profilo WireGuard iOS/Android/Desktop | Connessione e DNS passano |
| T-102 | Mobile network change | Reconnect e keepalive rispettano policy |
| T-103 | Split tunnel overlap | Validazione respinge il profilo |
| T-104 | Wstunnel dietro proxy supportato | Connessione con TLS valido e autenticazione |
| T-105 | Wstunnel dietro proxy incompatibile | Stato DEGRADED/FAILED, nessun fallback non protetto |
| T-106 | Certificato TLS scaduto | Connessione fallisce, alert e procedura renewal |
| T-107 | Tor DNS .onion | Mapping virtuale e traffico TCP transitano in Tor |
| T-108 | Tor daemon down | Nessun fallback clearnet per profili Tor |
| T-109 | Multi-hop egress down | Peer multi-hop perde egress, non esce direttamente |
| T-110 | rp_filter in modalità strict/loose | Nessun falso drop nei percorsi supportati |
| T-111 | CAKE/FQ_CODEL sotto saturazione | Report comparativo con parametri ripetibili |
| T-112 | Apple profile validation | Plist e comportamento testati; nessun claim Always-On improprio |
<!-- ANC-0306 -->
## 11.3 Security audit report
<!-- ANC-0307 -->
Ogni controllo deve produrre: ID, severità, stato, evidenza non sensibile, remediation e timestamp. Stati ammessi: PASS, WARN, FAIL, SKIPPED. SKIPPED non conta come PASS. Se manca una feature opzionale, il controllo relativo è SKIPPED con motivazione. Qualsiasi FAIL di un requisito P0 produce exit code 3.
<!-- ANC-0308 -->
## 11.4 Test di leak
<!-- ANC-0309 -->
I test devono usare almeno due punti di osservazione: client (resolver/route) e server (packet capture/contatori firewall). Testare UDP DNS, TCP DNS, DoT, IPv6, route default, DNS failover e spegnimento dei servizi. Le query devono essere sintetiche e non contenere cronologia o dati personali reali. I pcap sono dati sensibili: si conservano solo durante il test, si sanitizzano e si eliminano a fine run.
