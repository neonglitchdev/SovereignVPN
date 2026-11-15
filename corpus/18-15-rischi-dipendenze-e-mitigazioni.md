# 15. Rischi, dipendenze e mitigazioni

<!-- ANC-0354 -->
| Rischio | Probabilità | Impatto | Mitigazione |
|---|---|---|---|
| Docker bypassa la policy UFW prevista | Alta | Critico | Policy in chain Docker/user firewall, test esterno e port inventory [R3] |
| rp_filter=1 rompe routing asimmetrico | Media | Alto | Config per interfaccia, test policy routing e src_valid_mark [R4] |
| Falsa promessa Always-On su Apple | Alta | Alto | Separare profilo WireGuard da Always On IKEv2 supervisionato [R5][R6] |
| PSK descritta come PQC completa | Media | Alto | Claim limitato a layer simmetrico addizionale [R1] |
| “Zero log” non dimostrabile end-to-end | Alta | Alto | Matrice retention, configurazione host, audit e claim circoscritti [R7] |
| DoH/DoQ evade blocco porta 853 | Alta | Medio/Alto | Documentare limiti, DNS policy e mitigazioni endpoint [R10] |
| Qdisc in interfaccia errata | Media | Medio | Benchmark sotto saturazione e posizionamento corretto della qdisc |
| Tor DNSPort confuso con proxy trasparente completo | Media | Alto | Separare DNSPort, TransPort e regole iptables/nftables [R9] |
| Dipendenza stealth non compatibile con proxy | Media | Alto | Pin versioni, test e modalità disattivata per default [R8] |
| Private key conservate in chiaro | Media | Critico | Storage cifrato, permessi, export one-time, secret scan |
| Aggiornamento rompe schema/config | Media | Alto | Migrazione versionata, backup, rollback e test restore |
| Subnet Docker/VPN collide con LAN cliente | Alta | Medio | IPAM dinamico, preflight e custom subnet |
| Provider cloud conserva snapshot/telemetria | Media | Alto | Dichiarare trust boundary e guidare hardening provider |
