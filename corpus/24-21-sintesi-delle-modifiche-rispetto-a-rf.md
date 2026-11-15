# 21. Sintesi delle modifiche rispetto a RFC-2026-APEX-13

<!-- ANC-0446 -->
1. Da “prompt per generare 60 file in batch” a PRD/RFC con requisiti e gate verificabili.
<!-- ANC-0447 -->
2. Da “supera i provider commerciali” a posizionamento self-hosted onesto, con benchmark riproducibili.
<!-- ANC-0448 -->
3. Da “post-quantum symmetric PSK” a PSK addizionale con claim crittografico circoscritto.
<!-- ANC-0449 -->
4. Da “RAM-only Zero-Log provable” a Privacy-Minimized + Ephemeral Runtime con data lifecycle esplicito.
<!-- ANC-0450 -->
5. Da Always-On Apple generico a distinzione tra WireGuard import, On Demand e Always On IKEv2 supervisionato.
<!-- ANC-0451 -->
6. Da UFW come unico firewall a policy host + Docker + forwarding + port inventory.
<!-- ANC-0452 -->
7. Da rp_filter=1 globale a configurazione per scenario di routing.
<!-- ANC-0453 -->
8. Da FQ_CODEL su wg0 come cura universale a QoS misurata nel punto di congestione.
<!-- ANC-0454 -->
9. Da DoT block come anti-DoH totale a mitigazione parziale con limiti DoH/DoQ dichiarati.
<!-- ANC-0455 -->
10. Da DNS Tor via forwarding singolo a separazione DNSPort, TransPort e virtual address mapping.
<!-- ANC-0456 -->
11. Da atomicità teorica tra più sottosistemi a saga, stato di recovery e riconciliazione.
<!-- ANC-0457 -->
12. Da dashboard standard library implicitamente production-ready a API locale con hardening e superficie limitata.
<!-- ANC-0458 -->
13. Da lista fissa di 24 controlli ad audit estendibile con PASS/WARN/FAIL/SKIPPED e prove.
<!-- ANC-0459 -->
14. Da feature advanced tutte promesse a roadmap con feature flag, owner e release gate.
<!-- ANC-0460 -->
Fine documento — SovereignVPN PRD + RFC 14.0
