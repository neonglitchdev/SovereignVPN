# 20. Riferimenti tecnici primari

<!-- ANC-0434 -->
Riferimenti consultati per la revisione tecnica; consultare la documentazione ufficiale aggiornata prima di ogni release perché versioni, API e compatibilità possono cambiare.
<!-- ANC-0435 -->
[R1] WireGuard — Protocol & Cryptography: https://www.wireguard.com/protocol/ — Noise_IK, Curve25519 e PSK simmetrica aggiuntiva.
<!-- ANC-0436 -->
[R2] WireGuard — Quick Start: https://www.wireguard.com/quickstart/ — generazione chiavi e PersistentKeepalive.
<!-- ANC-0437 -->
[R3] Docker Docs — Packet filtering and firewalls: https://docs.docker.com/engine/network/packet-filtering-firewalls/ — port publishing, firewall backend e interazione con UFW.
<!-- ANC-0438 -->
[R4] Linux Kernel Docs — IP sysctl: https://docs.kernel.org/networking/ip-sysctl.html — rp_filter strict/loose e src_valid_mark.
<!-- ANC-0439 -->
[R5] Apple Platform Deployment — VPN overview: https://support.apple.com/guide/deployment/vpn-overview-depae3d361d0/ — Always On VPN e requisiti di supervisione.
<!-- ANC-0440 -->
[R6] Apple Developer — VPN payload: https://developer.apple.com/documentation/devicemanagement/vpn — payload com.apple.vpn.managed e capability AlwaysOn; https://developer.apple.com/documentation/devicemanagement/vpn/ikev2-data.dictionary — OnDemandRules e proprietà IKEv2.
<!-- ANC-0441 -->
[R7] Pi-hole Docs — Privacy levels: https://docs.pi-hole.net/ftldns/privacylevels/ — livelli privacy e disabilitazione query log/long-term database al livello anonymous.
<!-- ANC-0442 -->
[R8] Wstunnel — Project documentation: https://github.com/erebe/wstunnel — protocolli e modalità, compatibilità e note operative.
<!-- ANC-0443 -->
[R9] Tor — torrc man page: https://manpages.debian.org/bookworm/tor/torrc.5.en.html — DNSPort, TransPort, AutomapHostsOnResolve e limiti delle query supportate.
<!-- ANC-0444 -->
[R10] Pi-hole Docs — Configuration: https://docs.pi-hole.net/ftldns/configfile/ — query logging e configurazione FTL.
<!-- ANC-0445 -->
[R11] Pi-hole Docs — Unbound: https://docs.pi-hole.net/guides/dns/unbound/ — resolver ricorsivo, root hints e DNSSEC.
