# 14. Organizzazione del repository e piano di implementazione

<!-- ANC-0331 -->
Il vincolo originario “60 file in 10 batch” viene sostituito da un repository organizzato per componenti e da release verticali. Il numero di file non è un requisito di prodotto; la completezza, la coerenza, la riproducibilità e la copertura test lo sono.
<!-- ANC-0332 -->
sovereign-vpn/├── README.md├── LICENSE├── SECURITY.md├── CONTRIBUTING.md├── Makefile├── compose/│   ├── compose.yaml│   └── profiles/├── config/│   ├── schema/│   ├── examples/│   └── defaults/├── control-plane/│   ├── sovereignctl/│   ├── api/│   ├── models/│   ├── storage/│   ├── services/│   └── tests/├── networking/│   ├── firewall/│   ├── routing/│   ├── sysctl/│   └── qdisc/├── dns/│   ├── pihole/│   ├── unbound/│   └── tests/├── optional/│   ├── wstunnel/│   ├── tor/│   ├── multihop/│   └── udp2raw-experimental/├── ops/│   ├── systemd/│   ├── backup/│   ├── restore/│   ├── upgrade/│   └── diagnostics/├── security/│   ├── apparmor/│   ├── seccomp/│   ├── audit/│   └── threat-model/├── tests/│   ├── unit/│   ├── integration/│   ├── e2e/│   ├── security/│   └── fixtures/├── docs/│   ├── architecture/│   ├── deployment/│   ├── client-setup/│   ├── operations/│   └── decisions/└── .github/    └── workflows/
<!-- ANC-0333 -->
## 14.1 Stack e vincoli di implementazione
<!-- ANC-0334 -->
Control plane host: Python 3.11+ standard library per il nucleo, salvo decisione motivata e review delle dipendenze.
<!-- ANC-0335 -->
Storage: SQLite con WAL valutato, transazioni esplicite e backup consistente.
<!-- ANC-0336 -->
WireGuard: wg/wg-quick o gestione netlink equivalente; evitare parsing fragile di output non stabile senza test.
<!-- ANC-0337 -->
Firewall: nftables preferito per nuove installazioni; compatibilità iptables solo se mantenuta come backend separato.
<!-- ANC-0338 -->
DNS: Pi-hole e Unbound con versioni pin-nate, configurazione versionata.
<!-- ANC-0339 -->
API: implementazione limitata all'interfaccia locale; non assumere che la libreria standard fornisca automaticamente tutte le protezioni web necessarie.
<!-- ANC-0340 -->
Test: unittest/pytest (se dipendenza di test accettata), test VM, network namespaces e packet capture sintetica.
<!-- ANC-0341 -->
## 14.2 Contratto degli script Bash
<!-- ANC-0342 -->
Gli script che modificano host o rete devono usare set -Eeuo pipefail, IFS controllato, trap di errore sanitizzato, funzioni di cleanup e lock. Non devono stampare chiavi o token. Devono supportare --dry-run, controllare prerequisiti, essere idempotenti e distinguere errore di validazione da errore runtime. Un trap ERR non è rollback automatico: il rollback va codificato esplicitamente per ogni transazione.
<!-- ANC-0343 -->
## 14.3 Python e atomicità
<!-- ANC-0344 -->
Python 3.11+ con typing, modelli immutabili dove utili e gerarchia errori di dominio. Le chiamate subprocess devono usare argv list, timeout, ambiente controllato e check=True dove corretto; non interpolare input utente in shell command. Atomic write con file temporaneo nella stessa filesystem, flush/fsync e os.replace; fsync directory dove necessario. Atomicità tra database, kernel e filesystem deve essere gestita come processo di riconciliazione, non dichiarata come garantita da un singolo os.replace.
<!-- ANC-0345 -->
## 14.4 Piano di implementazione per vertical slice
<!-- ANC-0346 -->
1. Slice A — Base host: preflight, manifest, schema config, logging sanitizzato, installer dry-run.
<!-- ANC-0347 -->
2. Slice B — WireGuard core: peer create/list/revoke, routing, firewall baseline, test IPv4 e IPv6.
<!-- ANC-0348 -->
3. Slice C — DNS privacy: Pi-hole/Unbound, query logging off, blocklist updates, DNS leak suite.
<!-- ANC-0349 -->
4. Slice D — Persistence/recovery: DB, atomic apply, backup/restore, recovery state machine.
<!-- ANC-0350 -->
5. Slice E — Operations: watchdog, update/rollback, audit report, docs.
<!-- ANC-0351 -->
6. Slice F — UX: bundle, QR, API locale, dashboard se i gate security sono soddisfatti.
<!-- ANC-0352 -->
7. Slice G — Optional transports: WSS, Tor, multi-hop come progetti separati con gate dedicati.
<!-- ANC-0353 -->
Ogni slice produce release candidate installabile e testato; non si consegnano decine di file non integrati in un unico dump.
