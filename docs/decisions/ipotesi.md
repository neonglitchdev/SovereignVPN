# Ipotesi [H] in vigore

Dove il PRD+RFC 14.0.0 non decide, il codice usa un'ipotesi dichiarata: si marca [H] nel codice e nel rapporto, e si
chiude nel documento (regola di CLAUDE.md). Ognuna si rovescia cambiando una riga.

| | ipotesi | perché | dove | da confermare |
|---|---|---|---|---|
| H1 | La revoca è REVOKED + saga PENDING_APPLY, non un settimo stato REVOKED_PENDING | ANC-0244 ha già le due dimensioni; FR-PEER-003 ha sei stati | Slice B | Francesco |
| H2 | Chiave privata del peer generata sul client, sul server solo la pubblica | ANC-0148 «preferire generazione lato client»; domanda aperta 2 (ANC-0384) | Slice B | Francesco |
| H3 | Un prerequisito mancante esce col codice 1 (errore di sistema) | ANC-0255 non lo assegna; 2 è riservato all'input non valido | `sovereignctl init --check` | Francesco |
| H4 | Kernel minimo 5.6 | WireGuard è nel kernel mainline dalla 5.6; ANC-0163 chiede una minima «dichiarata» che non c'è | `preflight.KERNEL_MINIMO` | prima prova su Debian 12 |
| H5 | 10 GiB liberi su / | Il documento chiede il controllo (FR-BOOT-001) ma non la soglia | `preflight.DISCO_MINIMO` | dopo il primo `compose pull` misurato |
| H6 | IPAM: prima /24 libera fra 10.66.0.0 e 10.99.0.0 | ANC-0174 vuole un IPAM configurabile e senza collisioni, non dà la rete | `preflight.CANDIDATE_VPN` | Francesco |
| H7 | Porta di amministrazione TCP 8443, solo su 127.0.0.1 o sulla VPN | ADR-006: API e dashboard non pubbliche; il numero non c'è | `preflight.PORTA_ADMIN` | Francesco |
| H8 | La configurazione è un file TOML | `tomllib` è nella libreria standard dalla 3.11 (ANC-0334); YAML vorrebbe una dipendenza | `configurazione.leggi` | Francesco |
| H9 | MTU predefinita 1420, ammessa fra 1280 e 1500 | 1420 è il valore abituale di WireGuard; 1280 è il minimo di IPv6 | `configurazione.valida` | primo test di PMTU (FR-WG) |
| H10 | TTL di un peer da 1 a 365 giorni | ANC-0240 vuole un minimo e un massimo configurabili, senza numeri | `peer.TTL_MASSIMO_GIORNI` | Francesco |
| H11 | Il primo host della subnet VPN è del server; i peer partono dal secondo | Convenzione WireGuard; il documento non assegna l'indirizzo del server | `Archivio.aggiungi` | Francesco |
| H12 | Registro dei peer in /var/lib/sovereignvpn/registro.sqlite3, file 0600 | ANC-0244 dice SQLite, non il percorso; la cartella 0700 la crea l'installer | `peer.DB_PREDEFINITO` | Francesco |
| H13 | Interfaccia WireGuard `wg0`, chiave del server in /etc/sovereignvpn/wg-server.key (0600), generata da `init` con `wg genkey` | ANC-0148 vuole la chiave del server come file protetto; FR-WG-002 vuole `wg` per generarla; nome e percorso non ci sono | `runtime.INTERFACCIA`, `runtime.CHIAVE_SERVER` | Francesco |
| H14 | Firewall come tabella propria `inet sovereignvpn`; SSH ammesso solo da `admin_ssh_sources`, senza sorgenti il firewall non si compone; ICMP essenziale ammesso; il DNS dei peer va solo ai resolver interni | ANC-0182 vuole SSH «da sorgenti autorizzate» senza nominarle; un drop senza la via dell'amministratore lo chiuderebbe fuori | `firewall.componi` | Francesco |

Chiuse dal documento, senza ipotesi: backend firewall nftables (ADR-005, ANC-0372); porta WireGuard UDP 51820 (ANC-0173).
