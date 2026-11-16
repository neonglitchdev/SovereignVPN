# Confini di fiducia e traffico verso terzi della 1.0 (NFR-SEC-006) [H46]

«Self-hosted» non è zero dipendenze (regola di `CLAUDE.md`). Qui ogni condizione è scritta in modo che si possa
smentire, e accanto c'è la prova che la smentirebbe. Le prove vere girano nel CI (`.github/workflows/suite.yml`); i
controlli `AUD-xx` li ripete `sovereignctl audit run` sul server vivo. Questo file si aggiorna nella stessa PR di
ogni feature che apre un confine nuovo o un traffico nuovo verso fuori (NFR-SEC-006).

## Dove vive che cosa

| Condizione | Prova che la smentirebbe |
| --- | --- |
| Il tunnel termina sul server dell'amministratore: WireGuard del kernel su `wg0`, nessun relay di terzi | `prova_wg_vero.sh`; `prova_traffico_vero.sh` sezione 1 (il sito vede l'indirizzo del server) |
| Le chiavi dei peer nascono sui dispositivi, o nell'app del Mac che le porta al telefono solo col QR a schermo, senza scriverle su disco né nella VM (H51): il server non ne ha mai la privata (H2) | `test_peer.py`; il profilo esportato porta un segnaposto (`test_profilo.py`); `mac/prova-qr.sh` (il QR riletto è il profilo con la chiave; un profilo senza segnaposto è rifiutato) |
| La chiave del server è un file 0600 che non esce mai: né output, né log, né bundle | `prova_init_vero.sh` giri 1 e 5b; AUD-02; `test_diagnostica.py` e gitleaks nel giro 5b |
| Il pannello e l'API non esistono nella 1.0: niente in ascolto sulla porta di amministrazione fuori da loopback e VPN (H37) | AUD-19; `prova_traffico_vero.sh` sezione 4 (dal WAN fermo) |
| SSH si raggiunge solo dalle sorgenti dichiarate | `prova_traffico_vero.sh` sezione 5; AUD-12 avvisa se una sorgente è /0 |
| Il DNS è dell'amministratore: Pi-hole sull'indirizzo di wg0 (e sull'ULA, irraggiungibile), Unbound solo su 127.0.0.1 | `prova_dns_vero.sh` (nessuna risposta sulla «WAN»); inventario delle porte AUD-10 (T-016) |
| L'identità dei peer è il registro locale (SQLite 0600), mai un servizio esterno | AUD-11, AUD-21 |

## Che cosa parla con terzi, e che cosa no

| Traffico verso fuori | Perché | Prova |
| --- | --- | --- |
| Unbound interroga i server DNS autorevoli, dalle radici, con DNSSEC: nessun forwarder pubblico | DNS ricorsivo proprio (cap. 6) | `test_dns.py` (`test_ricorsivo_dalle_radici_con_dnssec`); `prova_dns_vero.sh` (isc.org col flag AD, dnssec-failed.org SERVFAIL) |
| I peer escono verso internet solo dalla WAN, in IPv4 mascherato; con un'uscita scelta (H48) solo dall'uscita, mai dalla WAN, e se l'uscita cade niente esce | è la VPN; l'uscita la sceglie l'amministratore | `prova_traffico_vero.sh` sezioni 1 e 9; `prova_uscite_vero.sh` sezioni 3, 5 e 6 (kill switch: ognuno dei due livelli basta da solo) |
| Un'uscita vede il traffico dei peer che non è cifrato, e i siti vedono il suo indirizzo: è un altro server SovereignVPN, dell'amministratore o di una persona fidata, o un server dell'amministratore (H50) | le uscite vengono da server propri, non da servizi VPN | `prova_uscite_vero.sh` sezione 3 (il sito vede l'uscita); `test_uscite.py` (Federazione) |
| Il nome di un'uscita (il server di casa col DNS dinamico) si chiede al resolver del server solo all'import e quando l'uscita non fa handshake da 180 s; al riavvio vale l'IP salvato, senza DNS (H50) | il server di casa cambia IP | `test_uscite.py` (NomeHost); `prova_uscite_vero.sh` (la seconda uscita ha un nome); `test_fiducia.py` ammette `socket` in `uscite.py` per questo |
| Nessun DNS dei peer verso fuori (salvo la DNS policy «libero», H34), DoT bloccato (H25) | il DNS resta dell'amministratore | sezioni 3, 3b, 6c; AUD-15, AUD-16 |
| Nessun IPv6 dei peer verso fuori: rifiutato subito nel tunnel (H38) | blocco verificato della 1.0 | sezione 9 (contatore lato server, fuga vista solo col profilo guastato) |
| Pi-hole non sincronizza l'ora e non ha server NTP; le liste di blocco sono file locali versionati, non URL | niente traffico implicito | `test_dns.py`; `prova_dns_vero.sh` (inventario delle porte) |
| All'installazione: le immagini dei container scaricate per digest (Pi-hole) o costruite dalla base pin-nata (Unbound); all'avvio mai (`--pull never`): un'immagine mancante ferma il DNS invece di far cercare a Docker un nome su Docker Hub | la release è riproducibile; un nome come `sovereignvpn-unbound` su Docker Hub potrebbe registrarlo chiunque | `test_dns.py` (`test_immagine_pin_nata_per_digest`); AUD-24 |
| Il backup è cifrato con age verso una chiave che non sta sul server; uscire dal server lo fa l'amministratore | il server non decide dove va | `prova_backup_vero.sh` (un'altra chiave non decifra) |
| Nessuna telemetria, nessun controllo di aggiornamenti, nessun crash report verso fuori | per costruzione | `test_fiducia.py`: nessun modulo importa librerie di rete; `socket` solo nello status (domande DNS in locale), nel preflight (un bind per sapere se una porta è libera) e nelle uscite (il nome dell'uscita, riga sopra). Una chiamata nuova verso fuori fa diventare rossa la prova e va dichiarata qui |
| La diagnostica non esce da sola: scrive un file locale redatto, e mandarlo è una scelta | ANC-0312 | `test_diagnostica.py`; gitleaks nel giro 5b |

## Confini dentro il server

| Confine | Prova |
| --- | --- |
| I container del DNS girano in rete host con capability minime e `no-new-privileges`; Unbound anche in sola lettura (H44) | AUD-32; `prova_dns_vero.sh` (vincoli controllati con `docker inspect`, l'Unbound «largo» come controllo negativo) |
| Il firewall è una tabella propria (`inet sovereignvpn`), separata dalle catene di Docker (H36) | `prova_nft_vero.sh`; AUD-05 |
| Registro illeggibile = nessun traffico dei peer finché non si ripristina (H41) | `prova_init_vero.sh` giro 6b; AUD-17 |

## Ripristino (NFR-AVL-003)

| Obiettivo | Prova |
| --- | --- |
| RTO di 30 minuti su host singolo con un backup valido: il restore (decifratura, scrittura, reconcile, status) si misura a ogni CI e diventa rosso oltre i 1800 s | `prova_backup_vero.sh` (riga «MISURA:»); il tempo di reinstallare l'host da zero non e' misurato qui |
| RPO = l'ultimo backup riuscito: tra un backup e il guasto si perde cio' che e' cambiato (peer, scadenze, byte delle quote) | per costruzione (H20); AUD-23 avvisa se non c'e' nessun backup |
