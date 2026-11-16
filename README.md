# SovereignVPN

Il tuo server VPN personale: un software che trasforma una macchina tua in un server WireGuard completo, con DNS
che blocca pubblicità e tracciatori, firewall, gestione dei dispositivi e uscite in altri paesi da server di persone
di cui ti fidi. Nessun abbonamento, nessun servizio VPN di terzi, nessuna telemetria.

## Come funziona

1. **Il dispositivo** (telefono, portatile) usa l'app ufficiale WireGuard con un profilo dato dal server: cifra tutto
   il traffico e lo manda al tuo server. Chi sta sullo stesso Wi-Fi, o l'operatore, vede solo dati cifrati.
2. **Il DNS** è sul server: Pi-hole blocca pubblicità e tracciatori per tutti i dispositivi, Unbound risolve i nomi da
   solo, dalle radici e con DNSSEC, senza Google né Cloudflare.
3. **L'uscita**: il traffico va su internet con l'IP del server; oppure da un altro server SovereignVPN, in un altro
   paese, che ti fa da uscita (la federazione), con kill switch (se l'uscita cade non esce niente) e rotazione dell'IP.
4. **Il server si cura da solo**: firewall chiuso tranne WireGuard, dispositivi con scadenza e revoca, controllo dello
   stato (`sovereignctl status`), audit di sicurezza, backup cifrati, ripristino a ogni avvio.

Che cosa **non** fa: non rende anonimi (il server vede il traffico, i siti vedono l'IP del server o dell'uscita) e non
crea paesi: un'uscita in un paese esiste solo dove c'è un server SovereignVPN.

## Dove gira

- **Server**: Ubuntu 24.04 amd64 con WireGuard nel kernel e Docker (per Pi-hole e Unbound). Va su una macchina sempre
  accesa e raggiungibile da internet sulla porta UDP 51820: un VPS, un Raspberry Pi con la porta aperta sul router, una
  macchina cloud gratuita. Installazione: `sudo bash ops/install.sh`, poi `sovereignctl init --check` e
  `sovereignctl init --apply --config /etc/sovereignvpn/server.toml --wan-interface <interfaccia verso internet>`.
- **App per Mac** (`mac/`): il pannello di controllo. Prepara il server in una VM locale (colima), aggiunge i
  dispositivi col QR, sceglie le uscite. `bash mac/build.sh` costruisce l'app.
  La VM sul Mac serve a provare il server: colima non porta dentro la VM il traffico UDP di WireGuard, quindi i
  dispositivi non vi si collegano (misurato il 16/11/2026).

## I comandi

`sovereignctl` con: `init`, `reconcile`, `status`, `audit`, `peer` (add, list, revoke, …), `profile export`, `dns`,
`firewall`, `host`, `backup`, `diagnostics`, `exit` (uscite: `key`, `import`, `list`, `set`, `rotation`, `remove`).

## Uscite in un altro paese (federazione)

1. Sul tuo server: `sovereignctl exit key` mostra la chiave pubblica da dare all'altro server.
2. Chi gestisce l'altro server la aggiunge come dispositivo (`peer add --public-key …`) e ti manda il profilo.
3. Sul tuo server: `sovereignctl exit import PROFILO --paese DE`, poi `exit set DE`.

I due server devono avere reti interne diverse; l'altro server può avere un indirizzo di casa che cambia (DNS dinamico).

## Documenti

- `docs/decisions/ipotesi.md`: le decisioni di progetto (H1-H51), ciascuna con le sue prove.
- `docs/decisions/fiducia.md`: chi vede che cosa, e che cosa parla con terzi, ogni riga con la prova che la smentirebbe.
