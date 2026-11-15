# SovereignVPN
Implementa PRD+RFC **14.0.0 — 15 novembre 2026 — Draft tecnico avanzato**,
baseline RFC-2026-APEX-13. Ogni artefatto porta questo pin.
- Prevalenza: in attesa della sezione «Principio guida» del corpo. In mancanza:
  RFC prevale su formati/endpoint/schemi/codici errore; PRD su scopo/priorità/AC;
  ogni divergenza si porta a Francesco, mai risolta in silenzio.
- «Self-hosted» non è zero dipendenze: le condizioni (dove vivono tunnel e
  pannello, chi detiene DNS e identità, che cosa parla con terzi) si elencano
  falsificabili e ognuna ha la sua prova.
- Il corpus è derivato, non canonico: si rigenera, non si modifica a mano.
- Un punto ambiguo del draft implementato si marca [H] e si chiude nel documento.
- Banchi: uscita intera in file, riepilogo nella sua riga (totale prima dei
  superati); ogni scansione ritorna esaminati/totale; un controllo che annuncia
  zero vale solo se una mutazione piantata lo fa dire rosso; ogni form respinto
  lato server nomina il campo mancante.
- Rilascio: richiesta di pubblicare solo se sta nel messaggio di Francesco;
  modifica non chiesta si mostra in anteprima (diff/PR bozza), unione solo al sì;
  mai scrivere accanto alla sorgente: output in cartella dedicata e tutto ciò che
  si scrive si rilegge.
- Push sul remoto del progetto: sempre, a ogni rilascio, senza chiedere; si chiede solo per
  force-push su ramo altrui o verso remoto pubblico/di terzi.
- Temporanei: ogni prova scrive in una cartella temporanea propria (`tempfile`), tolta alla fine; mai /tmp fissi, mai file
  di prova nella repo. Il preflight vero sul runner è una prova informativa, non un cancello: dipende dall'ambiente.
- Le prove valgono col banco dei mutanti: `cd control-plane && python3 tests/mutanti.py` (guasti presi, innocui vivi).
- Un punto alla volta; niente «fatto» non visto; una domanda per messaggio.
