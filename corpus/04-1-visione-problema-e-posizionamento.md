# 1. Visione, problema e posizionamento

<!-- ANC-0050 -->
## 1.1 Visione
<!-- ANC-0051 -->
Consentire a un individuo, a una famiglia o a un piccolo team tecnico di gestire un proprio gateway VPN con controllo diretto su identità, routing, policy DNS, aggiornamenti e ciclo di vita dei client, senza dipendere da un dashboard SaaS del fornitore VPN.
<!-- ANC-0052 -->
## 1.2 Problema da risolvere
<!-- ANC-0053 -->
Le soluzioni self-hosted spesso richiedono interventi manuali su chiavi, peer, firewall, DNS, certificati e route. Errori apparentemente piccoli possono produrre DNS leak, IPv6 leak, accesso laterale tra client, esposizione involontaria del pannello o indisponibilità dopo un aggiornamento. Le soluzioni commerciali semplificano la gestione, ma l'utente rinuncia al controllo diretto dell'infrastruttura e deve fidarsi del provider.
<!-- ANC-0054 -->
SovereignVPN deve ridurre la complessità operativa mantenendo il controllo locale e rendendo esplicito ciò che l'installazione può e non può garantire.
<!-- ANC-0055 -->
## 1.3 Principi non negoziabili
<!-- ANC-0056 -->
1. Secure by default, non “secure if configured correctly”.
<!-- ANC-0057 -->
2. Fail closed per le funzioni che dichiarano protezione da leak; nessun fallback silenzioso verso Internet diretto.
<!-- ANC-0058 -->
3. Minimo privilegio tra container, processi, utenti di sistema e API.
<!-- ANC-0059 -->
4. Nessuna chiave privata o token in log, output diagnostici o telemetry.
<!-- ANC-0060 -->
5. Ogni mutazione deve essere idempotente, validata e reversibile oppure accompagnata da una procedura di recovery.
<!-- ANC-0061 -->
6. Ogni feature avanzata ha un flag esplicito, uno stato di salute, una policy di fallback e test negativi.
<!-- ANC-0062 -->
7. Le dichiarazioni di privacy e sicurezza devono essere verificabili e circoscritte.
<!-- ANC-0063 -->
8. Dipendenze, immagini e release devono essere pin-ning e aggiornabili in modo riproducibile.
<!-- ANC-0064 -->
9. Il sistema deve funzionare senza SaaS, account remoto o telemetria obbligatoria.
<!-- ANC-0065 -->
10. Usabilità e sicurezza non devono essere delegate a un prompt di generazione del codice.
<!-- ANC-0066 -->
## 1.4 Non-obiettivi
<!-- ANC-0067 -->
Non promettere prestazioni superiori a NordVPN, Surfshark, Proton VPN o a qualsiasi provider commerciale.
<!-- ANC-0068 -->
Non offrire una rete globale di exit node o una distribuzione geografica automatica.
<!-- ANC-0069 -->
Non garantire anonimato assoluto, protezione contro endpoint compromessi, malware client o correlazione globale del traffico.
<!-- ANC-0070 -->
Non garantire l'elusione di ogni sistema DPI, firewall aziendale o captive portal.
<!-- ANC-0071 -->
Non sostituire MDM Apple, EDR, firewall aziendale o strumenti di gestione endpoint.
<!-- ANC-0072 -->
Non registrare o analizzare contenuti applicativi per costruire profili utente.
<!-- ANC-0073 -->
Non supportare inizialmente cluster multi-host, alta disponibilità geografica o bilanciamento automatico multi-region.
