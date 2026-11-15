# 2. Utenti, ruoli e casi d'uso

<!-- ANC-0074 -->
## 2.1 Persona primaria — Amministratore self-hosted
<!-- ANC-0075 -->
Possiede o noleggia un host Linux, conosce le basi di SSH, Docker e networking, vuole gestire in autonomia i peer e aggiornare il sistema con procedure ripetibili. Deve poter completare il bootstrap con un wizard/CLI e verificare l'installazione tramite un audit leggibile.
<!-- ANC-0076 -->
## 2.2 Persona secondaria — Utente finale
<!-- ANC-0077 -->
Usa i client WireGuard ufficiali o compatibili su desktop e mobile. Vuole importare un profilo, connettersi, capire lo stato e sapere quando il profilo scade. Non deve avere accesso al control plane amministrativo.
<!-- ANC-0078 -->
## 2.3 Persona — Ospite temporaneo
<!-- ANC-0079 -->
Riceve un profilo con una durata massima, una data di scadenza visibile e revoca immediata. Non può estendere autonomamente il proprio accesso.
<!-- ANC-0080 -->
## 2.4 Persona — Auditor/Reviewer
<!-- ANC-0081 -->
Vuole verificare configurazione, esposizione porte, stato servizi, policy DNS, integrità dei file e risultati dei test senza visualizzare segreti o dati personali non necessari.
<!-- ANC-0082 -->
## 2.5 Ruoli e autorizzazioni
<!-- ANC-0083 -->
| Ruolo | Permessi | Divieti |
|---|---|---|
| Owner | Bootstrap, backup, restore, configurazione globale, gestione admin, revoca di ogni peer | Non può disattivare audit di sicurezza senza generare un finding esplicito |
| Operator | Creare, elencare, sospendere, revocare peer; leggere stato e audit sanitizzato | Non legge private key già create; non cambia firewall globale |
| Auditor | Leggere stato, policy, versioni e report | Nessuna mutazione e nessun export di configurazioni contenenti segreti |
| Peer/User | Usare il proprio profilo e consultare scadenza/stato condiviso | Nessun accesso al control plane |
<!-- ANC-0084 -->
Il modello RBAC deve essere applicato lato server a ogni endpoint. Nascondere un pulsante nell'interfaccia non è un controllo di autorizzazione.
