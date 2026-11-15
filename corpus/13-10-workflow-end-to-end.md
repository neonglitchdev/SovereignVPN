# 10. Workflow end-to-end

<!-- ANC-0262 -->
## 10.1 Provisioning host
<!-- ANC-0263 -->
1. L'operatore esegue init --check.
<!-- ANC-0264 -->
2. Il sistema rileva prerequisiti e conflitti di rete/porte.
<!-- ANC-0265 -->
3. Genera un piano senza mutazioni.
<!-- ANC-0266 -->
4. L'operatore approva il piano.
<!-- ANC-0267 -->
5. Vengono salvati backup e manifest iniziali.
<!-- ANC-0268 -->
6. Si applicano container, firewall, sysctl e servizio WireGuard in fasi atomiche.
<!-- ANC-0269 -->
7. Si eseguono health check e test di leak.
<!-- ANC-0270 -->
8. Il sistema stampa il riepilogo e le sole azioni successive necessarie.
<!-- ANC-0271 -->
## 10.2 Onboarding peer
<!-- ANC-0272 -->
1. Operatore crea peer con display name e TTL opzionale.
<!-- ANC-0273 -->
2. Control plane controlla quota subnet, policy e route overlap.
<!-- ANC-0274 -->
3. Genera o riceve le chiavi secondo il modello scelto.
<!-- ANC-0275 -->
4. Scrive registro in stato PENDING_APPLY.
<!-- ANC-0276 -->
5. Aggiorna WireGuard tramite sync sicuro.
<!-- ANC-0277 -->
6. Verifica configurazione runtime.
<!-- ANC-0278 -->
7. Transizione a ACTIVE.
<!-- ANC-0279 -->
8. Export del profilo avviene una sola volta o con autorizzazione esplicita.
<!-- ANC-0280 -->
Se il punto 5 o 6 fallisce, il peer non resta ACTIVE: rollback o stato ERROR con recovery path.
<!-- ANC-0281 -->
## 10.3 Revoca peer
<!-- ANC-0282 -->
1. Richiesta autenticata e autorizzata.
<!-- ANC-0283 -->
2. Peer transita a REVOKED_PENDING.
<!-- ANC-0284 -->
3. Control plane rimuove peer dalla config runtime e applica il nuovo stato.
<!-- ANC-0285 -->
4. Verifica che la chiave non sia più presente in WireGuard.
<!-- ANC-0286 -->
5. Commit definitivo REVOKED.
<!-- ANC-0287 -->
6. Eventuale export/backup viene invalidato dove applicabile.
<!-- ANC-0288 -->
Il database non deve dichiarare revoca completata prima che lo stato live sia coerente.
<!-- ANC-0289 -->
## 10.4 Rotazione PSK
<!-- ANC-0290 -->
La rotazione può essere per singolo peer o per tutti. Deve gestire client non raggiungibili e profili non aggiornati. Strategia raccomandata: generazione chiave, creazione export aggiornato, distribuzione confermata (quando possibile), finestra di transizione controllata, applicazione e revoca della vecchia PSK. Se non esiste canale di conferma client, il sistema deve avvisare che la rotazione può causare disconnessione fino al nuovo import.
<!-- ANC-0291 -->
## 10.5 Expiration guest
<!-- ANC-0292 -->
Il TTL è interpretato in UTC. Il job è idempotente e può essere eseguito dopo reboot; non dipende da un timer in memoria. Il peer scaduto non è riattivabile con il medesimo UUID/chiave; un nuovo accesso richiede provisioning nuovo.
<!-- ANC-0293 -->
## 10.6 Upgrade e rollback
<!-- ANC-0294 -->
1. Verifica release, digest e stato backup.
<!-- ANC-0295 -->
2. Esecuzione test pre-upgrade.
<!-- ANC-0296 -->
3. Pull immagine pin-nata.
<!-- ANC-0297 -->
4. Migrazione schema versionata.
<!-- ANC-0298 -->
5. Deploy con health check.
<!-- ANC-0299 -->
6. Audit post-upgrade.
<!-- ANC-0300 -->
7. Se fallisce, rollback immagine/config/database secondo compatibilità schema; altrimenti marcare NEEDS_RECOVERY e bloccare ulteriori mutazioni.
