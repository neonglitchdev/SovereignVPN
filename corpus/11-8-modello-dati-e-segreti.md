# 8. Modello dati e segreti

<!-- ANC-0229 -->
## 8.1 Entità principali
<!-- ANC-0230 -->
ServerConfig — endpoint pubblico, porte, subnet, DNS, MTU, interfaccia WAN, dominio TLS, flags, profilo firewall, versioni e hash del token amministrativo. Non include plaintext secret dove è possibile un riferimento a secret storage.
<!-- ANC-0231 -->
PeerRecord — UUID, display name, public key, eventuale private key cifrata se il modello la conserva, PSK cifrata, address, allowed routes, DNS policy, created_at, expires_at, revoked_at, suspended_at, status, multihop eligibility, profile version.
<!-- ANC-0232 -->
AuditEvent — UUID, timestamp, actor, action, target UUID, outcome, request ID, sanitized reason. Vietati campi con URL, query DNS, private key, token, contenuto payload o IP pubblico del client salvo motivazione di sicurezza formalizzata e retention minima.
<!-- ANC-0233 -->
ReleaseManifest — versione SovereignVPN, OS/kernel, digest immagini, versioni componenti, schema versione, checksum config, stato migrazione.
<!-- ANC-0234 -->
BackupManifest — versione schema, timestamp, lista file, checksum, algoritmo cifratura, key ID, istruzioni di restore. Non registra il contenuto dei segreti.
<!-- ANC-0235 -->
## 8.2 Validazione
<!-- ANC-0236 -->
CIDR canonici, IPv4/IPv6 validati con librerie standard.
<!-- ANC-0237 -->
UUID non riutilizzati.
<!-- ANC-0238 -->
Peer name normalizzato e non usato come path filesystem.
<!-- ANC-0239 -->
Timestamp UTC ISO-8601, clock skew gestito.
<!-- ANC-0240 -->
TTL minimo/massimo configurabile e limite massimo per guest.
<!-- ANC-0241 -->
Chiavi e token non sono serializzati in error messages.
<!-- ANC-0242 -->
Schema versionato con migrazioni esplicite e backup pre-migrazione.
<!-- ANC-0243 -->
## 8.3 Storage e atomicità
<!-- ANC-0244 -->
Il registro può essere SQLite con transazioni BEGIN IMMEDIATE e vincoli univoci; ogni operazione deve eseguire precondition, modifica, commit e reconcile. File di configurazione generati sono scritti in file temporaneo nella stessa filesystem, fsync su file e directory ove appropriato, poi sostituiti atomicamente. Il lock di processo/DB impedisce allocazioni concorrenti. Non si deve presumere atomicità tra SQLite, filesystem, firewall e WireGuard: il control plane gestisce una saga con stato PENDING_APPLY, APPLIED, ROLLBACK_REQUIRED o ERROR e un processo di riconciliazione idempotente.
<!-- ANC-0245 -->
## 8.4 Segreti
<!-- ANC-0246 -->
Private key server e PSK non sono mai mostrate in list/status.
<!-- ANC-0247 -->
Il token admin viene verificato con funzione constant-time; preferire hash robusto e storage sicuro, non plain token.
<!-- ANC-0248 -->
Backup cifrati con algoritmo autenticato e derivazione chiave robusta, parametri versionati e salt unici.
<!-- ANC-0249 -->
La password di backup non deve essere conservata nello stesso backup.
<!-- ANC-0250 -->
I file di export sono temporanei, permessi restrittivi e con avviso di importanza.
<!-- ANC-0251 -->
Rotazione PSK deve prevedere fase preparatoria, sincronizzazione, conferma, timeout e rollback; se il peer non ha ricevuto il nuovo profilo, la rotazione non deve interrompere tutti i peer senza recovery path.
