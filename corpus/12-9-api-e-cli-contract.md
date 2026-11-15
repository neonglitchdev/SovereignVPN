# 9. API e CLI contract

<!-- ANC-0252 -->
## 9.1 CLI
<!-- ANC-0253 -->
Comandi di riferimento:
<!-- ANC-0254 -->
| Comando | Azione | Output |
|---|---|---|
| sovereignctl init | Preflight e bootstrap | Piano e report |
| sovereignctl status | Stato servizi e release | JSON o tabella, sanitizzato |
| sovereignctl peer add | Crea peer | UUID, profilo export esplicito |
| sovereignctl peer list | Elenca peer | Metadati non sensibili |
| sovereignctl peer show <id> | Dettaglio peer | Nessuna private key |
| sovereignctl peer suspend <id> | Sospende | Esito + audit event |
| sovereignctl peer revoke <id> | Revoca | Esito + sync runtime |
| sovereignctl peer expire-sweep | Applica scadenze | Conteggio sintetico |
| sovereignctl psk rotate <id\|--all> | Rotazione controllata | Stato per peer senza secret |
| sovereignctl profile export <id> | Esporta bundle | Percorso protetto e checksum |
| sovereignctl backup create | Crea backup cifrato | Manifest e checksum |
| sovereignctl backup restore <file> | Restore | Preflight e verifica |
| sovereignctl audit run | Security audit | PASS/WARN/FAIL per controllo |
| sovereignctl diagnostics collect | Diagnostica sanitizzata | Bundle senza segreti e query |
<!-- ANC-0255 -->
Codici di uscita: 0 successo; 1 errore runtime/sistema; 2 input o schema non valido; 3 security gate fallito; 4 operazione parzialmente applicata/necessario recovery. Le condizioni di exit code sono parte del contratto e sono testate.
<!-- ANC-0256 -->
## 9.2 API v1 — endpoint essenziali
<!-- ANC-0257 -->
Prefisso: /api/v1. Risposte JSON con request_id, status, data o error. Non esporre stack trace.
<!-- ANC-0258 -->
| Metodo | Endpoint | Scopo | Autorizzazione |
|---|---|---|---|
| GET | /status | Health e release sanitizzati | Auditor/Operator/Owner |
| GET | /peers | Elenco peer paginato | Operator/Owner |
| POST | /peers | Crea peer | Operator/Owner |
| GET | /peers/{uuid} | Dettaglio peer | Operator/Owner |
| POST | /peers/{uuid}/suspend | Sospensione | Operator/Owner |
| POST | /peers/{uuid}/resume | Riattivazione sospensione | Operator/Owner |
| DELETE | /peers/{uuid} | Revoca | Owner o Operator con policy |
| POST | /peers/{uuid}/export | Export autorizzato | Owner/Operator con step-up |
| POST | /psk/rotate | Avvia rotazione | Owner |
| GET | /audit | Audit sanitizzato | Auditor/Owner |
| POST | /backup | Crea backup | Owner |
<!-- ANC-0259 -->
La creazione peer deve supportare Idempotency-Key; le operazioni distruttive devono richiedere conferma logica e non essere ripetute in modo ambiguo. Le richieste hanno limiti di dimensione, timeout, rate limit e validazione schema.
<!-- ANC-0260 -->
## 9.3 Error model
<!-- ANC-0261 -->
Codici esempio: VALIDATION_ERROR, AUTH_REQUIRED, FORBIDDEN, PEER_NOT_FOUND, SUBNET_EXHAUSTED, CONFLICT, APPLY_FAILED, ROLLBACK_FAILED, DEPENDENCY_UNHEALTHY, SECURITY_AUDIT_FAILED. Gli errori esposti non contengono segreti o dettagli interni sfruttabili.
