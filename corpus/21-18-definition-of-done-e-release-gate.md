# 18. Definition of Done e release gate

<!-- ANC-0394 -->
Una release è Done solo quando:
<!-- ANC-0395 -->
Tutti i requisiti P0 sono implementati o esplicitamente esclusi dal perimetro con approvazione.
<!-- ANC-0396 -->
Le migration sono testate su DB vuoto e DB aggiornato da release precedente.
<!-- ANC-0397 -->
Tutti i test P0 e i test di regressione passano su host pulito.
<!-- ANC-0398 -->
Il security audit non presenta FAIL P0.
<!-- ANC-0399 -->
Il repository non contiene segreti e le immagini sono pin-nate.
<!-- ANC-0400 -->
SBOM, checksum, note release e procedura rollback sono pubblicati.
<!-- ANC-0401 -->
Backup/restore è stato provato su un ambiente isolato.
<!-- ANC-0402 -->
La documentazione indica chiaramente limiti, dipendenze, porte, dati persistenti e trust boundary.
<!-- ANC-0403 -->
Nessuna feature avanzata è attiva senza test e opt-in.
<!-- ANC-0404 -->
Le dichiarazioni di performance/privacy sono supportate da test riproducibili.
<!-- ANC-0405 -->
## 18.1 Release checklist
<!-- ANC-0406 -->
[ ] Preflight installazione pulita PASS
<!-- ANC-0407 -->
[ ] Upgrade da release precedente PASS
<!-- ANC-0408 -->
[ ] Rollback PASS
<!-- ANC-0409 -->
[ ] WireGuard peer lifecycle PASS
<!-- ANC-0410 -->
[ ] DNSSEC e DNS filtering PASS
<!-- ANC-0411 -->
[ ] DNS/IPv6 leak suite PASS
<!-- ANC-0412 -->
[ ] Firewall/Docker port exposure audit PASS
<!-- ANC-0413 -->
[ ] Peer isolation PASS
<!-- ANC-0414 -->
[ ] Backup/restore PASS
<!-- ANC-0415 -->
[ ] Secret scan PASS
<!-- ANC-0416 -->
[ ] SBOM e digest immagini pubblicati
<!-- ANC-0417 -->
[ ] Threat model aggiornato
<!-- ANC-0418 -->
[ ] README, deployment guide, client guide e incident response aggiornati
