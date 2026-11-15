# 12. Observability senza profilazione

<!-- ANC-0310 -->
Metriche ammesse: stato container, stato interfaccia, numero peer attivi (conteggio aggregato), utilizzo CPU/RAM, byte totali di interfaccia, errori firewall, scadenze prossime, stato certificati, versione e stato backup. Metriche non ammesse per default: domini richiesti, URL, app utilizzate, IP pubblici client associati a volume, cronologia per peer, timestamp di ogni handshake persistito.
<!-- ANC-0311 -->
Le statistiche WireGuard che contengono endpoint e handshake devono restare volatili e non essere esportate nel log persistente. La dashboard può mostrare online/offline in forma effimera, con caveat sulla precisione del concetto “online”.
<!-- ANC-0312 -->
Il diagnostic bundle deve avere due modalità: minimal (config sanitizzata, versioni, report) e extended (include log host selezionati solo dopo consenso esplicito). La modalità extended deve redigere token, chiavi, endpoint sensibili e dati DNS.
