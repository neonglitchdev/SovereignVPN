// Modelli dei JSON della CLI (status, audit run, peer list): gli stessi per l'app e per mac/prova-modelli.sh.
struct ControlloStatus: Decodable, Identifiable { let nome: String; let esito: String; let dettaglio: String; var id: String { nome } }
struct RapportoStatus: Decodable { let controlli: [ControlloStatus]; let superati: Int; let controlli_eseguiti: Int }
struct ControlloAudit: Decodable, Identifiable { let id: String; let severita: String; let nome: String; let stato: String; let evidenza: String; let rimedio: String }
struct RapportoAudit: Decodable { let controlli: [ControlloAudit]; let PASS: Int; let WARN: Int; let FAIL: Int; let SKIPPED: Int }
struct Peer: Decodable, Identifiable { let id: String; let nome: String; let indirizzo: String; let stato: String; let saga: String; let scade: String? }
