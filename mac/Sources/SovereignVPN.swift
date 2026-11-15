// SovereignVPN per Mac [H47]: un'app nativa che avvia e governa un server SovereignVPN dentro una VM Linux di colima
// (Ubuntu 24.04 amd64, la piattaforma della 1.0). Parla SOLO con la CLI in JSON (H37: nessuna API), non tiene segreti
// del server: le chiavi private nascono sui dispositivi (H2).
import SwiftUI
import AppKit

let PROFILO = "sovereignvpn"
let CONFIG = "/etc/sovereignvpn/server.toml"

struct Comando { let codice: Int32; let uscita: String; let errore: String }

/// Esegue un programma con un PATH che trova colima e limactl anche se l'app parte dal Finder.
func esegui(_ argomenti: [String], ingresso: Data? = nil) async -> Comando {
    await Task.detached {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        p.arguments = argomenti
        var env = ProcessInfo.processInfo.environment
        env["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
        p.environment = env
        let fuori = Pipe(), errori = Pipe(), dentro = Pipe()
        p.standardOutput = fuori; p.standardError = errori
        if ingresso != nil { p.standardInput = dentro }
        do { try p.run() } catch { return Comando(codice: 127, uscita: "", errore: "\(error)") }
        if let ingresso { dentro.fileHandleForWriting.write(ingresso); try? dentro.fileHandleForWriting.close() }
        let o = fuori.fileHandleForReading.readDataToEndOfFile(), e = errori.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return Comando(codice: p.terminationStatus, uscita: String(decoding: o, as: UTF8.self), errore: String(decoding: e, as: UTF8.self))
    }.value
}

/// `sovereignctl` nella VM, come root.
func sovereignctl(_ a: [String]) async -> Comando {
    await esegui(["colima", "ssh", "--profile", PROFILO, "--", "sudo", "/usr/local/bin/sovereignctl"] + a)
}

struct ControlloStatus: Decodable, Identifiable { let nome: String; let esito: String; let dettaglio: String; var id: String { nome } }
struct RapportoStatus: Decodable { let controlli: [ControlloStatus]; let superati: Int; let controlli_eseguiti: Int }
struct ControlloAudit: Decodable, Identifiable { let id: String; let severita: String; let nome: String; let stato: String; let evidenza: String; let rimedio: String }
struct RapportoAudit: Decodable { let controlli: [ControlloAudit]; let PASS: Int; let WARN: Int; let FAIL: Int; let SKIPPED: Int }
struct Peer: Decodable, Identifiable { let id: String; let nome: String; let indirizzo: String; let stato: String; let saga: String; let scade: String? }

enum StatoVM: Equatable { case sconosciuto, ferma, accesa }

@MainActor
final class Server: ObservableObject {
    @Published var vm: StatoVM = .sconosciuto
    @Published var status: RapportoStatus?
    @Published var installato = false
    @Published var peer: [Peer] = []
    @Published var audit: RapportoAudit?
    @Published var lavoro: String?
    @Published var messaggio: String?

    func aggiorna() async {
        let s = await esegui(["colima", "status", "--profile", PROFILO])
        vm = s.codice == 0 ? .accesa : .ferma
        guard vm == .accesa else { status = nil; peer = []; installato = false; return }  // mai dati vecchi a VM spenta
        let st = await sovereignctl(["status", "--config", CONFIG, "--json"])
        status = try? JSONDecoder().decode(RapportoStatus.self, from: Data(st.uscita.utf8))
        installato = status != nil
        let pl = await sovereignctl(["peer", "list", "--json"])
        peer = (try? JSONDecoder().decode([Peer].self, from: Data(pl.uscita.utf8))) ?? []
    }

    func fai(_ titolo: String, _ corpo: @escaping () async -> Comando) async {
        lavoro = titolo
        let r = await corpo()
        lavoro = nil
        messaggio = r.codice == 0 ? "\(titolo): fatto." : "\(titolo): non riuscito (codice \(r.codice)). \(r.errore.suffix(400))"
        await aggiorna()
    }

    func accendi() async { await fai("Avvio della VM") { await esegui(["colima", "start", "--profile", PROFILO, "--arch", "x86_64", "--vm-type", "qemu", "--cpu", "4", "--memory", "4", "--disk", "20"]) } }
    func spegni() async { await fai("Arresto della VM") { await esegui(["colima", "stop", "--profile", PROFILO]) } }

    /// Primo avvio: le sorgenti entrano nella VM come tar dentro ssh, poi prepara-server.sh fa il resto.
    func prepara() async {
        await fai("Preparazione del server") {
            guard let sorgenti = Bundle.main.resourceURL?.appendingPathComponent("sovereignvpn") else { return Comando(codice: 1, uscita: "", errore: "sorgenti assenti nell'app") }
            let dati = await Task.detached { () -> Data in
                let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/tar")
                p.arguments = ["-cz", "-C", sorgenti.deletingLastPathComponent().path, "sovereignvpn"]
                let o = Pipe(); p.standardOutput = o; try? p.run()
                let d = o.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit(); return d
            }.value
            let copia = await esegui(["colima", "ssh", "--profile", PROFILO, "--", "sudo", "sh", "-c", "rm -rf /opt/sovereignvpn-sorgente && mkdir -p /opt/sovereignvpn-sorgente && tar -xz -C /opt/sovereignvpn-sorgente"], ingresso: dati)
            guard copia.codice == 0 else { return copia }
            let ip = await esegui(["ipconfig", "getifaddr", "en0"])
            let endpoint = ip.uscita.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "127.0.0.1" : ip.uscita.trimmingCharacters(in: .whitespacesAndNewlines)
            let rete = await esegui(["colima", "ssh", "--profile", PROFILO, "--", "sh", "-c", "set -- $SSH_CONNECTION; echo \"${1%.*}.0/24\""])
            return await esegui(["colima", "ssh", "--profile", PROFILO, "--", "sudo", "bash", "/opt/sovereignvpn-sorgente/sovereignvpn/mac/prepara-server.sh",
                                 endpoint, rete.uscita.trimmingCharacters(in: .whitespacesAndNewlines)])
        }
    }

    func aggiungi(nome: String, chiave: String) async {
        await fai("Aggiunta di «\(nome)»") {
            let r = await sovereignctl(["peer", "add", "--name", nome, "--public-key", chiave, "--config", CONFIG, "--json"])
            return r.codice == 0 ? await sovereignctl(["reconcile", "--config", CONFIG]) : r
        }
    }
    func rinomina(_ p: Peer, in nome: String) async { await fai("Rinomina") { await sovereignctl(["peer", "rename", p.id, "--name", nome, "--json"]) } }
    func revoca(_ p: Peer) async {
        await fai("Revoca di «\(p.nome)»") {
            let r = await sovereignctl(["peer", "revoke", p.id, "--json"])
            return r.codice == 0 ? await sovereignctl(["reconcile", "--config", CONFIG]) : r
        }
    }
    /// Il bundle si scrive nella VM (0600) e si copia nei Download del Mac: percorso e checksum, mai il contenuto a schermo.
    func esportaBundle(_ p: Peer) async {
        await fai("Bundle di «\(p.nome)»") {
            let r = await sovereignctl(["profile", "export", p.id, "--conferma", "--bundle", "--config", CONFIG, "--json"])
            guard r.codice == 0, let j = try? JSONSerialization.jsonObject(with: Data(r.uscita.utf8)) as? [String: Any], let percorso = j["percorso"] as? String else { return r }
            let dest = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Downloads/SovereignVPN-\(p.id).tar.gz")
            let c = await esegui(["sh", "-c", "colima ssh --profile \(PROFILO) -- sudo cat '\(percorso)' > '\(dest.path)' && chmod 600 '\(dest.path)'"])
            if c.codice == 0 { NSWorkspace.shared.activateFileViewerSelecting([dest]) }
            return c
        }
    }
    func eseguiAudit() async {
        lavoro = "Security audit"
        let r = await sovereignctl(["audit", "run", "--config", CONFIG, "--json"])
        audit = try? JSONDecoder().decode(RapportoAudit.self, from: Data(r.uscita.utf8))
        lavoro = nil
        messaggio = audit == nil ? "Audit non riuscito (codice \(r.codice))." : nil
    }
}

func colore(_ stato: String) -> Color {
    switch stato { case "OK", "PASS", "ACTIVE": return .green; case "WARN", "PENDING", "SUSPENDED": return .orange
    case "FAIL", "GUASTO", "ERROR", "REVOKED", "EXPIRED": return .red; default: return .secondary }
}

struct Etichetta: View {
    let testo: String
    var body: some View {
        Text(testo).font(.caption.weight(.semibold)).padding(.horizontal, 6).padding(.vertical, 2)
            .background(colore(testo).opacity(0.18), in: Capsule()).foregroundStyle(colore(testo))
    }
}

enum Sezione: String, CaseIterable, Identifiable { case stato = "Stato", dispositivi = "Dispositivi", audit = "Security audit"; var id: String { rawValue } }

struct Contenuto: View {
    @EnvironmentObject var server: Server
    @State private var sezione: Sezione? = .stato
    var body: some View {
        NavigationSplitView {
            List(Sezione.allCases, selection: $sezione) { s in Text(s.rawValue).tag(s) }.navigationSplitViewColumnWidth(170)
        } detail: {
            VStack(alignment: .leading, spacing: 0) {
                switch sezione ?? .stato {
                case .stato: VistaStato()
                case .dispositivi: VistaDispositivi()
                case .audit: VistaAudit()
                }
                if let m = server.messaggio { Text(m).font(.callout).padding(10).frame(maxWidth: .infinity, alignment: .leading).background(.quaternary) }
            }
            .toolbar {
                if let l = server.lavoro { ProgressView().controlSize(.small); Text(l) }
                Button { Task { await server.aggiorna() } } label: { Label("Aggiorna", systemImage: "arrow.clockwise") }
            }
        }
        .task { await server.aggiorna() }
    }
}

struct VistaStato: View {
    @EnvironmentObject var server: Server
    var body: some View {
        Form {
            Section("Server") {
                LabeledContent("Macchina virtuale", value: server.vm == .accesa ? "accesa (Ubuntu 24.04 amd64, colima)" : server.vm == .ferma ? "spenta" : "…")
                if server.vm == .ferma {
                    Text("Server spento: nessun dato mostrato.").foregroundStyle(.secondary)
                    Button("Accendi") { Task { await server.accendi() } }
                } else if server.vm == .accesa {
                    if !server.installato {
                        Text("SovereignVPN non e' ancora installato nella VM.").foregroundStyle(.secondary)
                        Button("Prepara il server") { Task { await server.prepara() } }
                    }
                    Button("Spegni la VM") { Task { await server.spegni() } }
                }
            }
            if let s = server.status {
                Section("Controlli (\(s.controlli_eseguiti) eseguiti, \(s.superati) superati)") {
                    ForEach(s.controlli) { c in
                        HStack(alignment: .firstTextBaseline) { Etichetta(testo: c.esito); Text(c.nome).bold(); Text(c.dettaglio).foregroundStyle(.secondary).lineLimit(2) }
                    }
                }
            }
        }.formStyle(.grouped)
    }
}

struct VistaDispositivi: View {
    @EnvironmentObject var server: Server
    @State private var nuovo = false
    @State private var nome = ""
    @State private var chiave = ""
    @State private var daRinominare: Peer?
    @State private var daRevocare: Peer?
    var body: some View {
        VStack(alignment: .leading) {
            HStack { Text("Dispositivi").font(.title2.bold()); Spacer(); Button("Aggiungi…") { nome = ""; chiave = ""; nuovo = true }.disabled(!server.installato) }.padding()
            Table(server.peer) {
                TableColumn("Nome") { p in Text(p.nome) }
                TableColumn("Indirizzo") { p in Text(p.indirizzo).monospaced() }
                TableColumn("Stato") { p in Etichetta(testo: p.stato) }
                TableColumn("Scade") { p in Text(p.scade ?? "mai").foregroundStyle(.secondary) }
                TableColumn("") { p in
                    HStack {
                        Button("Bundle") { Task { await server.esportaBundle(p) } }.disabled(p.stato == "REVOKED" || p.stato == "EXPIRED")
                        Button("Rinomina") { nome = p.nome; daRinominare = p }
                        Button("Revoca", role: .destructive) { daRevocare = p }.disabled(p.stato == "REVOKED")
                    }
                }
            }
        }
        .sheet(isPresented: $nuovo) {
            Form {
                Text("Nuovo dispositivo").font(.headline)
                TextField("Nome", text: $nome)
                TextField("Chiave pubblica WireGuard del dispositivo", text: $chiave).monospaced()
                Text("La chiave privata nasce e resta sul dispositivo: qui solo la pubblica.").font(.caption).foregroundStyle(.secondary)
                HStack { Spacer(); Button("Annulla") { nuovo = false }; Button("Aggiungi") { nuovo = false; Task { await server.aggiungi(nome: nome, chiave: chiave) } }.keyboardShortcut(.defaultAction).disabled(nome.isEmpty || chiave.isEmpty) }
            }.padding().frame(width: 460)
        }
        .sheet(item: $daRinominare) { p in
            Form {
                Text("Rinomina «\(p.nome)»").font(.headline)
                TextField("Nuovo nome", text: $nome)
                HStack { Spacer(); Button("Annulla") { daRinominare = nil }; Button("Rinomina") { daRinominare = nil; Task { await server.rinomina(p, in: nome) } }.keyboardShortcut(.defaultAction) }
            }.padding().frame(width: 380)
        }
        .confirmationDialog("Revocare «\(daRevocare?.nome ?? "")»? La revoca e' definitiva: il dispositivo non si collega piu'.", isPresented: Binding(get: { daRevocare != nil }, set: { if !$0 { daRevocare = nil } }), titleVisibility: .visible) {
            Button("Revoca", role: .destructive) { if let p = daRevocare { Task { await server.revoca(p) } }; daRevocare = nil }
            Button("Annulla", role: .cancel) { daRevocare = nil }
        }
    }
}

struct VistaAudit: View {
    @EnvironmentObject var server: Server
    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text("Security audit").font(.title2.bold())
                if let a = server.audit { Text("\(a.controlli.count) controlli: \(a.PASS) PASS, \(a.WARN) WARN, \(a.FAIL) FAIL, \(a.SKIPPED) SKIPPED").foregroundStyle(.secondary) }
                Spacer(); Button("Esegui") { Task { await server.eseguiAudit() } }.disabled(!server.installato)
            }.padding()
            List(server.audit?.controlli ?? []) { c in
                VStack(alignment: .leading, spacing: 2) {
                    HStack { Etichetta(testo: c.stato); Text("\(c.id) \(c.severita)").monospaced().foregroundStyle(.secondary); Text(c.nome).bold() }
                    Text(c.evidenza).font(.callout).foregroundStyle(.secondary)
                    if !c.rimedio.isEmpty && c.stato == "FAIL" { Text("Rimedio: \(c.rimedio)").font(.callout) }
                }.padding(.vertical, 2)
            }
        }
    }
}

@main
struct SovereignVPNApp: App {
    @StateObject private var server = Server()
    var body: some Scene {
        WindowGroup("SovereignVPN") { Contenuto().environmentObject(server).frame(minWidth: 860, minHeight: 540) }
    }
}
