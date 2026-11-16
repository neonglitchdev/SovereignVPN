// SovereignVPN per Mac [H47]: un'app nativa che avvia e governa un server SovereignVPN dentro una VM Linux di colima
// (Ubuntu 24.04 amd64, la piattaforma della 1.0). Parla SOLO con la CLI in JSON (H37: nessuna API), non tiene segreti
// del server: le chiavi private nascono sui dispositivi (H2).
import SwiftUI
import AppKit
import UniformTypeIdentifiers

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
func sovereignctl(_ a: [String], ingresso: Data? = nil) async -> Comando {
    await esegui(["colima", "ssh", "--profile", PROFILO, "--", "sudo", "/usr/local/bin/sovereignctl"] + a, ingresso: ingresso)
}


enum StatoVM: Equatable { case sconosciuto, ferma, accesa }

@MainActor
final class Server: ObservableObject {
    @Published var vm: StatoVM = .sconosciuto
    @Published var status: RapportoStatus?
    @Published var installato = false
    @Published var peer: [Peer] = []
    @Published var audit: RapportoAudit?
    @Published var uscite: RapportoUscite?
    @Published var chiaveUscita: String?
    @Published var lavoro: String?
    @Published var messaggio: String?

    func aggiorna() async {
        let s = await esegui(["colima", "status", "--profile", PROFILO])
        vm = s.codice == 0 ? .accesa : .ferma
        guard vm == .accesa else { status = nil; peer = []; uscite = nil; installato = false; return }  // mai dati vecchi a VM spenta
        let st = await sovereignctl(["status", "--config", CONFIG, "--json"])
        status = try? JSONDecoder().decode(RapportoStatus.self, from: Data(st.uscita.utf8))
        installato = status != nil
        let pl = await sovereignctl(["peer", "list", "--json"])
        peer = (try? JSONDecoder().decode([Peer].self, from: Data(pl.uscita.utf8))) ?? []
        let us = await sovereignctl(["exit", "list", "--json"])
        uscite = try? JSONDecoder().decode(RapportoUscite.self, from: Data(us.uscita.utf8))
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
    /// Uscite per paese [H48, H50]: il file entra da stdin (mai copiato nella VM fuori dal pool 0600). Dal bundle che esporta
    /// un altro server SovereignVPN (.tar.gz) si prende il solo .conf: col segnaposto, che exit import riempie con la chiave di qui.
    func importaUscita(_ file: URL, paese: String, nome: String) async {
        await fai("Import dell'uscita") {
            var dati = try? Data(contentsOf: file)
            if file.pathExtension == "gz" {
                let estratto = await esegui(["tar", "-xzOf", file.path, "*.conf"])
                dati = estratto.codice == 0 ? Data(estratto.uscita.utf8) : nil
            }
            guard let dati, !dati.isEmpty, dati.count <= 65536 else { return Comando(codice: 2, uscita: "", errore: "file illeggibile, senza un .conf o oltre 64 KB") }
            return await sovereignctl(["exit", "import", "-", "--paese", paese.uppercased(), "--json"] + (nome.isEmpty ? [] : ["--nome", nome]), ingresso: dati)
        }
    }
    func scegliUscita(_ chi: String) async { await fai(chi == "off" ? "Uscita dal server" : "Uscita \(chi)") { await sovereignctl(["exit", "set", chi, "--config", CONFIG, "--json"]) } }
    func rotazione(_ minuti: Int) async { await fai("Rotazione") { await sovereignctl(["exit", "rotation", String(minuti), "--json"]) } }
    /// [H50] La chiave pubblica di questo server per usarne un altro come uscita: nasce nella VM (0600), a schermo solo la pubblica.
    func mostraChiaveUscita() async {
        await fai("Chiave di questo server") {
            let r = await sovereignctl(["exit", "key", "--json"])
            if r.codice == 0, let j = try? JSONSerialization.jsonObject(with: Data(r.uscita.utf8)) as? [String: Any] {
                self.chiaveUscita = j["chiave_pubblica"] as? String
            }
            return r
        }
    }
    func togliUscita(_ u: Uscita) async { await fai("Uscita \(u.id) tolta") { await sovereignctl(["exit", "remove", u.id, "--json"]) } }

    func eseguiAudit() async {
        lavoro = "Security audit"
        let r = await sovereignctl(["audit", "run", "--config", CONFIG, "--json"])
        audit = try? JSONDecoder().decode(RapportoAudit.self, from: Data(r.uscita.utf8))
        lavoro = nil
        messaggio = audit == nil ? "Audit non riuscito (codice \(r.codice))." : nil
    }
}

func colore(_ stato: String) -> Color {
    switch stato { case "OK", "PASS", "ACTIVE", "ATTIVA": return .green; case "WARN", "PENDING", "SUSPENDED": return .orange
    case "FAIL", "GUASTO", "ERROR", "REVOKED", "EXPIRED": return .red; default: return .secondary }
}

struct Etichetta: View {
    let testo: String
    var body: some View {
        Text(testo).font(.caption.weight(.semibold)).padding(.horizontal, 6).padding(.vertical, 2)
            .background(colore(testo).opacity(0.18), in: Capsule()).foregroundStyle(colore(testo))
    }
}

enum Sezione: String, CaseIterable, Identifiable { case stato = "Stato", dispositivi = "Dispositivi", uscite = "Uscite", audit = "Security audit"; var id: String { rawValue } }

struct Contenuto: View {
    @EnvironmentObject var server: Server
    // `open SovereignVPN.app --args -sezione Uscite` apre su una sezione (gli argomenti -chiave valore finiscono in UserDefaults)
    @State private var sezione: Sezione? = Sezione(rawValue: UserDefaults.standard.string(forKey: "sezione") ?? "") ?? .stato
    var body: some View {
        NavigationSplitView {
            List(Sezione.allCases, selection: $sezione) { s in Text(s.rawValue).tag(s) }.navigationSplitViewColumnWidth(170)
        } detail: {
            VStack(alignment: .leading, spacing: 0) {
                switch sezione ?? .stato {
                case .stato: VistaStato()
                case .dispositivi: VistaDispositivi()
                case .uscite: VistaUscite()
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
                    HStack(spacing: 6) {  // col riquadro e della stessa misura: in una colonna stretta andavano a capo a meta' parola
                        Button { Task { await server.esportaBundle(p) } } label: { Text("Bundle").frame(width: 64) }.disabled(p.stato == "REVOKED" || p.stato == "EXPIRED")
                        Button { nome = p.nome; daRinominare = p } label: { Text("Rinomina").frame(width: 64) }
                        Button(role: .destructive) { daRevocare = p } label: { Text("Revoca").frame(width: 64) }.disabled(p.stato == "REVOKED")
                    }.buttonStyle(.bordered).controlSize(.small).lineLimit(1)
                }.width(min: 250, ideal: 250)
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

func nomePaese(_ codice: String) -> String { Locale.current.localizedString(forRegionCode: codice) ?? codice }

/// Il paese dal nome del file del provider (mullvad-de-fra-wg-001.conf -> DE): solo un suggerimento, si corregge a mano.
func paeseDalFile(_ u: URL) -> String {
    let regioni = Set(Locale.Region.isoRegions.map(\.identifier))
    return u.deletingPathExtension().lastPathComponent.uppercased().split(whereSeparator: { !$0.isLetter }).map(String.init)
        .first { $0.count == 2 && regioni.contains($0) } ?? ""
}

struct VistaUscite: View {
    @EnvironmentObject var server: Server
    @State private var file: URL?
    @State private var paese = ""
    @State private var nome = ""
    @State private var daTogliere: Uscita?
    static let rotazioni = [0, 5, 15, 30, 60, 180]

    var body: some View {
        let r = server.uscite
        Form {
            Section("Uscita attuale") {
                if let a = r?.uscite.first(where: { $0.attiva }) {
                    HStack(spacing: 12) {
                        Text(a.bandierina).font(.system(size: 40))
                        VStack(alignment: .leading, spacing: 2) {
                            Text("\(nomePaese(a.paese)) — \(a.nome)").font(.title3.bold())
                            Text("I siti vedono l'IP del server d'uscita, non quello del server SovereignVPN. Server d'uscita: \(a.endpoint)").foregroundStyle(.secondary)
                            if let h = r?.handshake_secondi, h < 180 {
                                Label("Collegata: ultimo handshake \(h) s fa", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
                            } else {
                                Label("Non collegata: nessun handshake recente, i dispositivi sono senza Internet", systemImage: "xmark.octagon.fill").foregroundStyle(.red)
                            }
                            if let s = r?.prossimo_cambio_secondi { Text("Prossimo cambio d'IP fra \(max(1, (s + 59) / 60)) min").foregroundStyle(.secondary) }
                        }
                    }
                    Text("Se l'uscita cade, i dispositivi restano senza Internet finché non torna o non si passa a un'altra uscita dello stesso paese: mai un'uscita diretta dal server (kill switch).")
                        .font(.caption).foregroundStyle(.secondary)
                } else {
                    Text("Nessuna: i dispositivi escono con l'IP del server SovereignVPN.").foregroundStyle(.secondary)
                }
            }
            Section("Paese") {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 150), alignment: .leading)], alignment: .leading, spacing: 8) {
                    Button { Task { await server.scegliUscita("off") } } label: {
                        Label("Dal server", systemImage: "server.rack").frame(maxWidth: .infinity, alignment: .leading)
                    }.buttonStyle(.bordered).tint(r?.scelta == nil ? Color.accentColor : nil)
                    ForEach(r?.paesi ?? []) { p in
                        Button { Task { await server.scegliUscita(p.paese) } } label: {
                            HStack { Text(p.bandierina); Text(nomePaese(p.paese)).lineLimit(1); Spacer(); Text("\(p.uscite)").foregroundStyle(.secondary) }
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }.buttonStyle(.bordered).tint(r?.scelta == p.paese ? Color.accentColor : nil)
                    }
                }.disabled(!server.installato || server.lavoro != nil)
                if (r?.paesi ?? []).isEmpty {
                    Text("Nessun paese ancora: un'uscita è un altro server SovereignVPN, tuo o di una persona di cui ti fidi (sotto, come si fa).").foregroundStyle(.secondary)
                }
            }
            Section("Rotazione dell'IP") {
                Picker("Cambia uscita", selection: Binding(get: { r?.rotazione_minuti ?? 0 }, set: { m in Task { await server.rotazione(m) } })) {
                    ForEach(Self.rotazioni, id: \.self) { m in Text(m == 0 ? "Mai (IP statico)" : m < 60 ? "Ogni \(m) minuti" : "Ogni \(m / 60) ore").tag(m) }
                }.disabled(!server.installato || server.lavoro != nil)
                Text("Si ruota fra le uscite dello stesso paese: con una sola uscita l'IP resta quello.").font(.caption).foregroundStyle(.secondary)
            }
            Section("Usa un altro server come uscita") {
                Text("1. Dai questa chiave a chi gestisce l'altro server SovereignVPN: la aggiunge come dispositivo (Aggiungi…) e ti manda il bundle del profilo.")
                HStack {
                    if let k = server.chiaveUscita {
                        Text(k).monospaced().textSelection(.enabled).lineLimit(1)
                        Spacer()
                        Button("Copia") { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(k, forType: .string) }.buttonStyle(.bordered)
                    } else {
                        Text("La chiave nasce su questo server; si mostra solo la parte pubblica.").foregroundStyle(.secondary)
                        Spacer()
                        Button("Mostra la chiave") { Task { await server.mostraChiaveUscita() } }.buttonStyle(.bordered).disabled(!server.installato || server.lavoro != nil)
                    }
                }
                Text("2. Importa qui sotto il bundle (.tar.gz) o il profilo (.conf), col paese di quel server: la chiave privata di questo server la scrive l'import, non passa mai di mano.")
                Text("Le reti interne dei due server devono essere diverse; il server dell'amico va bene anche con un indirizzo di casa che cambia (DNS dinamico).")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section {
                ForEach(r?.uscite ?? []) { u in
                    HStack {
                        Text(u.bandierina); Text(u.nome).bold(); Text(u.id).monospaced().foregroundStyle(.secondary)
                        Text(u.endpoint).monospaced().foregroundStyle(.secondary)
                        Spacer()
                        if u.attiva { Etichetta(testo: "ATTIVA") } else {
                            Button("Usa questa") { Task { await server.scegliUscita(u.id) } }
                            Button("Togli", role: .destructive) { daTogliere = u }
                        }
                    }
                }
            } header: {
                HStack {
                    Text("Uscite nel pool")
                    Spacer()
                    Button("Importa un'uscita…") { apri() }.buttonStyle(.bordered).disabled(!server.installato)
                }
            }
        }
        .formStyle(.grouped)
        .sheet(isPresented: Binding(get: { file != nil }, set: { if !$0 { file = nil } })) {
            Form {
                Text("Nuova uscita").font(.headline)
                LabeledContent("File", value: file?.lastPathComponent ?? "")
                TextField("Paese (codice di due lettere: IT, DE, JP…)", text: $paese)
                if paese.count == 2 { Text(nomePaese(paese.uppercased())).foregroundStyle(.secondary) }
                TextField("Nome (facoltativo)", text: $nome)
                Text("Il profilo resta sul server in un file 0600 e la chiave privata non si mostra mai.").font(.caption).foregroundStyle(.secondary)
                HStack {
                    Spacer()
                    Button("Annulla") { file = nil }
                    Button("Importa") { if let f = file { file = nil; Task { await server.importaUscita(f, paese: paese, nome: nome) } } }
                        .keyboardShortcut(.defaultAction).disabled(paese.count != 2)
                }
            }.padding().frame(width: 460)
        }
        .confirmationDialog("Togliere l'uscita «\(daTogliere?.nome ?? "")» dal pool?", isPresented: Binding(get: { daTogliere != nil }, set: { if !$0 { daTogliere = nil } }), titleVisibility: .visible) {
            Button("Togli", role: .destructive) { if let u = daTogliere { Task { await server.togliUscita(u) } }; daTogliere = nil }
            Button("Annulla", role: .cancel) { daTogliere = nil }
        }
    }

    func apri() {
        let p = NSOpenPanel()
        p.allowsMultipleSelection = false; p.canChooseDirectories = false
        p.allowedContentTypes = [UTType(filenameExtension: "conf") ?? .data, .gzip]
        p.message = "Il bundle (.tar.gz) o il profilo (.conf) che ti ha dato l'altro server SovereignVPN"
        if p.runModal() == .OK, let u = p.url { paese = paeseDalFile(u); nome = ""; file = u }
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
