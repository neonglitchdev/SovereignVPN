// Decodifica i JSON veri della CLI con i modelli dell'app; esce 1 se uno non combacia.
import Foundation
@main struct ProvaModelli {
    static func main() {
        let a = CommandLine.arguments
        func prova<T: Decodable>(_ tipo: T.Type, _ file: String) -> Bool {
            do { _ = try JSONDecoder().decode(tipo, from: Data(contentsOf: URL(fileURLWithPath: file))); print("decodificato: \(file)"); return true }
            catch { print("NON decodificato: \(file): \(error)"); return false }
        }
        let ok = [prova([Peer].self, a[1]), prova(RapportoStatus.self, a[2]), prova(RapportoAudit.self, a[3]), prova(RapportoUscite.self, a[4])]
        exit(ok.allSatisfy { $0 } ? 0 : 1)
    }
}
