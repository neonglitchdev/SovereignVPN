import AppKit
import CoreImage

/// Il profilo da mettere nel QR per l'app WireGuard del telefono [H2, H51]: il .conf esportato dal server, col segnaposto
/// della chiave privata sostituito dalla privata nata nell'app del Mac, e senza i commenti (QR piu' piccolo). nil se il
/// profilo non ha la riga col segnaposto: un QR senza la chiave giusta non collegherebbe niente.
func confPerQR(_ profilo: String, privata: String, segnaposto: String = "<CHIAVE_PRIVATA_DEL_DISPOSITIVO>") -> String? {
    var trovata = false
    let righe = profilo.split(separator: "\n", omittingEmptySubsequences: false).compactMap { r -> String? in
        let t = r.trimmingCharacters(in: .whitespaces)
        if t.hasPrefix("#") { return nil }
        if t.hasPrefix("PrivateKey") && t.hasSuffix(segnaposto) { trovata = true; return "PrivateKey = \(privata)" }
        return String(r)
    }
    return trovata ? righe.joined(separator: "\n") : nil
}

/// Il QR del testo, con correzione d'errore media, ingrandito senza smussare.
func codiceQR(_ testo: String, scala: CGFloat = 10) -> NSImage? {
    guard let f = CIFilter(name: "CIQRCodeGenerator") else { return nil }
    f.setValue(Data(testo.utf8), forKey: "inputMessage")
    f.setValue("M", forKey: "inputCorrectionLevel")
    guard let img = f.outputImage?.transformed(by: CGAffineTransform(scaleX: scala, y: scala)) else { return nil }
    let rep = NSCIImageRep(ciImage: img)
    let n = NSImage(size: rep.size)
    n.addRepresentation(rep)
    return n
}

/// Il QR a schermo: solo l'immagine, mai il testo (che contiene la chiave privata).
struct QRDispositivo: Identifiable { let id = UUID(); let nome: String; let immagine: NSImage }
