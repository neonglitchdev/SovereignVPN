import AppKit
import CoreImage
import CryptoKit

/// Prova del QR dei dispositivi [H51]: il profilo col segnaposto diventa un QR che, riletto dal rilevatore di macOS, da'
/// esattamente il profilo con la chiave privata; un profilo senza segnaposto e' rifiutato.
@main struct ProvaQR {
    static func main() {
        let k = Curve25519.KeyAgreement.PrivateKey()
        let privata = k.rawRepresentation.base64EncodedString()
        let profilo = "# SovereignVPN — profilo\n# va scritta al posto di <CHIAVE_PRIVATA_DEL_DISPOSITIVO>\n\n[Interface]\nPrivateKey = <CHIAVE_PRIVATA_DEL_DISPOSITIVO>\nAddress = 10.71.0.5/32\nDNS = 10.71.0.1\n\n[Peer]\nPublicKey = c2VydmVyYXNlcnZlcmFzZXJ2ZXJhc2VydmVyYXNlcnY=\nEndpoint = 203.0.113.10:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n"
        guard let conf = confPerQR(profilo, privata: privata) else { fallisci("il profilo col segnaposto e' stato rifiutato") }
        guard conf.contains("PrivateKey = \(privata)"), !conf.contains("<CHIAVE_PRIVATA"), !conf.contains("#") else { fallisci("la configurazione del QR non e' quella attesa") }
        if confPerQR(profilo.replacingOccurrences(of: "<CHIAVE_PRIVATA_DEL_DISPOSITIVO>", with: "gia-una-chiave"), privata: privata) != nil {
            fallisci("un profilo senza segnaposto e' stato accettato: il QR non avrebbe la chiave giusta")
        }
        guard let img = codiceQR(conf), let tiff = img.tiffRepresentation, let ci = CIImage(data: tiff),
              let det = CIDetector(ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]),
              let letto = (det.features(in: ci).first as? CIQRCodeFeature)?.messageString else { fallisci("il QR non si rilegge") }
        guard letto == conf else { fallisci("il QR riletto e' diverso dal profilo") }
        print("OK: il QR riletto e' il profilo con la chiave privata (\(conf.utf8.count) byte); un profilo senza segnaposto e' rifiutato")
    }
    static func fallisci(_ m: String) -> Never { print("ROSSO: \(m)"); exit(1) }
}
