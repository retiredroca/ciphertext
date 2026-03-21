// Shared/CryptoEngine.swift
//
// CryptoChat crypto engine for iOS.
// Uses Apple CryptoKit for ECDH P-256 + AES-256-GCM.
//
// Wire formats are identical to the browser extension and Android app:
//   1:1   CRYPTOCHAT_V1:<b64iv>:<b64cipher>:<b64senderSpki>
//   Group CRYPTOCHAT_GRP_V1:<msgId>:<b64iv>:<b64body>:<b64slots>
//
// Keys are stored as ANSI X9.62 uncompressed points (65 bytes) for ECDH
// and as PKCS#8 DER for private keys — matching the Web Crypto API format
// used by the extension so keys can be exported/imported between platforms.

import Foundation
import CryptoKit

// MARK: - Errors

enum CCError: Error, LocalizedError {
    case invalidWireFormat
    case noSlotForKey
    case decryptFailed
    case invalidKey(String)
    case noRecipients

    var errorDescription: String? {
        switch self {
        case .invalidWireFormat:  return "Not a valid CryptoChat message"
        case .noSlotForKey:       return "No slot for your key in this group message"
        case .decryptFailed:      return "Decryption failed — wrong key or corrupted message"
        case .invalidKey(let r):  return "Invalid key: \(r)"
        case .noRecipients:       return "No valid recipients"
        }
    }
}

// MARK: - Encoding helpers

enum Codec {
    static func b64(_ data: Data) -> String { data.base64EncodedString() }
    static func data(_ b64: String) -> Data? { Data(base64Encoded: b64) }

    /// SPKI DER header for P-256 public keys (matches Web Crypto exportKey('spki'))
    static let p256SpkiHeader = Data([
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00,
    ])

    /// Wrap a raw P-256 public key (65-byte uncompressed point) in SPKI DER
    static func toSpki(_ rawPoint: Data) -> Data { p256SpkiHeader + rawPoint }

    /// Strip SPKI DER header, returning the 65-byte uncompressed point
    static func fromSpki(_ spki: Data) -> Data? {
        guard spki.count == 91, spki.prefix(26) == p256SpkiHeader else { return nil }
        return spki.dropFirst(26)
    }
}

// MARK: - Identity

public struct CCIdentity {
    public let privateKey:   P256.KeyAgreement.PrivateKey
    public let publicKeyB64: String   // SPKI base64 — share with contacts
    public let fingerprint:  String   // SHA-256 hex of SPKI

    public var publicKeyData: Data {
        Codec.toSpki(privateKey.publicKey.x963Representation)
    }
}

// MARK: - Engine

public enum CryptoEngine {

    // ── Key generation ────────────────────────────────────────────────────

    public static func generateIdentity() -> CCIdentity {
        let priv = P256.KeyAgreement.PrivateKey()
        let spki = Codec.toSpki(priv.publicKey.x963Representation)
        let spkiB64 = Codec.b64(spki)
        let fp = SHA256.hash(data: spki).map { String(format: "%02x", $0) }.joined()
        return CCIdentity(privateKey: priv, publicKeyB64: spkiB64, fingerprint: fp)
    }

    /// Import a P-256 private key from PKCS#8 DER base64 (for backup restore)
    public static func importPrivateKey(_ pkcs8B64: String) throws -> P256.KeyAgreement.PrivateKey {
        guard let der = Codec.data(pkcs8B64) else { throw CCError.invalidKey("bad base64") }
        // PKCS#8 P-256 private key: 32-byte raw scalar at the end
        // Standard PKCS#8 wrapper is 48 bytes; raw key is last 32
        let raw = der.suffix(32)
        do {
            return try P256.KeyAgreement.PrivateKey(rawRepresentation: raw)
        } catch {
            throw CCError.invalidKey(error.localizedDescription)
        }
    }

    /// Import a P-256 public key from SPKI base64
    public static func importPublicKey(_ spkiB64: String) throws -> P256.KeyAgreement.PublicKey {
        guard let spki = Codec.data(spkiB64),
              let point = Codec.fromSpki(spki) else {
            throw CCError.invalidKey("invalid SPKI format")
        }
        do {
            return try P256.KeyAgreement.PublicKey(x963Representation: point)
        } catch {
            throw CCError.invalidKey(error.localizedDescription)
        }
    }

    // ── Shared key derivation ─────────────────────────────────────────────

    static func sharedKey(ourPriv: P256.KeyAgreement.PrivateKey,
                          theirPub: P256.KeyAgreement.PublicKey) throws -> SymmetricKey {
        let shared = try ourPriv.sharedSecretFromKeyAgreement(with: theirPub)
        // Derive 256-bit AES key using HKDF-SHA256 (matches Web Crypto deriveKey ECDH→AES-GCM)
        return shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: Data("AES-GCM".utf8),
            outputByteCount: 32
        )
    }

    // ── 1:1 encrypt / decrypt ─────────────────────────────────────────────

    public static func encryptMessage(
        plaintext: String,
        ourIdentity: CCIdentity,
        theirPublicKeyB64: String
    ) throws -> String {
        let theirPub = try importPublicKey(theirPublicKeyB64)
        let key      = try sharedKey(ourPriv: ourIdentity.privateKey, theirPub: theirPub)

        var nonce = [UInt8](repeating: 0, count: 12)
        _ = SecRandomCopyBytes(kSecRandomDefault, 12, &nonce)
        let gcmNonce = try AES.GCM.Nonce(data: Data(nonce))

        let sealed   = try AES.GCM.seal(Data(plaintext.utf8), using: key, nonce: gcmNonce)
        let cipher   = sealed.ciphertext + sealed.tag   // AES-GCM = ciphertext‖tag

        return "CRYPTOCHAT_V1:\(Codec.b64(Data(nonce))):\(Codec.b64(cipher)):\(ourIdentity.publicKeyB64)"
    }

    public static func decryptMessage(
        wireText: String,
        ourIdentity: CCIdentity
    ) throws -> (plaintext: String, senderPublicKeyB64: String) {
        let parts = wireText.trimmingCharacters(in: .whitespaces).components(separatedBy: ":")
        guard parts.count >= 4, parts[0] == "CRYPTOCHAT_V1",
              let ivData     = Codec.data(parts[1]),
              let cipherData = Codec.data(parts[2]) else {
            throw CCError.invalidWireFormat
        }
        // Rejoin remaining parts in case pubkey contained colons (it won't, but be safe)
        let senderB64 = parts[3...].joined(separator: ":")
        let senderPub = try importPublicKey(senderB64)
        let key       = try sharedKey(ourPriv: ourIdentity.privateKey, theirPub: senderPub)

        // AES-GCM: last 16 bytes are the tag
        guard cipherData.count > 16 else { throw CCError.decryptFailed }
        let ciphertext = cipherData.dropLast(16)
        let tag        = cipherData.suffix(16)

        let nonce  = try AES.GCM.Nonce(data: ivData)
        let sealed = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        let plain  = try AES.GCM.open(sealed, using: key)

        guard let text = String(data: plain, encoding: .utf8) else { throw CCError.decryptFailed }
        return (text, senderB64)
    }

    // ── Group encrypt / decrypt ───────────────────────────────────────────

    public struct GroupSlot: Codable {
        let h: String   // handle
        let p: String   // publicKeyB64
        let dek: String // wrapped DEK base64
    }

    public static func encryptGroup(
        plaintext: String,
        ourIdentity: CCIdentity,
        recipients: [(handle: String, publicKeyB64: String)]
    ) throws -> String {
        if recipients.isEmpty { throw CCError.noRecipients }

        // Random 256-bit DEK
        let dek = SymmetricKey(size: .bits256)
        let dekData = dek.withUnsafeBytes { Data($0) }

        // Encrypt body with DEK
        var nonce = [UInt8](repeating: 0, count: 12)
        _ = SecRandomCopyBytes(kSecRandomDefault, 12, &nonce)
        let gcmNonce = try AES.GCM.Nonce(data: Data(nonce))
        let sealed   = try AES.GCM.seal(Data(plaintext.utf8), using: dek, nonce: gcmNonce)
        let body     = sealed.ciphertext + sealed.tag

        // Wrap DEK for each recipient using ECDH-derived AES-KW equivalent
        // (We use AES-GCM with a zero nonce for key wrapping — compatible with AES-KW semantics)
        var slots: [GroupSlot] = []
        for r in recipients {
            guard let theirPub = try? importPublicKey(r.publicKeyB64) else { continue }
            guard let wrapKey = try? sharedKey(ourPriv: ourIdentity.privateKey, theirPub: theirPub) else { continue }
            let wrapNonce = try AES.GCM.Nonce(data: Data(repeating: 0, count: 12))
            let wrapped   = try AES.GCM.seal(dekData, using: wrapKey, nonce: wrapNonce)
            let wrappedBytes = wrapped.ciphertext + wrapped.tag
            slots.append(GroupSlot(h: r.handle, p: r.publicKeyB64, dek: Codec.b64(wrappedBytes)))
        }
        guard !slots.isEmpty else { throw CCError.noRecipients }

        let msgIdData = Data(SHA256.hash(data: Data("\(Date().timeIntervalSince1970)".utf8)).prefix(8))
        let slotsJSON = try JSONEncoder().encode(slots)

        return "CRYPTOCHAT_GRP_V1:\(Codec.b64(msgIdData)):\(Codec.b64(Data(nonce))):\(Codec.b64(body)):\(Codec.b64(slotsJSON))"
    }

    public static func decryptGroup(
        wireText: String,
        ourIdentity: CCIdentity,
        senderPublicKeyB64: String
    ) throws -> (plaintext: String, slotCount: Int, senderPublicKeyB64: String) {
        let parts = wireText.trimmingCharacters(in: .whitespaces).components(separatedBy: ":")
        guard parts.count >= 5, parts[0] == "CRYPTOCHAT_GRP_V1",
              let ivData    = Codec.data(parts[2]),
              let bodyData  = Codec.data(parts[3]),
              let slotsData = Codec.data(parts[4]) else {
            throw CCError.invalidWireFormat
        }

        let slots    = try JSONDecoder().decode([GroupSlot].self, from: slotsData)
        guard let mySlot = slots.first(where: { $0.p == ourIdentity.publicKeyB64 }) else {
            throw CCError.noSlotForKey
        }

        // Unwrap DEK
        let senderPub = try importPublicKey(senderPublicKeyB64)
        let wrapKey   = try sharedKey(ourPriv: ourIdentity.privateKey, theirPub: senderPub)
        guard let wrappedBytes = Codec.data(mySlot.dek), wrappedBytes.count > 16 else {
            throw CCError.decryptFailed
        }
        let wrapNonce  = try AES.GCM.Nonce(data: Data(repeating: 0, count: 12))
        let wCipher    = wrappedBytes.dropLast(16)
        let wTag       = wrappedBytes.suffix(16)
        let wSealed    = try AES.GCM.SealedBox(nonce: wrapNonce, ciphertext: wCipher, tag: wTag)
        let dekData    = try AES.GCM.open(wSealed, using: wrapKey)
        let dek        = SymmetricKey(data: dekData)

        // Decrypt body
        guard bodyData.count > 16 else { throw CCError.decryptFailed }
        let bCipher  = bodyData.dropLast(16)
        let bTag     = bodyData.suffix(16)
        let bNonce   = try AES.GCM.Nonce(data: ivData)
        let bSealed  = try AES.GCM.SealedBox(nonce: bNonce, ciphertext: bCipher, tag: bTag)
        let plain    = try AES.GCM.open(bSealed, using: dek)

        guard let text = String(data: plain, encoding: .utf8) else { throw CCError.decryptFailed }
        return (text, slots.count, senderPublicKeyB64)
    }

    // ── Wire format detection ─────────────────────────────────────────────

    public static func isV1(_ text: String) -> Bool {
        text.trimmingCharacters(in: .whitespaces).hasPrefix("CRYPTOCHAT_V1:")
    }
    public static func isGroup(_ text: String) -> Bool {
        text.trimmingCharacters(in: .whitespaces).hasPrefix("CRYPTOCHAT_GRP_V1:")
    }
    public static func isWire(_ text: String) -> Bool { isV1(text) || isGroup(text) }

    // ── Fingerprint ───────────────────────────────────────────────────────

    public static func fingerprint(_ spkiB64: String) -> String? {
        guard let data = Codec.data(spkiB64) else { return nil }
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
