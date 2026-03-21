// Shared/KeyStore.swift
//
// Keychain-backed key and contact storage.
// Shared between the main app and the keyboard extension via an App Group.
// App Group ID: group.com.cryptochat.shared
//
// Identity private key → Keychain (SecureEnclave where available)
// Identity public key  → UserDefaults (App Group)
// Contacts            → UserDefaults (App Group)

import Foundation
import CryptoKit
import Security

// MARK: - App Group

private let APP_GROUP   = "group.com.cryptochat.shared"
private let K_PUB_KEY   = "cc_identity_pubkey_v2"
private let K_PRIV_KEY  = "cc_identity_privkey_v2"
private let K_CONTACTS  = "cc_contacts_v2"
private let K_FINGERPRINT = "cc_identity_fingerprint_v2"

// MARK: - Contact model

public struct CCContact: Codable, Identifiable, Equatable {
    public var id: String { "\(handle)::\(site)" }
    public var handle:       String
    public var site:         String          // free-text: "Signal", "web", etc.
    public var displayName:  String
    public var publicKeyB64: String?         // nil for RSA GPG contacts (future)
    public var fingerprint:  String?
    public var verified:     Bool
    public var addedAt:      Date

    public init(handle: String, site: String, displayName: String,
                publicKeyB64: String?, fingerprint: String?) {
        self.handle       = handle
        self.site         = site
        self.displayName  = displayName.isEmpty ? handle : displayName
        self.publicKeyB64 = publicKeyB64
        self.fingerprint  = fingerprint
        self.verified     = false
        self.addedAt      = Date()
    }
}

// MARK: - KeyStore

public actor KeyStore {

    public static let shared = KeyStore()
    private init() {}

    private var _identity: CCIdentity?

    // ── Shared UserDefaults (App Group) ───────────────────────────────────

    private var defaults: UserDefaults {
        UserDefaults(suiteName: APP_GROUP) ?? .standard
    }

    // ── Identity ──────────────────────────────────────────────────────────

    public func getOrCreateIdentity() async -> CCIdentity {
        if let id = _identity { return id }

        // Try loading from Keychain
        if let privB64 = keychainLoad(key: K_PRIV_KEY),
           let pubB64  = defaults.string(forKey: K_PUB_KEY),
           let fp      = defaults.string(forKey: K_FINGERPRINT),
           let priv    = try? CryptoEngine.importPrivateKey(privB64) {
            let id = CCIdentity(privateKey: priv, publicKeyB64: pubB64, fingerprint: fp)
            _identity = id
            return id
        }

        // Generate new identity
        let id = CryptoEngine.generateIdentity()
        let privData = id.privateKey.rawRepresentation  // 32-byte scalar

        // Build PKCS#8 wrapper (same as Web Crypto exportKey('pkcs8') for P-256)
        let pkcs8Header = Data([
            0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
            0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27,
            0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20,
        ])
        let pkcs8 = pkcs8Header + privData
        keychainSave(key: K_PRIV_KEY, value: pkcs8.base64EncodedString())
        defaults.set(id.publicKeyB64, forKey: K_PUB_KEY)
        defaults.set(id.fingerprint,  forKey: K_FINGERPRINT)

        _identity = id
        return id
    }

    public func deleteIdentity() {
        _identity = nil
        keychainDelete(key: K_PRIV_KEY)
        defaults.removeObject(forKey: K_PUB_KEY)
        defaults.removeObject(forKey: K_FINGERPRINT)
    }

    // ── Contacts ──────────────────────────────────────────────────────────

    public func listContacts() -> [CCContact] {
        guard let data = defaults.data(forKey: K_CONTACTS),
              let list = try? JSONDecoder().decode([CCContact].self, from: data) else { return [] }
        return list.sorted { $0.displayName < $1.displayName }
    }

    public func saveContact(_ contact: CCContact) {
        var list = listContacts()
        if let idx = list.firstIndex(where: { $0.id == contact.id }) {
            list[idx] = contact
        } else {
            list.append(contact)
        }
        if let data = try? JSONEncoder().encode(list) {
            defaults.set(data, forKey: K_CONTACTS)
        }
    }

    public func deleteContact(handle: String, site: String) {
        var list = listContacts()
        list.removeAll { $0.handle == handle && $0.site == site }
        if let data = try? JSONEncoder().encode(list) {
            defaults.set(data, forKey: K_CONTACTS)
        }
    }

    // ── Keychain helpers ──────────────────────────────────────────────────

    private func keychainSave(key: String, value: String) {
        let data = Data(value.utf8)
        let query: [String: Any] = [
            kSecClass as String:            kSecClassGenericPassword,
            kSecAttrService as String:      APP_GROUP,
            kSecAttrAccount as String:      key,
            kSecValueData as String:        data,
            kSecAttrAccessGroup as String:  APP_GROUP,
        ]
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }

    private func keychainLoad(key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String:            kSecClassGenericPassword,
            kSecAttrService as String:      APP_GROUP,
            kSecAttrAccount as String:      key,
            kSecAttrAccessGroup as String:  APP_GROUP,
            kSecReturnData as String:       true,
            kSecMatchLimit as String:       kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func keychainDelete(key: String) {
        SecItemDelete([
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: APP_GROUP,
            kSecAttrAccount as String: key,
        ] as CFDictionary)
    }
}
