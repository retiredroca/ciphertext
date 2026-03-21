// CryptoChat/ContentView.swift
// Main app UI — mirrors the browser extension popup and Android app.
// Compose tab also handles decrypt (paste a wire string to reveal plaintext).

import SwiftUI
import CryptoKit

struct ContentView: View {
    var body: some View {
        TabView {
            ComposeView()
                .tabItem { Label("Compose", systemImage: "lock.fill") }
            ContactsView()
                .tabItem { Label("Contacts", systemImage: "person.2.fill") }
            KeysView()
                .tabItem { Label("My Keys", systemImage: "key.fill") }
            SettingsView()
                .tabItem { Label("Settings", systemImage: "gearshape.fill") }
        }
        .accentColor(Color(red: 0.42, green: 0.31, blue: 0.94))
    }
}

// MARK: - Compose

struct ComposeView: View {
    @State private var identity: CCIdentity?
    @State private var contacts: [CCContact] = []
    @State private var mode:     ComposeMode = .oneToOne
    @State private var recipIdx: Int = 0
    @State private var groupSel: Set<String> = []
    @State private var plaintext: String = ""
    @State private var wireOut:  String = ""
    @State private var status:   String = ""
    @State private var statusOk: Bool = true
    @State private var busy:     Bool = false
    @State private var pasteText: String = ""
    @State private var decryptResult: String = ""

    enum ComposeMode: String, CaseIterable { case oneToOne = "1:1", group = "Group" }

    var usable: [CCContact] { contacts.filter { $0.publicKeyB64 != nil } }

    var body: some View {
        NavigationView {
            Form {
                // Mode
                Section {
                    Picker("Mode", selection: $mode) {
                        ForEach(ComposeMode.allCases, id: \.self) { m in
                            Text(m.rawValue).tag(m)
                        }
                    }
                    .pickerStyle(.segmented)
                }

                // Recipients
                Section(header: Text("Recipient")) {
                    if usable.isEmpty {
                        Text("Add contacts first")
                            .foregroundColor(.secondary)
                            .font(.caption)
                    } else if mode == .oneToOne {
                        Picker("Recipient", selection: $recipIdx) {
                            ForEach(Array(usable.enumerated()), id: \.offset) { i, c in
                                Text(c.displayName).tag(i)
                            }
                        }
                    } else {
                        ForEach(usable) { c in
                            Toggle(c.displayName, isOn: Binding(
                                get: { groupSel.contains(c.id) },
                                set: { if $0 { groupSel.insert(c.id) } else { groupSel.remove(c.id) } }
                            ))
                        }
                    }
                }

                // Message
                Section(header: Text("Message")) {
                    TextEditor(text: $plaintext)
                        .frame(minHeight: 80)
                        .font(.body)
                    Button(action: doEncrypt) {
                        HStack {
                            Spacer()
                            if busy { ProgressView().scaleEffect(0.8) }
                            Text(busy ? "Encrypting…" : "🔒 Encrypt & copy")
                                .fontWeight(.semibold)
                            Spacer()
                        }
                    }
                    .disabled(busy || plaintext.trimmingCharacters(in: .whitespaces).isEmpty)
                    .foregroundColor(Color(red: 0.42, green: 0.31, blue: 0.94))
                }

                // Result
                if !wireOut.isEmpty {
                    Section(header: Text("Ciphertext (copied)")) {
                        Text(wireOut)
                            .font(.system(.caption, design: .monospaced))
                            .lineLimit(4)
                            .foregroundColor(.secondary)
                    }
                }

                if !status.isEmpty {
                    Section {
                        Text(status)
                            .foregroundColor(statusOk ? Color(red: 0.11, green: 0.62, blue: 0.46) : .red)
                            .font(.caption)
                    }
                }

                // Decrypt section
                Section(header: Text("Decrypt")) {
                    TextField("Paste CRYPTOCHAT_V1:… here", text: $pasteText, axis: .vertical)
                        .font(.system(.caption, design: .monospaced))
                        .lineLimit(3...6)
                    Button("Decrypt") { doDecrypt() }
                        .disabled(pasteText.trimmingCharacters(in: .whitespaces).isEmpty)
                    if !decryptResult.isEmpty {
                        Text(decryptResult)
                            .font(.body)
                            .foregroundColor(Color(red: 0.11, green: 0.62, blue: 0.46))
                    }
                }
            }
            .navigationTitle("CryptoChat")
            .navigationBarTitleDisplayMode(.inline)
        }
        .task { await loadData() }
    }

    func loadData() async {
        identity = await KeyStore.shared.getOrCreateIdentity()
        contacts = await KeyStore.shared.listContacts()
    }

    func doEncrypt() {
        guard let id = identity else { return }
        busy = true; status = ""; wireOut = ""

        Task {
            do {
                let text = plaintext.trimmingCharacters(in: .whitespaces)
                let wire: String

                if mode == .oneToOne {
                    guard !usable.isEmpty, let pub = usable[recipIdx].publicKeyB64 else {
                        throw CCError.noRecipients
                    }
                    wire = try CryptoEngine.encryptMessage(plaintext: text, ourIdentity: id, theirPublicKeyB64: pub)
                } else {
                    let recipients = usable.filter { groupSel.contains($0.id) }
                        .compactMap { c -> (handle: String, publicKeyB64: String)? in
                            guard let pub = c.publicKeyB64 else { return nil }
                            return (c.handle, pub)
                        }
                    wire = try CryptoEngine.encryptGroup(plaintext: text, ourIdentity: id, recipients: recipients)
                }

                UIPasteboard.general.string = wire

                await MainActor.run {
                    wireOut  = wire
                    plaintext = ""
                    status   = "✓ Encrypted & copied to clipboard"
                    statusOk = true
                    busy     = false
                }
            } catch {
                await MainActor.run {
                    status   = "✗ \(error.localizedDescription)"
                    statusOk = false
                    busy     = false
                }
            }
        }
    }

    func doDecrypt() {
        guard let id = identity else { return }
        let wire = pasteText.trimmingCharacters(in: .whitespaces)
        decryptResult = ""

        Task {
            do {
                if CryptoEngine.isV1(wire) {
                    let (plaintext, senderB64) = try CryptoEngine.decryptMessage(wireText: wire, ourIdentity: id)
                    let sender = contacts.first { $0.publicKeyB64 == senderB64 }?.displayName ?? "?"
                    await MainActor.run { decryptResult = "🔓 From \(sender): \(plaintext)" }
                } else if CryptoEngine.isGroup(wire) {
                    // Try all contacts as potential senders
                    var result: String? = nil
                    for c in contacts {
                        guard let pub = c.publicKeyB64 else { continue }
                        if let (pt, _, _) = try? CryptoEngine.decryptGroup(wireText: wire, ourIdentity: id, senderPublicKeyB64: pub) {
                            result = "🔓 From \(c.displayName): \(pt)"
                            break
                        }
                    }
                    await MainActor.run {
                        decryptResult = result ?? "✗ Could not decrypt — sender not in contacts"
                    }
                } else {
                    await MainActor.run { decryptResult = "✗ Not a CryptoChat message" }
                }
            } catch {
                await MainActor.run { decryptResult = "✗ \(error.localizedDescription)" }
            }
        }
    }
}

// MARK: - Contacts

struct ContactsView: View {
    @State private var contacts:     [CCContact] = []
    @State private var showAdd:      Bool = false
    @State private var newHandle:    String = ""
    @State private var newSite:      String = ""
    @State private var newName:      String = ""
    @State private var newPubKey:    String = ""
    @State private var saveError:    String = ""

    var body: some View {
        NavigationView {
            List {
                ForEach(contacts) { c in
                    VStack(alignment: .leading, spacing: 3) {
                        Text(c.displayName).font(.headline)
                        Text(c.handle).font(.caption).foregroundColor(.secondary)
                        if let fp = c.fingerprint {
                            Text(fp.prefix(16).uppercased())
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundColor(.secondary)
                        }
                    }
                }
                .onDelete { idx in
                    Task {
                        for i in idx {
                            let c = contacts[i]
                            await KeyStore.shared.deleteContact(handle: c.handle, site: c.site)
                        }
                        contacts = await KeyStore.shared.listContacts()
                    }
                }
            }
            .navigationTitle("Contacts")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: { showAdd = true }) { Image(systemName: "plus") }
                }
                ToolbarItem(placement: .navigationBarLeading) { EditButton() }
            }
            .sheet(isPresented: $showAdd) {
                addContactSheet
            }
        }
        .task { contacts = await KeyStore.shared.listContacts() }
    }

    var addContactSheet: some View {
        NavigationView {
            Form {
                Section(header: Text("Handle")) {
                    TextField("@alice", text: $newHandle)
                }
                Section(header: Text("Site / app (optional)")) {
                    TextField("Signal, Discord, web…", text: $newSite)
                }
                Section(header: Text("Display name (optional)")) {
                    TextField("Alice", text: $newName)
                }
                Section(header: Text("Public key (SPKI base64)")) {
                    TextEditor(text: $newPubKey)
                        .font(.system(.caption, design: .monospaced))
                        .frame(height: 80)
                }
                if !saveError.isEmpty {
                    Section { Text(saveError).foregroundColor(.red).font(.caption) }
                }
            }
            .navigationTitle("Add Contact")
            .navigationBarItems(
                leading: Button("Cancel") { showAdd = false },
                trailing: Button("Save") { doSave() }.fontWeight(.semibold)
            )
        }
    }

    func doSave() {
        guard !newHandle.trimmingCharacters(in: .whitespaces).isEmpty else {
            saveError = "Handle is required"; return
        }
        guard !newPubKey.trimmingCharacters(in: .whitespaces).isEmpty else {
            saveError = "Public key is required"; return
        }
        let pub = newPubKey.trimmingCharacters(in: .whitespacesAndNewlines)
        let fp  = CryptoEngine.fingerprint(pub)

        Task {
            let contact = CCContact(
                handle:      newHandle.trimmingCharacters(in: .whitespaces),
                site:        newSite.trimmingCharacters(in: .whitespaces).isEmpty ? "web" : newSite,
                displayName: newName.trimmingCharacters(in: .whitespaces),
                publicKeyB64: pub,
                fingerprint:  fp
            )
            await KeyStore.shared.saveContact(contact)
            contacts = await KeyStore.shared.listContacts()
            showAdd  = false
            newHandle = ""; newSite = ""; newName = ""; newPubKey = ""; saveError = ""
        }
    }
}

// MARK: - My Keys

struct KeysView: View {
    @State private var identity:   CCIdentity?
    @State private var copiedKey:  Bool = false

    var body: some View {
        NavigationView {
            Form {
                if let id = identity {
                    Section(header: Text("Your public key")) {
                        Text("Share this with contacts. Safe to send publicly.")
                            .font(.caption).foregroundColor(.secondary)
                        Text(id.publicKeyB64)
                            .font(.system(.caption2, design: .monospaced))
                            .lineLimit(6)
                        Button(action: {
                            UIPasteboard.general.string = id.publicKeyB64
                            copiedKey = true
                            Task {
                                try? await Task.sleep(nanoseconds: 2_000_000_000)
                                await MainActor.run { copiedKey = false }
                            }
                        }) {
                            Label(copiedKey ? "Copied!" : "Copy public key",
                                  systemImage: copiedKey ? "checkmark" : "doc.on.doc")
                        }
                    }

                    Section(header: Text("Fingerprint")) {
                        Text(id.fingerprint.uppercased())
                            .font(.system(.caption, design: .monospaced))
                            .foregroundColor(.secondary)
                    }

                    Section(header: Text("Danger zone")) {
                        Button(role: .destructive, action: {
                            Task {
                                await KeyStore.shared.deleteIdentity()
                                identity = await KeyStore.shared.getOrCreateIdentity()
                            }
                        }) {
                            Label("Revoke & regenerate keypair", systemImage: "exclamationmark.triangle")
                        }
                    }
                } else {
                    ProgressView("Loading…")
                }
            }
            .navigationTitle("My Keys")
        }
        .task { identity = await KeyStore.shared.getOrCreateIdentity() }
    }
}

// MARK: - Settings

struct SettingsView: View {
    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("Keyboard Extension")) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Enable the CryptoChat keyboard to encrypt messages in any app.")
                            .font(.caption).foregroundColor(.secondary)
                        Text("Settings → General → Keyboard → Keyboards → Add New Keyboard → CryptoChat")
                            .font(.caption2).foregroundColor(.secondary).italic()
                        Button(action: { UIApplication.shared.open(URL(string: UIApplication.openSettingsURLString)!) }) {
                            Label("Open Settings", systemImage: "arrow.up.right.square")
                        }
                    }
                    .padding(.vertical, 4)
                }
                Section(header: Text("Full Access")) {
                    Text("The keyboard needs Full Access to load your contacts from the main app. Enable it in Settings → General → Keyboard → Keyboards → CryptoChat → Allow Full Access.")
                        .font(.caption).foregroundColor(.secondary)
                }
                Section(header: Text("About")) {
                    row("Version",    "0.7.0")
                    row("Crypto",     "ECDH P-256 · AES-256-GCM")
                    row("Group",      "Per-message DEK, per-recipient slot")
                    row("Compatible", "Browser extension, Android app")
                    row("Keys",       "Keychain (device-only)")
                }
            }
            .navigationTitle("Settings")
        }
    }

    func row(_ k: String, _ v: String) -> some View {
        HStack {
            Text(k).foregroundColor(.secondary)
            Spacer()
            Text(v).font(.caption)
        }
    }
}
