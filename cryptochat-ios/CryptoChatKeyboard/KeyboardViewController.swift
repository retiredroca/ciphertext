// CryptoChatKeyboard/KeyboardViewController.swift
//
// Custom keyboard extension — iOS equivalent of the Android floating button.
// The user switches to "CryptoChat" keyboard in any app.
// The keyboard area shows the encrypt panel instead of a standard keyboard.
//
// Setup: Settings → General → Keyboard → Keyboards → Add New Keyboard → CryptoChat
//
// Flow:
//   1. User opens any chat app and taps a text field
//   2. Switches to CryptoChat keyboard (globe icon)
//   3. Selects recipient, types plaintext, taps "Encrypt & insert"
//   4. The ciphertext is inserted directly into the text field
//   5. User taps Send in the chat app
//
// "Full Access" is required to load contacts from the App Group.
// Without Full Access, the keyboard still works but shows no contacts
// (user can paste a public key manually).

import UIKit
import SwiftUI

class KeyboardViewController: UIInputViewController {

    private var hostingController: UIHostingController<KeyboardPanelView>?

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor.systemGroupedBackground

        let panel = KeyboardPanelView(
            onInsert: { [weak self] text in
                self?.textDocumentProxy.insertText(text)
            },
            onSwitchKeyboard: { [weak self] in
                self?.advanceToNextInputMode()
            },
            hasFullAccess: hasFullAccess
        )

        let hc = UIHostingController(rootView: panel)
        addChild(hc)
        view.addSubview(hc.view)
        hc.view.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            hc.view.topAnchor.constraint(equalTo: view.topAnchor),
            hc.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            hc.view.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            hc.view.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
        hc.didMove(toParent: self)
        hostingController = hc
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        // Prefer a taller keyboard area for the compose panel
        let h = UIScreen.main.bounds.height * 0.45
        view.heightAnchor.constraint(equalToConstant: h).isActive = true
    }
}

// MARK: - SwiftUI Keyboard Panel

struct KeyboardPanelView: View {

    let onInsert:       (String) -> Void
    let onSwitchKeyboard: () -> Void
    let hasFullAccess:  Bool

    @State private var identity:   CCIdentity? = nil
    @State private var contacts:   [CCContact] = []
    @State private var mode:       ComposeMode = .oneToOne
    @State private var recipIdx:   Int = 0
    @State private var groupSel:   Set<String> = []
    @State private var plaintext:  String = ""
    @State private var status:     String = ""
    @State private var statusOk:   Bool = true
    @State private var busy:       Bool = false

    enum ComposeMode { case oneToOne, group }

    var usable: [CCContact] { contacts.filter { $0.publicKeyB64 != nil } }

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            recipientRow
            Divider().opacity(0.4)
            textArea
            if !status.isEmpty { statusBar }
            Divider()
            footer
        }
        .background(Color(.systemGroupedBackground))
        .task { await loadData() }
    }

    // ── Toolbar ────────────────────────────────────────────────────────

    var toolbar: some View {
        HStack(spacing: 10) {
            // Switch keyboard button
            Button(action: onSwitchKeyboard) {
                Image(systemName: "globe")
                    .font(.system(size: 18))
                    .foregroundColor(.secondary)
            }
            .frame(width: 36, height: 36)

            Text("CryptoChat")
                .font(.system(size: 13, weight: .semibold))
                .foregroundColor(Color(red: 0.42, green: 0.31, blue: 0.94))

            Spacer()

            // Mode toggle
            Picker("Mode", selection: $mode) {
                Text("1:1").tag(ComposeMode.oneToOne)
                Text("Group").tag(ComposeMode.group)
            }
            .pickerStyle(.segmented)
            .frame(width: 120)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
    }

    // ── Recipient row ──────────────────────────────────────────────────

    var recipientRow: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 6) {
                if usable.isEmpty {
                    Text(hasFullAccess ? "No contacts — add some in the CryptoChat app" : "Enable Full Access in Settings to load contacts")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .padding(.horizontal, 12)
                } else if mode == .oneToOne {
                    ForEach(Array(usable.enumerated()), id: \.offset) { i, c in
                        Button(action: { recipIdx = i }) {
                            Text(c.displayName)
                                .font(.system(size: 12, weight: .medium))
                                .padding(.horizontal, 10)
                                .padding(.vertical, 5)
                                .background(
                                    Capsule()
                                        .fill(recipIdx == i
                                              ? Color(red: 0.42, green: 0.31, blue: 0.94)
                                              : Color(.systemFill))
                                )
                                .foregroundColor(recipIdx == i ? .white : .primary)
                        }
                    }
                } else {
                    ForEach(usable) { c in
                        let on = groupSel.contains(c.id)
                        Button(action: {
                            if on { groupSel.remove(c.id) }
                            else  { groupSel.insert(c.id) }
                        }) {
                            HStack(spacing: 4) {
                                Image(systemName: on ? "checkmark.circle.fill" : "circle")
                                    .font(.system(size: 11))
                                Text(c.displayName)
                                    .font(.system(size: 12, weight: .medium))
                            }
                            .padding(.horizontal, 10)
                            .padding(.vertical, 5)
                            .background(
                                Capsule()
                                    .fill(on ? Color(red: 0.42, green: 0.31, blue: 0.94).opacity(0.15)
                                             : Color(.systemFill))
                            )
                            .foregroundColor(on ? Color(red: 0.42, green: 0.31, blue: 0.94) : .primary)
                            .overlay(Capsule().strokeBorder(
                                on ? Color(red: 0.42, green: 0.31, blue: 0.94) : Color.clear,
                                lineWidth: 1
                            ))
                        }
                    }
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
        }
    }

    // ── Text area ──────────────────────────────────────────────────────

    var textArea: some View {
        ZStack(alignment: .topLeading) {
            if plaintext.isEmpty {
                Text("Type your private message…")
                    .foregroundColor(.secondary)
                    .font(.system(size: 15))
                    .padding(.horizontal, 14)
                    .padding(.top, 10)
            }
            TextEditor(text: $plaintext)
                .font(.system(size: 15))
                .padding(.horizontal, 10)
                .scrollContentBackground(.hidden)
                .background(Color.clear)
        }
        .frame(maxWidth: .infinity, minHeight: 72)
    }

    // ── Status bar ─────────────────────────────────────────────────────

    var statusBar: some View {
        HStack {
            Text(status)
                .font(.caption)
                .foregroundColor(statusOk ? Color(red: 0.11, green: 0.62, blue: 0.46) : .red)
            Spacer()
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 4)
        .background(statusOk
            ? Color(red: 0.11, green: 0.62, blue: 0.46).opacity(0.08)
            : Color.red.opacity(0.08))
    }

    // ── Footer / send button ───────────────────────────────────────────

    var footer: some View {
        HStack {
            Text("🔒 AES-256-GCM · ECDH")
                .font(.system(size: 10))
                .foregroundColor(.secondary)
                .opacity(0.7)
            Spacer()
            Button(action: doEncrypt) {
                HStack(spacing: 5) {
                    if busy {
                        ProgressView().scaleEffect(0.7)
                    } else {
                        Image(systemName: "lock.fill")
                            .font(.system(size: 11))
                    }
                    Text("Encrypt & insert")
                        .font(.system(size: 13, weight: .semibold))
                }
                .foregroundColor(.white)
                .padding(.horizontal, 14)
                .padding(.vertical, 8)
                .background(
                    RoundedRectangle(cornerRadius: 9)
                        .fill(canEncrypt
                              ? Color(red: 0.42, green: 0.31, blue: 0.94)
                              : Color.gray.opacity(0.4))
                )
            }
            .disabled(!canEncrypt || busy)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    var canEncrypt: Bool {
        guard !plaintext.trimmingCharacters(in: .whitespaces).isEmpty else { return false }
        if mode == .oneToOne { return !usable.isEmpty }
        return !groupSel.isEmpty
    }

    // ── Actions ────────────────────────────────────────────────────────

    func loadData() async {
        identity = await KeyStore.shared.getOrCreateIdentity()
        contacts = await KeyStore.shared.listContacts()
    }

    func doEncrypt() {
        guard let id = identity, canEncrypt else { return }
        busy = true
        status = ""

        Task {
            do {
                let wire: String
                let text = plaintext.trimmingCharacters(in: .whitespaces)

                if mode == .oneToOne {
                    let c = usable[recipIdx]
                    guard let pub = c.publicKeyB64 else { throw CCError.invalidKey("no key") }
                    wire = try CryptoEngine.encryptMessage(
                        plaintext: text, ourIdentity: id, theirPublicKeyB64: pub
                    )
                } else {
                    let recipients = usable.filter { groupSel.contains($0.id) }
                        .compactMap { c -> (handle: String, publicKeyB64: String)? in
                            guard let pub = c.publicKeyB64 else { return nil }
                            return (c.handle, pub)
                        }
                    wire = try CryptoEngine.encryptGroup(
                        plaintext: text, ourIdentity: id, recipients: recipients
                    )
                }

                await MainActor.run {
                    onInsert(wire)
                    plaintext = ""
                    status = "✓ Encrypted and inserted"
                    statusOk = true
                    busy = false
                    // Clear status after 2s
                    Task {
                        try? await Task.sleep(nanoseconds: 2_000_000_000)
                        await MainActor.run { status = "" }
                    }
                }
            } catch {
                await MainActor.run {
                    status = "✗ \(error.localizedDescription)"
                    statusOk = false
                    busy = false
                }
            }
        }
    }
}
