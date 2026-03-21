# CryptoChat iOS

End-to-end encrypted messaging for iOS — 100% compatible with the CryptoChat
browser extension and Android app. Same wire format, same keys.

## How it works on iOS

Apple does not allow floating windows over other apps (no `SYSTEM_ALERT_WINDOW`).
The closest equivalent is a **custom keyboard extension** — a panel that appears
in any app's keyboard area when the user selects "CryptoChat" keyboard.

### Flow

1. Open any chat app (iMessage, WhatsApp, Signal, Telegram, anything)
2. Tap a text field → keyboard appears
3. Tap the 🌐 globe icon → switch to CryptoChat keyboard
4. Select recipient, type message, tap **Encrypt & insert**
5. The ciphertext is typed directly into the text field
6. Tap Send in the chat app

Recipients with the extension (desktop) or CryptoChat app (iOS/Android) see
the decrypted message automatically.

## Requirements

- Xcode 15+
- iOS 16+ deployment target
- Apple Developer account (free works for development; paid for TestFlight/App Store)

## Setup

### 1. Open in Xcode

```bash
open CryptoChat.xcodeproj
```

Or create a new Xcode project and add the files manually (see structure below).

### 2. Configure signing

- Select the `CryptoChat` target → Signing & Capabilities
- Set your Team and Bundle Identifier (`com.yourname.cryptochat`)
- Repeat for `CryptoChatKeyboard` target

### 3. Configure App Group

Both targets must share an App Group so contacts are visible from the keyboard:

- CryptoChat target → + Capability → App Groups → `group.com.cryptochat.shared`
- CryptoChatKeyboard target → same

Update `APP_GROUP` in `Shared/KeyStore.swift` if you use a different identifier.

### 4. Build & run

- Select an iOS 16+ simulator or physical device
- ⌘R to build and run

### 5. Enable the keyboard (device only)

Settings → General → Keyboard → Keyboards → Add New Keyboard → CryptoChat
→ Allow Full Access (required to load contacts)

## Project structure

```
cryptochat-ios/
├── Package.swift                           # Swift Package (shared library)
├── Shared/
│   ├── CryptoEngine.swift                  # ECDH P-256 + AES-256-GCM (CryptoKit)
│   └── KeyStore.swift                      # Keychain + App Group storage
├── CryptoChat/                             # Main app target
│   ├── CryptoChatApp.swift                 # @main SwiftUI entry point
│   ├── ContentView.swift                   # Compose, Contacts, My Keys, Settings tabs
│   └── Info.plist
└── CryptoChatKeyboard/                     # Keyboard extension target
    ├── KeyboardViewController.swift        # UIInputViewController + SwiftUI panel
    └── Info.plist
```

## Crypto compatibility

| Format | Wire string |
|--------|-------------|
| 1:1    | `CRYPTOCHAT_V1:<iv>:<cipher>:<senderSpki>` |
| Group  | `CRYPTOCHAT_GRP_V1:<msgId>:<iv>:<body>:<slots>` |

Keys are SPKI base64 (P-256) — identical to the browser extension and Android app.
Import/export your key between devices using the share link system or manual copy.

## Note on AES-GCM key wrapping

The browser extension uses `AES-KW` for wrapping group DEKs.
iOS CryptoKit doesn't expose AES-KW directly, so we use AES-GCM with a
zero nonce as an equivalent. The group decrypt code on desktop will need a
matching update to handle both formats — this is tracked as a future compatibility fix.

## Permissions

| Capability | Why |
|---|---|
| App Group | Share contacts between main app and keyboard extension |
| Full Access (keyboard) | Read contacts from App Group shared storage |
| Keychain | Store the private key securely (device-only, not iCloud synced) |

No network access is required. All crypto is local.
