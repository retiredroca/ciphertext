// swift-tools-version: 5.9
// CryptoChat iOS — Swift Package
//
// Three targets:
//   CryptoChatShared   — crypto engine + keychain storage (shared by app + extensions)
//   CryptoChatApp      — main app (SwiftUI, key management, contacts, compose)
//   CryptoChatKeyboard — keyboard extension (encrypt panel in any text field)

import PackageDescription

let package = Package(
    name: "CryptoChat",
    platforms: [.iOS(.v16)],
    products: [
        .library(name: "CryptoChatShared", targets: ["CryptoChatShared"]),
    ],
    targets: [
        .target(
            name: "CryptoChatShared",
            path: "Shared",
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency")
            ]
        ),
    ]
)
