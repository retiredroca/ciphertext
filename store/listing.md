# ciphertext — store listings

Copy for the Chrome Web Store and Mozilla Add-ons (AMO) listings. Version 0.9.0.

## Single purpose

ciphertext encrypts and decrypts messages in web chat input boxes, so supported
platforms only ever see ciphertext.

---

## Chrome Web Store

### Short description (≤ 132 characters)

```
End-to-end encryption for Discord, Slack, WhatsApp, Telegram, Instagram, X, and Facebook. No servers; keys stay local.
```

Alternate:

```
End-to-end encrypted messaging on Discord, Slack, WhatsApp, Telegram, Instagram, X, and Facebook. Keys never leave your device.
```

### Detailed description

```
ciphertext adds an independent layer of end-to-end encryption on top of the chat sites you already use. The platform stores and transmits only ciphertext — your plaintext never leaves your browser.

A small lock button appears on the message box. Click it, choose a recipient, type, and send. ciphertext encrypts locally and injects the ciphertext into the normal input box.

Works on: Discord, Slack, WhatsApp Web, Telegram Web, Instagram DMs, X/Twitter, and Facebook Messenger.

Features
• 1:1 and group messages
• ECDH P-256 + AES-256-GCM, with hybrid post-quantum encryption (ML-KEM-768)
• Add contacts by public key, GPG/OpenPGP armor, or a one-click share link
• Decrypts messages inline; unknown senders show a click-to-decrypt overlay
• Encrypted, passphrase-protected backups (.ccbackup)
• No accounts, no servers, no tracking — keys are stored locally and never leave your device

Back up before updating: export a .ccbackup (My Keys → Export backup) before installing a new version. Your identity and contacts live only in your browser, and a new version may change the message format.

Open source under AGPL-3.0.

ciphertext is alpha software and has not been independently audited. Do not rely on it where your safety or legal exposure depends on it.
```

### Category

Productivity

### Permission justifications

- **storage** — store the user's identity keypair and contacts locally, on-device only.
- **clipboardWrite** — copy the user's public key or encrypted text to the clipboard on request.
- **Host permissions** (`discord.com`, `*.slack.com`, `web.whatsapp.com`, `web.telegram.org`, `www.instagram.com`, `x.com`, `twitter.com`, `www.facebook.com`, `www.messenger.com`, `retiredroca.github.io`) — run the composer overlay on the supported platforms and the share-link page.

No optional/broad host permissions are requested. Any-site mode is a
Firefox/LibreWolf-only feature (see the AMO listing below).

### Data usage

No data is collected, transmitted, or sold. All cryptography runs locally in the
browser using the Web Crypto API. The extension contains no remote code.

---

## Mozilla Add-ons (AMO)

### Summary (≤ 250 characters)

```
End-to-end encrypted messaging on Discord, Slack, WhatsApp, Telegram, Instagram, X, and Facebook (plus any site, optionally). Keys never leave your browser; post-quantum hybrid encryption. No accounts, no servers.
```

### Description

```
ciphertext encrypts your messages in your browser before they reach the platform, so Discord, Slack, WhatsApp, Telegram, Instagram, X, and Facebook only ever see ciphertext.

A small lock button appears on the message box. Click it, pick a recipient, type, and send — ciphertext encrypts locally and injects the ciphertext into the normal input. Messages from contacts are decrypted inline; unknown senders show a click-to-decrypt overlay.

Works in Firefox and LibreWolf on: Discord, Slack, WhatsApp Web, Telegram Web, Instagram DMs, X/Twitter, and Facebook Messenger. An optional permission enables it on any site with a text field.

Features
• 1:1 and group messages
• ECDH P-256 + AES-256-GCM; hybrid post-quantum encryption (ML-KEM-768)
• Add contacts by public key, GPG/OpenPGP armor, or one-click share link
• Encrypted .ccbackup export/import to move your identity between browsers
• No accounts, no servers, no tracking — private keys stay on your device

Back up before updating: export a .ccbackup (My Keys → Export backup) before installing a new version. Your identity and contacts live only in your browser, and a new version may change the message format.

Open source under AGPL-3.0.

ciphertext is alpha software and has not been independently audited. Don't rely on it where your safety or legal exposure depends on it.
```

---

## Privacy policy

Hosted at: **https://retiredroca.github.io/ciphertext/privacy.html**
(source: [`privacy.html`](../privacy.html), served from the GitHub Pages root).

Chrome Web Store › Privacy practices answers:

- **Does the extension collect or use user data?** No.
- **Data types collected:** none.
- **Sold to third parties:** no.
- **Used for purposes unrelated to the single purpose:** no.
- **Used to determine creditworthiness or for lending:** no.
- **Remote code:** none.

Firefox/AMO also links this policy.
