// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * CryptoChat — Background message handler
 *
 * Bundled (with engine.js + keystore.js) into src/background-bundle.js by
 * `npm run bundle`. Runs as the MV3 service worker in Chrome and Firefox.
 */

import {
  isPqcAvailable,
  encryptMessage, decryptMessage, isV1Message,
  encryptGroupMessage, decryptGroupMessage, isGroupMessage,
  encryptMessageV2, decryptMessageV2, isV2Message,
  encryptGroupMessageV2, decryptGroupMessageV2WithSender, isV2GroupMessage,
  parseGpgPublicKey, isGpgArmor, importPublicKey, importPrivateKey,
  keyFingerprint, derivePassKey, buf2b64, b642buf, str2buf, buf2str,
} from '../crypto/engine.js';

import {
  getOrCreateIdentity, listContacts, saveContact, deleteContact,
  verifyContact, getContact, getSharedKeyForContact, deleteIdentity,
  upgradeIdentityToPqc, clearSharedKeyCache,
} from '../crypto/keystore.js';

const PREFS_KEY = 'cc_prefs';
const DEFAULT_PREFS = { blur: true, overlay: true, allSites: false };

chrome.runtime.onMessage.addListener((msg, _sender, respond) => {
  handle(msg).then(respond).catch(err => respond({ error: err.message || String(err) }));
  return true;
});

// Auto-upgrade identity to add ML-KEM keys when the PQC bundle first loads
(async () => { try { await upgradeIdentityToPqc(); } catch (_) {} })();

async function handle(msg) {
  switch (msg.type) {

    /* ── Encrypt 1:1 (V2 if both have ML-KEM keys, else V1) ─────────── */
    case 'ENCRYPT_MESSAGE': {
      const { plaintext, contactHandle, contactPlatform } = msg;
      if (!plaintext) return { error: 'No plaintext' };
      const id      = await getOrCreateIdentity();
      const contact = await getContact(contactHandle, contactPlatform);
      if (!contact?.publicKeyB64) return { error: `No key for ${contactHandle}` };

      if (isPqcAvailable() && id.mlkemPkB64 && contact.mlkemPkB64) {
        const ct = await encryptMessageV2(
          plaintext, id.publicKeyB64, id.privateKey,
          contact.publicKeyB64, new Uint8Array(b642buf(contact.mlkemPkB64))
        );
        return { ciphertext: ct, format: 'v2' };
      }
      const sk = await getSharedKeyForContact(contactHandle, contactPlatform);
      const ct = await encryptMessage(plaintext, sk, id.publicKeyB64);
      return { ciphertext: ct, format: 'v1' };
    }

    /* ── Encrypt group ───────────────────────────────────────────────── */
    case 'ENCRYPT_GROUP': {
      const { plaintext, recipients } = msg;
      if (!plaintext)          return { error: 'No plaintext' };
      if (!recipients?.length) return { error: 'No recipients' };
      const id = await getOrCreateIdentity();

      const allRecip = [...recipients];
      if (!allRecip.find(r => r.publicKeyB64 === id.publicKeyB64)) {
        allRecip.push({
          handle: '__self__', platform: 'self',
          publicKeyB64: id.publicKeyB64, mlkemPkB64: id.mlkemPkB64 || null,
        });
      }
      const resolved = [];
      for (const r of allRecip) {
        if (r.publicKeyB64) { resolved.push(r); continue; }
        const c = await getContact(r.handle, r.platform);
        if (c?.publicKeyB64) {
          resolved.push({ ...r, publicKeyB64: c.publicKeyB64, mlkemPkB64: c.mlkemPkB64 || null });
        }
      }

      const allHavePqc = isPqcAvailable() && id.mlkemPkB64 && resolved.every(r => r.mlkemPkB64);
      if (allHavePqc) {
        const v2r = resolved.map(r => ({
          handle: r.handle,
          ecdhPubB64: r.publicKeyB64,
          mlkemPkB64: r.mlkemPkB64,
        }));
        const ct = await encryptGroupMessageV2(plaintext, id.publicKeyB64, id.privateKey, v2r);
        return { ciphertext: ct, recipientCount: resolved.length, format: 'v2-group' };
      }
      const ct = await encryptGroupMessage(plaintext, id.publicKeyB64, id.privateKey, resolved);
      return { ciphertext: ct, recipientCount: resolved.length, format: 'v1-group' };
    }

    /* ── Decrypt (V2 group → V2 1:1 → V1 group → V1 1:1) ────────────── */
    case 'DECRYPT_MESSAGE': {
      const { wireText } = msg;
      if (!wireText) return { error: 'No ciphertext' };
      const id       = await getOrCreateIdentity();
      const contacts = await listContacts();

      if (isV2GroupMessage(wireText)) {
        if (!isPqcAvailable() || !id.mlkemSkB64)
          return { error: 'V2 (quantum-resistant) message — install the PQC bundle to decrypt.' };
        for (const c of contacts) {
          if (!c.publicKeyB64) continue;
          try {
            const r = await decryptGroupMessageV2WithSender(
              wireText, id.publicKeyB64, id.privateKey, id.mlkemSkB64, c.publicKeyB64
            );
            return { ...r, senderHandle: c.handle, senderPlatform: c.platform, senderVerified: c.verified, format: 'v2-group' };
          } catch (_) {}
        }
        try {
          const r = await decryptGroupMessageV2WithSender(
            wireText, id.publicKeyB64, id.privateKey, id.mlkemSkB64, id.publicKeyB64
          );
          return { ...r, senderHandle: '(you)', format: 'v2-group' };
        } catch (_) {}
        return { error: 'No matching key to decrypt this V2 group message' };
      }

      if (isV2Message(wireText)) {
        if (!isPqcAvailable() || !id.mlkemSkB64)
          return { error: 'V2 (quantum-resistant) message — install the PQC bundle to decrypt.' };
        const mlkemSk = new Uint8Array(b642buf(id.mlkemSkB64));
        for (const c of contacts) {
          if (!c.publicKeyB64) continue;
          try {
            const r = await decryptMessageV2(
              wireText, id.privateKey, c.publicKeyB64, mlkemSk, id.publicKeyB64
            );
            return { ...r, senderHandle: c.handle, senderPlatform: c.platform, senderVerified: c.verified, format: 'v2' };
          } catch (_) {}
        }
        return { error: 'No matching key to decrypt this V2 message' };
      }

      if (isGroupMessage(wireText)) {
        for (const c of contacts) {
          if (!c.publicKeyB64) continue;
          try {
            const r = await decryptGroupMessage(wireText, id.publicKeyB64, id.privateKey, c.publicKeyB64);
            return { ...r, senderHandle: c.handle, senderPlatform: c.platform, senderVerified: c.verified, format: 'group' };
          } catch (_) {}
        }
        try {
          const r = await decryptGroupMessage(wireText, id.publicKeyB64, id.privateKey, id.publicKeyB64);
          return { ...r, senderHandle: '(you)', format: 'group' };
        } catch (_) {}
        return { error: 'No matching key to decrypt group message' };
      }

      if (isV1Message(wireText)) {
        for (const c of contacts) {
          if (!c.publicKeyB64) continue;
          try {
            const sk = await getSharedKeyForContact(c.handle, c.platform);
            const r  = await decryptMessage(wireText, sk);
            return { ...r, senderHandle: c.handle, senderPlatform: c.platform, senderVerified: c.verified, format: 'v1' };
          } catch (_) {}
        }
        return { error: 'No key found — have you added the sender as a contact?' };
      }

      return { error: 'Unrecognized CryptoChat message format' };
    }

    /* ── Identity ────────────────────────────────────────────────────── */
    case 'GET_PUBLIC_KEY': {
      const id = await getOrCreateIdentity();
      return {
        publicKeyB64: id.publicKeyB64, fingerprint: id.fingerprint,
        mlkemPkB64: id.mlkemPkB64 || null, pqcEnabled: id.pqcEnabled,
      };
    }

    case 'UPGRADE_TO_PQC':
      return upgradeIdentityToPqc();

    case 'RESET_IDENTITY': {
      await deleteIdentity();
      clearSharedKeyCache();
      const id = await getOrCreateIdentity();
      broadcastContactsUpdated();
      return {
        success: true, publicKeyB64: id.publicKeyB64, fingerprint: id.fingerprint,
        pqcEnabled: id.pqcEnabled,
      };
    }

    /* ── Contacts ────────────────────────────────────────────────────── */
    case 'SAVE_CONTACT': {
      const { handle, platform, publicKeyB64, publicArmor, displayName, mlkemPkB64 } = msg;
      if (!handle || !platform) return { error: 'handle and platform required' };

      let record = {
        handle, platform, displayName, source: 'native',
        publicKeyB64, mlkemPkB64: mlkemPkB64 || null,
      };

      if (publicArmor && isGpgArmor(publicArmor)) {
        const gpg = await parseGpgPublicKey(publicArmor);
        if (gpg.error && !gpg.type) return { error: gpg.error };
        record = {
          ...record, source: 'gpg', publicArmor,
          publicKeyB64: gpg.publicKeyB64 || null,
          curve: gpg.curve || null,
          fingerprint: gpg.fingerprint || null,
          uid: gpg.uid || null,
        };
        if (gpg.error) record.gpgNote = gpg.error;
      } else if (publicKeyB64) {
        try {
          await importPublicKey(publicKeyB64);
          record.fingerprint = await keyFingerprint(publicKeyB64);
        } catch (_) {
          return { error: 'Invalid public key — expected base64 SPKI or PGP armor' };
        }
      } else {
        return { error: 'Provide a publicKeyB64 or GPG armored key' };
      }

      const saved = await saveContact(record);
      broadcastContactsUpdated();
      return { success: true, contact: saved };
    }

    case 'PARSE_GPG_KEY': {
      if (!msg.armor) return { error: 'No armor provided' };
      return { result: await parseGpgPublicKey(msg.armor) };
    }

    case 'LIST_CONTACTS':
      return { contacts: await listContacts() };

    case 'DELETE_CONTACT': {
      await deleteContact(msg.handle, msg.platform);
      broadcastContactsUpdated();
      return { success: true };
    }

    case 'VERIFY_CONTACT': {
      await verifyContact(msg.handle, msg.platform);
      return { success: true };
    }

    /* ── Preferences ─────────────────────────────────────────────────── */
    case 'GET_PREFS':
      return { prefs: { ...DEFAULT_PREFS, ...(await getPrefs()) } };

    case 'SET_PREFS':
      return { prefs: await setPrefs(msg.prefs || {}) };

    /* ── Export encrypted backup ─────────────────────────────────────── */
    case 'EXPORT_BACKUP': {
      const { passphrase } = msg;
      if (!passphrase || passphrase.length < 6) {
        return { error: 'Passphrase must be at least 6 characters' };
      }

      const id       = await getOrCreateIdentity();
      const contacts = await listContacts();

      const salt    = crypto.getRandomValues(new Uint8Array(16));
      const iv      = crypto.getRandomValues(new Uint8Array(12));
      const passKey = await derivePassKey(passphrase, salt);

      const rawIdentity = (await chrome.storage.local.get('cc_identity_v2'))['cc_identity_v2'];
      const privatePt = str2buf(JSON.stringify({
        privateKeyB64: rawIdentity.privateKeyB64,
        mlkemSkB64:    rawIdentity.mlkemSkB64 || null,
      }));
      const privateCt = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, passKey, privatePt);

      const backup = {
        version:        3,
        createdAt:      Date.now(),
        publicKeyB64:   id.publicKeyB64,
        fingerprint:    id.fingerprint,
        mlkemPkB64:     id.mlkemPkB64 || null,
        pqcEnabled:     !!id.mlkemPkB64,
        salt:           buf2b64(salt.buffer),
        iv:             buf2b64(iv.buffer),
        encPrivateKey:  buf2b64(privateCt),
        contacts:       contacts.map(c => ({
          handle:       c.handle,
          platform:     c.platform,
          displayName:  c.displayName,
          publicKeyB64: c.publicKeyB64,
          mlkemPkB64:   c.mlkemPkB64   || null,
          publicArmor:  c.publicArmor  || null,
          source:       c.source       || 'native',
          curve:        c.curve        || null,
          fingerprint:  c.fingerprint  || null,
          uid:          c.uid          || null,
          verified:     c.verified     || false,
          addedAt:      c.addedAt      || Date.now(),
        })),
      };

      return { success: true, backup: JSON.stringify(backup, null, 2) };
    }

    /* ── Import encrypted backup ─────────────────────────────────────── */
    case 'IMPORT_BACKUP': {
      const { backupJson, passphrase, mode } = msg;

      let backup;
      try {
        backup = JSON.parse(backupJson);
      } catch (_) {
        return { error: 'Invalid backup file — could not parse JSON' };
      }

      if (!backup.version || !backup.encPrivateKey || !backup.publicKeyB64) {
        return { error: 'Invalid backup format — missing required fields' };
      }
      if (!passphrase) return { error: 'Passphrase required' };

      let privateKeyB64, mlkemSkB64;
      try {
        const salt    = new Uint8Array(b642buf(backup.salt));
        const iv      = new Uint8Array(b642buf(backup.iv));
        const passKey = await derivePassKey(passphrase, salt);
        const plainBuf = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv }, passKey, b642buf(backup.encPrivateKey)
        );
        const plain   = JSON.parse(buf2str(plainBuf));
        privateKeyB64 = plain.privateKeyB64;
        mlkemSkB64    = plain.mlkemSkB64 || null;
      } catch (_) {
        return { error: 'Wrong passphrase or corrupted backup' };
      }

      try {
        await importPublicKey(backup.publicKeyB64);
        await importPrivateKey(privateKeyB64);
        if (backup.mlkemPkB64) {
          const pk = new Uint8Array(b642buf(backup.mlkemPkB64));
          if (pk.length !== 1184) throw new Error('bad ML-KEM public key length');
        }
        if (mlkemSkB64) {
          const sk = new Uint8Array(b642buf(mlkemSkB64));
          if (sk.length !== 2400) throw new Error('bad ML-KEM secret key length');
        }
      } catch (_) {
        return { error: 'Backup contains invalid key material' };
      }

      if (mode === 'replace') {
        await deleteIdentity();
        await new Promise(r => chrome.storage.local.remove('cc_contacts_v2', r));
      }

      // Restore identity (including ML-KEM keys when present in the backup)
      const fp = await keyFingerprint(backup.publicKeyB64);
      await new Promise(r => chrome.storage.local.set({
        cc_identity_v2: {
          publicKeyB64:  backup.publicKeyB64,
          privateKeyB64: privateKeyB64,
          fingerprint:   fp,
          mlkemPkB64:    backup.mlkemPkB64 || null,
          mlkemSkB64:    mlkemSkB64 || null,
        },
      }, r));
      clearSharedKeyCache();

      const existingContacts = mode === 'replace' ? [] : await listContacts();
      let added = 0, skipped = 0;
      for (const c of (backup.contacts || [])) {
        const exists = existingContacts.find(
          e => e.handle === c.handle && e.platform === c.platform
        );
        if (exists && mode === 'merge') { skipped++; continue; }
        await saveContact(c);
        added++;
      }

      broadcastContactsUpdated();
      return { success: true, contactsAdded: added, contactsSkipped: skipped, fingerprint: fp };
    }

    default:
      return { error: `Unknown message type: ${msg.type}` };
  }
}

/* ── Preferences storage ───────────────────────────────────────────── */

async function getPrefs() {
  return new Promise(r => chrome.storage.local.get(PREFS_KEY, x => r(x[PREFS_KEY] || {})));
}
async function setPrefs(patch) {
  const current = await getPrefs();
  const next = { ...DEFAULT_PREFS, ...current, ...patch };
  await new Promise(r => chrome.storage.local.set({ [PREFS_KEY]: next }, r));
  return next;
}

/* ── Cross-tab broadcast ───────────────────────────────────────────── */

function broadcastContactsUpdated() {
  chrome.tabs.query({}, tabs => {
    for (const tab of tabs) {
      if (tab.id) {
        try {
          chrome.tabs.sendMessage(tab.id, { type: 'CONTACTS_UPDATED' }).catch(() => {});
        } catch (_) {}
      }
    }
  });
}
