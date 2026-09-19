// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * ciphertext — Key Store
 *
 * Persists the user's identity keypair and all contacts in chrome.storage.local.
 * Keys are stored as base64-encoded SPKI (public) and PKCS8 (private) strings.
 *
 * Storage keys:
 *   cc_identity_v2  — { publicKeyB64, privateKeyB64, fingerprint,
 *                       mlkemPkB64, mlkemSkB64 }
 *   cc_contacts_v2  — Array<ContactRecord>
 *
 * ContactRecord shape:
 *   handle        string   — e.g. "@alice" or "alice#1234"
 *   platform      string   — 'discord' | 'slack' | 'instagram' | 'twitter' | etc.
 *   displayName   string
 *   publicKeyB64  string|null  — SPKI base64; null for RSA GPG contacts
 *   mlkemPkB64    string|null  — ML-KEM-768 public key (V2 hybrid)
 *   publicArmor   string|null  — raw PGP armor, present for GPG contacts
 *   source        'native'|'gpg'
 *   curve         string|null  — e.g. 'P-256'
 *   fingerprint   string|null  — hex fingerprint (SPKI SHA-256 or OpenPGP)
 *   uid           string|null  — GPG UID ("Alice <alice@example.com>")
 *   verified      boolean      — manually verified out-of-band
 *   addedAt       number       — Date.now()
 */

import {
  generateIdentityKeypair,
  exportPublicKey,
  exportPrivateKey,
  importPublicKey,
  importPrivateKey,
  deriveSharedKey,
  keyFingerprint,
  isPqcAvailable,
  mlkemGenerateKeypair,
  buf2b64,
} from './engine.js';

const K_IDENTITY = 'cc_identity_v2';
const K_CONTACTS = 'cc_contacts_v2';

/* ── Storage helpers ───────────────────────────────────────────────── */

function sGet(key) {
  return new Promise(resolve => chrome.storage.local.get(key, r => resolve(r[key] ?? null)));
}
function sSet(key, val) {
  return new Promise(resolve => chrome.storage.local.set({ [key]: val }, resolve));
}
function sDel(key) {
  return new Promise(resolve => chrome.storage.local.remove(key, resolve));
}

/* ── Identity keypair ──────────────────────────────────────────────── */

/**
 * Load the identity keypair from storage, generating one on first run.
 * Returns { publicKey, privateKey, publicKeyB64, fingerprint,
 *           mlkemPkB64, mlkemSkB64, pqcEnabled }.
 */
export async function getOrCreateIdentity() {
  const stored = await sGet(K_IDENTITY);
  if (stored) {
    return {
      publicKey:    await importPublicKey(stored.publicKeyB64),
      privateKey:   await importPrivateKey(stored.privateKeyB64),
      publicKeyB64: stored.publicKeyB64,
      fingerprint:  stored.fingerprint,
      mlkemPkB64:   stored.mlkemPkB64 || null,
      mlkemSkB64:   stored.mlkemSkB64 || null,
      pqcEnabled:   !!(stored.mlkemPkB64 && stored.mlkemSkB64),
    };
  }

  const kp           = await generateIdentityKeypair();
  const publicKeyB64 = await exportPublicKey(kp.publicKey);
  const privateKeyB64= await exportPrivateKey(kp.privateKey);
  const fingerprint  = await keyFingerprint(publicKeyB64);

  let mlkemPkB64 = null, mlkemSkB64 = null;
  if (isPqcAvailable()) {
    try {
      const mk = await mlkemGenerateKeypair();
      mlkemPkB64 = buf2b64(mk.mlkemPk.buffer);
      mlkemSkB64 = buf2b64(mk.mlkemSk.buffer);
    } catch (e) {
      console.warn('[ciphertext] ML-KEM keygen failed:', e.message);
    }
  }

  await sSet(K_IDENTITY, { publicKeyB64, privateKeyB64, fingerprint, mlkemPkB64, mlkemSkB64 });
  return {
    publicKey: kp.publicKey, privateKey: kp.privateKey,
    publicKeyB64, fingerprint, mlkemPkB64, mlkemSkB64,
    pqcEnabled: !!(mlkemPkB64 && mlkemSkB64),
  };
}

export async function getPublicKeyB64() {
  const stored = await sGet(K_IDENTITY);
  return stored?.publicKeyB64 ?? null;
}

export async function deleteIdentity() {
  await sDel(K_IDENTITY);
}

/**
 * Upgrade an existing ECDH-only identity to add ML-KEM keys.
 * Called automatically when the PQC bundle first loads.
 */
export async function upgradeIdentityToPqc() {
  if (!isPqcAvailable()) return { upgraded: false, reason: 'PQC bundle not loaded' };
  const s = await sGet(K_IDENTITY);
  if (!s) return { upgraded: false, reason: 'No identity yet' };
  if (s.mlkemPkB64 && s.mlkemSkB64) return { upgraded: false, reason: 'Already has ML-KEM keys' };

  const mk = await mlkemGenerateKeypair();
  s.mlkemPkB64 = buf2b64(mk.mlkemPk.buffer);
  s.mlkemSkB64 = buf2b64(mk.mlkemSk.buffer);
  await sSet(K_IDENTITY, s);
  return { upgraded: true, mlkemPkB64: s.mlkemPkB64 };
}

/* ── Contacts ──────────────────────────────────────────────────────── */

export async function listContacts() {
  return (await sGet(K_CONTACTS)) || [];
}

export async function saveContact(record) {
  const contacts = await listContacts();
  const idx = contacts.findIndex(
    c => c.handle === record.handle && c.platform === record.platform
  );
  const full = {
    handle:      record.handle,
    platform:    record.platform,
    displayName: record.displayName || record.handle,
    publicKeyB64:record.publicKeyB64  ?? null,
    mlkemPkB64:  record.mlkemPkB64    ?? null,
    publicArmor: record.publicArmor   ?? null,
    source:      record.source        ?? 'native',
    curve:       record.curve         ?? null,
    fingerprint: record.fingerprint   ?? null,
    uid:         record.uid           ?? null,
    verified:    record.verified      ?? false,
    addedAt:     Date.now(),
  };
  if (idx >= 0) contacts[idx] = { ...contacts[idx], ...full };
  else contacts.push(full);
  await sSet(K_CONTACTS, contacts);
  clearSharedKeyCache();
  return full;
}

export async function deleteContact(handle, platform) {
  await sSet(K_CONTACTS,
    (await listContacts()).filter(c => !(c.handle === handle && c.platform === platform))
  );
  clearSharedKeyCache();
}

export async function verifyContact(handle, platform) {
  const contacts = await listContacts();
  const idx = contacts.findIndex(c => c.handle === handle && c.platform === platform);
  if (idx >= 0) { contacts[idx].verified = true; await sSet(K_CONTACTS, contacts); }
}

export async function getContact(handle, platform) {
  return (await listContacts()).find(
    c => c.handle === handle && c.platform === platform
  ) ?? null;
}

/* ── Shared key derivation (session cache) ─────────────────────────── */

const _cache = new Map();

export function clearSharedKeyCache() { _cache.clear(); }

export async function getSharedKeyForContact(handle, platform) {
  const ck = `${platform}:${handle}`;
  if (_cache.has(ck)) return _cache.get(ck);
  const id      = await getOrCreateIdentity();
  const contact = await getContact(handle, platform);
  if (!contact?.publicKeyB64) throw new Error(`No key for ${handle} (${platform})`);
  const pub = await importPublicKey(contact.publicKeyB64, contact.curve);
  const sk  = await deriveSharedKey(id.privateKey, pub);
  _cache.set(ck, sk);
  return sk;
}

/* ── Group recipient resolution ────────────────────────────────────── */

/**
 * Given an array of { handle, platform }, return those that have usable keys.
 */
export async function resolveGroupRecipients(handles) {
  const out = [];
  for (const { handle, platform } of handles) {
    const c = await getContact(handle, platform);
    if (c?.publicKeyB64) {
      out.push({
        handle, platform,
        publicKeyB64: c.publicKeyB64,
        mlkemPkB64:   c.mlkemPkB64 || null,
        curve:        c.curve,
      });
    }
  }
  return out;
}
