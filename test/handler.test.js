// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Background handler tests — exercise the real message handler against an
 * in-memory chrome.* mock. Covers identity/ML-KEM generation, contact CRUD,
 * group self-decrypt, and the encrypted backup round trip (the previous
 * implementation silently dropped ML-KEM keys on import).
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { MlKem768 } from 'mlkem';

globalThis.MLKEM768 = { MlKem768 };

/* ── Minimal chrome.* mock ──────────────────────────────────────────── */

function installChromeMock() {
  const store = new Map();
  const listeners = [];

  const local = {
    get(key, cb) {
      const out = {};
      const keys = Array.isArray(key) ? key : [key];
      for (const k of keys) if (store.has(k)) out[k] = structuredClone(store.get(k));
      if (cb) { cb(out); return; }
      return Promise.resolve(out);
    },
    set(obj, cb) {
      for (const [k, v] of Object.entries(obj)) store.set(k, structuredClone(v));
      if (cb) { cb(); return; }
      return Promise.resolve();
    },
    remove(key, cb) {
      for (const k of (Array.isArray(key) ? key : [key])) store.delete(k);
      if (cb) { cb(); return; }
      return Promise.resolve();
    },
  };

  globalThis.chrome = {
    storage: { local },
    runtime: {
      lastError: null,
      onMessage: { addListener(fn) { listeners.push(fn); } },
    },
    tabs: {
      query(_q, cb) { cb([]); },
      sendMessage() { return Promise.resolve(); },
    },
  };

  return {
    store,
    call(msg) {
      const listener = listeners[0];
      assert.ok(listener, 'handler registered a listener');
      return new Promise((resolve) => listener(msg, {}, resolve));
    },
  };
}

const mock = installChromeMock();
const E = await import('../chrome/src/crypto/engine.js');
await import('../chrome/src/background/handler.js');

/* ── Tests ──────────────────────────────────────────────────────────── */

test('identity is created with ML-KEM keys when PQC is available', async () => {
  const id = await mock.call({ type: 'GET_PUBLIC_KEY' });
  assert.ok(id.publicKeyB64, 'ECDH public key');
  assert.ok(id.mlkemPkB64, 'ML-KEM public key present');
  assert.equal(id.pqcEnabled, true);
});

test('contact CRUD', async () => {
  const kp  = await E.generateIdentityKeypair();
  const pub = await E.exportPublicKey(kp.publicKey);

  const save = await mock.call({
    type: 'SAVE_CONTACT', handle: '@alice', platform: 'discord',
    displayName: 'Alice', publicKeyB64: pub,
  });
  assert.equal(save.success, true);
  assert.ok(save.contact.fingerprint);

  const list = await mock.call({ type: 'LIST_CONTACTS' });
  assert.equal(list.contacts.length, 1);
  assert.equal(list.contacts[0].handle, '@alice');

  await mock.call({ type: 'DELETE_CONTACT', handle: '@alice', platform: 'discord' });
  const after = await mock.call({ type: 'LIST_CONTACTS' });
  assert.equal(after.contacts.length, 0);
});

test('SAVE_CONTACT rejects an invalid public key', async () => {
  const r = await mock.call({
    type: 'SAVE_CONTACT', handle: '@bad', platform: 'discord', publicKeyB64: 'not-base64!!',
  });
  assert.match(r.error, /Invalid public key/);
});

test('ENC_(DE)CRYPT group round trip decrypts as (you)', async () => {
  const enc = await mock.call({
    type: 'ENCRYPT_GROUP',
    plaintext: 'self read test',
    recipients: [{ handle: '@ghost', platform: 'discord' }],
  });
  assert.ok(enc.ciphertext, 'group ciphertext produced');

  const dec = await mock.call({ type: 'DECRYPT_MESSAGE', wireText: enc.ciphertext });
  assert.equal(dec.plaintext, 'self read test');
  assert.equal(dec.senderHandle, '(you)');
});

test('backup export → reset → import preserves the identity AND ML-KEM keys', async () => {
  const before = await mock.call({ type: 'GET_PUBLIC_KEY' });
  assert.ok(before.mlkemPkB64);

  const exp = await mock.call({ type: 'EXPORT_BACKUP', passphrase: 'correct horse battery' });
  assert.equal(exp.success, true);
  const backup = JSON.parse(exp.backup);
  assert.equal(backup.version, 3);
  assert.equal(backup.mlkemPkB64, before.mlkemPkB64);

  // Wipe the identity, generating a different one.
  await mock.call({ type: 'RESET_IDENTITY' });
  const mid = await mock.call({ type: 'GET_PUBLIC_KEY' });
  assert.notEqual(mid.publicKeyB64, before.publicKeyB64);

  // Restore in replace mode.
  const imp = await mock.call({
    type: 'IMPORT_BACKUP', backupJson: exp.backup, passphrase: 'correct horse battery', mode: 'replace',
  });
  assert.equal(imp.success, true);

  const after = await mock.call({ type: 'GET_PUBLIC_KEY' });
  assert.equal(after.publicKeyB64, before.publicKeyB64, 'ECDH key restored');
  assert.equal(after.mlkemPkB64, before.mlkemPkB64, 'ML-KEM public key restored (regression)');
  assert.equal(after.pqcEnabled, true);
});

test('backup import with the wrong passphrase is refused', async () => {
  const exp = await mock.call({ type: 'EXPORT_BACKUP', passphrase: 'right passphrase' });
  const imp = await mock.call({
    type: 'IMPORT_BACKUP', backupJson: exp.backup, passphrase: 'wrong passphrase', mode: 'merge',
  });
  assert.match(imp.error, /Wrong passphrase/);
});
