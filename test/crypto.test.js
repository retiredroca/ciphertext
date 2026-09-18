// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Crypto engine round-trip tests.
 *
 *   npm test
 *
 * Uses Node's built-in WebCrypto (globalThis.crypto) and the real `mlkem`
 * package, so these exercise the exact code that ships in the background
 * bundle.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { MlKem768 } from 'mlkem';

globalThis.MLKEM768 = { MlKem768 };

const E = await import('../chrome/src/crypto/engine.js');

async function makeEcdhIdentity() {
  const kp  = await E.generateIdentityKeypair();
  const pub = await E.exportPublicKey(kp.publicKey);
  return { kp, pub };
}

async function sharedKey(myKp, theirPubB64) {
  return E.deriveSharedKey(myKp.privateKey, await E.importPublicKey(theirPubB64));
}

/* ── V1 1:1 ─────────────────────────────────────────────────────────── */

test('V1 1:1 round trip', async () => {
  const alice = await makeEcdhIdentity();
  const bob   = await makeEcdhIdentity();

  const wire = await E.encryptMessage('hello bob', await sharedKey(alice.kp, bob.pub), alice.pub);
  assert.ok(E.isV1Message(wire));

  const out = await E.decryptMessage(wire, await sharedKey(bob.kp, alice.pub));
  assert.equal(out.plaintext, 'hello bob');
  assert.equal(out.senderPubKeyB64, alice.pub);
});

test('V1 tampering is rejected', async () => {
  const alice = await makeEcdhIdentity();
  const bob   = await makeEcdhIdentity();
  const wire  = await E.encryptMessage('secret', await sharedKey(alice.kp, bob.pub), alice.pub);

  const parts = wire.split(':');
  parts[2] = parts[2].slice(0, -2) + (parts[2].endsWith('AA') ? 'BB' : 'AA');
  await assert.rejects(() => E.decryptMessage(parts.join(':'), sharedKey(bob.kp, alice.pub)));
});

/* ── V1 group ───────────────────────────────────────────────────────── */

test('V1 group round trip to every recipient', async () => {
  const sender = await makeEcdhIdentity();
  const r1 = await makeEcdhIdentity();
  const r2 = await makeEcdhIdentity();

  const wire = await E.encryptGroupMessage('group hi', sender.pub, sender.kp.privateKey, [
    { handle: '@a', publicKeyB64: r1.pub, curve: 'P-256' },
    { handle: '@b', publicKeyB64: r2.pub, curve: 'P-256' },
  ]);
  assert.ok(E.isGroupMessage(wire));

  for (const [id, r] of [['@a', r1], ['@b', r2]]) {
    const out = await E.decryptGroupMessage(wire, r.pub, r.kp.privateKey, sender.pub);
    assert.equal(out.plaintext, 'group hi');
    assert.equal(out.slotCount, 2);
    assert.deepEqual(out.recipientHandles.sort(), ['@a', '@b']);
    assert.ok(id);
  }
});

/* ── V2 hybrid 1:1 ──────────────────────────────────────────────────── */

test('V2 hybrid 1:1 round trip', async () => {
  const sender    = await makeEcdhIdentity();
  const recipient = await makeEcdhIdentity();
  const mk        = await E.mlkemGenerateKeypair();
  assert.equal(mk.mlkemPk.length, 1184);
  assert.equal(mk.mlkemSk.length, 2400);

  const wire = await E.encryptMessageV2(
    'quantum hello', sender.pub, sender.kp.privateKey, recipient.pub, mk.mlkemPk
  );
  assert.ok(E.isV2Message(wire));

  const out = await E.decryptMessageV2(
    wire, recipient.kp.privateKey, sender.pub, mk.mlkemSk, recipient.pub
  );
  assert.equal(out.plaintext, 'quantum hello');
  assert.equal(out.senderEcdhPubB64, sender.pub);
});

test('V2 rejects a mismatched recipient key (KDF binding)', async () => {
  const sender    = await makeEcdhIdentity();
  const recipient = await makeEcdhIdentity();
  const other     = await makeEcdhIdentity();
  const mk        = await E.mlkemGenerateKeypair();

  const wire = await E.encryptMessageV2('hi', sender.pub, sender.kp.privateKey, recipient.pub, mk.mlkemPk);
  // Same private key + ML-KEM secret, but a different second public key in the
  // KDF context must not reproduce the key.
  await assert.rejects(() =>
    E.decryptMessageV2(wire, recipient.kp.privateKey, sender.pub, mk.mlkemSk, other.pub)
  );
});

/* ── V2 group ───────────────────────────────────────────────────────── */

test('V2 group round trip to every recipient', async () => {
  const sender = await makeEcdhIdentity();
  const r1 = await makeEcdhIdentity();
  const r2 = await makeEcdhIdentity();
  const k1 = await E.mlkemGenerateKeypair();
  const k2 = await E.mlkemGenerateKeypair();

  const wire = await E.encryptGroupMessageV2('grp pqc', sender.pub, sender.kp.privateKey, [
    { handle: '@a', ecdhPubB64: r1.pub, mlkemPkB64: E.buf2b64(k1.mlkemPk.buffer) },
    { handle: '@b', ecdhPubB64: r2.pub, mlkemPkB64: E.buf2b64(k2.mlkemPk.buffer) },
  ]);
  assert.ok(E.isV2GroupMessage(wire));

  for (const [r, k] of [[r1, k1], [r2, k2]]) {
    const out = await E.decryptGroupMessageV2WithSender(
      wire, r.pub, r.kp.privateKey, E.buf2b64(k.mlkemSk.buffer), sender.pub
    );
    assert.equal(out.plaintext, 'grp pqc');
    assert.equal(out.slotCount, 2);
  }
});

test('V2 group: wrong sender key cannot decrypt', async () => {
  const sender = await makeEcdhIdentity();
  const impostor = await makeEcdhIdentity();
  const r1 = await makeEcdhIdentity();
  const k1 = await E.mlkemGenerateKeypair();

  const wire = await E.encryptGroupMessageV2('grp', sender.pub, sender.kp.privateKey, [
    { handle: '@a', ecdhPubB64: r1.pub, mlkemPkB64: E.buf2b64(k1.mlkemPk.buffer) },
  ]);

  await assert.rejects(() =>
    E.decryptGroupMessageV2WithSender(wire, r1.pub, r1.kp.privateKey, E.buf2b64(k1.mlkemSk.buffer), impostor.pub)
  );
});

/* ── OpenPGP fingerprint shape ──────────────────────────────────────── */

test('OpenPGP fingerprints have the correct length per version', async () => {
  const v4 = await E.openpgpFingerprint(new Uint8Array([4, 0, 0, 0, 0, 1, 2, 3, 4]));
  assert.match(v4, /^[0-9a-f]{40}$/);

  const v5 = await E.openpgpFingerprint(new Uint8Array([5, 0, 0, 0, 0, 1, 2, 3, 4]));
  assert.match(v5, /^[0-9a-f]{64}$/);
});
