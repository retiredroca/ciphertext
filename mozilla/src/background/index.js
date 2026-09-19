/**
 * CryptoChat — Background entry point
 *
 * Bundled by `npm run bundle` into src/background-bundle.js (classic IIFE).
 *
 * Import order matters: pqc-env.js sets globalThis.MLKEM768 before handler.js
 * runs its startup logic. ML-KEM-768 (NIST FIPS 203) is bundled in so the
 * background is fully self-contained — this avoids `importScripts()`, which is
 * unavailable in Firefox MV3 background event pages.
 */

import './pqc-env.js';
import * as Engine from '../crypto/engine.js';
import * as Keystore from '../crypto/keystore.js';
import './handler.js';

// Exposed for debugging from the background console.
globalThis.CCEngine   = Engine;
globalThis.CCKeystore = Keystore;
