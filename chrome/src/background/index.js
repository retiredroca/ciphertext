// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * CryptoChat — Background entry point
 *
 * Side-effect import of the message handler. Bundled by `npm run bundle`
 * into src/background-bundle.js (classic IIFE, importScripts-safe).
 *
 * The optional ML-KEM-768 bundle (src/vendor/mlkem768.js) is loaded by
 * background-loader.js before this bundle and sets globalThis.MLKEM768.
 */

import * as Engine from '../crypto/engine.js';
import * as Keystore from '../crypto/keystore.js';
import './handler.js';

// Exposed for debugging from the service-worker console.
globalThis.CCEngine   = Engine;
globalThis.CCKeystore = Keystore;
