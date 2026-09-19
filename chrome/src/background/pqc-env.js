/**
 * Loads ML-KEM-768 (NIST FIPS 203) and exposes it as globalThis.MLKEM768.
 *
 * Imported first by src/background/index.js so the crypto engine sees it.
 * Bundled in — no separate vendor script and no importScripts().
 */

import { MlKem768 } from 'mlkem';

if (!globalThis.MLKEM768) globalThis.MLKEM768 = { MlKem768 };
