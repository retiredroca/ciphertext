#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * scripts/build-pqc.js
 *
 * Bundles the `mlkem` npm package (NIST FIPS 203 ML-KEM-768) into a single
 * self-contained classic script safe for importScripts() in MV3 service
 * workers. The output replaces the stub and enables V2 hybrid encryption.
 *
 * Usage:
 *   npm install
 *   npm run build:pqc
 *
 * Output:
 *   chrome/src/vendor/mlkem768.js
 *   mozilla/src/vendor/mlkem768.js
 *
 * background-loader.js tries mlkem768.js first and falls back to the stub.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import esbuild from 'esbuild';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIRS = ['chrome', 'mozilla'];

const HEADER = `// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * mlkem768.js — ML-KEM-768 (NIST FIPS 203)
 * Bundled from: https://www.npmjs.com/package/mlkem  (MIT)
 * Build: npm run build:pqc
 * DO NOT EDIT — regenerate with scripts/build-pqc.js
 */
`;

console.log('\nCryptoChat PQC builder\n');
const entry = path.join(ROOT, '_pqc_entry_tmp.js');
fs.writeFileSync(entry, `import { MlKem768 } from 'mlkem';\nglobalThis.MLKEM768 = { MlKem768 };\n`);

try {
  for (const dir of DIRS) {
    const out = path.join(ROOT, dir, 'src', 'vendor', 'mlkem768.js');
    await esbuild.build({
      entryPoints: [entry],
      outfile: out,
      bundle: true,
      format: 'iife',
      platform: 'browser',
      target: ['chrome100', 'firefox109'],
      minify: true,
      banner: { js: HEADER },
      logLevel: 'warning',
    });
    const kb = (fs.statSync(out).size / 1024).toFixed(1);
    console.log(`  ✓  ${dir}/src/vendor/mlkem768.js  (${kb} KB)`);
  }
  console.log('\n✓ Post-quantum encryption enabled (ML-KEM-768).');
  console.log('  Reload the extension, then: npm run build\n');
} catch (err) {
  console.error('\nBuild failed:', err.message);
  process.exitCode = 1;
} finally {
  fs.existsSync(entry) && fs.unlinkSync(entry);
}
