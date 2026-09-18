#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * scripts/bundle-background.js
 *
 * Bundles the ES-module background sources (engine + keystore + handler)
 * into a single classic IIFE per browser directory:
 *
 *   chrome/src/background-bundle.js
 *   mozilla/src/background-bundle.js
 *
 * This is the single source of truth — do not edit background-bundle.js by
 * hand. Run `npm run bundle` after changing anything under src/crypto or
 * src/background.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import esbuild from 'esbuild';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const DIRS = ['chrome', 'mozilla'];

const BANNER = `// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * background-bundle.js — GENERATED FILE, DO NOT EDIT.
 *
 * Built by scripts/bundle-background.js from:
 *   src/crypto/engine.js
 *   src/crypto/keystore.js
 *   src/background/index.js + handler.js
 *
 * Regenerate with: npm run bundle
 */`;

let built = 0;
for (const dir of DIRS) {
  const entry = path.join(ROOT, dir, 'src', 'background', 'index.js');
  const out   = path.join(ROOT, dir, 'src', 'background-bundle.js');
  if (!fs.existsSync(entry)) {
    console.log(`  ·  skipping ${dir} (no ${path.relative(ROOT, entry)})`);
    continue;
  }
  await esbuild.build({
    entryPoints: [entry],
    outfile: out,
    bundle: true,
    format: 'iife',
    platform: 'browser',
    target: ['chrome100', 'firefox109'],
    banner: { js: BANNER },
    logLevel: 'warning',
  });
  const kb = (fs.statSync(out).size / 1024).toFixed(1);
  console.log(`  ✓  ${dir}/src/background-bundle.js  (${kb} KB)`);
  built++;
}
if (!built) {
  console.error('  ✗  no background sources found');
  process.exit(1);
}
