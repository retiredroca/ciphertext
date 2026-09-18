// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * scripts/run-firefox.js
 *
 * Launch LibreWolf with the Firefox build loaded, via Mozilla's web-ext.
 * Hot-reloads on file changes. Resolves the browser from LIBREWOLF_PATH or
 * common install locations (scripts/lib/librewolf.js), so nothing is hardcoded.
 *
 * Usage:
 *   npm run run:librewolf
 */

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import webExt from 'web-ext';
import { resolveLibreWolf } from './lib/librewolf.js';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const sourceDir = path.join(ROOT, 'mozilla');

const firefox = resolveLibreWolf();
if (!firefox) {
  console.error('LibreWolf not found. Set LIBREWOLF_PATH to librewolf(.exe) and retry.');
  process.exit(1);
}

console.log(`\nLaunching LibreWolf: ${firefox}`);
console.log(`Source: ${sourceDir}\n`);

try {
  await webExt.cmd.run(
    {
      sourceDir,
      firefox,
      noInput: true,
      // Keep the profile ephemeral; the extension is loaded temporarily.
    },
    { shouldExitProgram: true }
  );
} catch (err) {
  console.error(err.message || err);
  process.exit(1);
}
