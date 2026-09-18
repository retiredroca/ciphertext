#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * scripts/sync-firefox.js
 *
 * The chrome/ and mozilla/ directories are separate, independently loadable
 * extension packages whose runtime code is identical — only manifest.json
 * differs. This copies the shared runtime files from chrome/ to mozilla/ so
 * the two can never drift.
 *
 * Not synced (mozilla keeps its own): manifest.json, build.js, README.md.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const SRC  = path.join(ROOT, 'chrome');
const DST  = path.join(ROOT, 'mozilla');
const SHARED = ['src', 'icons', 'docs'];

export function sync({ quiet = false } = {}) {
  let count = 0;
  for (const rel of SHARED) {
    const from = path.join(SRC, rel);
    const to   = path.join(DST, rel);
    if (!fs.existsSync(from)) continue;
    fs.rmSync(to, { recursive: true, force: true });
    fs.cpSync(from, to, { recursive: true });
    if (!quiet) console.log(`  ✓  synced ${rel}/ → mozilla/`);
    count++;
  }
  if (!count) throw new Error('nothing to sync (is chrome/ present?)');
  if (!quiet) console.log('  ✓  mozilla/ runtime synced from chrome/');
  return count;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try { sync(); } catch (e) { console.error('  ✗ ', e.message); process.exit(1); }
}
