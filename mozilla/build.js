#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/** Firefox package build. Syncs runtime from chrome/ first, then packs. */
import { sync } from '../scripts/sync-firefox.js';
import { run } from '../scripts/pack-extension.js';

try {
  console.log('\nSyncing shared runtime from chrome/ …');
  sync({ quiet: true });
} catch (e) {
  console.warn('  ! sync skipped:', e.message);
}
run('firefox').catch(err => { console.error(err); process.exit(1); });
