#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * scripts/pack-extension.js
 *
 * Shared build logic for both browser packages.
 *
 *   run('chrome')  → verifies the Chrome manifest, bundles, packs
 *                    chrome/dist/ciphertext-chrome.zip
 *   run('firefox') → verifies the Firefox manifest, bundles, packs
 *                    mozilla/dist/ciphertext-firefox.xpi
 *
 * Cross-platform: uses the `archiver` package instead of the `zip` CLI.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import archiver from 'archiver';
import esbuild from 'esbuild';
import { BANNER } from './lib/banner.js';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');

const G = s => `\x1b[32m${s}\x1b[0m`;
const R = s => `\x1b[31m${s}\x1b[0m`;
const B = s => `\x1b[34m${s}\x1b[0m`;

const REQUIRED = [
  'manifest.json',
  'src/background-bundle.js',
  'src/content.js',
  'src/ui/popup.html',
  'src/ui/popup.css',
  'src/ui/popup.js',
  'icons/icon16.png',
  'icons/icon48.png',
  'icons/icon128.png',
];

const REFERENCE = [
  'src/crypto/engine.js',
  'src/crypto/keystore.js',
  'src/background/index.js',
  'src/background/handler.js',
];

function dirFor(browser) { return path.join(ROOT, browser === 'chrome' ? 'chrome' : 'mozilla'); }

export async function bundle(dir) {
  const entry = path.join(dir, 'src', 'background', 'index.js');
  const out   = path.join(dir, 'src', 'background-bundle.js');
  if (!fs.existsSync(entry)) return;
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
}

export function verify(dir, browser) {
  console.log(B(`\nciphertext — ${browser} package verification\n`));
  let ok = true;
  for (const f of REQUIRED) {
    const full = path.join(dir, f);
    if (fs.existsSync(full)) {
      const kb = (fs.statSync(full).size / 1024).toFixed(1);
      console.log(G('  ✓') + `  ${f.padEnd(40)} ${kb} KB`);
    } else {
      console.log(R('  ✗  MISSING: ') + f);
      ok = false;
    }
  }
  console.log('');
  for (const f of REFERENCE) {
    if (fs.existsSync(path.join(dir, f))) console.log(G('  ✓') + `  ${f.padEnd(40)} (source)`);
  }

  const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  if (browser === 'chrome') {
    if (manifest.background?.scripts) {
      console.log(R('\n  ✗  manifest.json has "scripts" — Chrome will reject this!')); ok = false;
    } else if (!manifest.background?.service_worker) {
      console.log(R('\n  ✗  manifest.json missing "service_worker"')); ok = false;
    } else {
      console.log(G('  ✓') + '  manifest.json: service_worker present (Chrome-safe)');
    }
  } else {
    if (manifest.background?.service_worker) {
      console.log(R('\n  ✗  manifest.json has "service_worker" — Firefox will reject this!')); ok = false;
    } else if (!manifest.background?.scripts) {
      console.log(R('\n  ✗  manifest.json missing "scripts"')); ok = false;
    } else {
      console.log(G('  ✓') + '  manifest.json: scripts[] present (Firefox-safe)');
    }
  }

  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  if (manifest.version !== pkg.version) {
    console.log(R(`\n  ✗  version mismatch: manifest ${manifest.version} vs package ${pkg.version}`)); ok = false;
  } else {
    console.log(G('  ✓') + `  version ${manifest.version} matches package.json`);
  }

  console.log('');
  return ok;
}

function pack(dir, outFile) {
  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  return new Promise((resolve, reject) => {
    const output = fs.createWriteStream(outFile);
    const archive = archiver('zip', { zlib: { level: 9 } });
    output.on('close', resolve);
    archive.on('error', reject);
    archive.pipe(output);
    archive.glob('**/*', {
      cwd: dir,
      dot: false,
      ignore: ['dist/**', 'node_modules/**', 'build.js', 'manifest.chrome.json', '**/*.zip', '**/*.xpi'],
    });
    archive.finalize();
  });
}

export async function run(browser) {
  if (browser !== 'chrome' && browser !== 'firefox') {
    throw new Error('browser must be "chrome" or "firefox"');
  }
  const dir = dirFor(browser);
  const name = browser === 'chrome' ? 'ciphertext-chrome.zip' : 'ciphertext-firefox.xpi';

  console.log(B('\nBundling background…'));
  await bundle(dir);
  console.log(G('  ✓  src/background-bundle.js'));

  const ok = verify(dir, browser);
  if (!ok) { console.log(R('Fix the errors above before packing.\n')); process.exit(1); }

  const out = path.join(dir, 'dist', name);
  await pack(dir, out);
  const kb = (fs.statSync(out).size / 1024).toFixed(1);
  console.log(G(`✓ Built ${path.relative(ROOT, out)}  (${kb} KB)\n`));
  console.log(B('Install Chrome: ') + 'chrome://extensions → Developer mode → Load unpacked → select chrome/');
  console.log(B('Install Firefox: ') + 'about:debugging → This Firefox → Load Temporary Add-on → select mozilla/manifest.json');
  if (browser === 'firefox') {
    console.log(B('Signed .xpi:     ') + 'Drag the .xpi onto Firefox, or submit it to addons.mozilla.org\n');
  }
}

const isMain = process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;
if (isMain) {
  run(process.argv[2]).catch(err => { console.error(err); process.exit(1); });
}
