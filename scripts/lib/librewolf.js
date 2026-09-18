// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * scripts/lib/librewolf.js
 *
 * Locate the LibreWolf binary for web-ext and Selenium. Resolution order:
 *   1. LIBREWOLF_PATH environment variable
 *   2. common install locations per platform
 *
 * Also exposes resolveGeckodriver() (GECKODRIVER_PATH or PATH lookup).
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const WIN_CANDIDATES = [
  'C:/Program Files/LibreWolf/librewolf.exe',
  'C:/Program Files (x86)/LibreWolf/librewolf.exe',
  process.env['ProgramFiles'] && path.join(process.env['ProgramFiles'], 'LibreWolf', 'librewolf.exe'),
  process.env['ProgramFiles(x86)'] && path.join(process.env['ProgramFiles(x86)'], 'LibreWolf', 'librewolf.exe'),
  process.env.LOCALAPPDATA && path.join(process.env.LOCALAPPDATA, 'Programs', 'LibreWolf', 'librewolf.exe'),
];

const LINUX_CANDIDATES = [
  '/usr/bin/librewolf',
  '/usr/local/bin/librewolf',
  '/snap/bin/librewolf',
  '/var/lib/flatpak/exports/bin/io.gitlab.librewolf-community',
];

const MAC_CANDIDATES = [
  '/Applications/LibreWolf.app/Contents/MacOS/librewolf',
  path.join(os.homedir(), 'Applications/LibreWolf.app/Contents/MacOS/librewolf'),
];

function firstExisting(list) {
  for (const p of list) {
    if (!p) continue;
    try { if (fs.existsSync(p)) return p; } catch (_) {}
  }
  return null;
}

export function resolveLibreWolf() {
  if (process.env.LIBREWOLF_PATH && fs.existsSync(process.env.LIBREWOLF_PATH)) {
    return process.env.LIBREWOLF_PATH;
  }
  if (process.platform === 'win32') return firstExisting(WIN_CANDIDATES);
  if (process.platform === 'darwin') return firstExisting(MAC_CANDIDATES);
  return firstExisting(LINUX_CANDIDATES);
}

export function resolveGeckodriver() {
  if (process.env.GECKODRIVER_PATH && fs.existsSync(process.env.GECKODRIVER_PATH)) {
    return process.env.GECKODRIVER_PATH;
  }
  return null; // selenium-webdriver finds "geckodriver" on PATH
}
