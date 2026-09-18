// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Selenium end-to-end smoke test for the Firefox/LibreWolf build.
 *
 *   npm run build:firefox   # produce mozilla/dist/cryptochat-firefox.xpi
 *   npm run test:e2e        # launches LibreWolf, installs a test build
 *
 * Drives the content-script path: installs a copy of the extension whose
 * manifest also matches a local fixture page, then asserts the input overlay
 * appears, the Shadow DOM panel opens, and the background responds to
 * LIST_CONTACTS (the panel shows an empty contact list).
 *
 * Env:
 *   LIBREWOLF_PATH, GECKODRIVER_PATH  override binaries
 *   CC_E2E_HEADLESS=1                 run headless
 */

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import * as H from './lib/harness.js';

let driver, server, baseUrl;

before(async () => {
  H.prepareTestAddon();
  ({ server, baseUrl } = await H.startServer());
  driver = await H.launchWithAddon({ headless: process.env.CC_E2E_HEADLESS === '1' });
});

after(async () => {
  if (driver) { try { await driver.quit(); } catch (_) {} }
  if (server) server.close();
  fs.rmSync(H.TMP, { recursive: true, force: true });
});

test('lock overlay is injected onto a detected input box', async () => {
  await driver.get(baseUrl);
  const btn = await H.waitForOverlay(driver);
  assert.ok(await btn.isDisplayed(), 'overlay button is visible');
});

test('compose panel opens in a shadow root and background responds', async () => {
  await driver.findElement({ css: 'button[data-cc-host="input"]' }).click();

  const panelReady = await driver.wait(async () => {
    return driver.executeScript(`
      const host = document.querySelector('[data-cc-host="panel"]');
      if (!host || !host.shadowRoot) return false;
      const ta = host.shadowRoot.getElementById('cc-ta');
      const sel = host.shadowRoot.getElementById('cc-recip');
      return !!(ta && sel && /contacts|recipient/i.test(sel.textContent));
    `);
  }, 15000, 'shadow panel should open with a contact list from the background');

  assert.equal(panelReady, true);
});

test('send stays disabled until there is a recipient and text', async () => {
  const disabled = await driver.executeScript(`
    const host = document.querySelector('[data-cc-host="panel"]');
    const sr = host.shadowRoot;
    const ta = sr.getElementById('cc-ta');
    ta.value = 'hello';
    ta.dispatchEvent(new Event('input', { bubbles: true }));
    return sr.getElementById('cc-send').disabled;
  `);
  // No contacts exist, so no recipient can be selected → button remains disabled.
  assert.equal(disabled, true);
});
