// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Selenium screenshot runner — drives the LibreWolf build and captures the
 * input overlay + compose panel to PNG files.
 *
 *   npm run build:firefox
 *   npm run test:screenshots
 *
 * Output: assets/screenshots/*.png  (override with CC_SHOT_DIR)
 * Images are capped at 1280x800.
 * Env:    CC_E2E_HEADED=1 to watch the browser, LIBREWOLF_PATH/GECKODRIVER_PATH
 */

import fs from 'node:fs';
import path from 'node:path';
import * as H from './lib/harness.js';

const OUT = process.env.CC_SHOT_DIR || path.join(H.ROOT, 'assets', 'screenshots');
const MAX_W = 1280, MAX_H = 800;

async function shot(driver, name) {
  const b64 = await driver.takeScreenshot();
  const file = path.join(OUT, `${name}.png`);
  fs.writeFileSync(file, Buffer.from(b64, 'base64'));
  console.log(`  ✓ ${path.relative(H.ROOT, file)}`);
}

async function panelReady(driver) {
  return driver.wait(() => driver.executeScript(`
    const h = document.querySelector('[data-cc-host="panel"]');
    return !!(h && h.shadowRoot && h.shadowRoot.getElementById('cc-ta'));
  `), 15000, 'compose panel should open');
}

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  H.prepareTestAddon();
  const { server, baseUrl } = await H.startServer();
  const driver = await H.launchWithAddon({ headless: process.env.CC_E2E_HEADED !== '1' });

  try {
    // Cap the capture so screenshots stay within 1280x800 for the README/Pages.
    await driver.manage().window().setRect({ width: MAX_W, height: MAX_H });
    await driver.get(baseUrl);

    const btn = await H.waitForOverlay(driver);
    await driver.sleep(400);
    await shot(driver, '01-overlay-lock');

    await btn.click();
    await panelReady(driver);
    await driver.sleep(400);
    await shot(driver, '02-compose-panel');

    await driver.executeScript(`
      const sr = document.querySelector('[data-cc-host="panel"]').shadowRoot;
      const ta = sr.getElementById('cc-ta');
      ta.value = 'This is a secret message';
      ta.dispatchEvent(new Event('input', { bubbles: true }));
    `);
    await driver.sleep(300);
    await shot(driver, '03-typed');

    console.log(`\nScreenshots written to ${OUT}`);
  } finally {
    try { await driver.quit(); } catch (_) {}
    server.close();
    fs.rmSync(H.TMP, { recursive: true, force: true });
  }
})().catch(err => { console.error(err); process.exit(1); });
