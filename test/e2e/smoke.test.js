// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Selenium end-to-end smoke test for the Firefox/LibreWolf build.
 *
 *   npm run build:firefox   # produce mozilla/dist/cryptochat-firefox.xpi
 *   npm run test:e2e        # launches LibreWolf, installs a test build
 *
 * Firefox/Marionette refuses WebDriver navigation to moz-extension:// URLs,
 * so this drives the content-script path instead: it installs a copy of the
 * extension whose manifest also matches a local fixture page, then asserts the
 * input overlay appears, the shadow-DOM panel opens, and the background
 * responds to LIST_CONTACTS (the panel shows an empty contact list).
 *
 * Env:
 *   LIBREWOLF_PATH, GECKODRIVER_PATH  override binaries
 *   CC_E2E_HEADLESS=1                 run headless
 */

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Builder } from 'selenium-webdriver';
import firefox from 'selenium-webdriver/firefox.js';
import { resolveLibreWolf, resolveGeckodriver } from '../../scripts/lib/librewolf.js';

const ROOT   = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const TMP    = path.join(ROOT, 'test', 'e2e', '.tmp-addon');
const TEST_HOST = 'http://127.0.0.1/*';

let driver, server, baseUrl;

/** Copy mozilla/ and widen the match patterns to include a localhost fixture. */
function prepareTestAddon() {
  fs.rmSync(TMP, { recursive: true, force: true });
  fs.cpSync(path.join(ROOT, 'mozilla'), TMP, {
    recursive: true,
    filter: p => !p.includes(`${path.sep}dist`),
  });
  const manifestFile = path.join(TMP, 'manifest.json');
  const m = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
  m.host_permissions = [...new Set([...(m.host_permissions || []), TEST_HOST])];
  for (const cs of m.content_scripts || []) {
    cs.matches = [...new Set([...cs.matches, TEST_HOST])];
  }
  fs.writeFileSync(manifestFile, JSON.stringify(m, null, 2));
}

function startServer() {
  return new Promise(resolve => {
    server = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(`<!doctype html><html><head><meta charset="utf-8"><title>CC E2E</title></head>
<body><h1>composer</h1>
<textarea id="composer" style="width:420px;height:90px"></textarea>
</body></html>`);
    });
    server.listen(0, '127.0.0.1', () => {
      baseUrl = `http://127.0.0.1:${server.address().port}/`;
      resolve(baseUrl);
    });
  });
}

before(async () => {
  const bin = resolveLibreWolf();
  assert.ok(bin, 'LibreWolf not found — set LIBREWOLF_PATH to librewolf(.exe)');

  prepareTestAddon();
  await startServer();

  const options = new firefox.Options().setBinary(bin);
  if (process.env.CC_E2E_HEADLESS === '1') options.addArguments('-headless');

  let builder = new Builder().forBrowser('firefox').setFirefoxOptions(options);
  const gd = resolveGeckodriver();
  if (gd) builder = builder.setFirefoxService(new firefox.ServiceBuilder(gd));
  driver = await builder.build();
  await driver.manage().setTimeouts({ implicit: 5000, pageLoad: 30000, script: 15000 });

  await driver.installAddon(TMP, true);
});

after(async () => {
  if (driver) { try { await driver.quit(); } catch (_) {} }
  if (server) server.close();
  fs.rmSync(TMP, { recursive: true, force: true });
});

test('lock overlay is injected onto a detected input box', async () => {
  await driver.get(baseUrl);
  const btn = await driver.wait(async () => {
    const els = await driver.findElements({ css: 'button[data-cc-host="input"]' });
    return els.length ? els[0] : false;
  }, 15000, 'overlay button should be injected');
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
