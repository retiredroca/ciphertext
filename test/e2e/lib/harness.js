// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Shared Selenium harness for the Firefox/LibreWolf end-to-end tests.
 *
 * Firefox/Marionette refuses WebDriver navigation to moz-extension:// URLs,
 * so tests drive the content-script path: a temporary copy of the extension
 * is installed whose manifest also matches a local fixture page.
 */

import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Builder } from 'selenium-webdriver';
import firefox from 'selenium-webdriver/firefox.js';
import { resolveLibreWolf, resolveGeckodriver } from '../../../scripts/lib/librewolf.js';

export const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
export const TMP = path.join(ROOT, 'test', 'e2e', '.tmp-addon');
export const TEST_HOST = 'http://127.0.0.1/*';

const FIXTURE_HTML = `<!doctype html><html><head><meta charset="utf-8"><title>CC E2E</title></head>
<body style="font-family:system-ui,sans-serif;margin:24px">
<h1>ciphertext test composer</h1>
<p>A fixture page the extension is allowed to run on.</p>
<textarea id="composer" style="width:420px;height:90px"></textarea>
</body></html>`;

/** Copy mozilla/ and widen the match patterns to include the localhost fixture. */
export function prepareTestAddon() {
  fs.rmSync(TMP, { recursive: true, force: true });
  fs.cpSync(path.join(ROOT, 'mozilla'), TMP, {
    recursive: true,
    filter: p => !p.includes(`${path.sep}dist`),
  });

  // Test-only probe: records whether the background responds, and whether the
  // ML-KEM bundle is active, onto the fixture's <html> element. Uses the same
  // promise-style sendMessage the popup relies on.
  fs.writeFileSync(path.join(TMP, 'src', 'cc-probe.js'), `
    (function () {
      chrome.runtime.sendMessage({ type: 'GET_PUBLIC_KEY' })
        .then((r) => {
          document.documentElement.setAttribute('data-cc-bg', JSON.stringify({
            publicKeyB64: r && r.publicKeyB64, mlkemPkB64: r && r.mlkemPkB64,
          }));
        })
        .catch((e) => {
          document.documentElement.setAttribute('data-cc-bg', JSON.stringify({ error: e.message }));
        });
    })();
  `);

  const manifestFile = path.join(TMP, 'manifest.json');
  const m = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
  m.host_permissions = [...new Set([...(m.host_permissions || []), TEST_HOST])];
  for (const cs of m.content_scripts || []) {
    cs.matches = [...new Set([...cs.matches, TEST_HOST])];
    cs.js = ['src/cc-probe.js', ...cs.js];
  }
  fs.writeFileSync(manifestFile, JSON.stringify(m, null, 2));
  return TMP;
}

export function startServer() {
  return new Promise(resolve => {
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(FIXTURE_HTML);
    });
    server.listen(0, '127.0.0.1', () => {
      resolve({ server, baseUrl: `http://127.0.0.1:${server.address().port}/` });
    });
  });
}

/** Launch LibreWolf and install the prepared test add-on (temporary). */
export async function launchWithAddon({ headless = false, addonPath = TMP } = {}) {
  const bin = resolveLibreWolf();
  if (!bin) throw new Error('LibreWolf not found — set LIBREWOLF_PATH to librewolf(.exe)');

  const options = new firefox.Options().setBinary(bin);
  if (headless) options.addArguments('-headless');

  let builder = new Builder().forBrowser('firefox').setFirefoxOptions(options);
  const gd = resolveGeckodriver();
  if (gd) builder = builder.setFirefoxService(new firefox.ServiceBuilder(gd));

  const driver = await builder.build();
  await driver.manage().setTimeouts({ implicit: 5000, pageLoad: 30000, script: 15000 });
  await driver.installAddon(addonPath, true);
  return driver;
}

export async function waitForOverlay(driver, timeout = 15000) {
  return driver.wait(async () => {
    const els = await driver.findElements({ css: 'button[data-cc-host="input"]' });
    return els.length ? els[0] : false;
  }, timeout, 'overlay button should be injected');
}
