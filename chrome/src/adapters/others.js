// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * CryptoChat — WhatsApp Web + Telegram Web adapter
 *
 * WhatsApp: footer composer is a contenteditable with `data-tab="10"`;
 * Telegram: `.input-field` / `#editable-message-text`. Send button is
 * `[data-testid="send"]` on WhatsApp, `.btn-send` on Telegram.
 *
 * Loaded as a classic content script before content.js.
 */
(function () {
  'use strict';
  const A = globalThis.CC_ADAPTERS || (globalThis.CC_ADAPTERS = []);
  A.push({
    id: 'whatsapp-telegram',
    match: h =>
      h === 'web.whatsapp.com' ||
      h === 'web.telegram.org' ||
      h.endsWith('.web.telegram.org'),
    inputSelectors: [
      // WhatsApp Web
      'div[contenteditable="true"][data-tab="10"]',
      'footer div[contenteditable="true"][role="textbox"]',
      // Telegram Web (A/K versions)
      'div[contenteditable="true"].input-field',
      '#editable-message-text',
      'div[contenteditable="true"][role="textbox"]',
    ],
    sendSelectors: [
      'button[data-testid="send"]',   // WhatsApp
      'button.tgico-send',            // Telegram
      '.btn-send',                    // Telegram legacy
    ],
    messageSelectors: [
      'div.message-in',
      '[data-testid="msg-text"]',
      '.message .text-content',
    ],
    notes: 'Both platforms already E2E-encrypt transport; CryptoChat adds content-layer encryption.',
  });
})();
