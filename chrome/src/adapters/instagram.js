// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * ciphertext — Instagram DMs adapter
 *
 * Instagram DMs use a Lexical contenteditable `div[role="textbox"]` in the
 * thread footer. Class names are hashed per deploy, so we key off roles and
 * aria-labels only.
 *
 * Loaded as a classic content script before content.js.
 */
(function () {
  'use strict';
  const A = globalThis.CC_ADAPTERS || (globalThis.CC_ADAPTERS = []);
  A.push({
    id: 'instagram',
    match: h => h === 'instagram.com' || h.endsWith('.instagram.com'),
    inputSelectors: [
      'div[contenteditable="true"][role="textbox"]',
      'div[contenteditable="true"][aria-label*="Message"]',
      'textarea[placeholder]',
    ],
    sendSelectors: [
      'div[role="button"][aria-label="Send"]',
      'button[type="submit"]',
    ],
    messageSelectors: [
      'div[role="button"] div[dir="auto"]',
      '[data-testid="message-text"]',
    ],
    notes: 'Lexical editor. Only active inside /direct/ threads.',
  });
})();
