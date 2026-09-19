// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * ciphertext — Facebook Messenger adapter
 *
 * Facebook Messenger uses a Draft.js contenteditable (often a
 * `p[contenteditable="true"]` inside the composer). Messenger.com now
 * redirects to facebook.com/messages, so both hosts route here.
 *
 * Loaded as a classic content script before content.js.
 */
(function () {
  'use strict';
  const A = globalThis.CC_ADAPTERS || (globalThis.CC_ADAPTERS = []);
  A.push({
    id: 'facebook',
    match: h =>
      h === 'facebook.com' || h.endsWith('.facebook.com') ||
      h === 'messenger.com' || h.endsWith('.messenger.com'),
    inputSelectors: [
      'div[contenteditable="true"][role="textbox"]',
      'p[contenteditable="true"]',
      'div[aria-label="Message"][contenteditable="true"]',
    ],
    sendSelectors: [
      'div[aria-label="Press enter to send"][role="button"]',
      'div[aria-label="Send"][role="button"]',
    ],
    messageSelectors: [
      '[data-testid="message-text"]',
      'div[role="row"] div[dir="auto"]',
    ],
    notes: 'Draft.js editor. messenger.com redirects to facebook.com/messages.',
  });
})();
