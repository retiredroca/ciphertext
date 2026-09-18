// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * CryptoChat — Discord adapter
 *
 * Discord's composer is a Slate.js editor. The editable element is
 * `[data-slate-editor="true"]` with `role="textbox"`. Class names
 * (`slateTextArea-…`) are hashed per build, so we avoid them.
 *
 * Loaded as a classic content script before content.js; registers itself on
 * globalThis.CC_ADAPTERS.
 */
(function () {
  'use strict';
  const A = globalThis.CC_ADAPTERS || (globalThis.CC_ADAPTERS = []);
  A.push({
    id: 'discord',
    match: h => h === 'discord.com' || h.endsWith('.discord.com'),
    inputSelectors: [
      'div[role="textbox"][contenteditable="true"][data-slate-editor="true"]',
      'div[role="textbox"][contenteditable="true"]',
    ],
    sendSelectors: [
      'button[aria-label="Send Message"]',
      'button[type="submit"]',
    ],
    messageSelectors: [
      'li[id^="chat-messages-"]',
      '[id^="message-content-"]',
    ],
    notes: 'Slate.js. Composer is a div[data-slate-editor=true]. Enter sends; Shift+Enter newlines.',
  });
})();
