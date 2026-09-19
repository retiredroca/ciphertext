// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * ciphertext — Slack adapter
 *
 * Slack wraps a Quill editor. The stable hook is `data-qa="message_input"`
 * on the contenteditable, or the `.ql-editor` element. Send button is
 * `data-qa="texty_send_button"`.
 *
 * Loaded as a classic content script before content.js.
 */
(function () {
  'use strict';
  const A = globalThis.CC_ADAPTERS || (globalThis.CC_ADAPTERS = []);
  A.push({
    id: 'slack',
    match: h => h === 'app.slack.com' || h.endsWith('.slack.com'),
    inputSelectors: [
      'div[data-qa="message_input"][contenteditable="true"]',
      '.ql-editor[contenteditable="true"]',
      'div[contenteditable="true"][role="textbox"]',
    ],
    sendSelectors: [
      'button[data-qa="texty_send_button"]',
      'button[aria-label="Send message"]',
    ],
    messageSelectors: [
      '[data-qa="message-text"]',
      '[data-qa="message_content"]',
      '.c-message__body',
    ],
    notes: 'Quill editor (.ql-editor). Workspace subdomains all end in .slack.com.',
  });
})();
