// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * CryptoChat — X / Twitter adapter
 *
 * Covers both legacy DMs (`dmComposerTextInput`) and XChat
 * (`dmComposer`/`xchatSendButton`). Tweet composer is included so the
 * overlay also appears when composing posts.
 *
 * Loaded as a classic content script before content.js.
 */
(function () {
  'use strict';
  const A = globalThis.CC_ADAPTERS || (globalThis.CC_ADAPTERS = []);
  A.push({
    id: 'twitter',
    match: h => h === 'x.com' || h.endsWith('.x.com') || h === 'twitter.com' || h.endsWith('.twitter.com'),
    inputSelectors: [
      'div[contenteditable="true"][data-testid^="dmComposerTextInput"]',
      'div[contenteditable="true"][data-testid="dmComposerTextInput"]',
      'div[contenteditable="true"][data-testid^="tweetTextarea_"]',
    ],
    sendSelectors: [
      'button[data-testid="dmComposerSendButton"]',
      'button[data-testid="xchatSendButton"]',
      'button[data-testid="tweetButtonInline"]',
      'button[data-testid="tweetButton"]',
    ],
    messageSelectors: [
      '[data-testid="messageEntry"]',
      '[data-testid="tweetText"]',
    ],
    notes: 'React contenteditable. DM + XChat + tweet composer.',
  });
})();
