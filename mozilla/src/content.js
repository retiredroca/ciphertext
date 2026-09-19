// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * ciphertext Content Script v8
 *
 * Platform-aware composer overlay:
 *   - Detects the page's message input(s) using the adapter registered for
 *     this host (src/adapters/*), or a generic selector set otherwise.
 *   - Attaches a small lock button directly to each input box.
 *   - Clicking it opens the ciphertext compose panel anchored to that input.
 *   - Ciphertext is injected into that same input and sent via the platform's
 *     send button (or Enter).
 *
 * Auto-decrypt runs independently in the feed for V1, V2, GRP_V1, GRPV2.
 *
 * This script only runs on enabled sites: the seven supported platforms are
 * declared statically, and other sites are covered by the optional
 * "all sites" permission registered at runtime.
 */

(function () {
  'use strict';

  try {

  if (globalThis.__ccContentLoaded) return;
  globalThis.__ccContentLoaded = true;

  /* ════════════════════════════════════════════════════════════════════
     WIRE FORMAT REGEXES
  ════════════════════════════════════════════════════════════════════ */

  const WIRE_V1   = /CIPHERTEXT_V1:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+/;
  const WIRE_GRP  = /CIPHERTEXT_GRP_V1:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+/;
  const WIRE_V2   = /CIPHERTEXT_V2:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+/;
  const WIRE_GRP2 = /CIPHERTEXT_GRPV2:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+/;
  const WIRE_ANY  = /CIPHERTEXT_(?:V[12]|GRP_V1|GRPV2):[A-Za-z0-9+/=:]+/;

  const PROCESSED = 'data-cc-v7';
  const HOST_ATTR = 'data-cc-host';

  const IS_GHPAGES = location.hostname === 'retiredroca.github.io';

  /* ════════════════════════════════════════════════════════════════════
     MESSAGING HELPER (callback form works in Chrome + Firefox)
  ════════════════════════════════════════════════════════════════════ */

  function sendMsg(m) {
    return new Promise(resolve => {
      try {
        chrome.runtime.sendMessage(m, r => {
          if (chrome.runtime.lastError) { resolve({ error: chrome.runtime.lastError.message }); return; }
          resolve(r || {});
        });
      } catch (e) { resolve({ error: e.message || 'Extension context unavailable' }); }
    });
  }

  /* ════════════════════════════════════════════════════════════════════
     GITHUB PAGES BRIDGE (share-link "add contact" flow)
  ════════════════════════════════════════════════════════════════════ */

  if (IS_GHPAGES) {
    const sig = document.createElement('div');
    sig.setAttribute('data-ciphertext-installed', 'true');
    sig.style.display = 'none';
    (document.head || document.documentElement).appendChild(sig);
    window.addEventListener('message', async (e) => {
      if (e.source !== window || e.data?.type !== 'CC_ADD_CONTACT') return;
      const { ccMsgId, contact } = e.data;
      if (!ccMsgId || !contact) return;
      const r = await sendMsg({
        type: 'SAVE_CONTACT', handle: contact.handle, platform: contact.platform,
        publicKeyB64: contact.pubKeyB64, displayName: contact.displayName,
      });
      if (r.error) window.postMessage({ ccReplyId: ccMsgId, error: r.error }, '*');
      else         window.postMessage({ ccReplyId: ccMsgId, success: true }, '*');
    });
    return;
  }

  /* ════════════════════════════════════════════════════════════════════
     PAGE STYLES — decrypted message bubbles in the feed
  ════════════════════════════════════════════════════════════════════ */

  if (!document.getElementById('cc-page-styles')) {
    const s = document.createElement('style');
    s.id = 'cc-page-styles';
    s.textContent = `
      .cc-decrypted{display:inline-flex;flex-direction:column;gap:3px;padding:8px 12px;
        border-radius:8px;background:rgba(29,158,117,.07);border:1px solid rgba(29,158,117,.2);
        font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
        font-size:14px;color:inherit;line-height:1.5;max-width:100%;
        word-break:break-word;white-space:pre-wrap;animation:ccfadein .18s ease}
      @keyframes ccfadein{from{opacity:0;transform:translateY(2px)}to{opacity:1;transform:none}}
      .cc-meta{font-size:10px;color:#1D9E75;font-weight:500;display:flex;
        align-items:center;gap:4px;flex-wrap:wrap;opacity:.85}
      .cc-meta .cc-badge{padding:1px 5px;background:rgba(29,158,117,.12);
        border-radius:999px;font-size:9px}
      .cc-meta .cc-from{font-weight:400;color:#2d7a60}
      .cc-pending{display:inline-flex;align-items:center;gap:6px;
        font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
        font-size:12px;color:rgba(108,79,240,.5)}
      .cc-spinner{width:12px;height:12px;border:1.5px solid rgba(108,79,240,.2);
        border-top-color:#6C4FF0;border-radius:50%;
        animation:ccspin .7s linear infinite;flex-shrink:0}
      @keyframes ccspin{to{transform:rotate(360deg)}}
      .cc-overlay-msg{display:inline-flex;align-items:center;gap:7px;padding:7px 12px;
        border-radius:8px;cursor:pointer;
        font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
        font-size:13px;line-height:1.4;user-select:none;
        background:rgba(108,79,240,.07);border:1px solid rgba(108,79,240,.22);
        color:#6C4FF0;transition:background .15s;white-space:normal;
        word-break:break-word;max-width:100%}
      .cc-overlay-msg:hover{background:rgba(108,79,240,.13)}
      .cc-overlay-msg.grp{background:rgba(29,158,117,.07);
        border-color:rgba(29,158,117,.22);color:#0F6E56}
      .cc-overlay-msg.busy{opacity:.5;pointer-events:none}
      .cc-err-msg{display:inline-flex;align-items:center;gap:6px;padding:6px 10px;
        border-radius:8px;background:rgba(216,90,48,.06);
        border:1px solid rgba(216,90,48,.2);
        font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
        font-size:12px;color:#993C1D;word-break:break-word}
    `;
    document.head.appendChild(s);
  }

  /* ════════════════════════════════════════════════════════════════════
     HELPERS
  ════════════════════════════════════════════════════════════════════ */

  function esc(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  /** Inject text into any contenteditable or textarea */
  function injectText(target, text) {
    if (!target) return;
    target.focus();
    if (target.tagName === 'TEXTAREA' || target.tagName === 'INPUT') {
      const start = target.selectionStart ?? target.value.length;
      target.value = target.value.slice(0, start) + text + target.value.slice(target.selectionEnd ?? start);
      target.dispatchEvent(new Event('input', { bubbles: true }));
    } else {
      const sel = window.getSelection();
      const rng = document.createRange();
      rng.selectNodeContents(target);
      sel.removeAllRanges();
      sel.addRange(rng);
      const ok = document.execCommand('insertText', false, text);
      if (!ok) {
        target.dispatchEvent(new InputEvent('input', {
          inputType: 'insertText', data: text, bubbles: true, cancelable: true,
        }));
      }
      setTimeout(() => target.focus(), 50);
    }
  }

  /* ════════════════════════════════════════════════════════════════════
     ADAPTER SELECTION
  ════════════════════════════════════════════════════════════════════ */

  const GENERIC_INPUT_SELECTORS = [
    'textarea:not([readonly]):not([disabled])',
    '[contenteditable="true"]',
    '[contenteditable=""]',
    'input[type="text"]:not([readonly]):not([disabled])',
  ];
  const GENERIC_SEND_SELECTORS = [
    'button[type="submit"]',
    'button[aria-label*="Send"]',
  ];

  const adapters = Array.isArray(globalThis.CC_ADAPTERS) ? globalThis.CC_ADAPTERS : [];
  const adapter = adapters.find(a => {
    try { return a.match(location.hostname); } catch (_) { return false; }
  }) || null;

  const INPUT_SELECTORS = adapter?.inputSelectors?.length ? adapter.inputSelectors : GENERIC_INPUT_SELECTORS;
  const SEND_SELECTORS  = adapter?.sendSelectors?.length  ? adapter.sendSelectors  : GENERIC_SEND_SELECTORS;

  /* ════════════════════════════════════════════════════════════════════
     PREFERENCES
  ════════════════════════════════════════════════════════════════════ */

  let prefs = { blur: true, overlay: true };

  async function initPrefs() {
    const r = await sendMsg({ type: 'GET_PREFS' });
    if (r && r.prefs) { prefs = { ...prefs, ...r.prefs }; }
    applyPrefs();
  }

  function applyPrefs() {
    tracked.forEach((_rec, el) => positionInput(el));
    if (!prefs.overlay) {
      tracked.forEach(rec => { rec.btn.style.display = 'none'; });
      if (panelOpen) closePanel();
    }
  }

  try {
    chrome.storage?.onChanged?.addListener((changes, area) => {
      if (area === 'local' && changes.cc_prefs) {
        prefs = { ...prefs, ...(changes.cc_prefs.newValue || {}) };
        applyPrefs();
      }
    });
  } catch (_) {}

  /* ════════════════════════════════════════════════════════════════════
     LAST-FOCUSED INPUT TRACKING (for popup "Encrypt & inject")
  ════════════════════════════════════════════════════════════════════ */

  let lastFocusedInput = null;

  document.addEventListener('focusin', (e) => {
    const t = e.target;
    if (!t) return;
    if (t.closest && t.closest('[' + HOST_ATTR + ']')) return;
    const tag = t.tagName;
    const ce  = t.isContentEditable || t.getAttribute?.('contenteditable') === 'true';
    if (tag === 'TEXTAREA' || tag === 'INPUT' || ce) lastFocusedInput = t;
  }, true);

  /* ════════════════════════════════════════════════════════════════════
     AUTO-DECRYPT
  ════════════════════════════════════════════════════════════════════ */

  function renderDecrypted(el, result) {
    const isGrp  = String(result.format || '').includes('group');
    const isPqc  = String(result.format || '').startsWith('v2');
    const pqcTag = isPqc ? ' · <span class="cc-badge">PQC</span>' : '';

    const bubble = document.createElement('span');
    bubble.className = 'cc-decrypted';
    const meta = document.createElement('span');
    meta.className = 'cc-meta';
    if (isGrp) {
      meta.innerHTML = `🔓 <span class="cc-badge">group · ${result.slotCount}</span>${pqcTag}` +
        (result.senderHandle && result.senderHandle !== '(you)'
          ? ` · <span class="cc-from">from ${esc(result.senderHandle)}${result.senderVerified?' ✓':''}</span>` : '') +
        (result.recipientHandles?.filter(h=>h!=='__self__').length
          ? ` · <span class="cc-from">to: ${result.recipientHandles.filter(h=>h!=='__self__').map(esc).join(', ')}</span>` : '');
    } else {
      meta.innerHTML = `🔓 <span class="cc-from">from ${esc(result.senderHandle||'?')}${result.senderVerified?' ✓':''}</span>${pqcTag}`;
    }
    const body = document.createElement('span');
    body.textContent = result.plaintext;
    bubble.appendChild(meta);
    bubble.appendChild(body);
    el.innerHTML = '';
    el.appendChild(bubble);
  }

  function renderFallbackOverlay(el, wire, isGrp) {
    el.setAttribute(PROCESSED, 'nk');
    const ov = document.createElement('span');
    ov.className = 'cc-overlay-msg' + (isGrp ? ' grp' : '');
    ov.innerHTML = isGrp
      ? '🔒 <strong>Encrypted group message</strong>&nbsp;<span style="font-size:11px;opacity:.6">add sender to contacts to auto-decrypt</span>'
      : '🔒 <strong>Encrypted message</strong>&nbsp;<span style="font-size:11px;opacity:.6">add sender to contacts to auto-decrypt</span>';
    el.textContent = '';
    el.appendChild(ov);
    ov.addEventListener('click', async () => {
      ov.classList.add('busy');
      ov.innerHTML = '<span class="cc-spinner"></span> Decrypting…';
      const r = await sendMsg({ type: 'DECRYPT_MESSAGE', wireText: wire });
      if (r.error) {
        ov.classList.remove('busy');
        ov.innerHTML = (isGrp ? '🔒 <strong>Encrypted group message</strong>' : '🔒 <strong>Encrypted message</strong>') +
          `&nbsp;<span style="font-size:11px;color:#D85A30">${esc(r.error)}</span>`;
        return;
      }
      el.setAttribute(PROCESSED, '1');
      renderDecrypted(el, r);
    });
  }

  const MAX_CONCURRENT = 4;
  let   active = 0;
  const queue  = [];
  function enqueue(el, wire, isGrp) { queue.push({el,wire,isGrp}); drain(); }
  function drain() {
    while (active < MAX_CONCURRENT && queue.length > 0) {
      const job = queue.shift(); active++;
      decryptJob(job).finally(() => { active--; drain(); });
    }
  }
  async function decryptJob({el, wire, isGrp}) {
    try {
      const r = await sendMsg({ type: 'DECRYPT_MESSAGE', wireText: wire });
      if (r.error) renderFallbackOverlay(el, wire, isGrp);
      else { el.setAttribute(PROCESSED,'1'); renderDecrypted(el, r); }
    } catch (_) { renderFallbackOverlay(el, wire, isGrp); }
  }

  function matchWire(text) {
    if (WIRE_GRP2.test(text)) return { re: WIRE_GRP2, grp: true };
    if (WIRE_GRP.test(text))  return { re: WIRE_GRP,  grp: true };
    if (WIRE_V2.test(text))   return { re: WIRE_V2,   grp: false };
    if (WIRE_V1.test(text))   return { re: WIRE_V1,   grp: false };
    return null;
  }

  function processEl(el) {
    if (!prefs.blur) return;
    const existing = el.getAttribute(PROCESSED);
    if (existing === '1' || existing === 'pending') return;
    if (el.closest('[contenteditable="true"]') || el.closest('[' + HOST_ATTR + ']')) return;
    const text = el.textContent || '';
    const hit = matchWire(text);
    if (!hit) return;
    const retrying = existing === 'nk';
    el.setAttribute(PROCESSED, 'pending');
    const wire = text.match(hit.re)[0];
    if (!retrying) {
      el.textContent = '';
      const p = document.createElement('span');
      p.className = 'cc-pending';
      p.innerHTML = '<span class="cc-spinner"></span>';
      el.appendChild(p);
    }
    enqueue(el, wire, hit.grp);
  }

  // Universal text node scanner — works on any site without message selectors.
  function scanTextNodes(root) {
    if (!prefs.blur) return;
    const start = (root && root.nodeType === 1) ? root : document.body;
    if (!start) return;
    const walker = document.createTreeWalker(
      start,
      NodeFilter.SHOW_TEXT,
      {
        acceptNode(node) {
          if (node.parentElement?.closest('[' + HOST_ATTR + ']')) return NodeFilter.FILTER_REJECT;
          const tag = node.parentElement?.tagName;
          if (tag === 'SCRIPT' || tag === 'STYLE') return NodeFilter.FILTER_REJECT;
          if (node.parentElement?.closest('[contenteditable="true"]')) return NodeFilter.FILTER_REJECT;
          return node.nodeValue && WIRE_ANY.test(node.nodeValue)
            ? NodeFilter.FILTER_ACCEPT
            : NodeFilter.FILTER_SKIP;
        }
      }
    );

    const parents = new Set();
    let node;
    while ((node = walker.nextNode())) {
      if (node.parentElement) parents.add(node.parentElement);
    }
    parents.forEach(processEl);
  }

  /* ════════════════════════════════════════════════════════════════════
     INPUT OVERLAY BUTTONS
  ════════════════════════════════════════════════════════════════════ */

  const LOCK_SVG = `<svg width="13" height="13" viewBox="0 0 16 16" fill="none" style="flex-shrink:0;display:block">
    <rect x="2" y="7" width="12" height="9" rx="2.5" fill="white" opacity=".95"/>
    <path d="M5 7V5a3 3 0 016 0v2" stroke="white" stroke-width="1.8" stroke-linecap="round" fill="none"/>
  </svg>`;

  const tracked = new Map(); // input element -> { btn }
  let activeInput = null;
  let activeBtn   = null;

  function isEligibleInput(el) {
    if (!el || el.nodeType !== 1) return false;
    if (el.closest && el.closest('[' + HOST_ATTR + ']')) return false;
    if (el.disabled || el.readOnly) return false;
    if (el.getAttribute('aria-hidden') === 'true') return false;
    if (el.tagName === 'INPUT') {
      const type = (el.getAttribute('type') || 'text').toLowerCase();
      const blocked = ['hidden','password','file','checkbox','radio','submit','button','image','range','color','date','time','search'];
      if (blocked.includes(type)) return false;
    }
    return true;
  }

  function makeButton(input) {
    const b = document.createElement('button');
    b.type = 'button';
    b.setAttribute(HOST_ATTR, 'input');
    b.setAttribute('aria-label', 'ciphertext — encrypt message');
    b.title = 'ciphertext — encrypt';
    b.innerHTML = LOCK_SVG;
    Object.assign(b.style, {
      position: 'fixed', zIndex: '2147483647', display: 'none',
      alignItems: 'center', justifyContent: 'center',
      width: '26px', height: '26px', padding: '0', border: 'none',
      borderRadius: '7px', background: 'rgba(108,79,240,.92)', color: '#fff',
      cursor: 'pointer', boxShadow: '0 2px 8px rgba(108,79,240,.45)',
      transition: 'opacity .12s, background .12s', opacity: '.92', lineHeight: '1',
    });
    b.addEventListener('pointerdown', e => { e.preventDefault(); e.stopPropagation(); });
    b.addEventListener('click', e => {
      e.preventDefault(); e.stopPropagation();
      togglePanel(input, b);
    });
    ['keydown','keyup','keypress'].forEach(ev =>
      b.addEventListener(ev, ev => ev.stopPropagation()));
    return b;
  }

  function addInput(el) {
    if (!(el instanceof Element) || tracked.has(el)) return;
    if (!isEligibleInput(el)) return;
    const btn = makeButton(el);
    const rec = { btn, ro: null };
    tracked.set(el, rec);
    (document.body || document.documentElement).appendChild(btn);
    if (window.ResizeObserver) {
      try {
        rec.ro = new ResizeObserver(() => positionInput(el));
        rec.ro.observe(el);
      } catch (_) {}
    }
    positionInput(el);
  }

  function discoverInputs(root) {
    const scope = (root && root.nodeType === 1) ? root : document;
    for (const sel of INPUT_SELECTORS) {
      try {
        if (scope.matches && scope.matches(sel)) addInput(scope);
        scope.querySelectorAll(sel).forEach(addInput);
      } catch (_) {}
    }
  }

  function positionInput(el) {
    const rec = tracked.get(el);
    if (!rec) return;
    const r = el.getBoundingClientRect();
    const visible = prefs.overlay &&
      r.width > 10 && r.height > 10 &&
      r.bottom > 0 && r.top < window.innerHeight &&
      r.right > 0 && r.left < window.innerWidth;
    if (!visible) { rec.btn.style.display = 'none'; return; }
    rec.btn.style.display = 'flex';
    const size = 26;
    let top  = r.top + r.height / 2 - size / 2;
    let left = r.right - size - 6;
    top  = Math.max(4, Math.min(top,  window.innerHeight - size - 4));
    left = Math.max(4, Math.min(left, window.innerWidth  - size - 4));
    rec.btn.style.top  = top + 'px';
    rec.btn.style.left = left + 'px';
  }

  let rafPending = false;
  function scheduleReposition() {
    if (rafPending) return;
    rafPending = true;
    requestAnimationFrame(() => {
      rafPending = false;
      tracked.forEach((_rec, el) => positionInput(el));
      if (panelOpen) positionPanel();
    });
  }

  window.addEventListener('scroll', scheduleReposition, { passive: true, capture: true });
  window.addEventListener('resize', scheduleReposition, { passive: true });
  document.addEventListener('focusin', scheduleReposition, true);

  function cleanupWithin(node) {
    for (const [el, rec] of tracked) {
      if (el === node || (node.contains && node.contains(el))) {
        try { rec.ro?.disconnect(); } catch (_) {}
        rec.btn.remove();
        tracked.delete(el);
        if (activeInput === el) closePanel();
      }
    }
  }

  /* ════════════════════════════════════════════════════════════════════
     SHADOW DOM PANEL CSS
  ════════════════════════════════════════════════════════════════════ */

  const PANEL_CSS = `
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :host { display: block; }
    #cc-panel {
      display: flex; flex-direction: column; width: 300px;
      background: #ffffff; border-radius: 14px; overflow: hidden;
      box-shadow: 0 12px 40px rgba(0,0,0,.18), 0 2px 10px rgba(108,79,240,.14);
      animation: cc-pop .16s cubic-bezier(.34,1.56,.64,1);
    }
    @media (prefers-color-scheme: dark) { #cc-panel { background: #1e1b2e; } }
    @keyframes cc-pop {
      from { opacity:0; transform: scale(.92) translateY(6px); }
      to   { opacity:1; transform: scale(1)   translateY(0); }
    }
    #cc-row1 {
      display: flex; align-items: center; justify-content: center; gap: 7px;
      padding: 8px 10px 6px; border-bottom: 1px solid rgba(108,79,240,.1); flex-wrap: wrap;
    }
    #cc-mode-toggle { display: flex; border: 1px solid rgba(108,79,240,.25); border-radius: 999px; overflow: hidden; flex-shrink: 0; }
    .cc-pill {
      padding: 3px 11px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 11px; font-weight: 500; background: transparent; border: none;
      color: #9490AE; cursor: pointer; transition: background .12s, color .12s; white-space: nowrap; line-height: 1.6;
    }
    .cc-pill.active { background: #6C4FF0; color: #fff; }
    .cc-pill:not(.active):hover { color: #6C4FF0; }
    #cc-recip {
      padding: 3px 22px 3px 7px; border: 1px solid rgba(108,79,240,.2); border-radius: 6px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 12px; color: #1A1625; background: rgba(108,79,240,.03);
      outline: none; cursor: pointer; appearance: none; max-width: 160px;
      background-image: url("data:image/svg+xml,%3Csvg width='8' height='5' viewBox='0 0 8 5' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M1 1l3 3 3-3' stroke='%239490AE' stroke-width='1.3' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");
      background-repeat: no-repeat; background-position: right 6px center; transition: border-color .14s;
    }
    #cc-recip:focus { border-color: #6C4FF0; }
    @media (prefers-color-scheme: dark) { #cc-recip { color: #EAE8F4; background-color: rgba(108,79,240,.08); } }
    #cc-chips { display: flex; flex-wrap: wrap; gap: 4px; align-items: center; justify-content: center; }
    .cc-chip {
      display: flex; align-items: center; gap: 3px; padding: 2px 8px;
      border: 1px solid rgba(108,79,240,.2); border-radius: 999px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 11px; font-weight: 500; color: #9490AE; background: transparent;
      cursor: pointer; user-select: none; transition: all .12s; white-space: nowrap;
    }
    .cc-chip.on { background: rgba(108,79,240,.1); border-color: #6C4FF0; color: #6C4FF0; }
    .cc-dot { width: 6px; height: 6px; border-radius: 50%; border: 1.5px solid currentColor; display: inline-block; flex-shrink: 0; transition: background .12s; }
    .cc-chip.on .cc-dot { background: #6C4FF0; border-color: #6C4FF0; }
    .cc-note { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 11px; color: #9490AE; }
    #cc-ta {
      width: 100%; height: 80px; resize: none; border: none; outline: none; padding: 8px 10px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 14px; line-height: 1.45; color: #1A1625; background: transparent; overflow-y: auto;
    }
    @media (prefers-color-scheme: dark) { #cc-ta { color: #EAE8F4; } }
    #cc-ta::placeholder { color: #9490AE; }
    #cc-foot { display: flex; align-items: center; gap: 6px; padding: 4px 10px 7px; border-top: 1px solid rgba(108,79,240,.08); }
    #cc-tag { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 10px; color: rgba(108,79,240,.45); flex: 1; }
    #cc-send {
      display: flex; align-items: center; gap: 4px; padding: 5px 13px; background: #6C4FF0; color: #fff;
      border: none; border-radius: 8px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 12px; font-weight: 600; cursor: pointer; white-space: nowrap; transition: opacity .14s, transform .1s;
    }
    #cc-send:hover:not(:disabled) { opacity: .88; }
    #cc-send:active:not(:disabled) { transform: scale(.97); }
    #cc-send:disabled { opacity: .4; cursor: not-allowed; }
    #cc-st { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 11px; padding: 0 10px 4px; display: none; }
    #cc-st.ok  { display: block; color: #1D9E75; }
    #cc-st.err { display: block; color: #D85A30; }
  `;

  /* ════════════════════════════════════════════════════════════════════
     PANEL OPEN / CLOSE / POSITION
  ════════════════════════════════════════════════════════════════════ */

  let panelOpen = false;
  let ccHost    = null;
  let ccShadow  = null;
  let contacts  = [];
  let groupSel  = new Set();

  function positionPanel() {
    if (!ccHost || !activeInput || !document.contains(activeInput)) return;
    const r = activeInput.getBoundingClientRect();
    const PANEL_W = 300, PANEL_H = 235;
    let left = Math.min(Math.max(8, r.left), window.innerWidth - PANEL_W - 8);
    let top  = r.top - PANEL_H - 8;
    if (top < 8) top = r.bottom + 8;
    top = Math.min(Math.max(8, top), window.innerHeight - PANEL_H - 8);
    ccHost.style.left = left + 'px';
    ccHost.style.top  = top + 'px';
  }

  function openPanel(input, btn) {
    activeInput = input;
    activeBtn   = btn || tracked.get(input)?.btn || null;
    if (!ccHost) buildPanel();
    panelOpen = true;
    positionPanel();
    ccHost.style.display = 'block';
    loadContactList();
    setTimeout(() => ccShadow?.getElementById('cc-ta')?.focus(), 40);
  }

  function closePanel() {
    panelOpen = false;
    activeInput = null;
    activeBtn = null;
    if (ccHost) ccHost.style.display = 'none';
  }

  function togglePanel(input, btn) {
    if (panelOpen && activeInput === input) closePanel();
    else openPanel(input, btn);
  }

  /* ════════════════════════════════════════════════════════════════════
     PANEL BUILD + EVENTS
  ════════════════════════════════════════════════════════════════════ */

  function buildPanel() {
    ccHost = document.createElement('div');
    ccHost.setAttribute(HOST_ATTR, 'panel');
    Object.assign(ccHost.style, {
      position: 'fixed', zIndex: '2147483646', display: 'none', width: '300px',
    });

    ccShadow = ccHost.attachShadow({ mode: 'open' });

    const style = document.createElement('style');
    style.textContent = PANEL_CSS;
    ccShadow.appendChild(style);

    const panel = document.createElement('div');
    panel.id = 'cc-panel';
    panel.innerHTML = `
      <div id="cc-row1">
        <div id="cc-mode-toggle">
          <button class="cc-pill active" data-m="1to1">1:1</button>
          <button class="cc-pill"        data-m="group">Group</button>
        </div>
        <select id="cc-recip"><option value="">Loading…</option></select>
        <div id="cc-chips" style="display:none"></div>
      </div>
      <textarea id="cc-ta" placeholder="Type encrypted message… (Enter to send)"></textarea>
      <div id="cc-st"></div>
      <div id="cc-foot">
        <span id="cc-tag">🔒 AES-256-GCM · ECDH</span>
        <button id="cc-send" disabled>Encrypt &amp; send</button>
      </div>
    `;
    ccShadow.appendChild(panel);

    ccShadow.querySelectorAll('.cc-pill').forEach(btn => {
      btn.addEventListener('click', () => {
        ccShadow.querySelectorAll('.cc-pill').forEach(b => b.classList.toggle('active', b === btn));
        const grp = btn.dataset.m === 'group';
        ccShadow.getElementById('cc-recip').style.display = grp ? 'none' : '';
        ccShadow.getElementById('cc-chips').style.display = grp ? ''     : 'none';
        groupSel.clear();
        renderChips();
        checkReady();
      });
    });

    ccShadow.getElementById('cc-recip').addEventListener('change', checkReady);

    const ta = ccShadow.getElementById('cc-ta');
    ['keydown','keyup','keypress'].forEach(evt => {
      ta.addEventListener(evt, e => {
        e.stopPropagation();
        if (evt === 'keydown' && e.key === 'Enter' && !e.shiftKey) {
          e.preventDefault();
          const btn = ccShadow.getElementById('cc-send');
          if (!btn.disabled) btn.click();
        }
      });
    });
    ta.addEventListener('input', checkReady);

    ccShadow.getElementById('cc-send').addEventListener('click', doEncrypt);

    (document.body || document.documentElement).appendChild(ccHost);
  }

  function checkReady() {
    if (!ccShadow) return;
    const btn      = ccShadow.getElementById('cc-send');
    const hasTxt   = (ccShadow.getElementById('cc-ta').value || '').trim().length > 0;
    const isGroup  = ccShadow.querySelector('.cc-pill[data-m="group"]')?.classList.contains('active');
    const hasRecip = isGroup ? groupSel.size > 0 : !!ccShadow.getElementById('cc-recip').value;
    if (btn) btn.disabled = !(hasTxt && hasRecip);
  }

  function setSt(msg, type) {
    const el = ccShadow?.getElementById('cc-st');
    if (!el) return;
    el.textContent = msg;
    el.className = type || '';
  }

  async function loadContactList() {
    if (!ccShadow) return;
    const { contacts: list } = await sendMsg({ type: 'LIST_CONTACTS' });
    contacts = (list || []).filter(c => c.publicKeyB64);

    const sel = ccShadow.getElementById('cc-recip');
    sel.innerHTML = contacts.length
      ? '<option value="">— select recipient —</option>'
      : '<option value="">No contacts yet</option>';
    contacts.forEach(c => {
      const opt = document.createElement('option');
      opt.value = JSON.stringify({ handle: c.handle, platform: c.platform });
      opt.textContent = `${c.displayName || c.handle} · ${c.platform}`;
      sel.appendChild(opt);
    });

    renderChips();
    checkReady();
  }

  function renderChips() {
    if (!ccShadow) return;
    const wrap = ccShadow.getElementById('cc-chips');
    if (!wrap) return;
    wrap.innerHTML = '';
    if (!contacts.length) {
      wrap.innerHTML = '<span class="cc-note">No contacts yet</span>';
      return;
    }
    contacts.forEach(c => {
      const key = `${c.handle}::${c.platform}`;
      const chip = document.createElement('div');
      chip.className = 'cc-chip' + (groupSel.has(key) ? ' on' : '');
      chip.dataset.key = key;
      chip.dataset.handle   = c.handle;
      chip.dataset.platform = c.platform;
      chip.dataset.pubkey   = c.publicKeyB64;
      chip.innerHTML = `<span class="cc-dot"></span>${esc(c.displayName || c.handle)}`;
      chip.addEventListener('click', () => {
        groupSel.has(key) ? groupSel.delete(key) : groupSel.add(key);
        chip.classList.toggle('on', groupSel.has(key));
        chip.querySelector('.cc-dot').style.background = groupSel.has(key) ? '#6C4FF0' : '';
        checkReady();
      });
      wrap.appendChild(chip);
    });
  }

  async function doEncrypt() {
    if (!ccShadow) return;
    const plaintext = ccShadow.getElementById('cc-ta').value.trim();
    if (!plaintext) return;

    const btn = ccShadow.getElementById('cc-send');
    btn.disabled = true;
    btn.textContent = '⏳';
    setSt('', '');

    try {
      const isGroup = ccShadow.querySelector('.cc-pill[data-m="group"]')?.classList.contains('active');
      let result;

      if (!isGroup) {
        const recip = JSON.parse(ccShadow.getElementById('cc-recip').value);
        result = await sendMsg({
          type: 'ENCRYPT_MESSAGE', plaintext,
          contactHandle: recip.handle, contactPlatform: recip.platform,
        });
      } else {
        const recipients = [];
        ccShadow.getElementById('cc-chips').querySelectorAll('.cc-chip.on').forEach(chip => {
          recipients.push({ handle: chip.dataset.handle, platform: chip.dataset.platform, publicKeyB64: chip.dataset.pubkey });
        });
        result = await sendMsg({ type: 'ENCRYPT_GROUP', plaintext, recipients });
      }

      if (result.error) throw new Error(result.error);

      const target = (activeInput && document.contains(activeInput)) ? activeInput : lastFocusedInput;
      if (!target || !document.contains(target)) throw new Error('Click a message box first, then Encrypt & send');

      injectText(target, result.ciphertext);
      clickSend(target);

      ccShadow.getElementById('cc-ta').value = '';
      groupSel.clear();
      renderChips();
      setSt('✓ Sent', 'ok');
      setTimeout(() => { setSt('', ''); closePanel(); }, 1500);

    } catch (err) {
      setSt('✗ ' + (err.message || 'Failed'), 'err');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Encrypt & send';
      checkReady();
    }
  }

  function clickSend(target) {
    setTimeout(() => {
      for (const sel of SEND_SELECTORS) {
        try {
          const btn = document.querySelector(sel);
          if (btn && !btn.disabled && btn.offsetParent !== null) { btn.click(); return; }
        } catch (_) {}
      }
      if (target) {
        target.dispatchEvent(new KeyboardEvent('keydown', {
          key:'Enter', code:'Enter', keyCode:13, which:13, bubbles:true, cancelable:true,
        }));
      }
    }, 80);
  }

  /* ════════════════════════════════════════════════════════════════════
     OBSERVERS + BOOT
  ════════════════════════════════════════════════════════════════════ */

  const obs = new MutationObserver((mutations) => {
    for (const m of mutations) {
      if (m.type !== 'childList') continue;
      m.addedNodes.forEach(n => {
        if (n.nodeType === Node.ELEMENT_NODE) {
          discoverInputs(n);
          scanTextNodes(n);
        } else if (n.nodeType === Node.TEXT_NODE && WIRE_ANY.test(n.nodeValue || '')) {
          if (n.parentElement) processEl(n.parentElement);
        }
      });
      m.removedNodes.forEach(n => { if (n.nodeType === Node.ELEMENT_NODE) cleanupWithin(n); });
    }
    scheduleReposition();
  });

  async function boot() {
    obs.observe(document.documentElement || document.body, { childList: true, subtree: true });
    await initPrefs();
    discoverInputs(document);
    scanTextNodes();
    scheduleReposition();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot, { once: true });
  } else {
    boot();
  }

  /* ════════════════════════════════════════════════════════════════════
     BACKGROUND MESSAGES + KEYBOARD
  ════════════════════════════════════════════════════════════════════ */

  chrome.runtime.onMessage.addListener((msg, _sender, respond) => {
    if (msg.type === 'CONTACTS_UPDATED') {
      document.querySelectorAll(`[${PROCESSED}="nk"]`).forEach(el => el.removeAttribute(PROCESSED));
      scanTextNodes();
      if (ccShadow && panelOpen) loadContactList();
    }

    if (msg.type === 'INJECT_ENCRYPTED') {
      const target = (activeInput && document.contains(activeInput)) ? activeInput : lastFocusedInput;
      if (!target || !document.contains(target)) { respond?.({ success: false, error: 'No input focused' }); return; }
      injectText(target, msg.ciphertext);
      respond?.({ success: true });
    }
  });

  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && panelOpen) closePanel();
  });

  } catch (err) {
    console.error('[ciphertext] Content script error:', err);
  }

})();
