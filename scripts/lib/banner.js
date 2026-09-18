// SPDX-License-Identifier: AGPL-3.0-or-later
/** Shared banner so `npm run bundle` and the pack step emit identical output. */
export const BANNER = `// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * background-bundle.js — GENERATED FILE, DO NOT EDIT.
 *
 * Built by scripts/bundle-background.js from:
 *   src/crypto/engine.js
 *   src/crypto/keystore.js
 *   src/background/index.js + handler.js
 *
 * Regenerate with: npm run bundle
 */`;
