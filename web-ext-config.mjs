// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * web-ext configuration (used by `npm run lint:firefox` and `run:librewolf`).
 *
 * `docs/` holds the GitHub Pages landing page and is intentionally not part
 * of the extension runtime, so it is excluded from lint/package.
 */
export default {
  sourceDir: 'mozilla',
  ignoreFiles: ['docs/**', 'dist/**'],
};
