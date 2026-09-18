// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * web-ext configuration (used by `npm run lint:firefox` and `run:librewof`).
 * The GitHub Pages landing page lives at the repo root, outside the package,
 * so only build output is ignored here.
 */
export default {
  sourceDir: 'mozilla',
  ignoreFiles: ['dist/**'],
};
