# CryptoChat — Firefox package

This directory is the Firefox build (MV3, `"background": { "scripts": [...] }`).
The full documentation lives in the [repository README](../README.md).

## Quick start

```bash
npm install
npm run build:firefox    # syncs runtime from ../chrome, then → mozilla/dist/cryptochat-firefox.xpi
```

1. Open `about:debugging` → **This Firefox**
2. **Load Temporary Add-on…** → select this `mozilla/manifest.json`

For a persistent install, drag the `.xpi` onto Firefox Developer Edition
(`xpinstall.signatures.required = false`) or sign it via
[addons.mozilla.org](https://addons.mozilla.org) ("On your own", unlisted).

## Notes

- Runtime source is under `src/`. It is kept in sync from [`../chrome/src`](../chrome/src)
  by `mozilla/build.js`; edit the Chrome copy, not this one.
- `src/background-bundle.js` is **generated** — do not edit it by hand.
- This manifest uses `"scripts"` and must not contain `"service_worker"`.

License: AGPL-3.0-or-later. See [`../LICENSE`](../LICENSE).
