# ciphertext — Chrome / Brave / Edge package

This directory is the Chrome-family build (MV3, `"background": { "service_worker": ... }`).
The full documentation lives in the [repository README](../README.md).

## Quick start

```bash
npm install
npm run build:chrome     # → chrome/dist/ciphertext-chrome.zip
```

1. Open `chrome://extensions/`
2. Enable **Developer mode**
3. **Load unpacked** → select this `chrome/` folder

## Notes

- Runtime source is under `src/`. `src/background-bundle.js` is **generated** by
  `npm run bundle` — do not edit it by hand.
- The Firefox build lives in [`../mozilla/`](../mozilla/); its runtime is synced
  from this directory by `mozilla/build.js`.

License: AGPL-3.0-or-later. See [`../LICENSE`](../LICENSE).
