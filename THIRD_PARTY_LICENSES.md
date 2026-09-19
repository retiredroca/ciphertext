# Third-party licenses

CryptoChat itself is licensed under **AGPL-3.0-or-later** (see `LICENSE`).
The extension has no third-party **runtime** dependencies for its default
build. The following packages are used at build time or in optional bundles.

| Package | License | Use |
|---|---|---|
| [`mlkem`](https://www.npmjs.com/package/mlkem) | MIT | Bundled at build time into `background-bundle.js` — ML-KEM-768 hybrid encryption |
| [`esbuild`](https://www.npmjs.com/package/esbuild) | MIT | Build tooling (bundling the background and PQC bundle) |
| [`archiver`](https://www.npmjs.com/package/archiver) | MIT | Build tooling (packaging `.zip` / `.xpi`) |
| [`web-ext`](https://www.npmjs.com/package/web-ext) | MPL-2.0 | Dev tooling (`npm run lint:firefox`, `run:librewolf`) |
| [`selenium-webdriver`](https://www.npmjs.com/package/selenium-webdriver) | Apache-2.0 | Dev tooling (`npm run test:e2e`) |
| [geckodriver](https://github.com/mozilla/geckodriver) | MPL-2.0 | Dev tooling (WebDriver bridge for LibreWolf/Firefox; installed separately) |

## Planned / not currently bundled

| Package | License | Use |
|---|---|---|
| [`openpgp.js`](https://www.npmjs.com/package/openpgp) | LGPL-3.0-or-later | Future RSA GPG bridge. If bundled, its license text and source will be included and users may replace the library; see the roadmap. |

## MIT notice

The MIT-licensed packages above are provided under the following terms:

> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in
> all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.
