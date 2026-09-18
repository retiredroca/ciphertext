#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * scripts/make-store-screenshots.js
 *
 * Turn the Selenium captures in assets/screenshots/ into Chrome Web Store
 * submission images. The store requires JPEG or 24-bit PNG with no alpha,
 * at 1280x800 or 640x400.
 *
 *   npm run test:screenshots   # capture at exactly 1280x800
 *   npm run screenshots:store  # write store/screenshots/{1280x800,640x400}
 *
 * Pure JS (pngjs + jpeg-js) — no native build step.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PNG } from 'pngjs';
import jpeg from 'jpeg-js';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const SRC  = path.join(ROOT, 'assets', 'screenshots');
const OUT  = path.join(ROOT, 'store', 'screenshots');

/** Composite RGBA onto white and return opaque RGBA. */
function flatten(png) {
  const { width, height, data } = png;
  const out = Buffer.alloc(width * height * 4);
  for (let i = 0; i < width * height; i++) {
    const a = data[i * 4 + 3];
    if (a === 255) {
      out[i * 4]     = data[i * 4];
      out[i * 4 + 1] = data[i * 4 + 1];
      out[i * 4 + 2] = data[i * 4 + 2];
    } else if (a === 0) {
      out[i * 4] = out[i * 4 + 1] = out[i * 4 + 2] = 255;
    } else {
      const af = a / 255;
      out[i * 4]     = Math.round(data[i * 4]     * af + 255 * (1 - af));
      out[i * 4 + 1] = Math.round(data[i * 4 + 1] * af + 255 * (1 - af));
      out[i * 4 + 2] = Math.round(data[i * 4 + 2] * af + 255 * (1 - af));
    }
    out[i * 4 + 3] = 255;
  }
  return { width, height, data: out };
}

/** Box-filter 2x downscale (1280x800 -> 640x400). */
function downscale2(png) {
  const { width, height, data } = png;
  const w = width >> 1, h = height >> 1;
  const out = Buffer.alloc(w * h * 4);
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      for (let c = 0; c < 4; c++) {
        const o0 = ((y * 2)     * width + x * 2)     * 4 + c;
        const o1 = ((y * 2)     * width + x * 2 + 1) * 4 + c;
        const o2 = ((y * 2 + 1) * width + x * 2)     * 4 + c;
        const o3 = ((y * 2 + 1) * width + x * 2 + 1) * 4 + c;
        out[(y * w + x) * 4 + c] = Math.round((data[o0] + data[o1] + data[o2] + data[o3]) / 4);
      }
    }
  }
  return { width: w, height: h, data: out };
}

function writePng24(file, img) {
  const rgb = Buffer.alloc(img.width * img.height * 3);
  for (let i = 0; i < img.width * img.height; i++) {
    rgb[i * 3]     = img.data[i * 4];
    rgb[i * 3 + 1] = img.data[i * 4 + 1];
    rgb[i * 3 + 2] = img.data[i * 4 + 2];
  }
  fs.writeFileSync(file, PNG.sync.write(
    { width: img.width, height: img.height, data: rgb },
    { colorType: 2, inputColorType: 2 }
  ));
}

function writeJpg(file, img) {
  fs.writeFileSync(file, jpeg.encode(
    { data: img.data, width: img.width, height: img.height }, 92
  ).data);
}

fs.mkdirSync(path.join(OUT, '1280x800'), { recursive: true });
fs.mkdirSync(path.join(OUT, '640x400'),  { recursive: true });

const sources = fs.readdirSync(SRC).filter(f => f.toLowerCase().endsWith('.png'));
if (!sources.length) {
  console.error(`No PNGs in ${SRC}. Run: npm run test:screenshots`);
  process.exit(1);
}

for (const file of sources) {
  const png = PNG.sync.read(fs.readFileSync(path.join(SRC, file)));
  if (png.width !== 1280 || png.height !== 800) {
    console.warn(`  ! ${file} is ${png.width}x${png.height}; expected 1280x800 — skipping`);
    continue;
  }
  const base = file.replace(/\.png$/i, '');
  const flat = flatten(png);

  writePng24(path.join(OUT, '1280x800', `${base}.png`), flat);
  writeJpg  (path.join(OUT, '1280x800', `${base}.jpg`), flat);

  const small = downscale2(flat);
  writePng24(path.join(OUT, '640x400', `${base}.png`), small);
  writeJpg  (path.join(OUT, '640x400', `${base}.jpg`), small);

  console.log(`  ✓ ${base}: 1280x800 + 640x400 (PNG 24-bit, JPEG)`);
}

console.log(`\nStore screenshots in ${path.relative(ROOT, OUT)}`);
