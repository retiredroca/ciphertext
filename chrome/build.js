#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
/** Chrome package build. See scripts/pack-extension.js */
import { run } from '../scripts/pack-extension.js';
run('chrome').catch(err => { console.error(err); process.exit(1); });
