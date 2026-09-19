// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * background-bundle.js — GENERATED FILE, DO NOT EDIT.
 *
 * Built by scripts/bundle-background.js from:
 *   src/crypto/engine.js
 *   src/crypto/keystore.js
 *   src/background/pqc-env.js
 *   src/background/index.js + handler.js
 *
 * Regenerate with: npm run bundle
 */
(() => {
  var __create = Object.create;
  var __defProp = Object.defineProperty;
  var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __getProtoOf = Object.getPrototypeOf;
  var __hasOwnProp = Object.prototype.hasOwnProperty;
  var __require = /* @__PURE__ */ ((x) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x, {
    get: (a, b) => (typeof require !== "undefined" ? require : a)[b]
  }) : x)(function(x) {
    if (typeof require !== "undefined") return require.apply(this, arguments);
    throw Error('Dynamic require of "' + x + '" is not supported');
  });
  var __export = (target, all) => {
    for (var name in all)
      __defProp(target, name, { get: all[name], enumerable: true });
  };
  var __copyProps = (to, from, except, desc) => {
    if (from && typeof from === "object" || typeof from === "function") {
      for (let key of __getOwnPropNames(from))
        if (!__hasOwnProp.call(to, key) && key !== except)
          __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
    }
    return to;
  };
  var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
    // If the importer is in node compatibility mode or this is not an ESM
    // file that has been converted to a CommonJS file using a Babel-
    // compatible transform (i.e. "__esModule" has not been set), then set
    // "default" to the CommonJS "module.exports" for node compatibility.
    isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
    mod
  ));

  // node_modules/mlkem/esm/src/errors.js
  var MlKemError = class extends Error {
    constructor(e) {
      let message;
      if (e instanceof Error) {
        message = e.message;
      } else if (typeof e === "string") {
        message = e;
      } else {
        message = "";
      }
      super(message);
      this.name = this.constructor.name;
    }
  };

  // node_modules/mlkem/esm/src/consts.js
  var N = 256;
  var Q = 3329;
  var Q_INV = 62209;
  var NTT_ZETAS = [
    2285,
    2571,
    2970,
    1812,
    1493,
    1422,
    287,
    202,
    3158,
    622,
    1577,
    182,
    962,
    2127,
    1855,
    1468,
    573,
    2004,
    264,
    383,
    2500,
    1458,
    1727,
    3199,
    2648,
    1017,
    732,
    608,
    1787,
    411,
    3124,
    1758,
    1223,
    652,
    2777,
    1015,
    2036,
    1491,
    3047,
    1785,
    516,
    3321,
    3009,
    2663,
    1711,
    2167,
    126,
    1469,
    2476,
    3239,
    3058,
    830,
    107,
    1908,
    3082,
    2378,
    2931,
    961,
    1821,
    2604,
    448,
    2264,
    677,
    2054,
    2226,
    430,
    555,
    843,
    2078,
    871,
    1550,
    105,
    422,
    587,
    177,
    3094,
    3038,
    2869,
    1574,
    1653,
    3083,
    778,
    1159,
    3182,
    2552,
    1483,
    2727,
    1119,
    1739,
    644,
    2457,
    349,
    418,
    329,
    3173,
    3254,
    817,
    1097,
    603,
    610,
    1322,
    2044,
    1864,
    384,
    2114,
    3193,
    1218,
    1994,
    2455,
    220,
    2142,
    1670,
    2144,
    1799,
    2051,
    794,
    1819,
    2475,
    2459,
    478,
    3221,
    3021,
    996,
    991,
    958,
    1869,
    1522,
    1628
  ];
  var NTT_ZETAS_INV = [
    1701,
    1807,
    1460,
    2371,
    2338,
    2333,
    308,
    108,
    2851,
    870,
    854,
    1510,
    2535,
    1278,
    1530,
    1185,
    1659,
    1187,
    3109,
    874,
    1335,
    2111,
    136,
    1215,
    2945,
    1465,
    1285,
    2007,
    2719,
    2726,
    2232,
    2512,
    75,
    156,
    3e3,
    2911,
    2980,
    872,
    2685,
    1590,
    2210,
    602,
    1846,
    777,
    147,
    2170,
    2551,
    246,
    1676,
    1755,
    460,
    291,
    235,
    3152,
    2742,
    2907,
    3224,
    1779,
    2458,
    1251,
    2486,
    2774,
    2899,
    1103,
    1275,
    2652,
    1065,
    2881,
    725,
    1508,
    2368,
    398,
    951,
    247,
    1421,
    3222,
    2499,
    271,
    90,
    853,
    1860,
    3203,
    1162,
    1618,
    666,
    320,
    8,
    2813,
    1544,
    282,
    1838,
    1293,
    2314,
    552,
    2677,
    2106,
    1571,
    205,
    2918,
    1542,
    2721,
    2597,
    2312,
    681,
    130,
    1602,
    1871,
    829,
    2946,
    3065,
    1325,
    2756,
    1861,
    1474,
    1202,
    2367,
    3147,
    1752,
    2707,
    171,
    3127,
    3042,
    1907,
    1836,
    1517,
    359,
    758,
    1441
  ];

  // node_modules/mlkem/esm/src/sha3/_u64.js
  var U32_MASK64 = 0xffffffffn;
  var _32n = 32n;
  function fromBig(n, le = false) {
    if (le) {
      return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
    }
    return {
      h: Number(n >> _32n & U32_MASK64) | 0,
      l: Number(n & U32_MASK64) | 0
    };
  }
  function split(lst, le = false) {
    const len = lst.length;
    const Ah = new Uint32Array(len);
    const Al = new Uint32Array(len);
    for (let i = 0; i < len; i++) {
      const { h, l } = fromBig(lst[i], le);
      [Ah[i], Al[i]] = [h, l];
    }
    return [Ah, Al];
  }
  var rotlSH = (h, l, s) => h << s | l >>> 32 - s;
  var rotlSL = (h, l, s) => l << s | h >>> 32 - s;
  var rotlBH = (h, l, s) => l << s - 32 | h >>> 64 - s;
  var rotlBL = (h, l, s) => h << s - 32 | l >>> 64 - s;

  // node_modules/mlkem/esm/src/sha3/utils.js
  function isBytes(a) {
    return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
  }
  function anumber(n, title = "") {
    if (!Number.isSafeInteger(n) || n < 0) {
      const prefix = title && `"${title}" `;
      throw new Error(`${prefix}expected integer >0, got ${n}`);
    }
  }
  function abytes(value, length, title = "") {
    const bytes = isBytes(value);
    const len = value?.length;
    const needsLen = length !== void 0;
    if (!bytes || needsLen && len !== length) {
      const prefix = title && `"${title}" `;
      const ofLen = needsLen ? ` of length ${length}` : "";
      const got = bytes ? `length=${len}` : `type=${typeof value}`;
      throw new Error(prefix + "expected Uint8Array" + ofLen + ", got " + got);
    }
    return value;
  }
  function aexists(instance, checkFinished = true) {
    if (instance.destroyed)
      throw new Error("Hash instance has been destroyed");
    if (checkFinished && instance.finished) {
      throw new Error("Hash#digest() has already been called");
    }
  }
  function aoutput(out, instance) {
    abytes(out, void 0, "digestInto() output");
    const min = instance.outputLen;
    if (out.length < min) {
      throw new Error('"digestInto() output" expected to be of length >=' + min);
    }
  }
  function u32(arr) {
    return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
  }
  function clean(...arrays) {
    for (let i = 0; i < arrays.length; i++) {
      arrays[i].fill(0);
    }
  }
  var isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
  function byteSwap(word) {
    return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
  }
  function byteSwap32(arr) {
    for (let i = 0; i < arr.length; i++) {
      arr[i] = byteSwap(arr[i]);
    }
    return arr;
  }
  var swap32IfBE = isLE ? (u) => u : byteSwap32;

  // node_modules/mlkem/esm/src/sha3/sha3.js
  var _0n = 0n;
  var _1n = 1n;
  var _2n = 2n;
  var _7n = 7n;
  var _256n = 256n;
  var _0x71n = 0x71n;
  var SHA3_PI = [];
  var SHA3_ROTL = [];
  var _SHA3_IOTA = [];
  for (let round = 0, R = _1n, x = 1, y = 0; round < 24; round++) {
    [x, y] = [y, (2 * x + 3 * y) % 5];
    SHA3_PI.push(2 * (5 * y + x));
    SHA3_ROTL.push((round + 1) * (round + 2) / 2 % 64);
    let t = _0n;
    for (let j = 0; j < 7; j++) {
      R = (R << _1n ^ (R >> _7n) * _0x71n) % _256n;
      if (R & _2n)
        t ^= _1n << (_1n << BigInt(j)) - _1n;
    }
    _SHA3_IOTA.push(t);
  }
  var IOTAS = split(_SHA3_IOTA, true);
  var SHA3_IOTA_H = IOTAS[0];
  var SHA3_IOTA_L = IOTAS[1];
  var rotlH = (h, l, s) => s > 32 ? rotlBH(h, l, s) : rotlSH(h, l, s);
  var rotlL = (h, l, s) => s > 32 ? rotlBL(h, l, s) : rotlSL(h, l, s);
  function keccakP(s, rounds = 24, B) {
    if (!B)
      B = new Uint32Array(10);
    for (let round = 24 - rounds; round < 24; round++) {
      for (let x = 0; x < 10; x++) {
        B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
      }
      {
        const Th2 = rotlH(B[2], B[3], 1) ^ B[8];
        const Tl2 = rotlL(B[2], B[3], 1) ^ B[9];
        s[0] ^= Th2;
        s[1] ^= Tl2;
        s[10] ^= Th2;
        s[11] ^= Tl2;
        s[20] ^= Th2;
        s[21] ^= Tl2;
        s[30] ^= Th2;
        s[31] ^= Tl2;
        s[40] ^= Th2;
        s[41] ^= Tl2;
      }
      {
        const Th2 = rotlH(B[4], B[5], 1) ^ B[0];
        const Tl2 = rotlL(B[4], B[5], 1) ^ B[1];
        s[2] ^= Th2;
        s[3] ^= Tl2;
        s[12] ^= Th2;
        s[13] ^= Tl2;
        s[22] ^= Th2;
        s[23] ^= Tl2;
        s[32] ^= Th2;
        s[33] ^= Tl2;
        s[42] ^= Th2;
        s[43] ^= Tl2;
      }
      {
        const Th2 = rotlH(B[6], B[7], 1) ^ B[2];
        const Tl2 = rotlL(B[6], B[7], 1) ^ B[3];
        s[4] ^= Th2;
        s[5] ^= Tl2;
        s[14] ^= Th2;
        s[15] ^= Tl2;
        s[24] ^= Th2;
        s[25] ^= Tl2;
        s[34] ^= Th2;
        s[35] ^= Tl2;
        s[44] ^= Th2;
        s[45] ^= Tl2;
      }
      {
        const Th2 = rotlH(B[8], B[9], 1) ^ B[4];
        const Tl2 = rotlL(B[8], B[9], 1) ^ B[5];
        s[6] ^= Th2;
        s[7] ^= Tl2;
        s[16] ^= Th2;
        s[17] ^= Tl2;
        s[26] ^= Th2;
        s[27] ^= Tl2;
        s[36] ^= Th2;
        s[37] ^= Tl2;
        s[46] ^= Th2;
        s[47] ^= Tl2;
      }
      {
        const Th2 = rotlH(B[0], B[1], 1) ^ B[6];
        const Tl2 = rotlL(B[0], B[1], 1) ^ B[7];
        s[8] ^= Th2;
        s[9] ^= Tl2;
        s[18] ^= Th2;
        s[19] ^= Tl2;
        s[28] ^= Th2;
        s[29] ^= Tl2;
        s[38] ^= Th2;
        s[39] ^= Tl2;
        s[48] ^= Th2;
        s[49] ^= Tl2;
      }
      let curH = s[2];
      let curL = s[3];
      let Th, Tl;
      Th = rotlSH(curH, curL, 1);
      Tl = rotlSL(curH, curL, 1);
      curH = s[20];
      curL = s[21];
      s[20] = Th;
      s[21] = Tl;
      Th = rotlSH(curH, curL, 3);
      Tl = rotlSL(curH, curL, 3);
      curH = s[14];
      curL = s[15];
      s[14] = Th;
      s[15] = Tl;
      Th = rotlSH(curH, curL, 6);
      Tl = rotlSL(curH, curL, 6);
      curH = s[22];
      curL = s[23];
      s[22] = Th;
      s[23] = Tl;
      Th = rotlSH(curH, curL, 10);
      Tl = rotlSL(curH, curL, 10);
      curH = s[34];
      curL = s[35];
      s[34] = Th;
      s[35] = Tl;
      Th = rotlSH(curH, curL, 15);
      Tl = rotlSL(curH, curL, 15);
      curH = s[36];
      curL = s[37];
      s[36] = Th;
      s[37] = Tl;
      Th = rotlSH(curH, curL, 21);
      Tl = rotlSL(curH, curL, 21);
      curH = s[6];
      curL = s[7];
      s[6] = Th;
      s[7] = Tl;
      Th = rotlSH(curH, curL, 28);
      Tl = rotlSL(curH, curL, 28);
      curH = s[10];
      curL = s[11];
      s[10] = Th;
      s[11] = Tl;
      Th = rotlBH(curH, curL, 36);
      Tl = rotlBL(curH, curL, 36);
      curH = s[32];
      curL = s[33];
      s[32] = Th;
      s[33] = Tl;
      Th = rotlBH(curH, curL, 45);
      Tl = rotlBL(curH, curL, 45);
      curH = s[16];
      curL = s[17];
      s[16] = Th;
      s[17] = Tl;
      Th = rotlBH(curH, curL, 55);
      Tl = rotlBL(curH, curL, 55);
      curH = s[42];
      curL = s[43];
      s[42] = Th;
      s[43] = Tl;
      Th = rotlSH(curH, curL, 2);
      Tl = rotlSL(curH, curL, 2);
      curH = s[48];
      curL = s[49];
      s[48] = Th;
      s[49] = Tl;
      Th = rotlSH(curH, curL, 14);
      Tl = rotlSL(curH, curL, 14);
      curH = s[8];
      curL = s[9];
      s[8] = Th;
      s[9] = Tl;
      Th = rotlSH(curH, curL, 27);
      Tl = rotlSL(curH, curL, 27);
      curH = s[30];
      curL = s[31];
      s[30] = Th;
      s[31] = Tl;
      Th = rotlBH(curH, curL, 41);
      Tl = rotlBL(curH, curL, 41);
      curH = s[46];
      curL = s[47];
      s[46] = Th;
      s[47] = Tl;
      Th = rotlBH(curH, curL, 56);
      Tl = rotlBL(curH, curL, 56);
      curH = s[38];
      curL = s[39];
      s[38] = Th;
      s[39] = Tl;
      Th = rotlSH(curH, curL, 8);
      Tl = rotlSL(curH, curL, 8);
      curH = s[26];
      curL = s[27];
      s[26] = Th;
      s[27] = Tl;
      Th = rotlSH(curH, curL, 25);
      Tl = rotlSL(curH, curL, 25);
      curH = s[24];
      curL = s[25];
      s[24] = Th;
      s[25] = Tl;
      Th = rotlBH(curH, curL, 43);
      Tl = rotlBL(curH, curL, 43);
      curH = s[4];
      curL = s[5];
      s[4] = Th;
      s[5] = Tl;
      Th = rotlBH(curH, curL, 62);
      Tl = rotlBL(curH, curL, 62);
      curH = s[40];
      curL = s[41];
      s[40] = Th;
      s[41] = Tl;
      Th = rotlSH(curH, curL, 18);
      Tl = rotlSL(curH, curL, 18);
      curH = s[28];
      curL = s[29];
      s[28] = Th;
      s[29] = Tl;
      Th = rotlBH(curH, curL, 39);
      Tl = rotlBL(curH, curL, 39);
      curH = s[44];
      curL = s[45];
      s[44] = Th;
      s[45] = Tl;
      Th = rotlBH(curH, curL, 61);
      Tl = rotlBL(curH, curL, 61);
      curH = s[18];
      curL = s[19];
      s[18] = Th;
      s[19] = Tl;
      Th = rotlSH(curH, curL, 20);
      Tl = rotlSL(curH, curL, 20);
      curH = s[12];
      curL = s[13];
      s[12] = Th;
      s[13] = Tl;
      Th = rotlBH(curH, curL, 44);
      Tl = rotlBL(curH, curL, 44);
      s[2] = Th;
      s[3] = Tl;
      for (let y = 0; y < 50; y += 10) {
        B[0] = s[y];
        B[1] = s[y + 1];
        B[2] = s[y + 2];
        B[3] = s[y + 3];
        B[4] = s[y + 4];
        B[5] = s[y + 5];
        B[6] = s[y + 6];
        B[7] = s[y + 7];
        B[8] = s[y + 8];
        B[9] = s[y + 9];
        s[y + 0] ^= ~B[2] & B[4];
        s[y + 1] ^= ~B[3] & B[5];
        s[y + 2] ^= ~B[4] & B[6];
        s[y + 3] ^= ~B[5] & B[7];
        s[y + 4] ^= ~B[6] & B[8];
        s[y + 5] ^= ~B[7] & B[9];
        s[y + 6] ^= ~B[8] & B[0];
        s[y + 7] ^= ~B[9] & B[1];
        s[y + 8] ^= ~B[0] & B[2];
        s[y + 9] ^= ~B[1] & B[3];
      }
      s[0] ^= SHA3_IOTA_H[round];
      s[1] ^= SHA3_IOTA_L[round];
    }
  }
  var Keccak = class _Keccak {
    // NOTE: we accept arguments in bytes instead of bits here.
    constructor(blockLen, suffix, outputLen, enableXOF = false, rounds = 24) {
      Object.defineProperty(this, "state", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "pos", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 0
      });
      Object.defineProperty(this, "posOut", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 0
      });
      Object.defineProperty(this, "finished", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: false
      });
      Object.defineProperty(this, "state32", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "destroyed", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: false
      });
      Object.defineProperty(this, "_B", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: new Uint32Array(10)
      });
      Object.defineProperty(this, "blockLen", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "suffix", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "outputLen", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "enableXOF", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: false
      });
      Object.defineProperty(this, "rounds", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      this.blockLen = blockLen;
      this.suffix = suffix;
      this.outputLen = outputLen;
      this.enableXOF = enableXOF;
      this.rounds = rounds;
      anumber(outputLen, "outputLen");
      if (!(0 < blockLen && blockLen < 200)) {
        throw new Error("only keccak-f1600 function is supported");
      }
      this.state = new Uint8Array(200);
      this.state32 = u32(this.state);
    }
    clone() {
      return this._cloneInto();
    }
    /** Resets instance to initial (empty) state for reuse. */
    reset() {
      this.state.fill(0);
      this.pos = 0;
      this.posOut = 0;
      this.finished = false;
      this.destroyed = false;
    }
    keccak() {
      swap32IfBE(this.state32);
      keccakP(this.state32, this.rounds, this._B);
      swap32IfBE(this.state32);
      this.posOut = 0;
      this.pos = 0;
    }
    update(data) {
      aexists(this);
      abytes(data);
      return this.updateUnsafe(data);
    }
    /** Like update(), but skips validation. Caller must ensure valid state and input. */
    updateUnsafe(data) {
      const { blockLen, state } = this;
      const len = data.length;
      for (let pos = 0; pos < len; ) {
        const take = Math.min(blockLen - this.pos, len - pos);
        for (let i = 0; i < take; i++)
          state[this.pos++] ^= data[pos++];
        if (this.pos === blockLen)
          this.keccak();
      }
      return this;
    }
    finish() {
      if (this.finished)
        return;
      this.finished = true;
      const { state, suffix, pos, blockLen } = this;
      state[pos] ^= suffix;
      if ((suffix & 128) !== 0 && pos === blockLen - 1)
        this.keccak();
      state[blockLen - 1] ^= 128;
      this.keccak();
    }
    writeInto(out) {
      aexists(this, false);
      abytes(out);
      return this.writeIntoUnsafe(out);
    }
    /** Like writeInto(), but skips validation. Caller must ensure valid state and output. */
    writeIntoUnsafe(out) {
      this.finish();
      const bufferOut = this.state;
      const { blockLen } = this;
      for (let pos = 0, len = out.length; pos < len; ) {
        if (this.posOut >= blockLen)
          this.keccak();
        const take = Math.min(blockLen - this.posOut, len - pos);
        out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
        this.posOut += take;
        pos += take;
      }
      return out;
    }
    xofInto(out) {
      if (!this.enableXOF) {
        throw new Error("XOF is not possible for this instance");
      }
      return this.writeInto(out);
    }
    xof(bytes) {
      anumber(bytes);
      return this.xofInto(new Uint8Array(bytes));
    }
    digestInto(out) {
      aoutput(out, this);
      if (this.finished)
        throw new Error("digest() was already called");
      this.writeInto(out);
      this.destroy();
      return out;
    }
    digest() {
      return this.digestInto(new Uint8Array(this.outputLen));
    }
    destroy() {
      this.destroyed = true;
      clean(this.state);
    }
    _cloneInto(to) {
      const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
      to ||= new _Keccak(blockLen, suffix, outputLen, enableXOF, rounds);
      to.state32.set(this.state32);
      to.pos = this.pos;
      to.posOut = this.posOut;
      to.finished = this.finished;
      to.rounds = rounds;
      to.suffix = suffix;
      to.outputLen = outputLen;
      to.enableXOF = enableXOF;
      to.destroyed = this.destroyed;
      return to;
    }
  };

  // node_modules/mlkem/esm/_dnt.shims.js
  var dntGlobals = {};
  var dntGlobalThis = createMergeProxy(globalThis, dntGlobals);
  function createMergeProxy(baseObj, extObj) {
    return new Proxy(baseObj, {
      get(_target, prop, _receiver) {
        if (prop in extObj) {
          return extObj[prop];
        } else {
          return baseObj[prop];
        }
      },
      set(_target, prop, value) {
        if (prop in extObj) {
          delete extObj[prop];
        }
        baseObj[prop] = value;
        return true;
      },
      deleteProperty(_target, prop) {
        let success = false;
        if (prop in extObj) {
          delete extObj[prop];
          success = true;
        }
        if (prop in baseObj) {
          delete baseObj[prop];
          success = true;
        }
        return success;
      },
      ownKeys(_target) {
        const baseKeys = Reflect.ownKeys(baseObj);
        const extKeys = Reflect.ownKeys(extObj);
        const extKeysSet = new Set(extKeys);
        return [...baseKeys.filter((k) => !extKeysSet.has(k)), ...extKeys];
      },
      defineProperty(_target, prop, desc) {
        if (prop in extObj) {
          delete extObj[prop];
        }
        Reflect.defineProperty(baseObj, prop, desc);
        return true;
      },
      getOwnPropertyDescriptor(_target, prop) {
        if (prop in extObj) {
          return Reflect.getOwnPropertyDescriptor(extObj, prop);
        } else {
          return Reflect.getOwnPropertyDescriptor(baseObj, prop);
        }
      },
      has(_target, prop) {
        return prop in extObj || prop in baseObj;
      }
    });
  }

  // node_modules/mlkem/esm/src/utils.js
  function byte(n) {
    return n & 255;
  }
  function int16(n) {
    return n << 16 >> 16;
  }
  function uint16(n) {
    return n & 65535;
  }
  function constantTimeCompare(x, y) {
    if (x.length != y.length) {
      return 0;
    }
    let v = 0;
    for (let i = 0; i < x.length; i++) {
      v |= x[i] ^ y[i];
    }
    let z = ~v & 255;
    z &= z >> 4;
    z &= z >> 2;
    z &= z >> 1;
    return z & 1;
  }
  function equalUint8Array(x, y) {
    if (x.length != y.length) {
      return false;
    }
    for (let i = 0; i < x.length; i++) {
      if (x[i] !== y[i]) {
        return false;
      }
    }
    return true;
  }
  async function loadCrypto() {
    if (typeof dntGlobalThis !== "undefined" && globalThis.crypto !== void 0) {
      return globalThis.crypto;
    }
    try {
      const { webcrypto } = await import("crypto");
      return webcrypto;
    } catch (_e) {
      throw new Error("failed to load Crypto");
    }
  }
  function byteopsLoad32(x, o = 0) {
    return (x[o] | x[o + 1] << 8 | x[o + 2] << 16 | x[o + 3] << 24) >>> 0;
  }

  // node_modules/mlkem/esm/src/mlKemBase.js
  var MlKemBase = class {
    /**
     * Creates a new instance of the MlKemBase class.
     */
    constructor() {
      Object.defineProperty(this, "_api", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "_k", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 0
      });
      Object.defineProperty(this, "_du", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 0
      });
      Object.defineProperty(this, "_dv", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 0
      });
      Object.defineProperty(this, "_eta1", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 0
      });
      Object.defineProperty(this, "_eta2", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 0
      });
      Object.defineProperty(this, "_skSize", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 0
      });
      Object.defineProperty(this, "_pkSize", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 0
      });
      Object.defineProperty(this, "_compressedUSize", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 0
      });
      Object.defineProperty(this, "_compressedVSize", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 0
      });
      Object.defineProperty(this, "_poolG", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "_poolH", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "_poolKdf", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "_poolXof", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "_poolPrf1", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "_poolPrf2", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "_bufG", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: new Uint8Array(64)
      });
      Object.defineProperty(this, "_bufH", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: new Uint8Array(32)
      });
      Object.defineProperty(this, "_bufKdf", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: new Uint8Array(32)
      });
      Object.defineProperty(this, "_bufXof", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: new Uint8Array(672)
      });
      Object.defineProperty(this, "_bufPrf1", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "_bufPrf2", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "_nonceBuf", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: new Uint8Array(1)
      });
      Object.defineProperty(this, "_xofSeed", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: new Uint8Array(34)
      });
      Object.defineProperty(this, "_kBuf", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "_matrixA", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "_noiseVecs", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "_polyVec", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "_bufPkCheck", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
      Object.defineProperty(this, "_bufCt", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: void 0
      });
    }
    _initPool() {
      this._poolG = new Keccak(72, 6, 64);
      this._poolH = new Keccak(136, 6, 32);
      this._poolKdf = new Keccak(136, 31, 32, true);
      this._poolXof = new Keccak(168, 31, 672, true);
      const prf1Len = this._eta1 * N / 4;
      this._poolPrf1 = new Keccak(136, 31, prf1Len, true);
      this._bufPrf1 = new Uint8Array(prf1Len);
      const prf2Len = this._eta2 * N / 4;
      this._poolPrf2 = new Keccak(136, 31, prf2Len, true);
      this._bufPrf2 = new Uint8Array(prf2Len);
      this._kBuf = new Uint8Array([this._k]);
      this._matrixA = new Array(this._k);
      for (let i = 0; i < this._k; i++) {
        this._matrixA[i] = new Array(this._k);
        for (let j = 0; j < this._k; j++) {
          this._matrixA[i][j] = new Int16Array(N);
        }
      }
      const maxNoise = 2 * this._k + 1;
      this._noiseVecs = new Array(maxNoise);
      for (let i = 0; i < maxNoise; i++) {
        this._noiseVecs[i] = new Int16Array(N);
      }
      this._polyVec = new Array(this._k);
      for (let i = 0; i < this._k; i++) {
        this._polyVec[i] = new Int16Array(N);
      }
      this._bufPkCheck = new Uint8Array(384 * this._k);
      this._bufCt = new Uint8Array(this._compressedUSize + this._compressedVSize);
    }
    _zeroPool() {
      this._bufG.fill(0);
      this._bufH.fill(0);
      this._bufKdf.fill(0);
      this._bufXof.fill(0);
      this._bufPrf1.fill(0);
      this._bufPrf2.fill(0);
      this._nonceBuf[0] = 0;
      this._xofSeed.fill(0);
      for (let i = 0; i < this._k; i++) {
        for (let j = 0; j < this._k; j++) {
          this._matrixA[i][j].fill(0);
        }
      }
      for (let i = 0; i < this._noiseVecs.length; i++) {
        this._noiseVecs[i].fill(0);
      }
      for (let i = 0; i < this._k; i++) {
        this._polyVec[i].fill(0);
      }
      this._bufPkCheck.fill(0);
      this._bufCt.fill(0);
      this._poolG.reset();
      this._poolH.reset();
      this._poolKdf.reset();
      this._poolXof.reset();
      this._poolPrf1.reset();
      this._poolPrf2.reset();
    }
    // Serialize polynomial into byte buffer at offset (eliminates intermediate Uint8Array(384))
    _polyToBytes(out, outOffset, a) {
      let t0, t1;
      for (let i = 0; i < N / 2; i++) {
        t0 = a[2 * i] - Q;
        t0 += t0 >> 31 & Q;
        t1 = a[2 * i + 1] - Q;
        t1 += t1 >> 31 & Q;
        out[outOffset + 3 * i + 0] = byte(t0);
        out[outOffset + 3 * i + 1] = byte(t0 >> 8) | byte(t1 << 4);
        out[outOffset + 3 * i + 2] = byte(t1 >> 4);
      }
    }
    // Deserialize bytes into polynomial (eliminates intermediate Int16Array(N))
    _polyFromBytes(out, a, aOffset) {
      for (let i = 0; i < N / 2; i++) {
        out[2 * i] = int16((uint16(a[aOffset + 3 * i + 0]) >> 0 | uint16(a[aOffset + 3 * i + 1]) << 8) & 4095);
        out[2 * i + 1] = int16((uint16(a[aOffset + 3 * i + 1]) >> 4 | uint16(a[aOffset + 3 * i + 2]) << 4) & 4095);
      }
    }
    // Hash G: SHA3-512
    _g(a, b) {
      this._poolG.reset();
      this._poolG.updateUnsafe(a);
      if (b !== void 0)
        this._poolG.updateUnsafe(b);
      this._poolG.writeIntoUnsafe(this._bufG);
      return [this._bufG.subarray(0, 32), this._bufG.subarray(32, 64)];
    }
    // Hash H: SHA3-256
    _h(msg) {
      this._poolH.reset();
      this._poolH.updateUnsafe(msg).writeIntoUnsafe(this._bufH);
      return this._bufH;
    }
    // KDF: SHAKE256(dkLen=32)
    _kdf(a, b) {
      this._poolKdf.reset();
      this._poolKdf.updateUnsafe(a);
      if (b !== void 0)
        this._poolKdf.updateUnsafe(b);
      this._poolKdf.writeIntoUnsafe(this._bufKdf);
      return this._bufKdf;
    }
    // XOF: SHAKE128(dkLen=672)
    _xof(seed) {
      this._poolXof.reset();
      this._poolXof.updateUnsafe(seed).writeIntoUnsafe(this._bufXof);
      return this._bufXof;
    }
    // PRF for eta1 noise sampling: SHAKE256(dkLen=eta1*N/4)
    _prf1(sigma, nonce) {
      this._nonceBuf[0] = nonce;
      this._poolPrf1.reset();
      this._poolPrf1.updateUnsafe(sigma).updateUnsafe(this._nonceBuf).writeIntoUnsafe(this._bufPrf1);
      return this._bufPrf1;
    }
    // PRF for eta2 noise sampling: SHAKE256(dkLen=eta2*N/4)
    _prf2(sigma, nonce) {
      this._nonceBuf[0] = nonce;
      this._poolPrf2.reset();
      this._poolPrf2.updateUnsafe(sigma).updateUnsafe(this._nonceBuf).writeIntoUnsafe(this._bufPrf2);
      return this._bufPrf2;
    }
    _generateKeyPairCore() {
      try {
        const rnd = new Uint8Array(64);
        this._api.getRandomValues(rnd);
        return this._deriveKeyPair(rnd);
      } finally {
        this._zeroPool();
      }
    }
    _deriveKeyPairCore(seed) {
      try {
        if (seed.byteLength !== 64) {
          throw new Error("seed must be 64 bytes in length");
        }
        return this._deriveKeyPair(seed);
      } finally {
        this._zeroPool();
      }
    }
    _encapCore(pk, seed) {
      try {
        if (pk.length !== 384 * this._k + 32) {
          throw new Error("invalid encapsulation key");
        }
        const m = this._getSeed(seed);
        const [k, r] = this._g(m, this._h(pk));
        this._encap(pk, m, r);
        return [this._bufCt.slice(), k.slice()];
      } finally {
        this._zeroPool();
      }
    }
    _decapCore(ct, sk) {
      try {
        if (ct.byteLength !== this._compressedUSize + this._compressedVSize) {
          throw new Error("Invalid ct size");
        }
        if (sk.length !== 768 * this._k + 96) {
          throw new Error("Invalid decapsulation key");
        }
        const sk2 = sk.subarray(0, this._skSize);
        const pk = sk.subarray(this._skSize, this._skSize + this._pkSize);
        const hpk = sk.subarray(this._skSize + this._pkSize, this._skSize + this._pkSize + 32);
        const z = sk.subarray(this._skSize + this._pkSize + 32, this._skSize + this._pkSize + 64);
        const m2 = this._decap(ct, sk2);
        const [k2, r2] = this._g(m2, hpk);
        const kBar = this._kdf(z, ct);
        this._encap(pk, m2, r2);
        return constantTimeCompare(ct, this._bufCt) === 1 ? k2.slice() : kBar.slice();
      } finally {
        this._zeroPool();
      }
    }
    /**
     * Sets up the MlKemBase instance by loading the necessary crypto library.
     * If the crypto library is already loaded, this method does nothing.
     * @returns {Promise<void>} A promise that resolves when the setup is complete.
     */
    async _setup() {
      if (this._api !== void 0) {
        return;
      }
      this._api = await loadCrypto();
    }
    /**
     * Returns a Uint8Array seed for cryptographic operations.
     * If no seed is provided, a random seed of length 32 bytes is generated.
     * If a seed is provided, it must be exactly 32 bytes in length.
     *
     * @param seed - Optional seed for cryptographic operations.
     * @returns A Uint8Array seed.
     * @throws Error if the provided seed is not 32 bytes in length.
     */
    _getSeed(seed) {
      if (seed == void 0) {
        const s = new Uint8Array(32);
        this._api.getRandomValues(s);
        return s;
      }
      if (seed.byteLength !== 32) {
        throw new Error("seed must be 32 bytes in length");
      }
      return seed;
    }
    /**
     * Derives a key pair from a given seed.
     *
     * @param seed - The seed used for key derivation.
     * @returns An array containing the public key and secret key.
     */
    _deriveKeyPair(seed) {
      const cpaSeed = seed.subarray(0, 32);
      const z = seed.subarray(32, 64);
      const [pk, skBody] = this._deriveCpaKeyPair(cpaSeed);
      const pkh = this._h(pk);
      const sk = new Uint8Array(this._skSize + this._pkSize + 64);
      sk.set(skBody, 0);
      sk.set(pk, this._skSize);
      sk.set(pkh, this._skSize + this._pkSize);
      sk.set(z, this._skSize + this._pkSize + 32);
      return [pk, sk];
    }
    // indcpaKeyGen generates public and private keys for the CPA-secure
    // public-key encryption scheme underlying ML-KEM.
    /**
     * Derives a CPA key pair using the provided CPA seed.
     *
     * @param cpaSeed - The CPA seed used for key derivation.
     * @returns An array containing the public key and private key.
     */
    _deriveCpaKeyPair(cpaSeed) {
      const [publicSeed, noiseSeed] = this._g(cpaSeed, this._kBuf);
      const a = this._sampleMatrix(publicSeed, false);
      const s = this._sampleNoise1(noiseSeed, 0, this._k);
      const e = this._sampleNoise1(noiseSeed, this._k, this._k);
      for (let i = 0; i < this._k; i++) {
        s[i] = ntt(s[i]);
        s[i] = reduce(s[i]);
        e[i] = ntt(e[i]);
      }
      const pk = new Array(this._k);
      for (let i = 0; i < this._k; i++) {
        pk[i] = polyToMont(multiply(a[i], s));
        pk[i] = add(pk[i], e[i]);
        pk[i] = reduce(pk[i]);
      }
      const pubKey = new Uint8Array(this._pkSize);
      for (let i = 0; i < this._k; i++) {
        this._polyToBytes(pubKey, i * 384, pk[i]);
      }
      pubKey.set(publicSeed, this._skSize);
      const privKey = new Uint8Array(this._skSize);
      for (let i = 0; i < this._k; i++) {
        this._polyToBytes(privKey, i * 384, s[i]);
      }
      return [pubKey, privKey];
    }
    // _encap is the encapsulation function of the CPA-secure
    // public-key encryption scheme underlying ML-KEM.
    /**
     * Encapsulates a message using the ML-KEM encryption scheme.
     *
     * @param pk - The public key.
     * @param msg - The message to be encapsulated.
     * @param seed - The seed used for generating random values.
     * @returns The encapsulated message as a Uint8Array.
     */
    _encap(pk, msg, seed) {
      const tHat = this._polyVec;
      const pkCheck = this._bufPkCheck;
      for (let i = 0; i < this._k; i++) {
        this._polyFromBytes(tHat[i], pk, i * 384);
        this._polyToBytes(pkCheck, i * 384, tHat[i]);
      }
      if (!equalUint8Array(pk.subarray(0, pkCheck.length), pkCheck)) {
        throw new Error("invalid encapsulation key");
      }
      const rho = pk.subarray(this._skSize);
      const a = this._sampleMatrix(rho, true);
      const r = this._sampleNoise1(seed, 0, this._k);
      const e1 = this._sampleNoise2(seed, this._k, this._k);
      const e2 = this._sampleNoise2(seed, this._k * 2, 1)[0];
      for (let i = 0; i < this._k; i++) {
        r[i] = ntt(r[i]);
        r[i] = reduce(r[i]);
      }
      const u = new Array(this._k);
      for (let i = 0; i < this._k; i++) {
        u[i] = multiply(a[i], r);
        u[i] = nttInverse(u[i]);
        u[i] = add(u[i], e1[i]);
        u[i] = reduce(u[i]);
      }
      const m = polyFromMsg(msg);
      let v = multiply(tHat, r);
      v = nttInverse(v);
      v = add(v, e2);
      v = add(v, m);
      v = reduce(v);
      this._compressU(this._bufCt.subarray(0, this._compressedUSize), u);
      this._compressV(this._bufCt.subarray(this._compressedUSize), v);
      return this._bufCt;
    }
    // indcpaDecrypt is the decryption function of the CPA-secure
    // public-key encryption scheme underlying ML-KEM.
    /**
     * Decapsulates the ciphertext using the provided secret key.
     *
     * @param ct - The ciphertext to be decapsulated.
     * @param sk - The secret key used for decapsulation.
     * @returns The decapsulated message as a Uint8Array.
     */
    _decap(ct, sk) {
      const u = this._decompressU(ct.subarray(0, this._compressedUSize));
      const v = this._decompressV(ct.subarray(this._compressedUSize));
      const privateKeyPolyvec = this._polyvecFromBytes(sk);
      for (let i = 0; i < this._k; i++) {
        u[i] = ntt(u[i]);
      }
      let mp = multiply(privateKeyPolyvec, u);
      mp = nttInverse(mp);
      mp = subtract(v, mp);
      mp = reduce(mp);
      return polyToMsg(mp);
    }
    // generateMatrixA deterministically generates a matrix `A` (or the transpose of `A`)
    // from a seed. Entries of the matrix are polynomials that look uniformly random.
    // Performs rejection sampling on the output of an extendable-output function (XOF).
    /**
     * Generates a sample matrix based on the provided seed and transposition flag.
     *
     * @param seed - The seed used for generating the matrix.
     * @param transposed - A flag indicating whether the matrix should be transposed or not.
     * @returns The generated sample matrix.
     */
    _sampleMatrix(seed, transposed) {
      const a = this._matrixA;
      this._xofSeed.set(seed);
      for (let ctr = 0, i = 0; i < this._k; i++) {
        for (let j = 0; j < this._k; j++) {
          if (transposed) {
            this._xofSeed[seed.length] = i;
            this._xofSeed[seed.length + 1] = j;
          } else {
            this._xofSeed[seed.length] = j;
            this._xofSeed[seed.length + 1] = i;
          }
          const output = this._xof(this._xofSeed);
          ctr = indcpaRejUniform(a[i][j], 0, output.subarray(0, 504), 504, N);
          while (ctr < N) {
            const outputn = output.subarray(504, 672);
            ctr += indcpaRejUniform(a[i][j], ctr, outputn, 168, N - ctr);
          }
        }
      }
      return a;
    }
    /**
     * Generates a 2D array of noise samples.
     *
     * @param sigma - The noise parameter.
     * @param offset - The offset value.
     * @param size - The size of the array.
     * @returns The generated 2D array of noise samples.
     */
    _sampleNoise1(sigma, offset, size) {
      const r = new Array(size);
      for (let i = 0; i < size; i++) {
        r[i] = this._noiseVecs[offset + i];
        byteopsCbd(r[i], this._prf1(sigma, offset + i), this._eta1);
      }
      return r;
    }
    /**
     * Generates a 2-dimensional array of noise samples.
     *
     * @param sigma - The noise parameter.
     * @param offset - The offset value.
     * @param size - The size of the array.
     * @returns The generated 2-dimensional array of noise samples.
     */
    _sampleNoise2(sigma, offset, size) {
      const r = new Array(size);
      for (let i = 0; i < size; i++) {
        r[i] = this._noiseVecs[offset + i];
        byteopsCbd(r[i], this._prf2(sigma, offset + i), this._eta2);
      }
      return r;
    }
    // polyvecFromBytes deserializes a vector of polynomials.
    /**
     * Converts a Uint8Array to a 2D array of numbers representing a polynomial vector.
     * Each element in the resulting array represents a polynomial.
     * @param a The Uint8Array to convert.
     * @returns The 2D array of numbers representing the polynomial vector.
     */
    _polyvecFromBytes(a) {
      const r = this._polyVec;
      for (let i = 0; i < this._k; i++) {
        this._polyFromBytes(r[i], a, i * 384);
      }
      return r;
    }
    // compressU lossily compresses and serializes a vector of polynomials.
    /**
     * Compresses the given array of coefficients into a Uint8Array.
     *
     * @param r - The output Uint8Array.
     * @param u - The array of coefficients.
     * @returns The compressed Uint8Array.
     */
    _compressU(r, u) {
      const t = new Array(4);
      for (let rr = 0, i = 0; i < this._k; i++) {
        for (let j = 0; j < N / 4; j++) {
          for (let k = 0; k < 4; k++) {
            t[k] = ((u[i][4 * j + k] << 10) + Q / 2) / Q & 1023;
          }
          r[rr++] = byte(t[0] >> 0);
          r[rr++] = byte(t[0] >> 8 | t[1] << 2);
          r[rr++] = byte(t[1] >> 6 | t[2] << 4);
          r[rr++] = byte(t[2] >> 4 | t[3] << 6);
          r[rr++] = byte(t[3] >> 2);
        }
      }
      return r;
    }
    // compressV lossily compresses and subsequently serializes a polynomial.
    /**
     * Compresses the given array of numbers into a Uint8Array.
     *
     * @param r - The Uint8Array to store the compressed values.
     * @param v - The array of numbers to compress.
     * @returns The compressed Uint8Array.
     */
    _compressV(r, v) {
      const t = new Uint8Array(8);
      for (let rr = 0, i = 0; i < N / 8; i++) {
        for (let j = 0; j < 8; j++) {
          t[j] = byte(((v[8 * i + j] << 4) + Q / 2) / Q) & 15;
        }
        r[rr++] = t[0] | t[1] << 4;
        r[rr++] = t[2] | t[3] << 4;
        r[rr++] = t[4] | t[5] << 4;
        r[rr++] = t[6] | t[7] << 4;
      }
      return r;
    }
    // decompressU de-serializes and decompresses a vector of polynomials and
    // represents the approximate inverse of compress1. Since compression is lossy,
    // the results of decompression will may not match the original vector of polynomials.
    /**
     * Decompresses a Uint8Array into a two-dimensional array of numbers.
     *
     * @param a The Uint8Array to decompress.
     * @returns The decompressed two-dimensional array.
     */
    _decompressU(a) {
      const r = new Array(this._k);
      for (let i = 0; i < this._k; i++) {
        r[i] = new Int16Array(N);
      }
      const t = new Array(4);
      for (let aa = 0, i = 0; i < this._k; i++) {
        for (let j = 0; j < N / 4; j++) {
          t[0] = uint16(a[aa + 0]) >> 0 | uint16(a[aa + 1]) << 8;
          t[1] = uint16(a[aa + 1]) >> 2 | uint16(a[aa + 2]) << 6;
          t[2] = uint16(a[aa + 2]) >> 4 | uint16(a[aa + 3]) << 4;
          t[3] = uint16(a[aa + 3]) >> 6 | uint16(a[aa + 4]) << 2;
          aa = aa + 5;
          for (let k = 0; k < 4; k++) {
            r[i][4 * j + k] = int16((t[k] & 1023) * Q + 512 >> 10);
          }
        }
      }
      return r;
    }
    // decompressV de-serializes and subsequently decompresses a polynomial,
    // representing the approximate inverse of compress2.
    // Note that compression is lossy, and thus decompression will not match the
    // original input.
    /**
     * Decompresses a Uint8Array into an array of numbers.
     *
     * @param a - The Uint8Array to decompress.
     * @returns An array of numbers.
     */
    _decompressV(a) {
      const r = new Int16Array(N);
      for (let aa = 0, i = 0; i < N / 2; i++, aa++) {
        r[2 * i + 0] = int16((a[aa] & 15) * Q + 8 >> 4);
        r[2 * i + 1] = int16((a[aa] >> 4) * Q + 8 >> 4);
      }
      return r;
    }
  };
  function polyToMsg(a) {
    const msg = new Uint8Array(32);
    let t, v;
    for (let i = 0; i < N / 8; i++) {
      for (let j = 0; j < 8; j++) {
        v = a[8 * i + j] - Q;
        v += v >> 31 & Q;
        t = ((uint16(v) << 1) + uint16(Q / 2)) / uint16(Q) & 1;
        msg[i] |= byte(t << j);
      }
    }
    return msg;
  }
  function polyFromMsg(msg) {
    const r = new Int16Array(N);
    let mask;
    for (let i = 0; i < N / 8; i++) {
      for (let j = 0; j < 8; j++) {
        mask = -1 * int16(msg[i] >> j & 1);
        r[8 * i + j] = mask & int16((Q + 1) / 2);
      }
    }
    return r;
  }
  function indcpaRejUniform(out, outOffset, buf, bufl, len) {
    let ctr = 0;
    let val0, val1;
    for (let pos = 0; ctr < len && pos + 3 <= bufl; ) {
      val0 = (uint16(buf[pos] >> 0) | uint16(buf[pos + 1]) << 8) & 4095;
      val1 = (uint16(buf[pos + 1] >> 4) | uint16(buf[pos + 2]) << 4) & 4095;
      pos = pos + 3;
      if (val0 < Q) {
        out[outOffset + ctr] = val0;
        ctr = ctr + 1;
      }
      if (ctr < len && val1 < Q) {
        out[outOffset + ctr] = val1;
        ctr = ctr + 1;
      }
    }
    return ctr;
  }
  function byteopsCbd(out, buf, eta) {
    let t, d;
    let a, b;
    for (let i = 0; i < N / 8; i++) {
      t = byteopsLoad32(buf, 4 * i);
      d = t & 1431655765;
      d = d + (t >> 1 & 1431655765);
      for (let j = 0; j < 8; j++) {
        a = int16(d >> 4 * j + 0 & 3);
        b = int16(d >> 4 * j + eta & 3);
        out[8 * i + j] = a - b;
      }
    }
  }
  function ntt(r) {
    for (let j = 0, k = 1, l = 128; l >= 2; l >>= 1) {
      for (let start = 0; start < 256; start = j + l) {
        const zeta = NTT_ZETAS[k];
        k = k + 1;
        for (j = start; j < start + l; j++) {
          const t = nttFqMul(zeta, r[j + l]);
          r[j + l] = r[j] - t;
          r[j] = r[j] + t;
        }
      }
    }
    return r;
  }
  function nttFqMul(a, b) {
    const ab = a * b;
    const u = Math.imul(ab, Q_INV) << 16 >> 16;
    return ab - u * Q >> 16;
  }
  function reduce(r) {
    for (let i = 0; i < N; i++) {
      r[i] = barrett(r[i]);
    }
    return r;
  }
  var BARRETT_V = ((1 << 24) + Q / 2) / Q;
  function barrett(a) {
    let t = BARRETT_V * a >> 24;
    t = t * Q;
    return a - t;
  }
  function polyToMont(r) {
    const f = 1353;
    for (let i = 0; i < N; i++) {
      const a = r[i] * f;
      const u = Math.imul(a, Q_INV) << 16 >> 16;
      r[i] = a - u * Q >> 16;
    }
    return r;
  }
  function multiply(a, b) {
    let r = polyBaseMulMontgomery(a[0], b[0]);
    let t;
    for (let i = 1; i < a.length; i++) {
      t = polyBaseMulMontgomery(a[i], b[i]);
      r = add(r, t);
    }
    return reduce(r);
  }
  function polyBaseMulMontgomery(a, b) {
    for (let i = 0; i < N / 4; i++) {
      const idx = 4 * i;
      const a0 = a[idx], a1 = a[idx + 1], a2 = a[idx + 2], a3 = a[idx + 3];
      const b0 = b[idx], b1 = b[idx + 1], b2 = b[idx + 2], b3 = b[idx + 3];
      const zeta = NTT_ZETAS[64 + i];
      a[idx] = nttFqMul(nttFqMul(a1, b1), zeta) + nttFqMul(a0, b0);
      a[idx + 1] = nttFqMul(a0, b1) + nttFqMul(a1, b0);
      a[idx + 2] = nttFqMul(nttFqMul(a3, b3), -zeta) + nttFqMul(a2, b2);
      a[idx + 3] = nttFqMul(a2, b3) + nttFqMul(a3, b2);
    }
    return a;
  }
  function add(a, b) {
    for (let i = 0; i < N; i++) {
      a[i] += b[i];
    }
    return a;
  }
  function subtract(a, b) {
    for (let i = 0; i < N; i++) {
      a[i] -= b[i];
    }
    return a;
  }
  function nttInverse(r) {
    let j = 0;
    for (let k = 0, l = 2; l <= 128; l <<= 1) {
      for (let start = 0; start < 256; start = j + l) {
        const zeta = NTT_ZETAS_INV[k];
        k = k + 1;
        for (j = start; j < start + l; j++) {
          const t = r[j];
          r[j] = barrett(t + r[j + l]);
          r[j + l] = t - r[j + l];
          r[j + l] = nttFqMul(zeta, r[j + l]);
        }
      }
    }
    for (j = 0; j < 256; j++) {
      r[j] = nttFqMul(r[j], NTT_ZETAS_INV[127]);
    }
    return r;
  }

  // node_modules/mlkem/esm/src/mlKem768.js
  var MlKem768 = class extends MlKemBase {
    constructor() {
      super();
      Object.defineProperty(this, "_k", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 3
      });
      Object.defineProperty(this, "_du", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 10
      });
      Object.defineProperty(this, "_dv", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 4
      });
      Object.defineProperty(this, "_eta1", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 2
      });
      Object.defineProperty(this, "_eta2", {
        enumerable: true,
        configurable: true,
        writable: true,
        value: 2
      });
      this._skSize = 12 * this._k * N / 8;
      this._pkSize = this._skSize + 32;
      this._compressedUSize = this._k * this._du * N / 8;
      this._compressedVSize = this._dv * N / 8;
      this._initPool();
    }
    /**
     * Generates a keypair [publicKey, privateKey].
     *
     * If an error occurred, throws {@link MlKemError}.
     *
     * @returns A kaypair [publicKey, privateKey].
     * @throws {@link MlKemError}
     */
    async generateKeyPair() {
      await this._setup();
      try {
        return this._generateKeyPairCore();
      } catch (e) {
        throw new MlKemError(e);
      }
    }
    /**
     * Derives a keypair [publicKey, privateKey] deterministically from a 64-octet seed.
     *
     * If an error occurred, throws {@link MlKemError}.
     *
     * @param seed A 64-octet seed for the deterministic key generation.
     * @returns A kaypair [publicKey, privateKey].
     * @throws {@link MlKemError}
     */
    async deriveKeyPair(seed) {
      await this._setup();
      try {
        return this._deriveKeyPairCore(seed);
      } catch (e) {
        throw new MlKemError(e);
      }
    }
    /**
     * Generates a shared secret from the encapsulated ciphertext and the private key.
     *
     * If an error occurred, throws {@link MlKemError}.
     *
     * @param pk A public key.
     * @param seed An optional 32-octet seed for the deterministic shared secret generation.
     * @returns A ciphertext (encapsulated public key) and a shared secret.
     * @throws {@link MlKemError}
     */
    async encap(pk, seed) {
      await this._setup();
      try {
        return this._encapCore(pk, seed);
      } catch (e) {
        throw new MlKemError(e);
      }
    }
    /**
     * Generates a ciphertext for the public key and a shared secret.
     *
     * If an error occurred, throws {@link MlKemError}.
     *
     * @param ct A ciphertext generated by {@link encap}.
     * @param sk A private key.
     * @returns A shared secret.
     * @throws {@link MlKemError}
     */
    async decap(ct, sk) {
      await this._setup();
      try {
        return this._decapCore(ct, sk);
      } catch (e) {
        throw new MlKemError(e);
      }
    }
  };

  // mozilla/src/background/pqc-env.js
  if (!globalThis.MLKEM768) globalThis.MLKEM768 = { MlKem768 };

  // mozilla/src/crypto/engine.js
  var engine_exports = {};
  __export(engine_exports, {
    b642buf: () => b642buf,
    buf2b64: () => buf2b64,
    buf2hex: () => buf2hex,
    buf2str: () => buf2str,
    decryptGroupMessage: () => decryptGroupMessage,
    decryptGroupMessageV2WithSender: () => decryptGroupMessageV2WithSender,
    decryptMessage: () => decryptMessage,
    decryptMessageV2: () => decryptMessageV2,
    deriveEcdhBits: () => deriveEcdhBits,
    derivePassKey: () => derivePassKey,
    deriveSharedKey: () => deriveSharedKey,
    encryptGroupMessage: () => encryptGroupMessage,
    encryptGroupMessageV2: () => encryptGroupMessageV2,
    encryptMessage: () => encryptMessage,
    encryptMessageV2: () => encryptMessageV2,
    exportPrivateKey: () => exportPrivateKey,
    exportPublicKey: () => exportPublicKey,
    generateIdentityKeypair: () => generateIdentityKeypair,
    hkdfAesGcmKey: () => hkdfAesGcmKey,
    hkdfAesKwKey: () => hkdfAesKwKey,
    importPrivateKey: () => importPrivateKey,
    importPublicKey: () => importPublicKey,
    isGpgArmor: () => isGpgArmor,
    isGroupMessage: () => isGroupMessage,
    isPqcAvailable: () => isPqcAvailable,
    isV1Message: () => isV1Message,
    isV2GroupMessage: () => isV2GroupMessage,
    isV2Message: () => isV2Message,
    keyFingerprint: () => keyFingerprint,
    mlkemGenerateKeypair: () => mlkemGenerateKeypair,
    openpgpFingerprint: () => openpgpFingerprint,
    parseGpgPublicKey: () => parseGpgPublicKey,
    str2buf: () => str2buf
  });
  function buf2b64(buf) {
    const bytes = new Uint8Array(buf);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }
  function b642buf(str) {
    const bin = atob(str);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
  }
  function str2buf(str) {
    return new TextEncoder().encode(str).buffer;
  }
  function buf2str(buf) {
    return new TextDecoder().decode(buf);
  }
  function buf2hex(buf) {
    return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  var ALGO_ECDH = { name: "ECDH", namedCurve: "P-256" };
  var ALGO_AES = { name: "AES-GCM", length: 256 };
  var ALGO_WRAP = { name: "AES-KW", length: 256 };
  async function generateIdentityKeypair() {
    return crypto.subtle.generateKey(ALGO_ECDH, true, ["deriveKey", "deriveBits"]);
  }
  async function exportPublicKey(key) {
    return buf2b64(await crypto.subtle.exportKey("spki", key));
  }
  async function exportPrivateKey(key) {
    return buf2b64(await crypto.subtle.exportKey("pkcs8", key));
  }
  async function importPublicKey(b64, namedCurve = "P-256") {
    return crypto.subtle.importKey(
      "spki",
      b642buf(b64),
      { name: "ECDH", namedCurve },
      true,
      []
    );
  }
  async function importPrivateKey(b64) {
    return crypto.subtle.importKey(
      "pkcs8",
      b642buf(b64),
      ALGO_ECDH,
      true,
      ["deriveKey", "deriveBits"]
    );
  }
  async function deriveSharedKey(ourPrivateKey, theirPublicKey) {
    return crypto.subtle.deriveKey(
      { name: "ECDH", public: theirPublicKey },
      ourPrivateKey,
      ALGO_AES,
      false,
      ["encrypt", "decrypt"]
    );
  }
  async function deriveEcdhBits(ourPrivateKey, theirPublicKey) {
    const bits = await crypto.subtle.deriveBits(
      { name: "ECDH", public: theirPublicKey },
      ourPrivateKey,
      256
    );
    return new Uint8Array(bits);
  }
  async function keyFingerprint(publicKeyB64) {
    return buf2hex(await crypto.subtle.digest("SHA-256", b642buf(publicKeyB64)));
  }
  async function hkdfBits(ikm, info, lengthBytes = 32) {
    const baseKey = await crypto.subtle.importKey(
      "raw",
      ikm,
      "HKDF",
      false,
      ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: str2buf(info) },
      baseKey,
      lengthBytes * 8
    );
    return new Uint8Array(bits);
  }
  async function hkdfAesGcmKey(ikm, info, usage = ["encrypt", "decrypt"]) {
    const raw = await hkdfBits(ikm, info);
    return crypto.subtle.importKey("raw", raw, ALGO_AES, false, usage);
  }
  async function hkdfAesKwKey(ikm, info, usage = ["wrapKey", "unwrapKey"]) {
    const raw = await hkdfBits(ikm, info);
    return crypto.subtle.importKey("raw", raw, ALGO_WRAP, false, usage);
  }
  var WIRE_V1_REGEX = /^CIPHERTEXT_V1:([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+)$/;
  async function encryptMessage(plaintext, sharedKey, senderPubKeyB64) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, sharedKey, str2buf(plaintext));
    return ["CIPHERTEXT_V1", buf2b64(iv.buffer), buf2b64(enc), senderPubKeyB64].join(":");
  }
  async function decryptMessage(wireText, sharedKey) {
    const m = wireText.match(WIRE_V1_REGEX);
    if (!m) throw new Error("Not a valid ciphertext V1 message");
    const [, ivB64, cipB64, senderPubKeyB64] = m;
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(b642buf(ivB64)) },
      sharedKey,
      b642buf(cipB64)
    );
    return { plaintext: buf2str(plain), senderPubKeyB64 };
  }
  function isV1Message(text) {
    return typeof text === "string" && WIRE_V1_REGEX.test(text.trim());
  }
  var WIRE_GRP_REGEX = /^CIPHERTEXT_GRP_V1:([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+)$/;
  async function encryptGroupMessage(plaintext, senderPubKeyB64, senderPrivateKey, recipients) {
    const dek = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const body = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, dek, str2buf(plaintext));
    const slots = [];
    for (const r of recipients) {
      try {
        const pub = await importPublicKey(r.publicKeyB64, r.curve);
        const wkey = await crypto.subtle.deriveKey(
          { name: "ECDH", public: pub },
          senderPrivateKey,
          ALGO_WRAP,
          false,
          ["wrapKey", "unwrapKey"]
        );
        const wdek = await crypto.subtle.wrapKey("raw", dek, wkey, { name: "AES-KW" });
        slots.push({ h: r.handle, p: r.publicKeyB64, dek: buf2b64(wdek) });
      } catch (e) {
        console.warn("[ciphertext] Skipping recipient:", r.handle, e.message);
      }
    }
    if (!slots.length) throw new Error("No valid recipients");
    const msgIdBuf = await crypto.subtle.digest("SHA-256", str2buf(buf2b64(body) + Date.now()));
    const msgId = buf2b64(msgIdBuf.slice(0, 8));
    const slotsB64 = buf2b64(str2buf(JSON.stringify(slots)));
    return ["CIPHERTEXT_GRP_V1", msgId, buf2b64(iv.buffer), buf2b64(body), slotsB64].join(":");
  }
  async function decryptGroupMessage(wireText, ourPubKeyB64, ourPrivateKey, senderPubKeyB64) {
    const m = wireText.match(WIRE_GRP_REGEX);
    if (!m) throw new Error("Not a valid ciphertext group message");
    const [, , ivB64, bodyB64, slotsB64] = m;
    const slots = JSON.parse(buf2str(b642buf(slotsB64)));
    const mySlot = slots.find((s) => s.p === ourPubKeyB64);
    if (!mySlot) throw new Error("No slot for your key in this group message");
    const senderPub = await importPublicKey(senderPubKeyB64);
    const wkey = await crypto.subtle.deriveKey(
      { name: "ECDH", public: senderPub },
      ourPrivateKey,
      ALGO_WRAP,
      false,
      ["wrapKey", "unwrapKey"]
    );
    const dek = await crypto.subtle.unwrapKey(
      "raw",
      b642buf(mySlot.dek),
      wkey,
      { name: "AES-KW" },
      ALGO_AES,
      false,
      ["encrypt", "decrypt"]
    );
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(b642buf(ivB64)) },
      dek,
      b642buf(bodyB64)
    );
    return {
      plaintext: buf2str(plain),
      slotCount: slots.length,
      recipientHandles: slots.map((s) => s.h),
      senderPubKeyB64
    };
  }
  function isGroupMessage(text) {
    return typeof text === "string" && WIRE_GRP_REGEX.test(text.trim());
  }
  var WIRE_V2_REGEX = /^CIPHERTEXT_V2:([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+)$/;
  var WIRE_GRP2_REGEX = /^CIPHERTEXT_GRPV2:([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+)$/;
  var V2_INFO = "ciphertext-V2";
  function isPqcAvailable() {
    return !!globalThis.MLKEM768?.MlKem768;
  }
  function requirePqc() {
    if (!isPqcAvailable()) throw new Error("ML-KEM bundle not loaded");
    return new globalThis.MLKEM768.MlKem768();
  }
  async function mlkemGenerateKeypair() {
    const kem = requirePqc();
    const [pk, sk] = await kem.generateKeyPair();
    return { mlkemPk: pk, mlkemSk: sk };
  }
  function combineSecrets(ecdhSecret, mlkemSecret) {
    const combined = new Uint8Array(ecdhSecret.length + mlkemSecret.length);
    combined.set(ecdhSecret);
    combined.set(mlkemSecret, ecdhSecret.length);
    return combined;
  }
  async function v2Info(senderPubB64, recipientPubB64, mlkemCtB64) {
    const h = await crypto.subtle.digest(
      "SHA-256",
      str2buf(`${V2_INFO}|${senderPubB64}|${recipientPubB64}|${mlkemCtB64}`)
    );
    return `${V2_INFO}|${buf2hex(h)}`;
  }
  async function encryptMessageV2(plaintext, senderEcdhPubB64, senderEcdhPriv, recipientEcdhPubB64, recipientMlkemPk) {
    const recipientEcdhPub = await importPublicKey(recipientEcdhPubB64);
    const ecdhSecret = await deriveEcdhBits(senderEcdhPriv, recipientEcdhPub);
    const kem = requirePqc();
    const [mlkemCt, mlkemSecret] = await kem.encap(recipientMlkemPk);
    const mlkemCtB64 = buf2b64(mlkemCt.buffer);
    const hybridKey = await hkdfAesGcmKey(
      combineSecrets(ecdhSecret, mlkemSecret),
      await v2Info(senderEcdhPubB64, recipientEcdhPubB64, mlkemCtB64)
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const bodyBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, hybridKey, str2buf(plaintext));
    return ["CIPHERTEXT_V2", buf2b64(iv.buffer), buf2b64(bodyBuf), senderEcdhPubB64, mlkemCtB64].join(":");
  }
  async function decryptMessageV2(wireText, recipientEcdhPriv, senderEcdhPubB64, recipientMlkemSk, recipientEcdhPubB64) {
    const m = wireText.match(WIRE_V2_REGEX);
    if (!m) throw new Error("Not a valid ciphertext V2 message");
    const [, ivB64, bodyB64, embeddedSenderPub, mlkemCtB64] = m;
    const senderPubToUse = senderEcdhPubB64 || embeddedSenderPub;
    if (!senderPubToUse) throw new Error("No sender key available");
    const senderEcdhPub = await importPublicKey(senderPubToUse);
    const ecdhSecret = await deriveEcdhBits(recipientEcdhPriv, senderEcdhPub);
    const mlkemCt = new Uint8Array(b642buf(mlkemCtB64));
    const kem = requirePqc();
    const mlkemSecret = await kem.decap(mlkemCt, recipientMlkemSk);
    const hybridKey = await hkdfAesGcmKey(
      combineSecrets(ecdhSecret, mlkemSecret),
      await v2Info(senderPubToUse, recipientEcdhPubB64, mlkemCtB64)
    );
    const plainBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(b642buf(ivB64)) },
      hybridKey,
      b642buf(bodyB64)
    );
    return { plaintext: buf2str(plainBuf), senderEcdhPubB64: senderPubToUse };
  }
  function isV2Message(t) {
    return typeof t === "string" && WIRE_V2_REGEX.test(t.trim());
  }
  async function encryptGroupMessageV2(plaintext, senderEcdhPubB64, senderEcdhPriv, recipients) {
    const dek = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const bodyBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, dek, str2buf(plaintext));
    const slots = [];
    for (const r of recipients) {
      try {
        const recipientEcdhPub = await importPublicKey(r.ecdhPubB64);
        const ecdhSecret = await deriveEcdhBits(senderEcdhPriv, recipientEcdhPub);
        const kem = requirePqc();
        const mlkemPk = new Uint8Array(b642buf(r.mlkemPkB64));
        const [mlkemCt, mlkemSecret] = await kem.encap(mlkemPk);
        const mlkemCtB64 = buf2b64(mlkemCt.buffer);
        const wrapKey = await hkdfAesKwKey(
          combineSecrets(ecdhSecret, mlkemSecret),
          await v2Info(senderEcdhPubB64, r.ecdhPubB64, mlkemCtB64)
        );
        const wrappedDek = await crypto.subtle.wrapKey("raw", dek, wrapKey, { name: "AES-KW" });
        slots.push({
          h: r.handle,
          ecdhPub: r.ecdhPubB64,
          mlkemCt: mlkemCtB64,
          wrappedDek: buf2b64(wrappedDek)
        });
      } catch (e) {
        console.warn("[CC PQC] skip group recipient", r.handle, e.message);
      }
    }
    if (!slots.length) throw new Error("No valid recipients for V2 group message");
    const msgIdBuf = await crypto.subtle.digest("SHA-256", str2buf(buf2b64(bodyBuf) + Date.now()));
    const msgId = buf2b64(msgIdBuf.slice(0, 8));
    const slotsB64 = buf2b64(str2buf(JSON.stringify(slots)));
    return ["CIPHERTEXT_GRPV2", msgId, buf2b64(iv.buffer), buf2b64(bodyBuf), slotsB64].join(":");
  }
  async function decryptGroupMessageV2WithSender(wireText, ourEcdhPubB64, ourEcdhPriv, ourMlkemSkB64, senderEcdhPubB64) {
    const m = wireText.match(WIRE_GRP2_REGEX);
    if (!m) throw new Error("Not a valid V2 group message");
    const [, , ivB64, bodyB64, slotsB64] = m;
    const slots = JSON.parse(buf2str(b642buf(slotsB64)));
    const mySlot = slots.find((s) => s.ecdhPub === ourEcdhPubB64);
    if (!mySlot) throw new Error("No slot for your key in this group message");
    const senderEcdhPub = await importPublicKey(senderEcdhPubB64);
    const ecdhSecret = await deriveEcdhBits(ourEcdhPriv, senderEcdhPub);
    const mlkemCt = new Uint8Array(b642buf(mySlot.mlkemCt));
    const mlkemSk = new Uint8Array(b642buf(ourMlkemSkB64));
    const kem = requirePqc();
    const mlkemSecret = await kem.decap(mlkemCt, mlkemSk);
    const unwrapKey = await hkdfAesKwKey(
      combineSecrets(ecdhSecret, mlkemSecret),
      await v2Info(senderEcdhPubB64, ourEcdhPubB64, mySlot.mlkemCt)
    );
    const dek = await crypto.subtle.unwrapKey(
      "raw",
      b642buf(mySlot.wrappedDek),
      unwrapKey,
      { name: "AES-KW" },
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(b642buf(ivB64)) },
      dek,
      b642buf(bodyB64)
    );
    return {
      plaintext: buf2str(plain),
      slotCount: slots.length,
      recipientHandles: slots.map((s) => s.h),
      senderEcdhPubB64
    };
  }
  function isV2GroupMessage(t) {
    return typeof t === "string" && WIRE_GRP2_REGEX.test(t.trim());
  }
  var OID_MAP = {
    "2a8648ce3d030107": { curve: "P-256", subtle: true },
    "2b81040022": { curve: "P-384", subtle: true },
    "2b81040023": { curve: "P-521", subtle: true },
    "2b060104019755010501": { curve: "X25519", subtle: false },
    "2b06010401da470f01": { curve: "Ed25519", subtle: false }
  };
  var SPKI_HDR = {
    "P-256": new Uint8Array([48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66, 0]),
    "P-384": new Uint8Array([48, 118, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 34, 3, 98, 0]),
    "P-521": new Uint8Array([48, 129, 155, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 35, 3, 134, 0])
  };
  function dearmor(armored) {
    const lines = armored.replace(/\r\n/g, "\n").split("\n");
    const b64 = [];
    let inBody = false;
    for (const line of lines) {
      if (line.startsWith("-----BEGIN")) {
        inBody = true;
        continue;
      }
      if (line.startsWith("-----END")) {
        break;
      }
      if (!inBody || line.startsWith("=") || line.trim() === "") continue;
      if (/^[A-Za-z0-9+/=]+$/.test(line.trim())) b64.push(line.trim());
    }
    return b642buf(b64.join(""));
  }
  function readMPI(view, off) {
    const bits = view.getUint16(off);
    off += 2;
    const byteLen = Math.ceil(bits / 8);
    return { bytes: new Uint8Array(view.buffer, view.byteOffset + off, byteLen), next: off + byteLen };
  }
  function buildEcSpki(curve, point) {
    const hdr = SPKI_HDR[curve];
    if (!hdr) return null;
    const p = point[0] === 64 ? new Uint8Array([4, ...point.slice(1)]) : point;
    const out = new Uint8Array(hdr.length + p.length);
    out.set(hdr);
    out.set(p, hdr.length);
    return out.buffer;
  }
  function parsePgpKeyPacket(buf) {
    const v = new DataView(buf);
    let off = 0;
    const ver = v.getUint8(off++);
    if (ver !== 4 && ver !== 5) return { type: "unsupported", reason: `PGP version ${ver}` };
    off += 4;
    const algo = v.getUint8(off++);
    if (algo === 18 || algo === 22 || algo === 19) {
      const olen = v.getUint8(off++);
      const obytes = new Uint8Array(buf, off, olen);
      off += olen;
      const ohex = Array.from(obytes).map((b) => b.toString(16).padStart(2, "0")).join("");
      const ci = OID_MAP[ohex];
      if (!ci) return { type: "unsupported", reason: `Unknown OID ${ohex}` };
      if (!ci.subtle) return { type: "unsupported", reason: `${ci.curve} not bridged to SubtleCrypto` };
      const mpi = readMPI(v, off);
      const spki = buildEcSpki(ci.curve, mpi.bytes);
      if (!spki) return { type: "unsupported", reason: "SPKI build failed" };
      return { type: "ecdh", curve: ci.curve, publicKeyB64: buf2b64(spki) };
    }
    if (algo === 1 || algo === 17) return { type: "rsa" };
    return { type: "unsupported", reason: `algo ${algo}` };
  }
  async function openpgpFingerprint(pubBody) {
    const body = new Uint8Array(pubBody);
    const ver = body[0];
    let prefix, hash;
    if (ver === 5) {
      hash = "SHA-256";
      prefix = new Uint8Array(5);
      prefix[0] = 154;
      prefix[1] = body.length >>> 24 & 255;
      prefix[2] = body.length >>> 16 & 255;
      prefix[3] = body.length >>> 8 & 255;
      prefix[4] = body.length & 255;
    } else {
      hash = "SHA-1";
      prefix = new Uint8Array(3);
      prefix[0] = 153;
      prefix[1] = body.length >>> 8 & 255;
      prefix[2] = body.length & 255;
    }
    const data = new Uint8Array(prefix.length + body.length);
    data.set(prefix);
    data.set(body, prefix.length);
    return buf2hex(await crypto.subtle.digest(hash, data));
  }
  async function parseGpgPublicKey(armored) {
    try {
      const raw = dearmor(armored);
      const bytes = new Uint8Array(raw);
      let off = 0;
      const pkts = [];
      while (off < bytes.length) {
        const tag = bytes[off++];
        if (!(tag & 128)) break;
        let ptag, len;
        if (tag & 64) {
          ptag = tag & 63;
          const fo = bytes[off++];
          if (fo < 192) {
            len = fo;
          } else if (fo < 224) {
            len = (fo - 192 << 8) + bytes[off++] + 192;
          } else if (fo === 255) {
            len = bytes[off] << 24 | bytes[off + 1] << 16 | bytes[off + 2] << 8 | bytes[off + 3];
            off += 4;
          } else break;
        } else {
          ptag = (tag & 60) >> 2;
          const lt = tag & 3;
          if (lt === 0) {
            len = bytes[off++];
          } else if (lt === 1) {
            len = bytes[off++] << 8 | bytes[off++];
          } else if (lt === 2) {
            len = bytes[off++] << 24 | bytes[off++] << 16 | bytes[off++] << 8 | bytes[off++];
          } else {
            len = bytes.length - off;
          }
        }
        pkts.push({ tag: ptag, body: raw.slice(off, off + len) });
        off += len;
      }
      const pub = pkts.find((p) => p.tag === 14) || pkts.find((p) => p.tag === 6);
      if (!pub) return { error: "No public key packet found" };
      const ki = parsePgpKeyPacket(pub.body);
      const uid = pkts.find((p) => p.tag === 13);
      const fp = await openpgpFingerprint(pub.body);
      if (ki.type === "ecdh") {
        return {
          type: "ecdh",
          curve: ki.curve,
          publicKeyB64: ki.publicKeyB64,
          fingerprint: fp,
          shortFingerprint: fp.slice(-16).toUpperCase(),
          uid: uid ? buf2str(uid.body) : null,
          source: "gpg"
        };
      }
      if (ki.type === "rsa") {
        return {
          type: "rsa",
          publicArmor: armored,
          fingerprint: fp,
          shortFingerprint: fp.slice(-16).toUpperCase(),
          uid: uid ? buf2str(uid.body) : null,
          source: "gpg",
          error: "RSA GPG key stored \u2014 encryption bridge coming soon"
        };
      }
      return { error: ki.reason || "Unsupported key type", source: "gpg" };
    } catch (e) {
      return { error: `GPG parse error: ${e.message}` };
    }
  }
  function isGpgArmor(text) {
    return typeof text === "string" && text.includes("-----BEGIN PGP PUBLIC KEY BLOCK-----");
  }
  async function derivePassKey(passphrase, salt) {
    const keyMat = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(passphrase),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 31e4, hash: "SHA-256" },
      keyMat,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  // mozilla/src/crypto/keystore.js
  var keystore_exports = {};
  __export(keystore_exports, {
    clearSharedKeyCache: () => clearSharedKeyCache,
    deleteContact: () => deleteContact,
    deleteIdentity: () => deleteIdentity,
    getContact: () => getContact,
    getOrCreateIdentity: () => getOrCreateIdentity,
    getPublicKeyB64: () => getPublicKeyB64,
    getSharedKeyForContact: () => getSharedKeyForContact,
    listContacts: () => listContacts,
    resolveGroupRecipients: () => resolveGroupRecipients,
    saveContact: () => saveContact,
    upgradeIdentityToPqc: () => upgradeIdentityToPqc,
    verifyContact: () => verifyContact
  });
  var K_IDENTITY = "cc_identity_v2";
  var K_CONTACTS = "cc_contacts_v2";
  function sGet(key) {
    return new Promise((resolve) => chrome.storage.local.get(key, (r) => resolve(r[key] ?? null)));
  }
  function sSet(key, val) {
    return new Promise((resolve) => chrome.storage.local.set({ [key]: val }, resolve));
  }
  function sDel(key) {
    return new Promise((resolve) => chrome.storage.local.remove(key, resolve));
  }
  async function getOrCreateIdentity() {
    const stored = await sGet(K_IDENTITY);
    if (stored) {
      return {
        publicKey: await importPublicKey(stored.publicKeyB64),
        privateKey: await importPrivateKey(stored.privateKeyB64),
        publicKeyB64: stored.publicKeyB64,
        fingerprint: stored.fingerprint,
        mlkemPkB64: stored.mlkemPkB64 || null,
        mlkemSkB64: stored.mlkemSkB64 || null,
        pqcEnabled: !!(stored.mlkemPkB64 && stored.mlkemSkB64)
      };
    }
    const kp = await generateIdentityKeypair();
    const publicKeyB64 = await exportPublicKey(kp.publicKey);
    const privateKeyB64 = await exportPrivateKey(kp.privateKey);
    const fingerprint = await keyFingerprint(publicKeyB64);
    let mlkemPkB64 = null, mlkemSkB64 = null;
    if (isPqcAvailable()) {
      try {
        const mk = await mlkemGenerateKeypair();
        mlkemPkB64 = buf2b64(mk.mlkemPk.buffer);
        mlkemSkB64 = buf2b64(mk.mlkemSk.buffer);
      } catch (e) {
        console.warn("[ciphertext] ML-KEM keygen failed:", e.message);
      }
    }
    await sSet(K_IDENTITY, { publicKeyB64, privateKeyB64, fingerprint, mlkemPkB64, mlkemSkB64 });
    return {
      publicKey: kp.publicKey,
      privateKey: kp.privateKey,
      publicKeyB64,
      fingerprint,
      mlkemPkB64,
      mlkemSkB64,
      pqcEnabled: !!(mlkemPkB64 && mlkemSkB64)
    };
  }
  async function getPublicKeyB64() {
    const stored = await sGet(K_IDENTITY);
    return stored?.publicKeyB64 ?? null;
  }
  async function deleteIdentity() {
    await sDel(K_IDENTITY);
  }
  async function upgradeIdentityToPqc() {
    if (!isPqcAvailable()) return { upgraded: false, reason: "PQC bundle not loaded" };
    const s = await sGet(K_IDENTITY);
    if (!s) return { upgraded: false, reason: "No identity yet" };
    if (s.mlkemPkB64 && s.mlkemSkB64) return { upgraded: false, reason: "Already has ML-KEM keys" };
    const mk = await mlkemGenerateKeypair();
    s.mlkemPkB64 = buf2b64(mk.mlkemPk.buffer);
    s.mlkemSkB64 = buf2b64(mk.mlkemSk.buffer);
    await sSet(K_IDENTITY, s);
    return { upgraded: true, mlkemPkB64: s.mlkemPkB64 };
  }
  async function listContacts() {
    return await sGet(K_CONTACTS) || [];
  }
  async function saveContact(record) {
    const contacts = await listContacts();
    const idx = contacts.findIndex(
      (c) => c.handle === record.handle && c.platform === record.platform
    );
    const full = {
      handle: record.handle,
      platform: record.platform,
      displayName: record.displayName || record.handle,
      publicKeyB64: record.publicKeyB64 ?? null,
      mlkemPkB64: record.mlkemPkB64 ?? null,
      publicArmor: record.publicArmor ?? null,
      source: record.source ?? "native",
      curve: record.curve ?? null,
      fingerprint: record.fingerprint ?? null,
      uid: record.uid ?? null,
      verified: record.verified ?? false,
      addedAt: Date.now()
    };
    if (idx >= 0) contacts[idx] = { ...contacts[idx], ...full };
    else contacts.push(full);
    await sSet(K_CONTACTS, contacts);
    clearSharedKeyCache();
    return full;
  }
  async function deleteContact(handle2, platform) {
    await sSet(
      K_CONTACTS,
      (await listContacts()).filter((c) => !(c.handle === handle2 && c.platform === platform))
    );
    clearSharedKeyCache();
  }
  async function verifyContact(handle2, platform) {
    const contacts = await listContacts();
    const idx = contacts.findIndex((c) => c.handle === handle2 && c.platform === platform);
    if (idx >= 0) {
      contacts[idx].verified = true;
      await sSet(K_CONTACTS, contacts);
    }
  }
  async function getContact(handle2, platform) {
    return (await listContacts()).find(
      (c) => c.handle === handle2 && c.platform === platform
    ) ?? null;
  }
  var _cache = /* @__PURE__ */ new Map();
  function clearSharedKeyCache() {
    _cache.clear();
  }
  async function getSharedKeyForContact(handle2, platform) {
    const ck = `${platform}:${handle2}`;
    if (_cache.has(ck)) return _cache.get(ck);
    const id = await getOrCreateIdentity();
    const contact = await getContact(handle2, platform);
    if (!contact?.publicKeyB64) throw new Error(`No key for ${handle2} (${platform})`);
    const pub = await importPublicKey(contact.publicKeyB64, contact.curve);
    const sk = await deriveSharedKey(id.privateKey, pub);
    _cache.set(ck, sk);
    return sk;
  }
  async function resolveGroupRecipients(handles) {
    const out = [];
    for (const { handle: handle2, platform } of handles) {
      const c = await getContact(handle2, platform);
      if (c?.publicKeyB64) {
        out.push({
          handle: handle2,
          platform,
          publicKeyB64: c.publicKeyB64,
          mlkemPkB64: c.mlkemPkB64 || null,
          curve: c.curve
        });
      }
    }
    return out;
  }

  // mozilla/src/background/handler.js
  var PREFS_KEY = "cc_prefs";
  var DEFAULT_PREFS = { blur: true, overlay: true, allSites: false };
  chrome.runtime.onMessage.addListener((msg, _sender, respond) => {
    handle(msg).then(respond).catch((err) => respond({ error: err.message || String(err) }));
    return true;
  });
  (async () => {
    try {
      await upgradeIdentityToPqc();
    } catch (_) {
    }
  })();
  async function handle(msg) {
    switch (msg.type) {
      /* ── Encrypt 1:1 (V2 if both have ML-KEM keys, else V1) ─────────── */
      case "ENCRYPT_MESSAGE": {
        const { plaintext, contactHandle, contactPlatform } = msg;
        if (!plaintext) return { error: "No plaintext" };
        const id = await getOrCreateIdentity();
        const contact = await getContact(contactHandle, contactPlatform);
        if (!contact?.publicKeyB64) return { error: `No key for ${contactHandle}` };
        if (isPqcAvailable() && id.mlkemPkB64 && contact.mlkemPkB64) {
          const ct2 = await encryptMessageV2(
            plaintext,
            id.publicKeyB64,
            id.privateKey,
            contact.publicKeyB64,
            new Uint8Array(b642buf(contact.mlkemPkB64))
          );
          return { ciphertext: ct2, format: "v2" };
        }
        const sk = await getSharedKeyForContact(contactHandle, contactPlatform);
        const ct = await encryptMessage(plaintext, sk, id.publicKeyB64);
        return { ciphertext: ct, format: "v1" };
      }
      /* ── Encrypt group ───────────────────────────────────────────────── */
      case "ENCRYPT_GROUP": {
        const { plaintext, recipients } = msg;
        if (!plaintext) return { error: "No plaintext" };
        if (!recipients?.length) return { error: "No recipients" };
        const id = await getOrCreateIdentity();
        const allRecip = [...recipients];
        if (!allRecip.find((r) => r.publicKeyB64 === id.publicKeyB64)) {
          allRecip.push({
            handle: "__self__",
            platform: "self",
            publicKeyB64: id.publicKeyB64,
            mlkemPkB64: id.mlkemPkB64 || null
          });
        }
        const resolved = [];
        for (const r of allRecip) {
          if (r.publicKeyB64) {
            resolved.push(r);
            continue;
          }
          const c = await getContact(r.handle, r.platform);
          if (c?.publicKeyB64) {
            resolved.push({ ...r, publicKeyB64: c.publicKeyB64, mlkemPkB64: c.mlkemPkB64 || null });
          }
        }
        const allHavePqc = isPqcAvailable() && id.mlkemPkB64 && resolved.every((r) => r.mlkemPkB64);
        if (allHavePqc) {
          const v2r = resolved.map((r) => ({
            handle: r.handle,
            ecdhPubB64: r.publicKeyB64,
            mlkemPkB64: r.mlkemPkB64
          }));
          const ct2 = await encryptGroupMessageV2(plaintext, id.publicKeyB64, id.privateKey, v2r);
          return { ciphertext: ct2, recipientCount: resolved.length, format: "v2-group" };
        }
        const ct = await encryptGroupMessage(plaintext, id.publicKeyB64, id.privateKey, resolved);
        return { ciphertext: ct, recipientCount: resolved.length, format: "v1-group" };
      }
      /* ── Decrypt (V2 group → V2 1:1 → V1 group → V1 1:1) ────────────── */
      case "DECRYPT_MESSAGE": {
        const { wireText } = msg;
        if (!wireText) return { error: "No ciphertext" };
        const id = await getOrCreateIdentity();
        const contacts = await listContacts();
        if (isV2GroupMessage(wireText)) {
          if (!isPqcAvailable() || !id.mlkemSkB64)
            return { error: "V2 (quantum-resistant) message \u2014 install the PQC bundle to decrypt." };
          for (const c of contacts) {
            if (!c.publicKeyB64) continue;
            try {
              const r = await decryptGroupMessageV2WithSender(
                wireText,
                id.publicKeyB64,
                id.privateKey,
                id.mlkemSkB64,
                c.publicKeyB64
              );
              return { ...r, senderHandle: c.handle, senderPlatform: c.platform, senderVerified: c.verified, format: "v2-group" };
            } catch (_) {
            }
          }
          try {
            const r = await decryptGroupMessageV2WithSender(
              wireText,
              id.publicKeyB64,
              id.privateKey,
              id.mlkemSkB64,
              id.publicKeyB64
            );
            return { ...r, senderHandle: "(you)", format: "v2-group" };
          } catch (_) {
          }
          return { error: "No matching key to decrypt this V2 group message" };
        }
        if (isV2Message(wireText)) {
          if (!isPqcAvailable() || !id.mlkemSkB64)
            return { error: "V2 (quantum-resistant) message \u2014 install the PQC bundle to decrypt." };
          const mlkemSk = new Uint8Array(b642buf(id.mlkemSkB64));
          for (const c of contacts) {
            if (!c.publicKeyB64) continue;
            try {
              const r = await decryptMessageV2(
                wireText,
                id.privateKey,
                c.publicKeyB64,
                mlkemSk,
                id.publicKeyB64
              );
              return { ...r, senderHandle: c.handle, senderPlatform: c.platform, senderVerified: c.verified, format: "v2" };
            } catch (_) {
            }
          }
          return { error: "No matching key to decrypt this V2 message" };
        }
        if (isGroupMessage(wireText)) {
          for (const c of contacts) {
            if (!c.publicKeyB64) continue;
            try {
              const r = await decryptGroupMessage(wireText, id.publicKeyB64, id.privateKey, c.publicKeyB64);
              return { ...r, senderHandle: c.handle, senderPlatform: c.platform, senderVerified: c.verified, format: "group" };
            } catch (_) {
            }
          }
          try {
            const r = await decryptGroupMessage(wireText, id.publicKeyB64, id.privateKey, id.publicKeyB64);
            return { ...r, senderHandle: "(you)", format: "group" };
          } catch (_) {
          }
          return { error: "No matching key to decrypt group message" };
        }
        if (isV1Message(wireText)) {
          for (const c of contacts) {
            if (!c.publicKeyB64) continue;
            try {
              const sk = await getSharedKeyForContact(c.handle, c.platform);
              const r = await decryptMessage(wireText, sk);
              return { ...r, senderHandle: c.handle, senderPlatform: c.platform, senderVerified: c.verified, format: "v1" };
            } catch (_) {
            }
          }
          return { error: "No key found \u2014 have you added the sender as a contact?" };
        }
        return { error: "Unrecognized ciphertext message format" };
      }
      /* ── Identity ────────────────────────────────────────────────────── */
      case "GET_PUBLIC_KEY": {
        const id = await getOrCreateIdentity();
        return {
          publicKeyB64: id.publicKeyB64,
          fingerprint: id.fingerprint,
          mlkemPkB64: id.mlkemPkB64 || null,
          pqcEnabled: id.pqcEnabled
        };
      }
      case "UPGRADE_TO_PQC":
        return upgradeIdentityToPqc();
      case "RESET_IDENTITY": {
        await deleteIdentity();
        clearSharedKeyCache();
        const id = await getOrCreateIdentity();
        broadcastContactsUpdated();
        return {
          success: true,
          publicKeyB64: id.publicKeyB64,
          fingerprint: id.fingerprint,
          pqcEnabled: id.pqcEnabled
        };
      }
      /* ── Contacts ────────────────────────────────────────────────────── */
      case "SAVE_CONTACT": {
        const { handle: handle2, platform, publicKeyB64, publicArmor, displayName, mlkemPkB64 } = msg;
        if (!handle2 || !platform) return { error: "handle and platform required" };
        let record = {
          handle: handle2,
          platform,
          displayName,
          source: "native",
          publicKeyB64,
          mlkemPkB64: mlkemPkB64 || null
        };
        if (publicArmor && isGpgArmor(publicArmor)) {
          const gpg = await parseGpgPublicKey(publicArmor);
          if (gpg.error && !gpg.type) return { error: gpg.error };
          record = {
            ...record,
            source: "gpg",
            publicArmor,
            publicKeyB64: gpg.publicKeyB64 || null,
            curve: gpg.curve || null,
            fingerprint: gpg.fingerprint || null,
            uid: gpg.uid || null
          };
          if (gpg.error) record.gpgNote = gpg.error;
        } else if (publicKeyB64) {
          try {
            await importPublicKey(publicKeyB64);
            record.fingerprint = await keyFingerprint(publicKeyB64);
          } catch (_) {
            return { error: "Invalid public key \u2014 expected base64 SPKI or PGP armor" };
          }
        } else {
          return { error: "Provide a publicKeyB64 or GPG armored key" };
        }
        const saved = await saveContact(record);
        broadcastContactsUpdated();
        return { success: true, contact: saved };
      }
      case "PARSE_GPG_KEY": {
        if (!msg.armor) return { error: "No armor provided" };
        return { result: await parseGpgPublicKey(msg.armor) };
      }
      case "LIST_CONTACTS":
        return { contacts: await listContacts() };
      case "DELETE_CONTACT": {
        await deleteContact(msg.handle, msg.platform);
        broadcastContactsUpdated();
        return { success: true };
      }
      case "VERIFY_CONTACT": {
        await verifyContact(msg.handle, msg.platform);
        return { success: true };
      }
      /* ── Preferences ─────────────────────────────────────────────────── */
      case "GET_PREFS":
        return { prefs: { ...DEFAULT_PREFS, ...await getPrefs() } };
      case "SET_PREFS":
        return { prefs: await setPrefs(msg.prefs || {}) };
      /* ── Export encrypted backup ─────────────────────────────────────── */
      case "EXPORT_BACKUP": {
        const { passphrase } = msg;
        if (!passphrase || passphrase.length < 6) {
          return { error: "Passphrase must be at least 6 characters" };
        }
        const id = await getOrCreateIdentity();
        const contacts = await listContacts();
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const passKey = await derivePassKey(passphrase, salt);
        const rawIdentity = (await chrome.storage.local.get("cc_identity_v2"))["cc_identity_v2"];
        const privatePt = str2buf(JSON.stringify({
          privateKeyB64: rawIdentity.privateKeyB64,
          mlkemSkB64: rawIdentity.mlkemSkB64 || null
        }));
        const privateCt = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, passKey, privatePt);
        const backup = {
          version: 3,
          createdAt: Date.now(),
          publicKeyB64: id.publicKeyB64,
          fingerprint: id.fingerprint,
          mlkemPkB64: id.mlkemPkB64 || null,
          pqcEnabled: !!id.mlkemPkB64,
          salt: buf2b64(salt.buffer),
          iv: buf2b64(iv.buffer),
          encPrivateKey: buf2b64(privateCt),
          contacts: contacts.map((c) => ({
            handle: c.handle,
            platform: c.platform,
            displayName: c.displayName,
            publicKeyB64: c.publicKeyB64,
            mlkemPkB64: c.mlkemPkB64 || null,
            publicArmor: c.publicArmor || null,
            source: c.source || "native",
            curve: c.curve || null,
            fingerprint: c.fingerprint || null,
            uid: c.uid || null,
            verified: c.verified || false,
            addedAt: c.addedAt || Date.now()
          }))
        };
        return { success: true, backup: JSON.stringify(backup, null, 2) };
      }
      /* ── Import encrypted backup ─────────────────────────────────────── */
      case "IMPORT_BACKUP": {
        const { backupJson, passphrase, mode } = msg;
        let backup;
        try {
          backup = JSON.parse(backupJson);
        } catch (_) {
          return { error: "Invalid backup file \u2014 could not parse JSON" };
        }
        if (!backup.version || !backup.encPrivateKey || !backup.publicKeyB64) {
          return { error: "Invalid backup format \u2014 missing required fields" };
        }
        if (!passphrase) return { error: "Passphrase required" };
        let privateKeyB64, mlkemSkB64;
        try {
          const salt = new Uint8Array(b642buf(backup.salt));
          const iv = new Uint8Array(b642buf(backup.iv));
          const passKey = await derivePassKey(passphrase, salt);
          const plainBuf = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv },
            passKey,
            b642buf(backup.encPrivateKey)
          );
          const plain = JSON.parse(buf2str(plainBuf));
          privateKeyB64 = plain.privateKeyB64;
          mlkemSkB64 = plain.mlkemSkB64 || null;
        } catch (_) {
          return { error: "Wrong passphrase or corrupted backup" };
        }
        try {
          await importPublicKey(backup.publicKeyB64);
          await importPrivateKey(privateKeyB64);
          if (backup.mlkemPkB64) {
            const pk = new Uint8Array(b642buf(backup.mlkemPkB64));
            if (pk.length !== 1184) throw new Error("bad ML-KEM public key length");
          }
          if (mlkemSkB64) {
            const sk = new Uint8Array(b642buf(mlkemSkB64));
            if (sk.length !== 2400) throw new Error("bad ML-KEM secret key length");
          }
        } catch (_) {
          return { error: "Backup contains invalid key material" };
        }
        if (mode === "replace") {
          await deleteIdentity();
          await new Promise((r) => chrome.storage.local.remove("cc_contacts_v2", r));
        }
        const fp = await keyFingerprint(backup.publicKeyB64);
        await new Promise((r) => chrome.storage.local.set({
          cc_identity_v2: {
            publicKeyB64: backup.publicKeyB64,
            privateKeyB64,
            fingerprint: fp,
            mlkemPkB64: backup.mlkemPkB64 || null,
            mlkemSkB64: mlkemSkB64 || null
          }
        }, r));
        clearSharedKeyCache();
        const existingContacts = mode === "replace" ? [] : await listContacts();
        let added = 0, skipped = 0;
        for (const c of backup.contacts || []) {
          const exists = existingContacts.find(
            (e) => e.handle === c.handle && e.platform === c.platform
          );
          if (exists && mode === "merge") {
            skipped++;
            continue;
          }
          await saveContact(c);
          added++;
        }
        broadcastContactsUpdated();
        return { success: true, contactsAdded: added, contactsSkipped: skipped, fingerprint: fp };
      }
      default:
        return { error: `Unknown message type: ${msg.type}` };
    }
  }
  async function getPrefs() {
    return new Promise((r) => chrome.storage.local.get(PREFS_KEY, (x) => r(x[PREFS_KEY] || {})));
  }
  async function setPrefs(patch) {
    const current = await getPrefs();
    const next = { ...DEFAULT_PREFS, ...current, ...patch };
    await new Promise((r) => chrome.storage.local.set({ [PREFS_KEY]: next }, r));
    return next;
  }
  function broadcastContactsUpdated() {
    chrome.tabs.query({}, (tabs) => {
      for (const tab of tabs) {
        if (tab.id) {
          try {
            chrome.tabs.sendMessage(tab.id, { type: "CONTACTS_UPDATED" }).catch(() => {
            });
          } catch (_) {
          }
        }
      }
    });
  }

  // mozilla/src/background/index.js
  globalThis.CCEngine = engine_exports;
  globalThis.CCKeystore = keystore_exports;
})();
/*! Bundled license information:

mlkem/esm/src/sha3/utils.js:
  (*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) *)
*/
