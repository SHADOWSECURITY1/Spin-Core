/**
 * Encoding helpers with no platform dependencies (no Buffer, no btoa), so the
 * same code runs in browsers, Node and React Native (Hermes).
 *
 * Formats match what SPIN Vault already stores: standard base64 with padding,
 * lowercase hex.
 */
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_LOOKUP = new Int16Array(128).fill(-1);
for (let i = 0; i < B64.length; i++) B64_LOOKUP[B64.charCodeAt(i)] = i;

export function bytesToBase64(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out += B64[n >> 18]! + B64[(n >> 12) & 63]! + B64[(n >> 6) & 63]! + B64[n & 63]!;
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i]! << 16;
    out += B64[n >> 18]! + B64[(n >> 12) & 63]! + '==';
  } else if (rest === 2) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    out += B64[n >> 18]! + B64[(n >> 12) & 63]! + B64[(n >> 6) & 63]! + '=';
  }
  return out;
}

export function base64ToBytes(b64: string): Uint8Array {
  const clean = b64.replace(/\s+/g, '');
  if (clean.length % 4 !== 0) throw new Error('Invalid base64: length is not a multiple of 4');
  const pad = clean.endsWith('==') ? 2 : clean.endsWith('=') ? 1 : 0;
  const out = new Uint8Array((clean.length / 4) * 3 - pad);
  let o = 0;
  for (let i = 0; i < clean.length; i += 4) {
    let n = 0;
    for (let j = 0; j < 4; j++) {
      const c = clean.charCodeAt(i + j);
      const v = c === 61 /* = */ && i + j >= clean.length - pad ? 0 : c < 128 ? B64_LOOKUP[c]! : -1;
      if (v < 0) throw new Error('Invalid base64 character');
      n = (n << 6) | v;
    }
    if (o < out.length) out[o++] = (n >> 16) & 255;
    if (o < out.length) out[o++] = (n >> 8) & 255;
    if (o < out.length) out[o++] = n & 255;
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += bytes[i]!.toString(16).padStart(2, '0');
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) throw new Error('Invalid hex string');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/*
 * UTF-8 without TextEncoder/TextDecoder: Hermes (React Native <= 0.73) has
 * neither. Behaves exactly like them (WHATWG Encoding): lone surrogates encode
 * as U+FFFD; invalid byte sequences decode as U+FFFD per maximal subpart; a
 * leading byte-order mark is stripped on decode. Tested against Node's
 * implementations.
 */
export function utf8Encode(s: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
        i++;
      } else c = 0xfffd;
    } else if (c >= 0xd800 && c <= 0xdfff) c = 0xfffd;
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  }
  return Uint8Array.from(out);
}

export function utf8Decode(bytes: Uint8Array): string {
  const cps: number[] = [];
  let cp = 0, needed = 0, seen = 0, lower = 0x80, upper = 0xbf;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]!;
    if (needed === 0) {
      if (b <= 0x7f) cps.push(b);
      else if (b >= 0xc2 && b <= 0xdf) { needed = 1; cp = b & 0x1f; }
      else if (b >= 0xe0 && b <= 0xef) {
        if (b === 0xe0) lower = 0xa0;
        if (b === 0xed) upper = 0x9f;
        needed = 2; cp = b & 0xf;
      } else if (b >= 0xf0 && b <= 0xf4) {
        if (b === 0xf0) lower = 0x90;
        if (b === 0xf4) upper = 0x8f;
        needed = 3; cp = b & 0x7;
      } else cps.push(0xfffd);
      continue;
    }
    if (b < lower || b > upper) {
      cp = needed = seen = 0; lower = 0x80; upper = 0xbf;
      cps.push(0xfffd);
      i--; // reprocess this byte as the start of a new sequence
      continue;
    }
    lower = 0x80; upper = 0xbf;
    cp = (cp << 6) | (b & 0x3f);
    if (++seen === needed) { cps.push(cp); cp = needed = seen = 0; }
  }
  if (needed !== 0) cps.push(0xfffd);
  let start = cps[0] === 0xfeff ? 1 : 0;
  let out = '';
  for (; start < cps.length; start += 8192) out += String.fromCodePoint(...cps.slice(start, start + 8192));
  return out;
}
