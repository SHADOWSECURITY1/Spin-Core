import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomInt } from 'node:crypto';
import { utf8Decode, utf8Encode } from '../src/vault/encoding.js';

const enc = new TextEncoder();
const dec = new TextDecoder();

test('encode matches TextEncoder, including emoji and lone surrogates', () => {
  const samples = ['', 'ascii', 'é è ñ ü', '中文字符', '🔒🧩📱', 'a\uD800b', '\uDC00', 'x\uD83D', '﻿bom', '\u0000\u007F\u0080߿ࠀ￿'];
  for (let n = 0; n < 2000; n++) {
    let s = '';
    for (let k = randomInt(0, 40); k > 0; k--) s += String.fromCharCode(randomInt(0, 0x10000));
    samples.push(s);
  }
  for (const s of samples) assert.deepEqual(utf8Encode(s), enc.encode(s), JSON.stringify(s));
});

test('decode matches TextDecoder on valid text and on random bytes', () => {
  for (const s of ['', 'héllo', '🔒 secure', '﻿with BOM', 'a﻿b']) {
    assert.equal(utf8Decode(enc.encode(s)), dec.decode(enc.encode(s)));
  }
  const edge = [[0xc0, 0x80], [0xe0, 0x80, 0x80], [0xed, 0xa0, 0x80], [0xf4, 0x90, 0x80, 0x80], [0xf0, 0x9f], [0xe2, 0x82], [0xff], [0x80, 0x41], [0xef, 0xbb, 0xbf, 0x41]];
  for (const e of edge) assert.equal(utf8Decode(Uint8Array.from(e)), dec.decode(Uint8Array.from(e)), String(e));
  for (let n = 0; n < 5000; n++) {
    const b = new Uint8Array(randomBytes(randomInt(0, 24)));
    assert.equal(utf8Decode(b), dec.decode(b), String([...b]));
  }
  const big = enc.encode('🔒'.repeat(100_000));
  assert.equal(utf8Decode(big), dec.decode(big));
});

test("@spin/core's own code never needs TextEncoder or TextDecoder", async () => {
  // Load first: @noble/curves 2.x calls TextEncoder while loading, so a runtime
  // without it needs a polyfill (see README). After loading, remove both and
  // run the whole message flow: none of @spin/core's code may touch them.
  const v = await import('../src/vault/index.js');
  const saved = { TE: globalThis.TextEncoder, TD: globalThis.TextDecoder };
  // @ts-expect-error simulating Hermes
  delete globalThis.TextEncoder; // @ts-expect-error simulating Hermes
  delete globalThis.TextDecoder;
  try {
    const master = v.rawMasterKey(await v.deriveMasterKeyBytes('pw', '00'.repeat(32)));
    const user = async () => {
      const x = await v.generateX25519Identity(master);
      const k = v.generateKyberKeyPair();
      return {
        pub: { x25519PublicKeyBase64: x.publicKeyBase64, kyberPublicKeyBase64: v.bytesToBase64(k.publicKey) },
        keys: { x25519PrivateKey: await v.unwrapX25519PrivateKey(x.wrappedPrivateKey, x.privateKeyIV, master), kyberSecretKey: k.secretKey },
      };
    };
    const [a, b] = await Promise.all([user(), user()]);
    const m = v.encryptMessage('héllo 🔒 from Hermes', b.pub, a.pub);
    assert.equal(v.decryptMessage(m, b.keys, 'recipient'), 'héllo 🔒 from Hermes');
  } finally {
    globalThis.TextEncoder = saved.TE;
    globalThis.TextDecoder = saved.TD;
  }
});
