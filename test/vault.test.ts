import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes as nodeRandom } from 'node:crypto';
import {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  hexToBytes,
  decryptFile,
  decryptMessage,
  deriveMasterKeyBytes,
  deriveWebCryptoMasterKey,
  encryptFile,
  encryptMessage,
  generateKyberKeyPair,
  generateSalt,
  generateX25519Identity,
  rawMasterKey,
  rewrapFileDek,
  rewrapKyberSecretKey,
  rewrapX25519PrivateKey,
  secureRandom,
  unwrapKyberSecretKey,
  unwrapX25519PrivateKey,
  wrapKyberSecretKey,
  type MasterKey,
} from '../src/vault/index.js';

describe('encoding', () => {
  test('base64 and hex match Node for every length 0-64 and a large buffer', () => {
    for (let n = 0; n <= 64; n++) {
      const b = new Uint8Array(nodeRandom(n));
      assert.equal(bytesToBase64(b), Buffer.from(b).toString('base64'));
      assert.deepEqual(base64ToBytes(Buffer.from(b).toString('base64')), b);
      assert.equal(bytesToHex(b), Buffer.from(b).toString('hex'));
      assert.deepEqual(hexToBytes(bytesToHex(b)), b);
    }
    // Mobile's old btoa(String.fromCharCode(...bytes)) overflows the stack on large files.
    const big = new Uint8Array(nodeRandom(5_000_000));
    assert.equal(bytesToBase64(big), Buffer.from(big).toString('base64'));
  });
  test('rejects malformed input', () => {
    assert.throws(() => base64ToBytes('abc'));
    assert.throws(() => base64ToBytes('ab$='));
    assert.throws(() => hexToBytes('abc'));
    assert.throws(() => hexToBytes('zz'));
  });
});

async function masters(password = 'pw', salt = generateSalt()) {
  const raw = rawMasterKey(await deriveMasterKeyBytes(password, salt));
  const { masterKey: web } = await deriveWebCryptoMasterKey(password, salt);
  return { raw, web, salt };
}

describe('master key', () => {
  test('raw and Web Crypto keys from the same password are interchangeable', async () => {
    const { raw, web } = await masters();
    const iv = secureRandom(12);
    const secret = secureRandom(32);
    assert.deepEqual(await web.open(iv, await raw.seal(iv, secret)), secret);
    assert.deepEqual(await raw.open(iv, await web.seal(iv, secret)), secret);
  });
  test('rejects wrong key and IV sizes', async () => {
    assert.throws(() => rawMasterKey(new Uint8Array(16)));
    await assert.rejects(rawMasterKey(new Uint8Array(32)).seal(new Uint8Array(16), new Uint8Array(1)));
  });
});

describe('files', () => {
  test('round trip across raw and Web Crypto master keys', async () => {
    const { raw, web } = await masters();
    const data = new Uint8Array(nodeRandom(100_000));
    assert.deepEqual(await decryptFile(await encryptFile(data, web), raw), data);
    assert.deepEqual(await decryptFile(await encryptFile(data, raw), web), data);
  });
  test('tampering with any field is detected', async () => {
    const { raw } = await masters();
    const p = await encryptFile(new Uint8Array([1, 2, 3, 4]), raw);
    const flip = (b64: string) => { const b = base64ToBytes(b64); b[0] = b[0]! ^ 1; return bytesToBase64(b); };
    await assert.rejects(decryptFile({ ...p, encryptedFile: flip(p.encryptedFile) }, raw));
    await assert.rejects(decryptFile({ ...p, encryptedDEK: flip(p.encryptedDEK) }, raw));
    await assert.rejects(decryptFile({ ...p, fileIV: '00'.repeat(12) }, raw));
  });
  test('password change: rewrapped DEK opens with the new key only', async () => {
    const a = await masters('old');
    const b = await masters('new');
    const p = await encryptFile(new Uint8Array([9, 9, 9]), a.raw);
    const r = await rewrapFileDek(p.encryptedDEK, p.dekIV, a.raw, b.web);
    assert.deepEqual(await decryptFile({ ...p, ...r }, b.raw), new Uint8Array([9, 9, 9]));
    await assert.rejects(decryptFile({ ...p, ...r }, a.raw));
  });
});

async function makeUser(master: MasterKey) {
  const x = await generateX25519Identity(master);
  const kyber = generateKyberKeyPair();
  const wk = await wrapKyberSecretKey(kyber.secretKey, master);
  return {
    pub: { x25519PublicKeyBase64: x.publicKeyBase64, kyberPublicKeyBase64: bytesToBase64(kyber.publicKey) },
    wrapped: { x, wk },
    keys: {
      x25519PrivateKey: await unwrapX25519PrivateKey(x.wrappedPrivateKey, x.privateKeyIV, master),
      kyberSecretKey: await unwrapKyberSecretKey(wk.wrappedKyberPrivateKey, wk.kyberPrivateKeyIV, master),
    },
  };
}

describe('messages', () => {
  test('recipient and sender can read; a third party cannot', async () => {
    const [a, b, c] = await Promise.all([masters('a'), masters('b'), masters('c')]);
    const alice = await makeUser(a.web), bob = await makeUser(b.raw), carol = await makeUser(c.raw);
    const m = encryptMessage('hi bob \u{1F512}', bob.pub, alice.pub);
    assert.equal(decryptMessage(m, bob.keys, 'recipient'), 'hi bob \u{1F512}');
    assert.equal(decryptMessage(m, alice.keys, 'sender'), 'hi bob \u{1F512}');
    assert.throws(() => decryptMessage(m, carol.keys, 'recipient'));
    assert.throws(() => decryptMessage(m, alice.keys, 'recipient'));
  });
  test('breaking ONE KEM is not enough: both keys are required', async () => {
    const [a, b, c] = await Promise.all([masters('a'), masters('b'), masters('c')]);
    const alice = await makeUser(a.raw), bob = await makeUser(b.raw), mallory = await makeUser(c.raw);
    const m = encryptMessage('secret', bob.pub, alice.pub);
    assert.throws(() => decryptMessage(m, { x25519PrivateKey: bob.keys.x25519PrivateKey, kyberSecretKey: mallory.keys.kyberSecretKey }, 'recipient'));
    assert.throws(() => decryptMessage(m, { x25519PrivateKey: mallory.keys.x25519PrivateKey, kyberSecretKey: bob.keys.kyberSecretKey }, 'recipient'));
  });
  test('tampering is detected', async () => {
    const [a, b] = await Promise.all([masters('a'), masters('b')]);
    const alice = await makeUser(a.raw), bob = await makeUser(b.raw);
    const m = encryptMessage('x', bob.pub, alice.pub);
    const c = base64ToBytes(m.encryptedContent); c[0] = c[0]! ^ 1;
    assert.throws(() => decryptMessage({ ...m, encryptedContent: bytesToBase64(c) }, bob.keys, 'recipient'));
    const [ct, packed] = m.encryptedDEKForRecipientKyber.split('.') as [string, string];
    const pk = base64ToBytes(packed); pk[20] = pk[20]! ^ 1;
    assert.throws(() => decryptMessage({ ...m, encryptedDEKForRecipientKyber: `${ct}.${bytesToBase64(pk)}` }, bob.keys, 'recipient'));
  });
  test('rejects missing keys, wrong lengths and a low-order X25519 key', async () => {
    const [a, b] = await Promise.all([masters('a'), masters('b')]);
    const alice = await makeUser(a.raw), bob = await makeUser(b.raw);
    assert.throws(() => encryptMessage('x', { ...bob.pub, kyberPublicKeyBase64: '' }, alice.pub), /Post-quantum key missing/);
    assert.throws(() => encryptMessage('x', { ...bob.pub, x25519PublicKeyBase64: bytesToBase64(new Uint8Array(31)) }, alice.pub), /wrong length/);
    assert.throws(() => encryptMessage('x', { ...bob.pub, x25519PublicKeyBase64: bytesToBase64(new Uint8Array(32)) }, alice.pub), /Invalid X25519|invalid private or public key/);
    const m = encryptMessage('x', bob.pub, alice.pub);
    assert.throws(() => decryptMessage({ ...m, encryptedDEKForRecipientKyber: 'nodot' }, bob.keys, 'recipient'), /Malformed/);
  });
});

describe('identity keys', () => {
  test('password change: rewrapped keys open with the new master key only', async () => {
    const a = await masters('old'), b = await masters('new');
    const u = await makeUser(a.raw);
    const x2 = await rewrapX25519PrivateKey(u.wrapped.x.wrappedPrivateKey, u.wrapped.x.privateKeyIV, a.raw, b.web);
    const k2 = await rewrapKyberSecretKey(u.wrapped.wk.wrappedKyberPrivateKey, u.wrapped.wk.kyberPrivateKeyIV, a.raw, b.web);
    assert.deepEqual(await unwrapX25519PrivateKey(x2.wrappedPrivateKey, x2.privateKeyIV, b.raw), u.keys.x25519PrivateKey);
    assert.deepEqual(await unwrapKyberSecretKey(k2.wrappedKyberPrivateKey, k2.kyberPrivateKeyIV, b.raw), u.keys.kyberSecretKey);
    await assert.rejects(unwrapX25519PrivateKey(x2.wrappedPrivateKey, x2.privateKeyIV, a.raw));
  });
});

test('secureRandom refuses to run without crypto.getRandomValues', () => {
  const saved = Object.getOwnPropertyDescriptor(globalThis, 'crypto')!;
  Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true });
  try {
    assert.throws(() => secureRandom(16), /react-native-get-random-values/);
  } finally {
    Object.defineProperty(globalThis, 'crypto', saved);
  }
});
