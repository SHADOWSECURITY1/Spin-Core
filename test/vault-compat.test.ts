/**
 * Compatibility with what SPIN Vault already stores. The fixtures were
 * produced by the real, pre-spin-core implementations:
 *   web-v1.json    SPIN-Vault client/src/lib/vault-crypto.ts (Web Crypto + @noble 2.x)
 *   mobile-v1.json SpinVault-Mobile src/services (pure @noble 1.x)
 *   core-v1.json   @spin/core 0.2.0 itself (pins the format for future versions)
 * If any of these fail, existing users' files, keys or messages would stop
 * opening after migrating to @spin/core.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  base64ToBytes,
  decryptFile,
  decryptMessage,
  deriveMasterKeyBytes,
  deriveWebCryptoMasterKey,
  rawMasterKey,
  unwrapKyberSecretKey,
  unwrapX25519PrivateKey,
  type MasterKey,
} from '../src/vault/index.js';

const load = (name: string) => JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));

async function keysFor(u: any, master: MasterKey) {
  return {
    x25519PrivateKey: await unwrapX25519PrivateKey(u.x25519.wrappedPrivateKey, u.x25519.privateKeyIV, master),
    kyberSecretKey: await unwrapKyberSecretKey(u.wrappedKyberPrivateKey, u.kyberPrivateKeyIV, master),
  };
}

for (const name of ['web-v1.json', 'mobile-v1.json', 'core-v1.json']) {
  const f = load(name);
  describe(`existing data from ${f.source}`, () => {
    test('files decrypt with a raw (mobile-style) master key', async () => {
      const master = rawMasterKey(await deriveMasterKeyBytes(f.alice.password, f.alice.salt));
      const plain = await decryptFile(f.filePayload, master);
      assert.deepEqual(plain, base64ToBytes(f.filePlaintextBase64));
    });

    test('files decrypt with a non-extractable Web Crypto master key', async () => {
      const { masterKey } = await deriveWebCryptoMasterKey(f.alice.password, f.alice.salt);
      assert.deepEqual(await decryptFile(f.filePayload, masterKey), base64ToBytes(f.filePlaintextBase64));
    });

    test('identity keys unwrap and the message opens for the recipient and the sender', async () => {
      const aliceMaster = rawMasterKey(await deriveMasterKeyBytes(f.alice.password, f.alice.salt));
      const bobMaster = rawMasterKey(await deriveMasterKeyBytes(f.bob.password, f.bob.salt));
      assert.equal(decryptMessage(f.message, await keysFor(f.bob, bobMaster), 'recipient'), f.messagePlaintext);
      assert.equal(decryptMessage(f.message, await keysFor(f.alice, aliceMaster), 'sender'), f.messagePlaintext);
    });

    test('the wrong password opens nothing', async () => {
      const wrong = rawMasterKey(await deriveMasterKeyBytes('not-the-password', f.alice.salt));
      await assert.rejects(decryptFile(f.filePayload, wrong));
      await assert.rejects(unwrapX25519PrivateKey(f.alice.x25519.wrappedPrivateKey, f.alice.x25519.privateKeyIV, wrong));
    });

    test("one party's keys can't open the other's copy", async () => {
      const aliceMaster = rawMasterKey(await deriveMasterKeyBytes(f.alice.password, f.alice.salt));
      assert.throws(() => decryptMessage(f.message, { x25519PrivateKey: new Uint8Array(32).fill(7), kyberSecretKey: new Uint8Array(2400) }, 'recipient'));
      return keysFor(f.alice, aliceMaster).then((k) => assert.throws(() => decryptMessage(f.message, k, 'recipient')));
    });
  });
}
