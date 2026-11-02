/**
 * Forward-secret messaging state written by SPIN Vault web's previous
 * implementation (ratchet.ts / ratchet-session.ts / fs-messaging.ts) must keep
 * working in @spin/core. The fixture is a conversation captured mid-flight:
 * Bob published 40 prekeys, Alice opened a session (consuming one) and sent two
 * messages Bob hasn't read; Alice's session is stored, wrapped with her master key.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  decryptIncoming,
  deriveMasterKeyBytes,
  deriveWebCryptoMasterKey,
  rawMasterKey,
  sendMessage,
  unwrapKyberSecretKey,
  unwrapX25519PrivateKey,
  type FsIdentity,
  type MasterKey,
} from '../src/vault/index.js';
import { makeFsServer } from './helpers/fs-server.js';

const f = JSON.parse(readFileSync(new URL('./fixtures/ratchet-web-v1.json', import.meta.url), 'utf8'));

async function identity(u: any, master: MasterKey): Promise<FsIdentity> {
  return {
    userId: u.userId,
    masterKey: master,
    x25519Pub: u.x25519.publicKeyBase64,
    x25519Priv: await unwrapX25519PrivateKey(u.x25519.wrappedPrivateKey, u.x25519.privateKeyIV, master),
    kyberSecret: await unwrapKyberSecretKey(u.wrappedKyberPrivateKey, u.kyberPrivateKeyIV, master),
  };
}

test('the web-written conversation continues in @spin/core, in both directions', async () => {
  const server = makeFsServer(f.server);
  // Bob on mobile-style raw key; Alice on a non-extractable Web Crypto key.
  const bob = await identity(f.bob, rawMasterKey(await deriveMasterKeyBytes(f.bob.password, f.bob.salt)));
  const alice = await identity(f.alice, (await deriveWebCryptoMasterKey(f.alice.password, f.alice.salt)).masterKey);
  const header = JSON.parse(server.messages[0].ratchetHeader);
  assert.ok(server.prekeys.get(2)!.has(header.oneTimeId), 'fixture: the consumed prekey is still on the server');

  // Bob reads Alice's web-encrypted messages: the handshake uses his web-wrapped prekey.
  const read = await decryptIncoming(bob, server.transportFor(2), 1, server.inbox(2, 1));
  assert.deepEqual([...read.values()], f.expectedPlaintexts);
  assert.ok(!server.prekeys.get(2)!.has(header.oneTimeId), 'consumed one-time prekey was deleted');

  // Re-reading the same messages: the chain has moved on (forward secrecy).
  const again = await decryptIncoming(bob, server.transportFor(2), 1, server.inbox(2, 1));
  assert.deepEqual([...again.values()], ['[expired]', '[expired]']);

  // Bob replies; Alice continues from her web-wrapped session and reads it.
  await sendMessage(bob, server.transportFor(2), 1, 'reply from @spin/core ✓');
  const aliceRead = await decryptIncoming(alice, server.transportFor(1), 2, server.inbox(1, 2));
  assert.deepEqual([...aliceRead.values()], ['reply from @spin/core ✓']);

  // Alice continues her existing chain (n = 2, no new handshake).
  const sent = await sendMessage(alice, server.transportFor(1), 2, 'third');
  assert.equal(sent.ratchetN, 2);
  assert.equal(server.messages.at(-1).ratchetHeader, null);
  const bobRead = await decryptIncoming(bob, server.transportFor(2), 1, server.inbox(2, 1));
  assert.equal(bobRead.get(sent.messageId), 'third');
});
