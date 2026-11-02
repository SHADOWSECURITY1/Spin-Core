import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  bytesToBase64,
  decryptIncoming,
  deriveMasterKeyBytes,
  deserializeSession,
  ensurePrekeyPool,
  establishAsInitiator,
  establishAsResponder,
  generateKyberKeyPair,
  generateOneTimePreKey,
  initSession,
  initiateSession,
  rawMasterKey,
  ratchetDecrypt,
  ratchetEncrypt,
  respondToSession,
  sendMessage,
  serializeSession,
  unwrapSession,
  wrapSession,
  PREKEY_BATCH,
  type FsIdentity,
} from '../src/vault/index.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { makeFsServer } from './helpers/fs-server.js';

function party() {
  const x = x25519.utils.randomSecretKey();
  const k = generateKyberKeyPair();
  return {
    pub: { x25519: bytesToBase64(x25519.getPublicKey(x)), kyber: bytesToBase64(k.publicKey) },
    sec: { x25519Priv: x, kyberSecret: k.secretKey },
  };
}

function handshake() {
  const alice = party(), bob = party();
  const opk = generateOneTimePreKey('opk-1');
  const a = establishAsInitiator(alice.sec.x25519Priv, alice.pub.x25519, { identity: bob.pub, oneTime: opk.pub });
  const b = establishAsResponder(a.header, bob.sec, opk.sec);
  return { alice, bob, opk, a: a.session, b: b.session, header: a.header };
}

describe('handshake', () => {
  test('both sides derive the same root, and matching opposite chains', () => {
    const alice = party(), bob = party();
    const opk = generateOneTimePreKey('k');
    const i = initiateSession({ identityX25519Priv: alice.sec.x25519Priv, identityX25519Pub: alice.pub.x25519 }, { identity: bob.pub, oneTime: opk.pub });
    const r = respondToSession(i.header, bob.sec, opk.sec);
    assert.deepEqual(r.rootKey, i.rootKey);
    const sa = initSession(i.rootKey, 'initiator'), sb = initSession(r.rootKey, 'responder');
    assert.deepEqual(sa.send.chainKey, sb.recv.chainKey);
    assert.deepEqual(sa.recv.chainKey, sb.send.chainKey);
    assert.notDeepEqual(sa.send.chainKey, sa.recv.chainKey);
  });

  test("the wrong one-time prekey, identity key or a tampered header doesn't produce the session", () => {
    const { bob, opk, header, a } = handshake();
    const other = generateOneTimePreKey('opk-1');
    const m = ratchetEncrypt(a.send, 'x').message;
    const wrongOpk = establishAsResponder(header, bob.sec, other.sec).session;
    assert.throws(() => ratchetDecrypt(wrongOpk.recv, m));
    const wrongId = establishAsResponder(header, party().sec, opk.sec).session;
    assert.throws(() => ratchetDecrypt(wrongId.recv, m));
    assert.throws(() => establishAsResponder({ ...header, oneTimeId: 'other' }, bob.sec, opk.sec), /different one-time prekey/);
    assert.throws(() => establishAsResponder({ ...header, ek: bytesToBase64(new Uint8Array(32)) }, bob.sec, opk.sec));
  });
});

describe('ratchet', () => {
  test('messages flow both ways, in order', () => {
    let { a, b } = handshake();
    for (const text of ['one', 'two', 'three']) {
      const e = ratchetEncrypt(a.send, text); a = { ...a, send: e.send };
      const d = ratchetDecrypt(b.recv, e.message); b = { ...b, recv: d.recv };
      assert.equal(d.plaintext, text);
    }
    const e = ratchetEncrypt(b.send, 'back');
    assert.equal(ratchetDecrypt(a.recv, e.message).plaintext, 'back');
  });

  test('forward secrecy: an earlier message cannot be decrypted once the chain has moved past it', () => {
    let { a, b } = handshake();
    const m0 = ratchetEncrypt(a.send, 'm0'); a.send = m0.send;
    const m1 = ratchetEncrypt(a.send, 'm1');
    b.recv = ratchetDecrypt(b.recv, m1.message).recv; // skips m0
    assert.throws(() => ratchetDecrypt(b.recv, m0.message), /forward secrecy/);
  });

  test('gaps up to maxSkip are skipped; beyond it they are refused', () => {
    let { a, b } = handshake();
    let send = a.send, last;
    for (let i = 0; i < 5; i++) { last = ratchetEncrypt(send, `m${i}`); send = last.send; }
    assert.equal(ratchetDecrypt(b.recv, last!.message).plaintext, 'm4');
    assert.throws(() => ratchetDecrypt(b.recv, last!.message, { maxSkip: 3 }), /Too many skipped/);
  });

  test('a failed decrypt leaves the receive state untouched', () => {
    const { a, b } = handshake();
    const before = serializeSession(b);
    const e = ratchetEncrypt(a.send, 'x');
    assert.throws(() => ratchetDecrypt(b.recv, { ...e.message, ciphertext: bytesToBase64(new Uint8Array(32)) }));
    assert.deepEqual(serializeSession(b), before);
    assert.equal(ratchetDecrypt(b.recv, e.message).plaintext, 'x');
  });
});

describe('session state at rest', () => {
  test('serializes to 73 bytes and seals with the master key', async () => {
    const { a } = handshake();
    const bytes = serializeSession(a);
    assert.equal(bytes.length, 73);
    assert.deepEqual(deserializeSession(bytes), a);
    const mk = rawMasterKey(await deriveMasterKeyBytes('pw', '00'.repeat(32)));
    const w = await wrapSession(a, mk);
    assert.deepEqual(await unwrapSession(w.wrappedState, w.stateIv, mk), a);
    const other = rawMasterKey(await deriveMasterKeyBytes('other', '00'.repeat(32)));
    await assert.rejects(unwrapSession(w.wrappedState, w.stateIv, other));
    const corrupt = serializeSession(a); corrupt[0] = 9;
    assert.throws(() => deserializeSession(corrupt), /Unsupported or corrupt/);
  });
});

describe('fs-messaging orchestration', () => {
  async function user(userId: number, server: ReturnType<typeof makeFsServer>): Promise<FsIdentity> {
    const p = party();
    server.identities.set(userId, p.pub);
    return { userId, x25519Priv: p.sec.x25519Priv, x25519Pub: p.pub.x25519, kyberSecret: p.sec.kyberSecret, masterKey: rawMasterKey(await deriveMasterKeyBytes(`pw${userId}`, '11'.repeat(32))) };
  }

  test('prekey pool tops up only when low, and stores only sealed private keys', async () => {
    const server = makeFsServer();
    const bob = await user(2, server);
    assert.equal(await ensurePrekeyPool(bob, server.transportFor(2)), PREKEY_BATCH);
    assert.equal(await ensurePrekeyPool(bob, server.transportFor(2)), 0);
    const row = [...server.prekeys.get(2)!.values()][0]!;
    assert.ok(row.wrappedX25519Priv.length > 0 && row.wrappedKyberPriv.length > 0);
  });

  test('a full conversation; one-time prekeys are consumed; read messages expire', async () => {
    const server = makeFsServer();
    const alice = await user(1, server), bob = await user(2, server);
    await assert.rejects(sendMessage(alice, server.transportFor(1), 2, 'x'), /no prekeys/);
    await ensurePrekeyPool(bob, server.transportFor(2));
    await sendMessage(alice, server.transportFor(1), 2, 'hello');
    await sendMessage(alice, server.transportFor(1), 2, 'again');
    assert.equal(server.prekeys.get(2)!.size, PREKEY_BATCH);
    const r = await decryptIncoming(bob, server.transportFor(2), 1, server.inbox(2, 1));
    assert.deepEqual([...r.values()], ['hello', 'again']);
    assert.equal(server.prekeys.get(2)!.size, PREKEY_BATCH - 1);
    await sendMessage(bob, server.transportFor(2), 1, 'hi alice');
    assert.deepEqual([...(await decryptIncoming(alice, server.transportFor(1), 2, server.inbox(1, 2))).values()], ['hi alice']);
    assert.deepEqual([...(await decryptIncoming(bob, server.transportFor(2), 1, server.inbox(2, 1))).values()], ['[expired]', '[expired]']);
  });

  test("ignores other senders' messages and plain (non-ratchet) messages", async () => {
    const server = makeFsServer();
    const bob = await user(2, server);
    const out = await decryptIncoming(bob, server.transportFor(2), 1, [
      { id: 1, senderId: 3, ratchetN: 0, ratchetHeader: null, encryptedContent: '', encryptionIV: '' },
      { id: 2, senderId: 1, ratchetN: null, ratchetHeader: null, encryptedContent: '', encryptionIV: '' },
    ]);
    assert.equal(out.size, 0);
  });
});
