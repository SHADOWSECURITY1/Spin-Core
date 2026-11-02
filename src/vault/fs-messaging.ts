import { base64ToBytes, bytesToBase64, bytesToHex, hexToBytes } from './encoding.js';
import { sealSecret, type MasterKey } from './master-key.js';
import {
  establishAsInitiator,
  establishAsResponder,
  generateOneTimePreKey,
  sessionDecrypt,
  sessionEncrypt,
  unwrapSession,
  wrapSession,
  type HandshakeHeader,
  type OneTimePreKeySecret,
  type PreKeyBundle,
  type Session,
} from './ratchet.js';

/**
 * Forward-secret messaging orchestration: prekey pool, send, receive.
 * Transport-agnostic: the app passes in how to reach its server, so web and
 * mobile share this logic. Same stored formats as SPIN Vault web's
 * fs-messaging.ts.
 *
 * Messages are readable while the chat is open: the receive chain advances as
 * messages are read and the session is saved, so a message the chain has
 * moved past comes back as '[expired]'.
 */

export interface FsIdentity<UserId = number> {
  userId: UserId;
  x25519Priv: Uint8Array;
  x25519Pub: string; // base64
  kyberSecret: Uint8Array;
  masterKey: MasterKey;
}

export interface WrappedPrekeyUpload {
  keyId: string;
  x25519Pub: string;
  kyberPub: string;
  wrappedX25519Priv: string;
  x25519PrivIv: string;
  wrappedKyberPriv: string;
  kyberPrivIv: string;
}

export interface FsTransport<UserId = number> {
  getPrekeyCount(): Promise<number>;
  uploadPrekeys(prekeys: WrappedPrekeyUpload[]): Promise<void>;
  getPrekeyBundle(peerId: UserId): Promise<PreKeyBundle | null>;
  getPrekeyPrivate(keyId: string): Promise<Pick<WrappedPrekeyUpload, 'wrappedX25519Priv' | 'x25519PrivIv' | 'wrappedKyberPriv' | 'kyberPrivIv'> | null>;
  deletePrekey(keyId: string): Promise<void>;
  getSession(peerId: UserId): Promise<{ wrappedState: string; stateIv: string } | null>;
  putSession(peerId: UserId, wrappedState: string, stateIv: string): Promise<void>;
  postMessage(body: Record<string, unknown>): Promise<{ id: number }>;
}

export interface FsIncomingMessage<UserId = number> {
  id: number;
  senderId: UserId;
  ratchetN: number | null;
  ratchetHeader: string | null; // JSON HandshakeHeader on a session's first message
  encryptedContent: string;
  encryptionIV: string;
}

export const PREKEY_MIN = 15;
export const PREKEY_BATCH = 40;

let keyCounter = 0;
function newKeyId(userId: unknown): string {
  keyCounter += 1;
  return `${String(userId)}-${Date.now()}-${keyCounter}`;
}

async function sealBytes(bytes: Uint8Array, masterKey: MasterKey): Promise<{ wrapped: string; iv: string }> {
  const { sealed, iv } = await sealSecret(bytes, masterKey);
  return { wrapped: bytesToBase64(sealed), iv: bytesToHex(iv) };
}

async function openBytes(wrapped: string, iv: string, masterKey: MasterKey): Promise<Uint8Array> {
  return masterKey.open(hexToBytes(iv), base64ToBytes(wrapped));
}

/** Top up the published one-time prekey pool if it's running low. Returns how many were added. */
export async function ensurePrekeyPool<U>(id: FsIdentity<U>, t: FsTransport<U>): Promise<number> {
  if ((await t.getPrekeyCount()) >= PREKEY_MIN) return 0;
  const batch: WrappedPrekeyUpload[] = [];
  for (let i = 0; i < PREKEY_BATCH; i++) {
    const { pub, sec } = generateOneTimePreKey(newKeyId(id.userId));
    const wx = await sealBytes(sec.x25519Priv, id.masterKey);
    const wk = await sealBytes(sec.kyberSecret, id.masterKey);
    sec.x25519Priv.fill(0);
    sec.kyberSecret.fill(0);
    batch.push({
      keyId: pub.id,
      x25519Pub: pub.x25519,
      kyberPub: pub.kyber,
      wrappedX25519Priv: wx.wrapped,
      x25519PrivIv: wx.iv,
      wrappedKyberPriv: wk.wrapped,
      kyberPrivIv: wk.iv,
    });
  }
  await t.uploadPrekeys(batch);
  return batch.length;
}

/** Send a forward-secret message, establishing the session on the first send. */
export async function sendMessage<U>(
  id: FsIdentity<U>,
  t: FsTransport<U>,
  peerId: U,
  plaintext: string,
): Promise<{ messageId: number; ratchetN: number; plaintext: string }> {
  let session: Session;
  let header: HandshakeHeader | null = null;
  const stored = await t.getSession(peerId);
  if (stored) {
    session = await unwrapSession(stored.wrappedState, stored.stateIv, id.masterKey);
  } else {
    const bundle = await t.getPrekeyBundle(peerId);
    if (!bundle) throw new Error("This contact can't receive secure messages yet (no prekeys available).");
    ({ session, header } = establishAsInitiator(id.x25519Priv, id.x25519Pub, bundle));
  }

  const enc = sessionEncrypt(session, plaintext);
  const w = await wrapSession(enc.session, id.masterKey);
  await t.putSession(peerId, w.wrappedState, w.stateIv);

  const posted = await t.postMessage({
    receiverId: peerId,
    encryptedContent: enc.message.ciphertext,
    encryptionIV: enc.message.iv,
    ratchetN: enc.message.n,
    ratchetHeader: header ? JSON.stringify(header) : null,
  });
  return { messageId: posted.id, ratchetN: enc.message.n, plaintext };
}

/**
 * Decrypt received messages, advancing the receive chain, and save the session.
 * Establishes the responder session from the first message carrying a
 * handshake header, then deletes the consumed one-time prekey.
 */
export async function decryptIncoming<U>(
  id: FsIdentity<U>,
  t: FsTransport<U>,
  peerId: U,
  messages: FsIncomingMessage<U>[],
): Promise<Map<number, string>> {
  const out = new Map<number, string>();
  const received = messages
    .filter((m) => m.senderId === peerId && m.ratchetN !== null)
    .sort((a, b) => (a.ratchetN as number) - (b.ratchetN as number));
  if (received.length === 0) return out;

  let session: Session | null = null;
  const stored = await t.getSession(peerId);
  if (stored) session = await unwrapSession(stored.wrappedState, stored.stateIv, id.masterKey);

  for (const m of received) {
    if (!session) {
      if (!m.ratchetHeader) { out.set(m.id, '[No session]'); continue; }
      const header: HandshakeHeader = JSON.parse(m.ratchetHeader);
      const priv = await t.getPrekeyPrivate(header.oneTimeId);
      if (!priv) { out.set(m.id, '[Prekey already consumed]'); continue; }
      const oneTime: OneTimePreKeySecret = {
        id: header.oneTimeId,
        x25519Priv: await openBytes(priv.wrappedX25519Priv, priv.x25519PrivIv, id.masterKey),
        kyberSecret: await openBytes(priv.wrappedKyberPriv, priv.kyberPrivIv, id.masterKey),
      };
      try {
        session = establishAsResponder(header, { x25519Priv: id.x25519Priv, kyberSecret: id.kyberSecret }, oneTime).session;
      } finally {
        oneTime.x25519Priv.fill(0);
        oneTime.kyberSecret.fill(0);
      }
      await t.deletePrekey(header.oneTimeId); // consumed → deleted (forward secrecy)
    }
    try {
      const dec = sessionDecrypt(session, { n: m.ratchetN as number, iv: m.encryptionIV, ciphertext: m.encryptedContent });
      session = dec.session;
      out.set(m.id, dec.plaintext);
    } catch {
      out.set(m.id, '[expired]');
    }
  }

  if (session) {
    const w = await wrapSession(session, id.masterKey);
    await t.putSession(peerId, w.wrappedState, w.stateIv);
  }
  return out;
}
