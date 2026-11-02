import { base64ToBytes, bytesToBase64, bytesToHex, hexToBytes } from './encoding.js';
import { sealSecret, type MasterKey } from './master-key.js';
import {
  establishAsInitiator,
  establishAsResponder,
  generateOneTimePreKey,
  MAX_PREVIOUS_SESSIONS,
  sessionDecrypt,
  sessionEncrypt,
  unwrapSessionStore,
  wrapSessionStore,
  type HandshakeHeader,
  type OneTimePreKeySecret,
  type PreKeyBundle,
  type SessionStore,
  type StoredSession,
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
 *
 * Identity: a handshake is accepted only if the initiator identity key in it
 * is the sender's known identity key (FsTransport.getIdentityKey), and a
 * sender only opens a session to a bundle carrying the peer's known key.
 * The responder's one-time prekey is deleted and the new session saved only
 * after the handshake message actually decrypts, so a forged or corrupt
 * handshake costs nothing.
 *
 * Sessions are labelled with an id both sides derive from the root key
 * (ratchetHeader: the handshake plus "sid" on a session's first message,
 * {"sid"} after). If both sides open a session at the same time ("glare"),
 * both converge on the one opened by the lower identity key, and the other
 * is kept receive-only so its messages still read. Messages without a sid
 * (written before 0.4) use the active session.
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
  /**
   * The peer's identity key as this app knows it: pinned or verified if the
   * app does that, otherwise the server's record. null if unknown.
   */
  getIdentityKey(peerId: UserId): Promise<{ x25519: string } | null>;
  getSession(peerId: UserId): Promise<{ wrappedState: string; stateIv: string } | null>;
  putSession(peerId: UserId, wrappedState: string, stateIv: string): Promise<void>;
  postMessage(body: Record<string, unknown>): Promise<{ id: number }>;
}

export interface FsIncomingMessage<UserId = number> {
  id: number;
  senderId: UserId;
  ratchetN: number | null;
  ratchetHeader: string | null; // JSON: HandshakeHeader + sid on a session's first message, {sid} after; null before 0.4
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

/** What ratchetHeader carries: the handshake on a session's first message, its id on every message (0.4+). */
type WireHeader = Partial<HandshakeHeader> & { sid?: string };

const isHandshake = (h: WireHeader | null): h is HandshakeHeader & { sid?: string } =>
  !!h && typeof h.ek === 'string' && typeof h.oneTimeId === 'string' && typeof h.initiatorIdentityX25519 === 'string';

function parseHeader(raw: string | null): WireHeader | null | undefined {
  if (raw === null) return null;
  try {
    const h = JSON.parse(raw);
    return h && typeof h === 'object' ? (h as WireHeader) : undefined;
  } catch {
    return undefined; // unparseable
  }
}

function sameKey(a: string, b: string): boolean {
  const x = base64ToBytes(a), y = base64ToBytes(b);
  return x.length === y.length && x.every((v, i) => v === y[i]);
}

/** Lexicographic byte order of two base64 keys: true if a sorts before b. */
function keyLess(a: string, b: string): boolean {
  const x = base64ToBytes(a), y = base64ToBytes(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i]! < y[i]!;
  return x.length < y.length;
}

async function loadStore<U>(id: FsIdentity<U>, t: FsTransport<U>, peerId: U): Promise<SessionStore | null> {
  const stored = await t.getSession(peerId);
  return stored ? unwrapSessionStore(stored.wrappedState, stored.stateIv, id.masterKey) : null;
}

async function saveStore<U>(id: FsIdentity<U>, t: FsTransport<U>, peerId: U, store: SessionStore): Promise<void> {
  const w = await wrapSessionStore(store, id.masterKey);
  await t.putSession(peerId, w.wrappedState, w.stateIv);
}

/** Send a forward-secret message, establishing the session on the first send. */
export async function sendMessage<U>(
  id: FsIdentity<U>,
  t: FsTransport<U>,
  peerId: U,
  plaintext: string,
): Promise<{ messageId: number; ratchetN: number; plaintext: string }> {
  let store = await loadStore(id, t, peerId);
  let header: WireHeader | null;
  if (store) {
    header = store.active.sessionId ? { sid: store.active.sessionId } : null;
  } else {
    const bundle = await t.getPrekeyBundle(peerId);
    if (!bundle) throw new Error("This contact can't receive secure messages yet (no prekeys available).");
    const known = await t.getIdentityKey(peerId);
    if (!known || !sameKey(known.x25519, bundle.identity.x25519)) {
      throw new Error("This contact's prekey bundle doesn't match their identity key; not sending.");
    }
    const est = establishAsInitiator(id.x25519Priv, id.x25519Pub, bundle);
    store = { active: { session: est.session, sessionId: est.sessionId, initiatedByMe: true }, previous: [] };
    header = { ...est.header, sid: est.sessionId };
  }

  const enc = sessionEncrypt(store.active.session, plaintext);
  store.active.session = enc.session;
  await saveStore(id, t, peerId, store); // before posting, so a chain position is never reused

  const posted = await t.postMessage({
    receiverId: peerId,
    encryptedContent: enc.message.ciphertext,
    encryptionIV: enc.message.iv,
    ratchetN: enc.message.n,
    ratchetHeader: header ? JSON.stringify(header) : null,
  });
  return { messageId: posted.id, ratchetN: enc.message.n, plaintext };
}

/** Try one message on one session; on success advance it in place. */
function tryDecrypt<U>(entry: StoredSession, m: FsIncomingMessage<U>): string | null {
  try {
    const dec = sessionDecrypt(entry.session, { n: m.ratchetN as number, iv: m.encryptionIV, ciphertext: m.encryptedContent });
    entry.session = dec.session;
    return dec.plaintext;
  } catch {
    return null;
  }
}

/**
 * Decrypt received messages (in message-id order), advancing the receive
 * chains, and save the session store. A handshake message opens a responder
 * session only if it names the sender's known identity key and its first
 * message decrypts; only then is the one-time prekey deleted.
 *
 * Results per message id: the plaintext, or '[expired]' (chain has moved
 * past it), '[Unverified sender]' (handshake identity isn't the sender's
 * known key), '[Unreadable]' (forged or corrupt), '[Prekey already
 * consumed]' or '[No session]'.
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
    .sort((a, b) => a.id - b.id);
  if (received.length === 0) return out;

  let store = await loadStore(id, t, peerId);
  let dirty = false;
  const consumedPrekeys: string[] = [];
  let knownIdentity: { x25519: string } | null | undefined;

  const all = (s: SessionStore) => [s.active, ...s.previous];

  for (const m of received) {
    const h = parseHeader(m.ratchetHeader);
    if (h === undefined) { out.set(m.id, '[Unreadable]'); continue; }
    const sid = typeof h?.sid === 'string' ? h.sid : null;
    const known = store && sid ? all(store).find((e) => e.sessionId === sid) : undefined;

    // A message on a session we already have (including a re-read handshake).
    if (known) {
      out.set(m.id, tryDecrypt(known, m) ?? '[expired]');
      dirty = true;
      continue;
    }

    if (!isHandshake(h)) {
      if (!store) { out.set(m.id, '[No session]'); continue; }
      // Pre-0.4 messages carry no sid: use the active session. A sid we don't
      // know may belong to a pre-0.4 session saved without one: try that.
      const legacy = sid ? all(store).find((e) => e.sessionId === null) : store.active;
      if (!legacy) { out.set(m.id, '[expired]'); continue; }
      const pt = tryDecrypt(legacy, m);
      if (pt !== null && sid) legacy.sessionId = sid;
      out.set(m.id, pt ?? '[expired]');
      dirty = true;
      continue;
    }

    // A handshake for a session we don't have.
    if (knownIdentity === undefined) knownIdentity = await t.getIdentityKey(peerId);
    if (!knownIdentity || !sameKey(knownIdentity.x25519, h.initiatorIdentityX25519)) {
      out.set(m.id, '[Unverified sender]');
      continue;
    }
    const priv = consumedPrekeys.includes(h.oneTimeId) ? null : await t.getPrekeyPrivate(h.oneTimeId);
    if (!priv) {
      if (store && !sid) {
        // Pre-0.4 handshake re-read after its session was saved.
        const pt = tryDecrypt(store.active, m);
        out.set(m.id, pt ?? '[expired]');
        dirty = true;
      } else {
        out.set(m.id, store ? '[expired]' : '[Prekey already consumed]');
      }
      continue;
    }
    const oneTime: OneTimePreKeySecret = {
      id: h.oneTimeId,
      x25519Priv: await openBytes(priv.wrappedX25519Priv, priv.x25519PrivIv, id.masterKey),
      kyberSecret: await openBytes(priv.wrappedKyberPriv, priv.kyberPrivIv, id.masterKey),
    };
    let entry: StoredSession;
    try {
      const est = establishAsResponder(h, { x25519Priv: id.x25519Priv, kyberSecret: id.kyberSecret }, oneTime);
      entry = { session: est.session, sessionId: est.sessionId, initiatedByMe: false };
    } catch {
      out.set(m.id, '[Unreadable]');
      continue;
    } finally {
      oneTime.x25519Priv.fill(0);
      oneTime.kyberSecret.fill(0);
    }
    const pt = sid !== null && sid !== entry.sessionId ? null : tryDecrypt(entry, m);
    if (pt === null) { out.set(m.id, '[Unreadable]'); continue; } // nothing kept, prekey untouched

    // Commit. Glare: if our own session is still unanswered, both sides keep
    // the one opened by the lower identity key; otherwise the peer re-opened
    // and the new session takes over. The other stays receive-only.
    out.set(m.id, pt);
    consumedPrekeys.push(h.oneTimeId);
    dirty = true;
    if (!store) {
      store = { active: entry, previous: [] };
    } else {
      const a = store.active;
      const keepMine = a.initiatedByMe && a.session.recv.n === 0 && keyLess(id.x25519Pub, h.initiatorIdentityX25519);
      if (keepMine) store.previous.unshift(entry);
      else { store.previous.unshift(a); store.active = entry; }
      store.previous = store.previous.slice(0, MAX_PREVIOUS_SESSIONS);
    }
  }

  if (store && dirty) await saveStore(id, t, peerId, store);
  // Only after the session is saved: the prekey is now unneeded (forward secrecy).
  for (const keyId of consumedPrekeys) await t.deletePrekey(keyId);
  return out;
}
