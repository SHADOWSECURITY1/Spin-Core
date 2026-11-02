import { gcm } from '@noble/ciphers/aes.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { base64ToBytes, bytesToBase64, bytesToHex, hexToBytes, utf8Decode, utf8Encode } from './encoding.js';
import { KYBER_PUBLIC_KEY_BYTES, KYBER_SECRET_KEY_BYTES, X25519_KEY_BYTES } from './identity.js';
import { IV_BYTES, sealSecret, type MasterKey } from './master-key.js';
import { secureRandom } from './random.js';

/**
 * Forward-secret messaging, v1: a PQXDH-style handshake into a symmetric-key
 * ratchet. Byte-for-byte the format SPIN Vault web already uses (see
 * test/fixtures/ratchet-web-v1.json and docs/FORWARD_SECRECY_DESIGN.md there).
 *
 * Handshake: root = HKDF(DH(IK_A,OPK_B) ‖ DH(EK_A,IK_B) ‖ DH(EK_A,OPK_B) ‖
 * MLKEM(IK_B) ‖ MLKEM(OPK_B), "spin-vault/pqxdh/v1"). Post-quantum, and forward
 * secret once the initiator drops its ephemeral key and the responder deletes
 * the consumed one-time prekey.
 *
 * Ratchet: each message key = HKDF(chainKey, MK), next chainKey = HKDF(chainKey,
 * CK). Chains only move forward, so holding today's chain key reveals nothing
 * about earlier messages.
 *
 * Known limits: no DH ratchet, so no post-compromise
 * security; skipped message keys are discarded, so out-of-order delivery past
 * the chain position is unreadable by design.
 */

const PQXDH_INFO = 'spin-vault/pqxdh/v1';
const CK_INIT_A = 'spin-vault/ratchet/chain/initiator->responder/v1';
const CK_INIT_B = 'spin-vault/ratchet/chain/responder->initiator/v1';
const MK_INFO = 'spin-vault/ratchet/mk/v1';
const SID_INFO = 'spin-vault/ratchet/sid/v1';
const CK_INFO = 'spin-vault/ratchet/ck/v1';
const KYBER_CIPHERTEXT_BYTES = 1088;
export const DEFAULT_MAX_SKIP = 256;

// ── primitives ───────────────────────────────────────────────────────────────

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

/** HKDF-SHA256 → 32 bytes, empty salt, domain-separated by `info`. */
function hkdf32(ikm: Uint8Array, info: string): Uint8Array {
  return hkdf(sha256, ikm, new Uint8Array(0), utf8Encode(info), 32);
}

function keyBytes(b64: string, length: number, what: string): Uint8Array {
  const b = base64ToBytes(b64);
  if (b.length !== length) throw new Error(`${what} has the wrong length`);
  return b;
}

function dh(priv: Uint8Array, pub: Uint8Array): Uint8Array {
  const s = x25519.getSharedSecret(priv, pub);
  if (s.every((v) => v === 0)) throw new Error('Invalid X25519 public key');
  return s;
}

// ── identity and one-time prekeys ────────────────────────────────────────────

export interface IdentityPublic { x25519: string; kyber: string } // base64
export interface IdentitySecret { x25519Priv: Uint8Array; kyberSecret: Uint8Array }
export interface OneTimePreKeyPublic { id: string; x25519: string; kyber: string }
export interface OneTimePreKeySecret { id: string; x25519Priv: Uint8Array; kyberSecret: Uint8Array }
export interface PreKeyBundle { identity: IdentityPublic; oneTime: OneTimePreKeyPublic }

/** A one-time prekey for the published pool. Delete the secret once it's consumed. */
export function generateOneTimePreKey(id: string): { pub: OneTimePreKeyPublic; sec: OneTimePreKeySecret } {
  const xPriv = x25519.utils.randomSecretKey();
  const k = ml_kem768.keygen();
  return {
    pub: { id, x25519: bytesToBase64(x25519.getPublicKey(xPriv)), kyber: bytesToBase64(k.publicKey) },
    sec: { id, x25519Priv: xPriv, kyberSecret: k.secretKey },
  };
}

// ── handshake ────────────────────────────────────────────────────────────────

export interface HandshakeHeader {
  ek: string; // initiator ephemeral X25519 public (base64)
  ctIdentity: string; // ML-KEM ciphertext to the responder's identity key (base64)
  ctOneTime: string; // ML-KEM ciphertext to the responder's one-time prekey (base64)
  initiatorIdentityX25519: string; // initiator identity X25519 public (base64)
  oneTimeId: string; // which one-time prekey was consumed
}

/** Initiator side. The ephemeral key is never returned, so it can't be kept. */
export function initiateSession(
  initiator: { identityX25519Priv: Uint8Array; identityX25519Pub: string },
  bundle: PreKeyBundle,
): { rootKey: Uint8Array; header: HandshakeHeader } {
  const ikB = keyBytes(bundle.identity.x25519, X25519_KEY_BYTES, 'Identity X25519 key');
  const opkB = keyBytes(bundle.oneTime.x25519, X25519_KEY_BYTES, 'One-time X25519 key');
  const ikBKyber = keyBytes(bundle.identity.kyber, KYBER_PUBLIC_KEY_BYTES, 'Identity ML-KEM key');
  const opkBKyber = keyBytes(bundle.oneTime.kyber, KYBER_PUBLIC_KEY_BYTES, 'One-time ML-KEM key');

  const ekPriv = x25519.utils.randomSecretKey();
  const ekPub = x25519.getPublicKey(ekPriv);
  const dhA = dh(initiator.identityX25519Priv, opkB);
  const dhB = dh(ekPriv, ikB);
  const dhC = dh(ekPriv, opkB);
  ekPriv.fill(0);
  const encIk = ml_kem768.encapsulate(ikBKyber);
  const encOpk = ml_kem768.encapsulate(opkBKyber);

  const ikm = concat(dhA, dhB, dhC, encIk.sharedSecret, encOpk.sharedSecret);
  const rootKey = hkdf32(ikm, PQXDH_INFO);
  ikm.fill(0);
  return {
    rootKey,
    header: {
      ek: bytesToBase64(ekPub),
      ctIdentity: bytesToBase64(encIk.cipherText),
      ctOneTime: bytesToBase64(encOpk.cipherText),
      initiatorIdentityX25519: initiator.identityX25519Pub,
      oneTimeId: bundle.oneTime.id,
    },
  };
}

/** Responder side. Delete the consumed one-time prekey afterwards (server and local). */
export function respondToSession(
  header: HandshakeHeader,
  responderIdentity: IdentitySecret,
  oneTime: OneTimePreKeySecret,
): { rootKey: Uint8Array } {
  if (oneTime.id !== header.oneTimeId) throw new Error('Handshake names a different one-time prekey');
  if (responderIdentity.kyberSecret.length !== KYBER_SECRET_KEY_BYTES) throw new Error('ML-KEM-768 secret key has the wrong length');
  const ikA = keyBytes(header.initiatorIdentityX25519, X25519_KEY_BYTES, 'Initiator identity key');
  const ekA = keyBytes(header.ek, X25519_KEY_BYTES, 'Ephemeral key');
  const dhA = dh(oneTime.x25519Priv, ikA);
  const dhB = dh(responderIdentity.x25519Priv, ekA);
  const dhC = dh(oneTime.x25519Priv, ekA);
  const ssIk = ml_kem768.decapsulate(keyBytes(header.ctIdentity, KYBER_CIPHERTEXT_BYTES, 'ML-KEM ciphertext'), responderIdentity.kyberSecret);
  const ssOpk = ml_kem768.decapsulate(keyBytes(header.ctOneTime, KYBER_CIPHERTEXT_BYTES, 'ML-KEM ciphertext'), oneTime.kyberSecret);
  const ikm = concat(dhA, dhB, dhC, ssIk, ssOpk);
  const rootKey = hkdf32(ikm, PQXDH_INFO);
  ikm.fill(0);
  return { rootKey };
}

// ── symmetric ratchet ────────────────────────────────────────────────────────

export interface ChainState { chainKey: Uint8Array; n: number }
export interface Session { send: ChainState; recv: ChainState }
export interface RatchetMessage { n: number; iv: string; ciphertext: string } // iv hex, ciphertext base64

/** Both parties derive matching directional chains from the root. */
export function initSession(rootKey: Uint8Array, role: 'initiator' | 'responder'): Session {
  const ckA = hkdf32(rootKey, CK_INIT_A);
  const ckB = hkdf32(rootKey, CK_INIT_B);
  return role === 'initiator'
    ? { send: { chainKey: ckA, n: 0 }, recv: { chainKey: ckB, n: 0 } }
    : { send: { chainKey: ckB, n: 0 }, recv: { chainKey: ckA, n: 0 } };
}

/** Encrypt and advance the send chain. The old chain key and message key aren't kept. */
export function ratchetEncrypt(send: ChainState, plaintext: string): { send: ChainState; message: RatchetMessage } {
  const mk = hkdf32(send.chainKey, MK_INFO);
  const nextCk = hkdf32(send.chainKey, CK_INFO);
  const iv = secureRandom(IV_BYTES);
  const ct = gcm(mk, iv).encrypt(utf8Encode(plaintext));
  mk.fill(0);
  return { send: { chainKey: nextCk, n: send.n + 1 }, message: { n: send.n, iv: bytesToHex(iv), ciphertext: bytesToBase64(ct) } };
}

/**
 * Decrypt and advance the receive chain, skipping over gaps up to maxSkip.
 * A message older than the chain position throws: its key is gone (forward
 * secrecy). The input state is never modified; use the returned state only
 * on success.
 */
export function ratchetDecrypt(
  recv: ChainState,
  message: RatchetMessage,
  opts: { maxSkip?: number } = {},
): { recv: ChainState; plaintext: string } {
  const maxSkip = opts.maxSkip ?? DEFAULT_MAX_SKIP;
  if (!Number.isInteger(message.n) || message.n < 0) throw new Error('Invalid message number');
  if (message.n < recv.n) throw new Error('Message key no longer available (forward secrecy): the chain has advanced past it');
  if (message.n - recv.n > maxSkip) throw new Error('Too many skipped messages');
  let ck = recv.chainKey;
  for (let i = recv.n; i < message.n; i++) ck = hkdf32(ck, CK_INFO);
  const mk = hkdf32(ck, MK_INFO);
  try {
    const plaintext = utf8Decode(gcm(mk, hexToBytes(message.iv)).decrypt(base64ToBytes(message.ciphertext)));
    return { recv: { chainKey: hkdf32(ck, CK_INFO), n: message.n + 1 }, plaintext };
  } finally {
    mk.fill(0);
  }
}

// ── session state at rest ────────────────────────────────────────────────────

const SESSION_VERSION = 1;
const SESSION_BYTES = 1 + 4 + 4 + 32 + 32; // [ver][sendN:4][recvN:4][sendCk:32][recvCk:32]

export function serializeSession(s: Session): Uint8Array {
  const out = new Uint8Array(SESSION_BYTES);
  const dv = new DataView(out.buffer);
  out[0] = SESSION_VERSION;
  dv.setUint32(1, s.send.n);
  dv.setUint32(5, s.recv.n);
  out.set(s.send.chainKey, 9);
  out.set(s.recv.chainKey, 41);
  return out;
}

export function deserializeSession(bytes: Uint8Array): Session {
  if (bytes.length !== SESSION_BYTES || bytes[0] !== SESSION_VERSION) throw new Error('Unsupported or corrupt session state');
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    send: { n: dv.getUint32(1), chainKey: bytes.slice(9, 41) },
    recv: { n: dv.getUint32(5), chainKey: bytes.slice(41, 73) },
  };
}

/** Seal session state with the master key for server storage (server stays blind). */
export async function wrapSession(s: Session, masterKey: MasterKey): Promise<{ wrappedState: string; stateIv: string }> {
  const plain = serializeSession(s);
  const { sealed, iv } = await sealSecret(plain, masterKey);
  plain.fill(0);
  return { wrappedState: bytesToBase64(sealed), stateIv: bytesToHex(iv) };
}

export async function unwrapSession(wrappedState: string, stateIv: string, masterKey: MasterKey): Promise<Session> {
  return deserializeSession(await masterKey.open(hexToBytes(stateIv), base64ToBytes(wrappedState)));
}

// ── session convenience ──────────────────────────────────────────────────────

/**
 * A public 8-byte id for a session (hex), derived from its root key so both
 * parties compute the same value. Lets messages say which session they belong
 * to when a conversation has more than one (see SessionStore).
 */
export function sessionIdFromRoot(rootKey: Uint8Array): string {
  return bytesToHex(hkdf32(rootKey, SID_INFO).slice(0, 8));
}

export function establishAsInitiator(
  myIdentityX25519Priv: Uint8Array,
  myIdentityX25519Pub: string,
  bundle: PreKeyBundle,
): { session: Session; header: HandshakeHeader; sessionId: string } {
  const { rootKey, header } = initiateSession({ identityX25519Priv: myIdentityX25519Priv, identityX25519Pub: myIdentityX25519Pub }, bundle);
  const session = initSession(rootKey, 'initiator');
  const sessionId = sessionIdFromRoot(rootKey);
  rootKey.fill(0);
  return { session, header, sessionId };
}

export function establishAsResponder(
  header: HandshakeHeader,
  myIdentity: IdentitySecret,
  oneTime: OneTimePreKeySecret,
): { session: Session; sessionId: string } {
  const { rootKey } = respondToSession(header, myIdentity, oneTime);
  const session = initSession(rootKey, 'responder');
  const sessionId = sessionIdFromRoot(rootKey);
  rootKey.fill(0);
  return { session, sessionId };
}

export function sessionEncrypt(session: Session, plaintext: string): { session: Session; message: RatchetMessage } {
  const { send, message } = ratchetEncrypt(session.send, plaintext);
  return { session: { ...session, send }, message };
}

export function sessionDecrypt(session: Session, message: RatchetMessage): { session: Session; plaintext: string } {
  const { recv, plaintext } = ratchetDecrypt(session.recv, message);
  return { session: { ...session, recv }, plaintext };
}

// ── per-conversation session store (v2) ──────────────────────────────────────

/**
 * Everything one user keeps about their conversation with one peer: the
 * active session (used to send) plus up to MAX_PREVIOUS_SESSIONS older ones,
 * kept receive-only so messages still in flight on them can be read.
 *
 * Stored sealed with the master key, in the same field as v1 sessions.
 * Layout v2: [2][count] then per entry [flags][sid:8][sendN:4][recvN:4]
 * [sendCk:32][recvCk:32], active entry first. flags: bit0 has sid, bit1 we
 * initiated. A v1 blob (one 73-byte session) reads as an active entry with
 * no id, initiated by an unknown party.
 */
export interface StoredSession {
  session: Session;
  sessionId: string | null; // null: a v1 session from before ids existed
  initiatedByMe: boolean;
}
export interface SessionStore {
  active: StoredSession;
  previous: StoredSession[]; // newest first, receive-only
}

export const MAX_PREVIOUS_SESSIONS = 4;
const STORE_VERSION = 2;
const ENTRY_BYTES = 1 + 8 + 4 + 4 + 32 + 32;

export function serializeSessionStore(store: SessionStore): Uint8Array {
  const entries = [store.active, ...store.previous.slice(0, MAX_PREVIOUS_SESSIONS)];
  const out = new Uint8Array(2 + entries.length * ENTRY_BYTES);
  const dv = new DataView(out.buffer);
  out[0] = STORE_VERSION;
  out[1] = entries.length;
  entries.forEach((e, i) => {
    const o = 2 + i * ENTRY_BYTES;
    out[o] = (e.sessionId ? 1 : 0) | (e.initiatedByMe ? 2 : 0);
    if (e.sessionId) out.set(hexToBytes(e.sessionId), o + 1);
    dv.setUint32(o + 9, e.session.send.n);
    dv.setUint32(o + 13, e.session.recv.n);
    out.set(e.session.send.chainKey, o + 17);
    out.set(e.session.recv.chainKey, o + 49);
  });
  return out;
}

export function deserializeSessionStore(bytes: Uint8Array): SessionStore {
  if (bytes[0] === SESSION_VERSION) {
    return { active: { session: deserializeSession(bytes), sessionId: null, initiatedByMe: false }, previous: [] };
  }
  const count = bytes[1] ?? 0;
  if (bytes[0] !== STORE_VERSION || count < 1 || bytes.length !== 2 + count * ENTRY_BYTES) {
    throw new Error('Unsupported or corrupt session state');
  }
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const entries: StoredSession[] = [];
  for (let i = 0; i < count; i++) {
    const o = 2 + i * ENTRY_BYTES;
    const flags = bytes[o]!;
    entries.push({
      sessionId: flags & 1 ? bytesToHex(bytes.slice(o + 1, o + 9)) : null,
      initiatedByMe: (flags & 2) !== 0,
      session: {
        send: { n: dv.getUint32(o + 9), chainKey: bytes.slice(o + 17, o + 49) },
        recv: { n: dv.getUint32(o + 13), chainKey: bytes.slice(o + 49, o + 81) },
      },
    });
  }
  return { active: entries[0]!, previous: entries.slice(1) };
}

export async function wrapSessionStore(store: SessionStore, masterKey: MasterKey): Promise<{ wrappedState: string; stateIv: string }> {
  const plain = serializeSessionStore(store);
  const { sealed, iv } = await sealSecret(plain, masterKey);
  plain.fill(0);
  return { wrappedState: bytesToBase64(sealed), stateIv: bytesToHex(iv) };
}

/** Reads v2 stores and v1 single-session blobs. */
export async function unwrapSessionStore(wrappedState: string, stateIv: string, masterKey: MasterKey): Promise<SessionStore> {
  return deserializeSessionStore(await masterKey.open(hexToBytes(stateIv), base64ToBytes(wrappedState)));
}
