import { gcm } from '@noble/ciphers/aes.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { base64ToBytes, bytesToBase64, bytesToHex, hexToBytes, utf8Decode, utf8Encode } from './encoding.js';
import { KYBER_PUBLIC_KEY_BYTES, KYBER_SECRET_KEY_BYTES, X25519_KEY_BYTES } from './identity.js';
import { AES_KEY_BYTES, IV_BYTES } from './master-key.js';
import { secureRandom } from './random.js';

/**
 * Hybrid post-quantum message encryption, wire format v1.
 *
 * The message is AES-256-GCM encrypted with a fresh DEK. For each party
 * (recipient, and a copy for the sender), the DEK is wrapped under a KEK
 * derived with HKDF-SHA256 from BOTH an X25519 ephemeral-static shared secret
 * AND an ML-KEM-768 shared secret. Recovering the DEK requires breaking both:
 * a quantum computer that breaks X25519 still faces ML-KEM.
 *
 * Byte-for-byte the format SPIN Vault web and mobile already produce:
 * - encryptedContent: base64(ciphertext || tag); contentIV: hex
 * - encryptedDEKFor{Recipient,Sender}: base64(ephemeral X25519 public key)
 * - encryptedDEKFor{Recipient,Sender}Kyber: base64(ML-KEM ct) + "." + base64(iv || wrapped DEK)
 * - KEK = HKDF-SHA256(ikm = x25519SS || mlkemSS, salt = empty, info = HYBRID_KEK_INFO, 32)
 */
export const HYBRID_KEK_INFO = 'spin-vault/msg-hybrid-kek/x25519-mlkem/v1';
const HYBRID_KEK_INFO_BYTES = utf8Encode(HYBRID_KEK_INFO);
const KYBER_CIPHERTEXT_BYTES = 1088;

export interface MessageEncryptPayload {
  encryptedContent: string;
  contentIV: string;
  encryptedDEKForRecipient: string;
  encryptedDEKForSender: string;
  encryptedDEKForRecipientKyber: string;
  encryptedDEKForSenderKyber: string;
}

export interface PartyPublicKeys {
  x25519PublicKeyBase64: string;
  kyberPublicKeyBase64: string;
}

function deriveKek(sClassical: Uint8Array, sKyber: Uint8Array): Uint8Array {
  const ikm = new Uint8Array(sClassical.length + sKyber.length);
  ikm.set(sClassical, 0);
  ikm.set(sKyber, sClassical.length);
  const kek = hkdf(sha256, ikm, new Uint8Array(0), HYBRID_KEK_INFO_BYTES, 32);
  ikm.fill(0);
  return kek;
}

function ecdh(priv: Uint8Array, pub: Uint8Array): Uint8Array {
  if (pub.length !== X25519_KEY_BYTES) throw new Error('X25519 public key has the wrong length');
  const shared = x25519.getSharedSecret(priv, pub);
  // An all-zero result means a low-order public key: refuse rather than derive from it.
  if (shared.every((b) => b === 0)) throw new Error('Invalid X25519 public key');
  return shared;
}

function wrapDekForParty(dek: Uint8Array, party: PartyPublicKeys): { classicalPub: string; kyberBlob: string } {
  const kyberPub = base64ToBytes(party.kyberPublicKeyBase64);
  if (kyberPub.length !== KYBER_PUBLIC_KEY_BYTES) throw new Error('ML-KEM-768 public key has the wrong length');

  const ephPriv = x25519.utils.randomSecretKey();
  const ephPub = x25519.getPublicKey(ephPriv);
  const sClassical = ecdh(ephPriv, base64ToBytes(party.x25519PublicKeyBase64));
  ephPriv.fill(0);
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(kyberPub);

  const kek = deriveKek(sClassical, sharedSecret);
  const iv = secureRandom(IV_BYTES);
  const wrapped = gcm(kek, iv).encrypt(dek);
  kek.fill(0);
  const packed = new Uint8Array(IV_BYTES + wrapped.length);
  packed.set(iv, 0);
  packed.set(wrapped, IV_BYTES);
  return { classicalPub: bytesToBase64(ephPub), kyberBlob: `${bytesToBase64(cipherText)}.${bytesToBase64(packed)}` };
}

function unwrapDekForParty(
  classicalPub: string,
  kyberBlob: string,
  x25519PrivateKey: Uint8Array,
  kyberSecretKey: Uint8Array,
): Uint8Array {
  if (x25519PrivateKey.length !== X25519_KEY_BYTES) throw new Error('X25519 private key has the wrong length');
  if (kyberSecretKey.length !== KYBER_SECRET_KEY_BYTES) throw new Error('ML-KEM-768 secret key has the wrong length');
  const dot = kyberBlob.indexOf('.');
  if (dot <= 0) throw new Error('Malformed hybrid key blob');
  const kyberCt = base64ToBytes(kyberBlob.slice(0, dot));
  const packed = base64ToBytes(kyberBlob.slice(dot + 1));
  if (kyberCt.length !== KYBER_CIPHERTEXT_BYTES || packed.length !== IV_BYTES + AES_KEY_BYTES + 16) {
    throw new Error('Malformed hybrid key blob');
  }
  const sClassical = ecdh(x25519PrivateKey, base64ToBytes(classicalPub));
  const sKyber = ml_kem768.decapsulate(kyberCt, kyberSecretKey);
  const kek = deriveKek(sClassical, sKyber);
  try {
    return gcm(kek, packed.slice(0, IV_BYTES)).decrypt(packed.slice(IV_BYTES));
  } finally {
    kek.fill(0);
  }
}

/** Both parties need an X25519 and an ML-KEM key; there is deliberately no single-KEM path. */
export function encryptMessage(
  content: string,
  recipient: PartyPublicKeys,
  sender: PartyPublicKeys,
): MessageEncryptPayload {
  for (const [who, p] of [['recipient', recipient], ['sender', sender]] as const) {
    if (!p.x25519PublicKeyBase64) throw new Error(`Identity key missing for ${who}: an X25519 key is required`);
    if (!p.kyberPublicKeyBase64) throw new Error(`Post-quantum key missing for ${who}: an ML-KEM-768 key is required`);
  }
  const dek = secureRandom(AES_KEY_BYTES);
  const contentIV = secureRandom(IV_BYTES);
  const encryptedContent = gcm(dek, contentIV).encrypt(utf8Encode(content));
  const r = wrapDekForParty(dek, recipient);
  const s = wrapDekForParty(dek, sender);
  dek.fill(0);
  return {
    encryptedContent: bytesToBase64(encryptedContent),
    contentIV: bytesToHex(contentIV),
    encryptedDEKForRecipient: r.classicalPub,
    encryptedDEKForSender: s.classicalPub,
    encryptedDEKForRecipientKyber: r.kyberBlob,
    encryptedDEKForSenderKyber: s.kyberBlob,
  };
}

/**
 * Decrypt as the recipient or as the sender (reading your own sent copy).
 * Throws if the keys are wrong or anything was tampered with.
 */
export function decryptMessage(
  payload: MessageEncryptPayload,
  keys: { x25519PrivateKey: Uint8Array; kyberSecretKey: Uint8Array },
  as: 'recipient' | 'sender',
): string {
  const classicalPub = as === 'recipient' ? payload.encryptedDEKForRecipient : payload.encryptedDEKForSender;
  const kyberBlob = as === 'recipient' ? payload.encryptedDEKForRecipientKyber : payload.encryptedDEKForSenderKyber;
  if (!classicalPub || !kyberBlob) throw new Error('Message is missing hybrid key material');
  const dek = unwrapDekForParty(classicalPub, kyberBlob, keys.x25519PrivateKey, keys.kyberSecretKey);
  try {
    if (dek.length !== AES_KEY_BYTES) throw new Error('Unwrapped DEK has the wrong length');
    return utf8Decode(gcm(dek, hexToBytes(payload.contentIV)).decrypt(base64ToBytes(payload.encryptedContent)));
  } finally {
    dek.fill(0);
  }
}
