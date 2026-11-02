import { x25519 } from '@noble/curves/ed25519.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { base64ToBytes, bytesToBase64, bytesToHex, hexToBytes } from './encoding.js';
import { sealSecret, type MasterKey } from './master-key.js';

/**
 * A user's messaging identity: an X25519 key pair (classical) and an
 * ML-KEM-768 key pair (post-quantum). Public keys go to the server for other
 * users; private keys are sealed with the master key before they leave the
 * device. Field names match what SPIN Vault stores.
 */
export const X25519_KEY_BYTES = 32;
export const KYBER_PUBLIC_KEY_BYTES = 1184;
export const KYBER_SECRET_KEY_BYTES = 2400;

export interface X25519Identity {
  publicKeyBase64: string;
  wrappedPrivateKey: string; // base64
  privateKeyIV: string; // hex
}

export interface WrappedKyberSecretKey {
  wrappedKyberPrivateKey: string; // base64
  kyberPrivateKeyIV: string; // hex
}

async function openSecret(
  wrapped: string,
  ivHex: string,
  masterKey: MasterKey,
  expectedLength: number,
  what: string,
): Promise<Uint8Array> {
  const secret = await masterKey.open(hexToBytes(ivHex), base64ToBytes(wrapped));
  if (secret.length !== expectedLength) throw new Error(`Unwrapped ${what} has the wrong length`);
  return secret;
}

export async function generateX25519Identity(masterKey: MasterKey): Promise<X25519Identity> {
  const priv = x25519.utils.randomSecretKey();
  const pub = x25519.getPublicKey(priv);
  const { sealed, iv } = await sealSecret(priv, masterKey);
  priv.fill(0);
  return { publicKeyBase64: bytesToBase64(pub), wrappedPrivateKey: bytesToBase64(sealed), privateKeyIV: bytesToHex(iv) };
}

export function unwrapX25519PrivateKey(wrappedPrivateKey: string, privateKeyIV: string, masterKey: MasterKey) {
  return openSecret(wrappedPrivateKey, privateKeyIV, masterKey, X25519_KEY_BYTES, 'X25519 private key');
}

export async function rewrapX25519PrivateKey(
  wrappedPrivateKey: string,
  privateKeyIV: string,
  oldMasterKey: MasterKey,
  newMasterKey: MasterKey,
): Promise<{ wrappedPrivateKey: string; privateKeyIV: string }> {
  const priv = await unwrapX25519PrivateKey(wrappedPrivateKey, privateKeyIV, oldMasterKey);
  try {
    const { sealed, iv } = await sealSecret(priv, newMasterKey);
    return { wrappedPrivateKey: bytesToBase64(sealed), privateKeyIV: bytesToHex(iv) };
  } finally {
    priv.fill(0);
  }
}

export function generateKyberKeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  return ml_kem768.keygen();
}

export async function wrapKyberSecretKey(secretKey: Uint8Array, masterKey: MasterKey): Promise<WrappedKyberSecretKey> {
  if (secretKey.length !== KYBER_SECRET_KEY_BYTES) throw new Error('ML-KEM-768 secret key has the wrong length');
  const { sealed, iv } = await sealSecret(secretKey, masterKey);
  return { wrappedKyberPrivateKey: bytesToBase64(sealed), kyberPrivateKeyIV: bytesToHex(iv) };
}

export function unwrapKyberSecretKey(wrappedKyberPrivateKey: string, kyberPrivateKeyIV: string, masterKey: MasterKey) {
  return openSecret(wrappedKyberPrivateKey, kyberPrivateKeyIV, masterKey, KYBER_SECRET_KEY_BYTES, 'ML-KEM-768 secret key');
}

export async function rewrapKyberSecretKey(
  wrappedKyberPrivateKey: string,
  kyberPrivateKeyIV: string,
  oldMasterKey: MasterKey,
  newMasterKey: MasterKey,
): Promise<WrappedKyberSecretKey> {
  const secret = await unwrapKyberSecretKey(wrappedKyberPrivateKey, kyberPrivateKeyIV, oldMasterKey);
  try {
    return await wrapKyberSecretKey(secret, newMasterKey);
  } finally {
    secret.fill(0);
  }
}
