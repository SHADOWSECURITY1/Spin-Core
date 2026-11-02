import { gcm } from '@noble/ciphers/aes.js';
import { pbkdf2Async } from '@noble/hashes/pbkdf2.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hexToBytes, bytesToHex, utf8Encode } from './encoding.js';
import { secureRandom } from './random.js';

/** OWASP 2023 recommendation for PBKDF2-HMAC-SHA256. */
export const PBKDF2_ITERATIONS = 210_000;
export const AES_KEY_BYTES = 32;
export const IV_BYTES = 12;

/**
 * The user's master key, as an AES-256-GCM key that can only be *used*.
 *
 * Two implementations, same ciphertexts:
 * - webCryptoMasterKey(): a non-extractable Web Crypto key. Page scripts can
 *   use it but never read its bytes, which limits what an XSS can steal.
 * - rawMasterKey(): raw bytes, for platforms without Web Crypto (React Native)
 *   where the bytes live in the OS secure store.
 *
 * seal() returns ciphertext || 16-byte tag, exactly like Web Crypto's
 * AES-GCM encrypt and wrapKey('raw', …).
 */
export interface MasterKey {
  seal(iv: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array>;
  open(iv: Uint8Array, sealed: Uint8Array): Promise<Uint8Array>;
}

function checkIv(iv: Uint8Array) {
  if (iv.length !== IV_BYTES) throw new Error(`AES-GCM IV must be ${IV_BYTES} bytes`);
}

export function rawMasterKey(bytes: Uint8Array): MasterKey {
  if (bytes.length !== AES_KEY_BYTES) throw new Error(`Master key must be ${AES_KEY_BYTES} bytes`);
  const key = bytes.slice();
  return {
    async seal(iv, plaintext) {
      checkIv(iv);
      return gcm(key, iv).encrypt(plaintext);
    },
    async open(iv, sealed) {
      checkIv(iv);
      return gcm(key, iv).decrypt(sealed);
    },
  };
}

type Subtle = {
  importKey(...args: unknown[]): Promise<unknown>;
  deriveKey(...args: unknown[]): Promise<unknown>;
  encrypt(alg: unknown, key: unknown, data: Uint8Array): Promise<ArrayBuffer>;
  decrypt(alg: unknown, key: unknown, data: Uint8Array): Promise<ArrayBuffer>;
};

function subtle(): Subtle {
  const s = (globalThis as { crypto?: { subtle?: Subtle } }).crypto?.subtle;
  if (!s) throw new Error('Web Crypto (crypto.subtle) is not available on this platform');
  return s;
}

/** Wrap an existing Web Crypto AES-GCM key (with encrypt/decrypt usages). */
export function webCryptoMasterKey(cryptoKey: unknown): MasterKey {
  return {
    async seal(iv, plaintext) {
      checkIv(iv);
      return new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv }, cryptoKey, plaintext));
    },
    async open(iv, sealed) {
      checkIv(iv);
      return new Uint8Array(await subtle().decrypt({ name: 'AES-GCM', iv }, cryptoKey, sealed));
    },
  };
}

/** A new random 32-byte salt, hex, for a new user. Not secret. */
export function generateSalt(): string {
  return bytesToHex(secureRandom(32));
}

/** PBKDF2-SHA256 → 32 raw key bytes (for rawMasterKey). Async so UIs stay responsive. */
export async function deriveMasterKeyBytes(password: string, saltHex: string): Promise<Uint8Array> {
  return pbkdf2Async(sha256, utf8Encode(password), hexToBytes(saltHex), {
    c: PBKDF2_ITERATIONS,
    dkLen: AES_KEY_BYTES,
  });
}

/**
 * PBKDF2-SHA256 → a NON-EXTRACTABLE Web Crypto key. Same key material as
 * deriveMasterKeyBytes(), so data sealed with either opens with the other.
 * Returns the MasterKey plus the CryptoKey for callers that need it.
 */
export async function deriveWebCryptoMasterKey(
  password: string,
  saltHex: string,
): Promise<{ masterKey: MasterKey; cryptoKey: unknown }> {
  const s = subtle();
  const material = await s.importKey('raw', utf8Encode(password), { name: 'PBKDF2' }, false, ['deriveKey']);
  const cryptoKey = await s.deriveKey(
    { name: 'PBKDF2', salt: hexToBytes(saltHex), iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
  );
  return { masterKey: webCryptoMasterKey(cryptoKey), cryptoKey };
}

/** Seal a secret (a DEK or a private key) with the master key: base64 ciphertext, hex IV. */
export async function sealSecret(
  secret: Uint8Array,
  masterKey: MasterKey,
): Promise<{ sealed: Uint8Array; iv: Uint8Array }> {
  const iv = secureRandom(IV_BYTES);
  return { sealed: await masterKey.seal(iv, secret), iv };
}
