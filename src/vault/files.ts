import { gcm } from '@noble/ciphers/aes.js';
import { base64ToBytes, bytesToBase64, bytesToHex, hexToBytes } from './encoding.js';
import { AES_KEY_BYTES, IV_BYTES, sealSecret, type MasterKey } from './master-key.js';
import { secureRandom } from './random.js';

/**
 * Zero-knowledge file storage (envelope encryption). Each file gets a fresh
 * random 256-bit DEK; the file is AES-256-GCM encrypted with the DEK, and the
 * DEK is sealed with the user's master key. The server stores all four fields
 * and can read none of the content.
 *
 * Field names and encodings are exactly what SPIN Vault already stores.
 */
export interface VaultFilePayload {
  encryptedFile: string; // base64: file ciphertext || tag
  fileIV: string; // hex, 12 bytes
  encryptedDEK: string; // base64: DEK sealed with the master key
  dekIV: string; // hex, 12 bytes
}

export async function encryptFile(data: Uint8Array, masterKey: MasterKey): Promise<VaultFilePayload> {
  const dek = secureRandom(AES_KEY_BYTES);
  const fileIV = secureRandom(IV_BYTES);
  const encrypted = gcm(dek, fileIV).encrypt(data);
  const { sealed, iv } = await sealSecret(dek, masterKey);
  dek.fill(0);
  return {
    encryptedFile: bytesToBase64(encrypted),
    fileIV: bytesToHex(fileIV),
    encryptedDEK: bytesToBase64(sealed),
    dekIV: bytesToHex(iv),
  };
}

async function openDek(encryptedDEK: string, dekIV: string, masterKey: MasterKey): Promise<Uint8Array> {
  const dek = await masterKey.open(hexToBytes(dekIV), base64ToBytes(encryptedDEK));
  if (dek.length !== AES_KEY_BYTES) throw new Error('Unwrapped DEK has the wrong length');
  return dek;
}

/** Throws if the master key is wrong or anything was tampered with. */
export async function decryptFile(payload: VaultFilePayload, masterKey: MasterKey): Promise<Uint8Array> {
  const dek = await openDek(payload.encryptedDEK, payload.dekIV, masterKey);
  try {
    return gcm(dek, hexToBytes(payload.fileIV)).decrypt(base64ToBytes(payload.encryptedFile));
  } finally {
    dek.fill(0);
  }
}

/** Re-seal a file's DEK under a new master key (password change). File content is untouched. */
export async function rewrapFileDek(
  encryptedDEK: string,
  dekIV: string,
  oldMasterKey: MasterKey,
  newMasterKey: MasterKey,
): Promise<{ encryptedDEK: string; dekIV: string }> {
  const dek = await openDek(encryptedDEK, dekIV, oldMasterKey);
  try {
    const { sealed, iv } = await sealSecret(dek, newMasterKey);
    return { encryptedDEK: bytesToBase64(sealed), dekIV: bytesToHex(iv) };
  } finally {
    dek.fill(0);
  }
}
