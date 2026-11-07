/**
 * Where the key that wraps record keys lives.
 *
 * The database stores each record key only wrapped. Whoever can unwrap can
 * read, so the wrapping key belongs in a cloud key service (AWS KMS, Google
 * Cloud KMS) or an HSM, reached only by the key service in ./service.ts. Then
 * a stolen database, backup or app server holds no key, only ciphertext.
 */
import { gcm } from "@noble/ciphers/aes.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { b64u } from "./format.js";

export interface DataKeyring {
  /** Wrap a 32-byte record key, binding `aad`. */
  wrap(recordKey: Uint8Array, aad: Uint8Array): Promise<{ kekId: string; wrapped: Uint8Array }>;
  /** Unwrap; must fail if `aad` differs from what was bound. */
  unwrap(kekId: string, wrapped: Uint8Array, aad: Uint8Array): Promise<Uint8Array>;
  /** For logs and health checks, e.g. "software" or "aws-kms". Never key material. */
  readonly description: string;
}

export class DataKeyringError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "DataKeyringError";
  }
}

const enc = new TextEncoder();

/**
 * A wrapping key held in this process, derived from a secret of at least 32
 * bytes. Fine for development and the sandbox. In production the secret would
 * sit on the key service's host; use remoteDataKeyring with KMS or an HSM.
 */
export function softwareDataKeyring(secret: string | Uint8Array): DataKeyring {
  const ikm = typeof secret === "string" ? enc.encode(secret) : secret;
  if (ikm.length < 32) throw new DataKeyringError("Data keyring secret must be at least 32 bytes");
  const kek = hkdf(sha256, ikm, undefined, enc.encode("spin/data-kek/v1"), 32);
  const kekId = `sw_${b64u.encode(sha256(kek).subarray(0, 8))}`;
  return {
    description: "software",
    async wrap(recordKey, aad) {
      const iv = randomBytes(12);
      const ct = gcm(kek, iv, aad).encrypt(recordKey);
      const wrapped = new Uint8Array(12 + ct.length);
      wrapped.set(iv, 0);
      wrapped.set(ct, 12);
      return { kekId, wrapped };
    },
    async unwrap(id, wrapped, aad) {
      if (id !== kekId) throw new DataKeyringError("Record was wrapped by a different key");
      return gcm(kek, wrapped.subarray(0, 12), aad).decrypt(wrapped.subarray(12));
    },
  };
}

/**
 * A keyring whose key lives elsewhere (KMS, HSM). Fails closed: any error, or
 * a record key that isn't 32 bytes, throws DataKeyringError, so nothing is
 * released on a keyring fault.
 *
 * AWS KMS (symmetric key; `aad` goes in as the encryption context):
 *
 *   const kms = new KMSClient({});
 *   const ctx = (aad: Uint8Array) => ({ spin: Buffer.from(aad).toString("base64url") });
 *   const keyring = remoteDataKeyring({
 *     description: "aws-kms",
 *     wrap: async (key, aad) => {
 *       const r = await kms.send(new EncryptCommand({ KeyId: "alias/spin-data", Plaintext: key, EncryptionContext: ctx(aad) }));
 *       return { kekId: "alias/spin-data", wrapped: r.CiphertextBlob! };
 *     },
 *     unwrap: async (kekId, wrapped, aad) =>
 *       (await kms.send(new DecryptCommand({ KeyId: kekId, CiphertextBlob: wrapped, EncryptionContext: ctx(aad) }))).Plaintext!,
 *   });
 */
export function remoteDataKeyring(opts: {
  description: string;
  wrap: (recordKey: Uint8Array, aad: Uint8Array) => Promise<{ kekId: string; wrapped: Uint8Array }>;
  unwrap: (kekId: string, wrapped: Uint8Array, aad: Uint8Array) => Promise<Uint8Array>;
}): DataKeyring {
  return {
    description: opts.description,
    async wrap(recordKey, aad) {
      try {
        const out = await opts.wrap(recordKey, aad);
        if (typeof out?.kekId !== "string" || !(out.wrapped instanceof Uint8Array)) throw new Error("malformed result");
        return out;
      } catch (err) {
        throw new DataKeyringError(`Keyring (${opts.description}) failed to wrap`, { cause: err });
      }
    },
    async unwrap(kekId, wrapped, aad) {
      let out: Uint8Array;
      try {
        out = await opts.unwrap(kekId, wrapped, aad);
      } catch (err) {
        throw new DataKeyringError(`Keyring (${opts.description}) failed to unwrap`, { cause: err });
      }
      if (!(out instanceof Uint8Array) || out.length !== 32) {
        throw new DataKeyringError(`Keyring (${opts.description}) returned a malformed record key`);
      }
      return out;
    },
  };
}
