import { createHmac } from "node:crypto";

/**
 * Where the key behind card numbers lives.
 *
 * Every card number SPIN issues is derived with a keyed hash (HMAC), and the
 * store keeps a keyed fingerprint of it instead of the number. Whoever holds
 * that key plus a copy of the database can recompute or brute-force live
 * numbers (the varying part is only 9 digits). So the key should live where
 * it can't be copied: a cloud key service (AWS KMS / Google Cloud KMS MAC
 * keys) or an HSM. The app then only asks the keyring to compute; stealing
 * the app server and database gets an attacker no key, only the ability to
 * make requests through the key service, which are rate-limited and logged.
 *
 * Two purposes, each its own key in a hardware keyring:
 *   "pan-derive"       derives a card number from an envelope's details
 *   "pan-fingerprint"  the stored, searchable stand-in for a card number
 *
 * Switching keyrings changes every number and fingerprint, so envelopes live
 * at the moment of the switch stop working (they last an hour at most).
 */
export type PanKeyPurpose = "pan-derive" | "pan-fingerprint";

export interface PanKeyring {
  /** HMAC-SHA256 of `data` under this purpose's key. 32 bytes. */
  mac(purpose: PanKeyPurpose, data: Uint8Array): Promise<Uint8Array>;
  /** For logs and health checks, e.g. "software" or "aws-kms". Never key material. */
  readonly description: string;
}

export class PayEnvelopeKeyringError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "PayEnvelopeKeyringError";
  }
}

const FINGERPRINT_KEY_INFO = "spin/pay-envelope/pan-digest/v1";

/**
 * Keys held in this process, derived from one secret. Exactly what 0.5
 * computed, so stored fingerprints keep working. Fine for development and the
 * sandbox; in production the secret sits in the server's environment, so a
 * server breach exposes it. Use remotePanKeyring there.
 */
export function softwarePanKeyring(hmacSecret: string): PanKeyring {
  const fingerprintKey = createHmac("sha256", hmacSecret).update(FINGERPRINT_KEY_INFO).digest();
  return {
    description: "software",
    async mac(purpose, data) {
      const key = purpose === "pan-derive" ? hmacSecret : fingerprintKey;
      return new Uint8Array(createHmac("sha256", key).update(data).digest());
    },
  };
}

/**
 * A keyring whose keys live elsewhere (KMS, HSM). `mac` makes the remote
 * call; this wrapper checks the result and fails closed: any error or a
 * malformed MAC throws PayEnvelopeKeyringError, so nothing is approved and no
 * envelope is created on a keyring fault.
 *
 * AWS KMS, with two HMAC_256 keys:
 *
 *   const kms = new KMSClient({});
 *   const keyId = { "pan-derive": "alias/spin-pan-derive", "pan-fingerprint": "alias/spin-pan-fingerprint" };
 *   const keyring = remotePanKeyring({
 *     description: "aws-kms",
 *     mac: async (purpose, data) =>
 *       (await kms.send(new GenerateMacCommand({ KeyId: keyId[purpose], Message: data, MacAlgorithm: "HMAC_SHA_256" }))).Mac!,
 *   });
 */
export function remotePanKeyring(opts: {
  description: string;
  mac: (purpose: PanKeyPurpose, data: Uint8Array) => Promise<Uint8Array>;
}): PanKeyring {
  return {
    description: opts.description,
    async mac(purpose, data) {
      let out: Uint8Array;
      try {
        out = await opts.mac(purpose, data);
      } catch (err) {
        throw new PayEnvelopeKeyringError(`Keyring (${opts.description}) failed for ${purpose}`, { cause: err });
      }
      if (!(out instanceof Uint8Array) || out.length !== 32) {
        throw new PayEnvelopeKeyringError(`Keyring (${opts.description}) returned a malformed MAC for ${purpose}`);
      }
      return out;
    },
  };
}
