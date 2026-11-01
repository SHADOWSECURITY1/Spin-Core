import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Merchant API keys for the Pay Envelope endpoints. Only the SHA-256 hash is
 * stored; the key is 32 random bytes, so a fast hash is appropriate.
 */

export type PayEnvelopeKeyEnvironment = "live" | "test";

export function hashPayEnvelopeKey(key: string): string {
  return createHash("sha256").update(key).digest("hex");
}

export function generatePayEnvelopeKey(environment: PayEnvelopeKeyEnvironment): {
  key: string;
  keyHash: string;
  keyPrefix: string;
} {
  const key = `env_${environment}_${randomBytes(32).toString("base64url")}`;
  return { key, keyHash: hashPayEnvelopeKey(key), keyPrefix: `${key.slice(0, 20)}...` };
}

/** Constant-time comparison. A malformed stored hash returns false, not a throw. */
export function validatePayEnvelopeKey(key: string, keyHash: string): boolean {
  const given = Buffer.from(hashPayEnvelopeKey(key), "hex");
  if (!/^[0-9a-f]{64}$/i.test(keyHash)) return false;
  return timingSafeEqual(given, Buffer.from(keyHash, "hex"));
}
