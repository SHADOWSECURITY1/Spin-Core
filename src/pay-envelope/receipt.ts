import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * Compact HS256 JWS receipts. Same wire format both apps already issue:
 * base64url(header).base64url(payload).base64url(HMAC-SHA256), with iat/exp
 * in seconds. Adds the verifier neither app had.
 */

const HEADER = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
export const DEFAULT_RECEIPT_TTL_SECONDS = 900;

export interface ReceiptClaims {
  iat: number;
  exp: number;
  [claim: string]: unknown;
}

function mac(secret: string, signingInput: string): Buffer {
  return createHmac("sha256", secret).update(signingInput).digest();
}

export function signReceipt(
  secret: string,
  payload: Record<string, unknown>,
  opts: { now?: Date; ttlSeconds?: number } = {},
): string {
  const iat = Math.floor((opts.now ?? new Date()).getTime() / 1000);
  const exp = iat + (opts.ttlSeconds ?? DEFAULT_RECEIPT_TTL_SECONDS);
  const body = Buffer.from(JSON.stringify({ ...payload, iat, exp })).toString("base64url");
  const signingInput = `${HEADER}.${body}`;
  return `${signingInput}.${mac(secret, signingInput).toString("base64url")}`;
}

/**
 * Returns the claims if the signature is valid, the header is the HS256 one
 * this module issues (no "alg: none" or algorithm switching), and the receipt
 * has not expired. Otherwise returns null.
 */
export function verifyReceipt(
  secret: string,
  token: string,
  opts: { now?: Date } = {},
): ReceiptClaims | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [header, body, signature] = parts as [string, string, string];
  if (header !== HEADER) return null;

  const expected = mac(secret, `${header}.${body}`);
  const given = Buffer.from(signature, "base64url");
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null;

  let claims: unknown;
  try {
    claims = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch {
    return null;
  }
  if (typeof claims !== "object" || claims === null) return null;
  const { iat, exp } = claims as Record<string, unknown>;
  if (typeof iat !== "number" || typeof exp !== "number") return null;
  const now = Math.floor((opts.now ?? new Date()).getTime() / 1000);
  if (now >= exp) return null;
  return claims as ReceiptClaims;
}
