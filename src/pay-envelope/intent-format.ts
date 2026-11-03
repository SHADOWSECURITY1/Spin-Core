/**
 * The customer-signed intent's format: what a device signs, and the checks on
 * it. No Node or platform APIs, so the approval kit (browser, React Native)
 * and the server share exactly the same definition.
 */

export interface CustomerIntent {
  v: 1;
  /** The customer (payer), as registered by the integrator. */
  payerId: string;
  /** Payee merchant. */
  merchantId: string;
  /** Minor units (cents). Exact: no tolerance with a signed intent. */
  amount: number;
  currency: string;
  /** "CNP" | "CP", or null for either. */
  channel: string | null;
  /** ISO 8601. The credential can't outlive the approval. */
  expiresAt: string;
  /** Single use. 16+ random characters chosen by the device. */
  nonce: string;
}

export const CHALLENGE_PREFIX = "spin/customer-intent/v1\n";
export const MIN_NONCE_LENGTH = 16;

/** Fixed key order, so device and server hash identical bytes. */
export function canonicalIntent(i: CustomerIntent): string {
  return JSON.stringify([i.v, i.payerId, i.merchantId, i.amount, i.currency, i.channel, i.expiresAt, i.nonce]);
}

/** Structural checks on attacker-controlled input. */
export function isWellFormedIntent(i: unknown): i is CustomerIntent {
  if (!i || typeof i !== "object") return false;
  const x = i as Record<string, unknown>;
  return (
    x.v === 1 &&
    typeof x.payerId === "string" && x.payerId.length > 0 &&
    typeof x.merchantId === "string" && x.merchantId.length > 0 &&
    Number.isInteger(x.amount) && (x.amount as number) > 0 &&
    typeof x.currency === "string" && /^[A-Z]{3}$/.test(x.currency) &&
    (x.channel === null || x.channel === "CNP" || x.channel === "CP") &&
    typeof x.expiresAt === "string" && !Number.isNaN(Date.parse(x.expiresAt)) &&
    typeof x.nonce === "string" && x.nonce.length >= MIN_NONCE_LENGTH && x.nonce.length <= 128
  );
}

/** Currencies without minor units (amounts are whole units). */
const ZERO_DECIMAL = new Set(["JPY", "KRW", "VND", "CLP", "ISK", "UGX", "XAF", "XOF", "PYG", "RWF"]);

export function minorUnitDigits(currency: string): number {
  return ZERO_DECIMAL.has(currency) ? 0 : 2;
}

/** "4.50" in USD → 450. Null if malformed or more precise than the currency allows. */
export function toMinorUnits(value: string, currency: string): number | null {
  if (!/^\d+(\.\d+)?$/.test(value)) return null;
  const digits = minorUnitDigits(currency);
  const [whole, frac = ""] = value.split(".");
  if (frac.length > digits) return null;
  return Number(whole) * 10 ** digits + Number(frac.padEnd(digits, "0") || "0");
}

/** 450 in USD → "4.50"; 500 in JPY → "500". */
export function fromMinorUnits(amount: number, currency: string): string {
  const digits = minorUnitDigits(currency);
  if (digits === 0) return String(amount);
  const s = String(amount).padStart(digits + 1, "0");
  return `${s.slice(0, -digits)}.${s.slice(-digits)}`;
}
