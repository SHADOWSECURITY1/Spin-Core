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
  /**
   * Set when an agent signs the purchase under a person's standing rule
   * (a mandate): that mandate's id. Covered by the signature.
   */
  mandateId?: string;
}

export const CHALLENGE_PREFIX = "spin/customer-intent/v1\n";
export const MIN_NONCE_LENGTH = 16;

/** Fixed key order, so device and server hash identical bytes. */
export function canonicalIntent(i: CustomerIntent): string {
  const base = [i.v, i.payerId, i.merchantId, i.amount, i.currency, i.channel, i.expiresAt, i.nonce];
  // Intents without a mandate keep their original bytes.
  return JSON.stringify(i.mandateId === undefined ? base : [...base, i.mandateId]);
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
    typeof x.nonce === "string" && x.nonce.length >= MIN_NONCE_LENGTH && x.nonce.length <= 128 &&
    (x.mandateId === undefined || (typeof x.mandateId === "string" && x.mandateId.length >= MIN_NONCE_LENGTH && x.mandateId.length <= 128))
  );
}

/**
 * A person's standing rule for an AI agent (docs/design/agent-mandates.md):
 * which of their enrolled agent keys may sign purchases, at which merchants,
 * up to how much per purchase and per rolling 24 hours, until when. Signed
 * once on one of the person's own devices; checked on every purchase the
 * agent signs.
 */
export interface Mandate {
  v: 1;
  payerId: string;
  /** The agent's enrolled key (role "agent") allowed to sign under it. */
  agentKeyId: string;
  /** Merchant ids the agent may pay (1 to 50). */
  merchants: string[];
  currency: string;
  /** Minor units. */
  maxPerPurchase: number;
  /** Minor units, over any rolling 24 hours. */
  maxPerDay: number;
  /** "CNP" | "CP", or null for either. */
  channel: string | null;
  /** ISO 8601. At most 90 days ahead when created. */
  expiresAt: string;
  /** The mandate's id: 16+ random characters. */
  nonce: string;
}

export const MANDATE_PREFIX = "spin/mandate/v1\n";
export const MAX_MANDATE_MERCHANTS = 50;

/** Fixed key order, so device and server hash identical bytes. */
export function canonicalMandate(m: Mandate): string {
  return JSON.stringify([m.v, m.payerId, m.agentKeyId, m.merchants, m.currency, m.maxPerPurchase, m.maxPerDay, m.channel, m.expiresAt, m.nonce]);
}

/** Structural checks on attacker-controlled input. */
export function isWellFormedMandate(m: unknown): m is Mandate {
  if (!m || typeof m !== "object") return false;
  const x = m as Record<string, unknown>;
  const merchants = x.merchants;
  return (
    x.v === 1 &&
    typeof x.payerId === "string" && x.payerId.length > 0 &&
    typeof x.agentKeyId === "string" && x.agentKeyId.length > 0 &&
    Array.isArray(merchants) && merchants.length >= 1 && merchants.length <= MAX_MANDATE_MERCHANTS &&
    merchants.every((v) => typeof v === "string" && v.length > 0 && v.length <= 128) &&
    new Set(merchants).size === merchants.length &&
    typeof x.currency === "string" && /^[A-Z]{3}$/.test(x.currency) &&
    Number.isInteger(x.maxPerPurchase) && (x.maxPerPurchase as number) > 0 &&
    Number.isInteger(x.maxPerDay) && (x.maxPerDay as number) >= (x.maxPerPurchase as number) &&
    (x.channel === null || x.channel === "CNP" || x.channel === "CP") &&
    typeof x.expiresAt === "string" && !Number.isNaN(Date.parse(x.expiresAt)) &&
    typeof x.nonce === "string" && x.nonce.length >= MIN_NONCE_LENGTH && x.nonce.length <= 128
  );
}

export type MandateViolation = "mandate_mismatch" | "mandate_expired";

/**
 * Does this purchase fit the mandate? Pure: no store, no signatures (checked
 * elsewhere). The daily cap needs spending history, so the store checks it.
 */
export function checkPurchaseAgainstMandate(intent: CustomerIntent, m: Mandate, now: Date): MandateViolation | null {
  if (intent.payerId !== m.payerId || intent.mandateId !== m.nonce) return "mandate_mismatch";
  const until = Date.parse(m.expiresAt);
  if (now.getTime() >= until || Date.parse(intent.expiresAt) > until) return "mandate_expired";
  if (!m.merchants.includes(intent.merchantId)) return "mandate_mismatch";
  if (intent.currency !== m.currency) return "mandate_mismatch";
  if (m.channel !== null && intent.channel !== m.channel) return "mandate_mismatch";
  if (intent.amount > m.maxPerPurchase) return "mandate_mismatch";
  return null;
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
