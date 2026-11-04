/**
 * @spin/core/approval: the customer's side of a payment approval, for
 * browsers and React Native. No Node APIs.
 *
 * The point is that what the customer is shown and what their device signs
 * come from the same intent object, through code you don't write: you can't
 * show "$4.50 to Coffee Co." and sign "$450 to Thief's Shop", by mistake or
 * because your web page was tampered with.
 *
 * Two ways to approve:
 *
 *   approveWithSecurePaymentConfirmation()  web, strongest. The BROWSER draws
 *     the amount and payee in its own window, outside the page, and SPIN's
 *     server checks the signature covers exactly what it drew. Chrome and Edge
 *     on desktop and Android today.
 *
 *   approveIntent()  everywhere else (other browsers with passkeys, native
 *     apps with a device key). Your app draws the screen, but from the text
 *     this function derives from the intent it then signs.
 *
 * What neither can stop: malware controlling the customer's phone or
 * browser. Only screens the operating system draws (e.g. Android Protected
 * Confirmation) are beyond that; see docs/design/approval-screen.md.
 */
import { sha256 } from "@noble/hashes/sha2.js";
import {
  CHALLENGE_PREFIX,
  MANDATE_PREFIX,
  canonicalIntent,
  canonicalMandate,
  fromMinorUnits,
  isWellFormedIntent,
  isWellFormedMandate,
  minorUnitDigits,
  type CustomerIntent,
  type Mandate,
} from "../pay-envelope/intent-format.js";

export type { CustomerIntent, Mandate } from "../pay-envelope/intent-format.js";

/** What SPIN knows about the payee, from SPIN Pay's merchant lookup. */
export interface PayeeProfile {
  /** The merchant's verified name. */
  name: string;
  /** SPIN verified the business. */
  verified: boolean;
  /** ISO 8601: when the merchant joined SPIN. */
  onSpinSince?: string | null;
  /** This customer hasn't approved a payment to this merchant before. */
  firstTime?: boolean;
}

/** Exactly what the approval screen must show. Derived only from the intent and payee. */
export interface ApprovalDescription {
  /** "Pay $4.50 to Coffee Co." */
  title: string;
  /** Facts to show under the title. */
  details: string[];
  /** Show these prominently. */
  warnings: string[];
}

export interface SignedIntentOut {
  intent: CustomerIntent;
  keyId: string;
  signature: string;
  authenticatorData?: string;
  clientDataJSON?: string;
}

/** UTF-8 without TextEncoder (older Hermes lacks it). */
function utf8(s: string): Uint8Array {
  const out: number[] = [];
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  }
  return Uint8Array.from(out);
}

const B64U = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
/** base64url without padding, without btoa/Buffer. */
export function toBase64Url(bytes: Uint8Array | ArrayBuffer): string {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let out = "";
  for (let i = 0; i < b.length; i += 3) {
    const n = (b[i]! << 16) | ((b[i + 1] ?? 0) << 8) | (b[i + 2] ?? 0);
    out += B64U[(n >> 18) & 63]! + B64U[(n >> 12) & 63]!;
    if (i + 1 < b.length) out += B64U[(n >> 6) & 63]!;
    if (i + 2 < b.length) out += B64U[n & 63]!;
  }
  return out;
}

/** The 32 bytes a device signs for this intent (the same as the server's intentChallenge). */
export function intentChallenge(intent: CustomerIntent): Uint8Array {
  return sha256(utf8(CHALLENGE_PREFIX + canonicalIntent(intent)));
}

/** 450 USD → "$4.50" (locale formatting when available). */
export function formatAmount(amount: number, currency: string, locale?: string): string {
  const value = Number(fromMinorUnits(amount, currency));
  try {
    const digits = minorUnitDigits(currency);
    return new Intl.NumberFormat(locale, { style: "currency", currency, minimumFractionDigits: digits, maximumFractionDigits: digits }).format(value);
  } catch {
    return `${fromMinorUnits(amount, currency)} ${currency}`;
  }
}

/** The approval screen's content. Your app shows exactly this. */
export function describeIntent(intent: CustomerIntent, payee: PayeeProfile, locale?: string): ApprovalDescription {
  const details: string[] = [];
  const warnings: string[] = [];
  details.push(payee.verified ? "Verified business" : "Not verified by SPIN");
  if (payee.onSpinSince) {
    const since = new Date(payee.onSpinSince);
    if (!Number.isNaN(since.getTime())) {
      details.push(`On SPIN since ${since.toLocaleDateString(locale, { month: "long", year: "numeric" })}`);
    }
  }
  if (intent.channel === "CNP") details.push("Online payment");
  if (intent.channel === "CP") details.push("In-person payment");
  if (payee.firstTime) warnings.push(`You haven't paid ${payee.name} before. Make sure you meant to.`);
  if (!payee.verified) warnings.push(`SPIN hasn't verified ${payee.name}. Only approve if you know them.`);
  return { title: `Pay ${formatAmount(intent.amount, intent.currency, locale)} to ${payee.name}`, details, warnings };
}

/**
 * A fresh intent for a payment, with a random nonce. Expires in 5 minutes by
 * default. An AI agent passes the `mandateId` it buys under.
 */
export function newIntent(p: {
  payerId: string;
  merchantId: string;
  amount: number;
  currency: string;
  channel?: "CNP" | "CP" | null;
  ttlSeconds?: number;
  now?: Date;
  mandateId?: string;
}): CustomerIntent {
  const nonce = new Uint8Array(16);
  globalThis.crypto.getRandomValues(nonce);
  const now = p.now ?? new Date();
  return {
    v: 1,
    payerId: p.payerId,
    merchantId: p.merchantId,
    amount: p.amount,
    currency: p.currency,
    channel: p.channel ?? null,
    expiresAt: new Date(now.getTime() + (p.ttlSeconds ?? 300) * 1000).toISOString(),
    nonce: toBase64Url(nonce),
    ...(p.mandateId !== undefined ? { mandateId: p.mandateId } : {}),
  };
}

// ── Standing rules for AI agents (mandates) ──────────────────────────────────

/** The 32 bytes a person's device signs to set a mandate (the same as the server's mandateChallenge). */
export function mandateChallenge(m: Mandate): Uint8Array {
  return sha256(utf8(MANDATE_PREFIX + canonicalMandate(m)));
}

/** A fresh mandate with a random id. Lasts 30 days by default (at most 90). */
export function newMandate(p: {
  payerId: string;
  agentKeyId: string;
  merchants: string[];
  currency: string;
  maxPerPurchase: number;
  maxPerDay: number;
  channel?: "CNP" | "CP" | null;
  days?: number;
  now?: Date;
}): Mandate {
  const nonce = new Uint8Array(16);
  globalThis.crypto.getRandomValues(nonce);
  const now = p.now ?? new Date();
  return {
    v: 1,
    payerId: p.payerId,
    agentKeyId: p.agentKeyId,
    merchants: [...p.merchants],
    currency: p.currency,
    maxPerPurchase: p.maxPerPurchase,
    maxPerDay: p.maxPerDay,
    channel: p.channel ?? null,
    expiresAt: new Date(now.getTime() + Math.min(p.days ?? 30, 90) * 86_400_000).toISOString(),
    nonce: toBase64Url(nonce),
  };
}

/** What the person's approval screen shows for a mandate. Derived only from the mandate. */
export function describeMandate(m: Mandate, opts: { agentName: string; merchantNames?: Record<string, string>; locale?: string }): ApprovalDescription {
  const names = m.merchants.map((id) => opts.merchantNames?.[id] ?? id);
  const until = new Date(m.expiresAt).toLocaleDateString(opts.locale, { year: "numeric", month: "long", day: "numeric" });
  return {
    title: `Let ${opts.agentName} spend up to ${formatAmount(m.maxPerDay, m.currency, opts.locale)} a day`,
    details: [
      `Up to ${formatAmount(m.maxPerPurchase, m.currency, opts.locale)} per purchase`,
      `Only at: ${names.join(", ")}`,
      m.channel === "CNP" ? "Online purchases only" : m.channel === "CP" ? "In-person purchases only" : "Online or in person",
      `Until ${until}, unless you revoke it sooner`,
    ],
    warnings: [`${opts.agentName} can buy without asking you each time, within these limits.`],
  };
}

/**
 * Show a mandate and sign it, as one step (a person's own device; never the
 * agent's key). Returns null if the person declines.
 */
export async function approveMandate(p: {
  mandate: Mandate;
  agentName: string;
  merchantNames?: Record<string, string>;
  keyId: string;
  confirm: (description: ApprovalDescription) => Promise<boolean>;
  sign: (challenge: Uint8Array) => Promise<Uint8Array | { signature: Uint8Array; authenticatorData?: Uint8Array; clientDataJSON?: Uint8Array }>;
  locale?: string;
}): Promise<{ mandate: Mandate; keyId: string; signature: string; authenticatorData?: string; clientDataJSON?: string } | null> {
  if (!isWellFormedMandate(p.mandate)) throw new Error("Malformed mandate");
  if (p.keyId === p.mandate.agentKeyId) throw new Error("A mandate is signed by a person's device, not the agent's key");
  const mandate = Object.freeze({ ...p.mandate, merchants: Object.freeze([...p.mandate.merchants]) as string[] });
  const description = describeMandate(mandate, { agentName: p.agentName, merchantNames: p.merchantNames, locale: p.locale });
  if (!(await p.confirm(description))) return null;
  const out = await p.sign(mandateChallenge(mandate));
  if (out instanceof Uint8Array) return { mandate, keyId: p.keyId, signature: toBase64Url(out) };
  return {
    mandate,
    keyId: p.keyId,
    signature: toBase64Url(out.signature),
    ...(out.authenticatorData ? { authenticatorData: toBase64Url(out.authenticatorData) } : {}),
    ...(out.clientDataJSON ? { clientDataJSON: toBase64Url(out.clientDataJSON) } : {}),
  };
}

// ── Approving an AI agent's key ──────────────────────────────────────────────

/** A request to add an agent's key, as the person's device approves it (the server's DeviceEnrollment with role "agent"). */
export interface AgentEnrollment {
  v: 1;
  payerId: string;
  newKey: { keyId: string; scheme: "ecdsa-p256"; publicKey: string; role: "agent" };
  expiresAt: string;
  nonce: string;
}

/** The 32 bytes a person's device signs to add a key (the same as the server's enrollmentChallenge). */
export function enrollmentChallenge(e: {
  v: 1;
  payerId: string;
  newKey: { keyId: string; scheme: string; publicKey: string; role?: "agent" };
  expiresAt: string;
  nonce: string;
}): Uint8Array {
  const base = [e.v, e.payerId, e.newKey.keyId, e.newKey.scheme, e.newKey.publicKey, e.expiresAt, e.nonce];
  return sha256(utf8("spin/enroll-device/v1\n" + JSON.stringify(e.newKey.role === undefined ? base : [...base, e.newKey.role])));
}

/** A fresh request to add an agent's P-256 key (raw public key, base64url). Expires in 10 minutes by default (at most 60). */
export function newAgentEnrollment(p: { payerId: string; keyId: string; publicKey: string; ttlSeconds?: number; now?: Date }): AgentEnrollment {
  const nonce = new Uint8Array(16);
  globalThis.crypto.getRandomValues(nonce);
  const now = p.now ?? new Date();
  return {
    v: 1,
    payerId: p.payerId,
    newKey: { keyId: p.keyId, scheme: "ecdsa-p256", publicKey: p.publicKey, role: "agent" },
    expiresAt: new Date(now.getTime() + Math.min(p.ttlSeconds ?? 600, 3600) * 1000).toISOString(),
    nonce: toBase64Url(nonce),
  };
}

/** What the person's approval screen shows for adding an agent. The key's fingerprint lets them match it to what the agent's platform shows. */
export function describeAgentEnrollment(e: AgentEnrollment, opts: { agentName: string }): ApprovalDescription {
  const fingerprint = Array.from(sha256(utf8(e.newKey.publicKey)).slice(0, 4), (b) => b.toString(16).padStart(2, "0")).join(" ").toUpperCase();
  return {
    title: `Add ${opts.agentName} as an AI agent`,
    details: [
      "It can only buy under standing rules you set, and you can remove it any time",
      "It can't approve devices, set its own rules, or see your card numbers",
      `Key ${e.newKey.keyId}, fingerprint ${fingerprint}`,
    ],
    warnings: ["Only approve an agent you set up yourself."],
  };
}

/**
 * Show a request to add an agent's key and sign it, as one step (a person's
 * own device). Returns the approval to send with the agent's enrollment, or
 * null if the person declines.
 */
export async function approveAgentEnrollment(p: {
  enrollment: AgentEnrollment;
  agentName: string;
  keyId: string;
  confirm: (description: ApprovalDescription) => Promise<boolean>;
  sign: (challenge: Uint8Array) => Promise<Uint8Array | { signature: Uint8Array; authenticatorData?: Uint8Array; clientDataJSON?: Uint8Array }>;
}): Promise<{ enrollment: AgentEnrollment; keyId: string; signature: string; authenticatorData?: string; clientDataJSON?: string } | null> {
  const e = p.enrollment;
  if (e.v !== 1 || e.newKey.role !== "agent" || e.newKey.scheme !== "ecdsa-p256" || !e.payerId || !e.newKey.keyId || !e.newKey.publicKey) {
    throw new Error("Malformed agent enrollment");
  }
  if (p.keyId === e.newKey.keyId) throw new Error("An agent's key is approved by a person's device, not by itself");
  const enrollment = Object.freeze({ ...e, newKey: Object.freeze({ ...e.newKey }) }) as AgentEnrollment;
  if (!(await p.confirm(describeAgentEnrollment(enrollment, { agentName: p.agentName })))) return null;
  const out = await p.sign(enrollmentChallenge(enrollment));
  if (out instanceof Uint8Array) return { enrollment, keyId: p.keyId, signature: toBase64Url(out) };
  return {
    enrollment,
    keyId: p.keyId,
    signature: toBase64Url(out.signature),
    ...(out.authenticatorData ? { authenticatorData: toBase64Url(out.authenticatorData) } : {}),
    ...(out.clientDataJSON ? { clientDataJSON: toBase64Url(out.clientDataJSON) } : {}),
  };
}

/**
 * Show the approval and sign it, as one step. `confirm` receives only the
 * description derived from `intent`; `sign` receives only the challenge for
 * that same `intent`. Returns null if the customer declines.
 *
 * Native apps: `sign` uses the device key (Secure Enclave / Android
 * Keystore) and returns its raw signature. Web with a passkey: use
 * `signWithPasskey` below as `sign`.
 */
export async function approveIntent(p: {
  intent: CustomerIntent;
  payee: PayeeProfile;
  keyId: string;
  confirm: (description: ApprovalDescription) => Promise<boolean>;
  sign: (challenge: Uint8Array) => Promise<Uint8Array | { signature: Uint8Array; authenticatorData?: Uint8Array; clientDataJSON?: Uint8Array }>;
  locale?: string;
}): Promise<SignedIntentOut | null> {
  if (!isWellFormedIntent(p.intent)) throw new Error("Malformed intent");
  // Freeze a copy, so nothing can change what's signed after it's shown.
  const intent = Object.freeze({ ...p.intent });
  if (!(await p.confirm(describeIntent(intent, p.payee, p.locale)))) return null;
  const out = await p.sign(intentChallenge(intent));
  if (out instanceof Uint8Array) return { intent, keyId: p.keyId, signature: toBase64Url(out) };
  return {
    intent,
    keyId: p.keyId,
    signature: toBase64Url(out.signature),
    ...(out.authenticatorData ? { authenticatorData: toBase64Url(out.authenticatorData) } : {}),
    ...(out.clientDataJSON ? { clientDataJSON: toBase64Url(out.clientDataJSON) } : {}),
  };
}

/** A `sign` for approveIntent using a passkey (WebAuthn) in the browser. */
export function signWithPasskey(p: { rpId: string; credentialId: Uint8Array; timeoutMs?: number }) {
  return async (challenge: Uint8Array) => {
    const cred = (await navigator.credentials.get({
      publicKey: {
        challenge: challenge as BufferSource,
        rpId: p.rpId,
        userVerification: "required",
        allowCredentials: [{ type: "public-key", id: p.credentialId as BufferSource }],
        timeout: p.timeoutMs ?? 60_000,
      },
    })) as PublicKeyCredential | null;
    if (!cred) throw new Error("The passkey prompt was dismissed.");
    const r = cred.response as AuthenticatorAssertionResponse;
    return {
      signature: new Uint8Array(r.signature),
      authenticatorData: new Uint8Array(r.authenticatorData),
      clientDataJSON: new Uint8Array(r.clientDataJSON),
    };
  };
}

/** True if this browser can show a Secure Payment Confirmation prompt. */
export async function securePaymentConfirmationAvailable(): Promise<boolean> {
  const PR = (globalThis as { PaymentRequest?: typeof PaymentRequest }).PaymentRequest;
  if (!PR) return false;
  try {
    const req = new PR(
      [{ supportedMethods: "secure-payment-confirmation", data: { rpId: "example.com", credentialIds: [new Uint8Array(1)], challenge: new Uint8Array(1), instrument: { displayName: "x", icon: "data:," }, payeeName: "x" } }],
      { total: { label: "Total", amount: { currency: "USD", value: "0.01" } } },
    );
    return await req.canMakePayment();
  } catch {
    return false;
  }
}

/**
 * Approve with Secure Payment Confirmation: the browser shows the payee and
 * amount in its own window and the customer confirms with their passkey.
 * SPIN's server checks the signature covers that total and `payee.name`.
 */
export async function approveWithSecurePaymentConfirmation(p: {
  intent: CustomerIntent;
  payee: PayeeProfile;
  keyId: string;
  rpId: string;
  credentialId: Uint8Array;
  /** How the card appears in the prompt, e.g. { displayName: "SPIN card", icon: "https://.../icon.png" }. */
  instrument: { displayName: string; icon: string };
  payeeOrigin?: string;
  timeoutMs?: number;
}): Promise<SignedIntentOut> {
  if (!isWellFormedIntent(p.intent)) throw new Error("Malformed intent");
  const intent = Object.freeze({ ...p.intent });
  const PR = (globalThis as { PaymentRequest?: typeof PaymentRequest }).PaymentRequest;
  if (!PR) throw new Error("Secure Payment Confirmation isn't available in this browser.");
  const request = new PR(
    [
      {
        supportedMethods: "secure-payment-confirmation",
        data: {
          rpId: p.rpId,
          credentialIds: [p.credentialId],
          challenge: intentChallenge(intent),
          instrument: p.instrument,
          payeeName: p.payee.name,
          ...(p.payeeOrigin ? { payeeOrigin: p.payeeOrigin } : {}),
          timeout: p.timeoutMs ?? 60_000,
        },
      },
    ],
    { total: { label: "Total", amount: { currency: intent.currency, value: fromMinorUnits(intent.amount, intent.currency) } } },
  );
  const response = await request.show();
  await response.complete("success");
  const cred = response.details as PublicKeyCredential;
  const r = cred.response as AuthenticatorAssertionResponse;
  return {
    intent,
    keyId: p.keyId,
    signature: toBase64Url(r.signature),
    authenticatorData: toBase64Url(r.authenticatorData),
    clientDataJSON: toBase64Url(r.clientDataJSON),
  };
}
