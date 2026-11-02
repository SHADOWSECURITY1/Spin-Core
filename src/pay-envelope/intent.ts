import { createHash, createPublicKey, verify as nodeVerify } from "node:crypto";
import { p256 } from "@noble/curves/nist.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

/**
 * Customer-signed intent (docs/design/customer-signed-intent.md).
 *
 * A credential may be created only from an approval the customer signed on
 * their own device, covering exactly the payee, amount, currency, channel and
 * expiry. A stolen integrator API key, or a breached payer server, can then
 * create nothing the customer didn't approve.
 *
 * The device signs a 32-byte challenge derived from the canonical intent:
 *   challenge = SHA-256("spin/customer-intent/v1\n" + canonicalIntent(intent))
 *
 * Schemes:
 *   "ed25519"                 native apps; SPKI DER public key (base64url),
 *                             the same format as SPIN Pay's deviceKeyProof
 *   "hybrid-ed25519-mldsa65"  post-quantum: "<ed25519 spki>.<ml-dsa-65 pub>",
 *                             signature "<ed25519 sig>.<ml-dsa-65 sig>"; BOTH must verify
 *   "webauthn-es256"          passkeys and Secure Payment Confirmation on the web;
 *                             raw P-256 public key (65 bytes, base64url), the
 *                             challenge in clientDataJSON, user verification required
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

export type IntentScheme = "ed25519" | "hybrid-ed25519-mldsa65" | "webauthn-es256";

export interface SignedIntent {
  intent: CustomerIntent;
  /** Which enrolled key of `intent.payerId` signed it. */
  keyId: string;
  /** base64url. For webauthn-es256: the DER ECDSA signature from the assertion. */
  signature: string;
  /** webauthn-es256 only (base64url). */
  authenticatorData?: string;
  /** webauthn-es256 only (base64url). */
  clientDataJSON?: string;
}

export interface PayerKey {
  payerId: string;
  keyId: string;
  scheme: IntentScheme;
  /** base64url; format per scheme (see above). */
  publicKey: string;
  revokedAt: Date | null;
}

/**
 * Enrolled customer keys and spent approval nonces. Apps implement this over
 * their own tables. `useNonce` MUST be one atomic insert-if-absent (a unique
 * index on (payer_id, nonce)), or the same approval could create two
 * credentials.
 */
export interface PayerKeyStore {
  findKey(payerId: string, keyId: string): Promise<PayerKey | null>;
  /** Record the nonce as spent. Returns false if it was already spent. */
  useNonce(payerId: string, nonce: string, expiresAt: Date): Promise<boolean>;
}

/** Where passkey assertions are accepted from. Required for webauthn-es256. */
export interface WebAuthnPolicy {
  /** Relying party id the passkeys were created for, e.g. "pay.example.com". */
  rpId: string;
  /** Exact origins the assertion may come from, e.g. ["https://pay.example.com"]. */
  origins: string[];
}

export type IntentRejection =
  | "intent_required"
  | "intent_invalid"
  | "intent_mismatch"
  | "intent_expired"
  | "intent_replayed";

export class PayEnvelopeIntentError extends Error {
  constructor(
    readonly code: IntentRejection,
    message: string,
  ) {
    super(message);
    this.name = "PayEnvelopeIntentError";
  }
}

const CHALLENGE_PREFIX = "spin/customer-intent/v1\n";
const MIN_NONCE_LENGTH = 16;

/** Fixed key order, so device and server hash identical bytes. */
export function canonicalIntent(i: CustomerIntent): string {
  return JSON.stringify([i.v, i.payerId, i.merchantId, i.amount, i.currency, i.channel, i.expiresAt, i.nonce]);
}

/** What the device signs (or passes as the WebAuthn challenge). */
export function intentChallenge(i: CustomerIntent): Uint8Array {
  return new Uint8Array(createHash("sha256").update(CHALLENGE_PREFIX + canonicalIntent(i), "utf8").digest());
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

const b64u = (s: string) => new Uint8Array(Buffer.from(s, "base64url"));

function verifyEd25519(spkiB64u: string, msg: Uint8Array, sigB64u: string): boolean {
  const key = createPublicKey({ key: Buffer.from(spkiB64u, "base64url"), format: "der", type: "spki" });
  if (key.asymmetricKeyType !== "ed25519") return false;
  return nodeVerify(null, msg, key, Buffer.from(sigB64u, "base64url"));
}

/** Minor units per currency for comparing SPC's decimal totals. */
const ZERO_DECIMAL = new Set(["JPY", "KRW", "VND", "CLP", "ISK", "UGX", "XAF", "XOF", "PYG", "RWF"]);
function toMinorUnits(value: string, currency: string): number | null {
  if (!/^\d+(\.\d+)?$/.test(value)) return null;
  const digits = ZERO_DECIMAL.has(currency) ? 0 : 2;
  const [whole, frac = ""] = value.split(".");
  if (frac.length > digits) return null;
  return Number(whole) * 10 ** digits + Number(frac.padEnd(digits, "0") || "0");
}

function verifyWebAuthn(si: SignedIntent, key: PayerKey, policy: WebAuthnPolicy | undefined): boolean {
  if (!policy || !si.authenticatorData || !si.clientDataJSON) return false;
  const clientDataBytes = b64u(si.clientDataJSON);
  const clientData = JSON.parse(Buffer.from(clientDataBytes).toString("utf8")) as Record<string, unknown>;

  if (clientData.type !== "webauthn.get" && clientData.type !== "payment.get") return false;
  if (clientData.challenge !== Buffer.from(intentChallenge(si.intent)).toString("base64url")) return false;
  if (typeof clientData.origin !== "string" || !policy.origins.includes(clientData.origin)) return false;

  // Secure Payment Confirmation: the browser itself showed the total, so it must be the intent's.
  if (clientData.type === "payment.get") {
    const payment = clientData.payment as { total?: { currency?: string; value?: string } } | undefined;
    const total = payment?.total;
    if (!total || total.currency !== si.intent.currency) return false;
    if (toMinorUnits(String(total.value), si.intent.currency) !== si.intent.amount) return false;
  }

  const authData = b64u(si.authenticatorData);
  if (authData.length < 37) return false;
  const rpIdHash = createHash("sha256").update(policy.rpId, "utf8").digest();
  if (!Buffer.from(authData.subarray(0, 32)).equals(rpIdHash)) return false;
  const flags = authData[32]!;
  const userPresent = (flags & 0x01) !== 0;
  const userVerified = (flags & 0x04) !== 0; // biometric or PIN, not just a tap
  if (!userPresent || !userVerified) return false;

  const clientDataHash = createHash("sha256").update(clientDataBytes).digest();
  const signed = new Uint8Array(authData.length + clientDataHash.length);
  signed.set(authData, 0);
  signed.set(clientDataHash, authData.length);
  // Authenticators may emit high-S signatures, so lowS is relaxed (as WebAuthn allows).
  return p256.verify(b64u(si.signature), signed, b64u(key.publicKey), { format: "der", lowS: false });
}

/**
 * True iff `si` is signed by `key` under its scheme. Never throws: any
 * malformed input is simply invalid, so it's safe on attacker-controlled data.
 * Does not check revocation, nonces or that the intent matches a request;
 * PayEnvelopeService.create does all of that.
 */
export function verifySignedIntent(si: SignedIntent, key: PayerKey, webauthn?: WebAuthnPolicy): boolean {
  try {
    if (!isWellFormedIntent(si.intent) || si.intent.payerId !== key.payerId) return false;
    const challenge = intentChallenge(si.intent);
    switch (key.scheme) {
      case "ed25519":
        return verifyEd25519(key.publicKey, challenge, si.signature);
      case "hybrid-ed25519-mldsa65": {
        const [edPub, pqPub] = key.publicKey.split(".");
        const [edSig, pqSig] = si.signature.split(".");
        if (!edPub || !pqPub || !edSig || !pqSig) return false;
        // AND: a forgery must break both Ed25519 and ML-DSA-65.
        if (!verifyEd25519(edPub, challenge, edSig)) return false;
        return ml_dsa65.verify(b64u(pqSig), challenge, b64u(pqPub));
      }
      case "webauthn-es256":
        return verifyWebAuthn(si, key, webauthn);
      default:
        return false;
    }
  } catch {
    return false;
  }
}

const P256_SPKI_PREFIX = Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex");

/**
 * Enrollment helper: a passkey's public key as browsers return it
 * (PublicKeyCredential.response.getPublicKey(): SPKI DER) to the raw P-256
 * point stored for webauthn-es256. Returns null for anything else.
 */
export function p256PublicKeyFromSpki(spki: Uint8Array): string | null {
  if (spki.length !== P256_SPKI_PREFIX.length + 65) return null;
  if (!Buffer.from(spki.subarray(0, P256_SPKI_PREFIX.length)).equals(P256_SPKI_PREFIX)) return null;
  const point = spki.subarray(P256_SPKI_PREFIX.length);
  if (point[0] !== 0x04) return null;
  return Buffer.from(point).toString("base64url");
}

/** In-process store for tests and local tooling. */
export class MemoryPayerKeyStore implements PayerKeyStore {
  readonly keys = new Map<string, PayerKey>();
  readonly spent = new Map<string, Date>();

  add(key: PayerKey): void {
    this.keys.set(`${key.payerId}\u0000${key.keyId}`, { ...key });
  }

  revoke(payerId: string, keyId: string, at = new Date()): void {
    const k = this.keys.get(`${payerId}\u0000${keyId}`);
    if (k) k.revokedAt = at;
  }

  async findKey(payerId: string, keyId: string) {
    const k = this.keys.get(`${payerId}\u0000${keyId}`);
    return k ? { ...k } : null;
  }

  async useNonce(payerId: string, nonce: string, expiresAt: Date) {
    const id = `${payerId}\u0000${nonce}`;
    if (this.spent.has(id)) return false;
    this.spent.set(id, expiresAt);
    return true;
  }
}
