import { createHash, createPublicKey, verify as nodeVerify } from "node:crypto";
import { p256 } from "@noble/curves/nist.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { CHALLENGE_PREFIX, MIN_NONCE_LENGTH, canonicalIntent, isWellFormedIntent, toMinorUnits, type CustomerIntent } from "./intent-format.js";

export { canonicalIntent, isWellFormedIntent, minorUnitDigits, toMinorUnits, fromMinorUnits } from "./intent-format.js";
export type { CustomerIntent } from "./intent-format.js";

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

/** What the device signs (or passes as the WebAuthn challenge). */
export function intentChallenge(i: CustomerIntent): Uint8Array {
  return new Uint8Array(createHash("sha256").update(CHALLENGE_PREFIX + canonicalIntent(i), "utf8").digest());
}

const b64u = (s: string) => new Uint8Array(Buffer.from(s, "base64url"));

function verifyEd25519(spkiB64u: string, msg: Uint8Array, sigB64u: string): boolean {
  const key = createPublicKey({ key: Buffer.from(spkiB64u, "base64url"), format: "der", type: "spki" });
  if (key.asymmetricKeyType !== "ed25519") return false;
  return nodeVerify(null, msg, key, Buffer.from(sigB64u, "base64url"));
}

/**
 * What a Secure Payment Confirmation prompt must have shown: the browser draws
 * the total and payee itself, so a compromised page can't misrepresent them.
 */
export interface SpcExpectation {
  amount: number;
  currency: string;
  /** The merchant's verified name. When set, the prompt must have shown exactly this. */
  payeeName?: string;
}

/** A signature over a challenge, as a device produces it. */
export interface KeyProof {
  /** base64url. For webauthn-es256: the DER ECDSA signature from the assertion. */
  signature: string;
  /** webauthn-es256 only (base64url). */
  authenticatorData?: string;
  /** webauthn-es256 only (base64url). */
  clientDataJSON?: string;
}

function verifyWebAuthn(
  proof: KeyProof,
  key: PayerKey,
  challenge: Uint8Array,
  policy: WebAuthnPolicy | undefined,
  spc: SpcExpectation | undefined,
): boolean {
  if (!policy || !proof.authenticatorData || !proof.clientDataJSON) return false;
  const clientDataBytes = b64u(proof.clientDataJSON);
  const clientData = JSON.parse(Buffer.from(clientDataBytes).toString("utf8")) as Record<string, unknown>;

  if (clientData.type !== "webauthn.get" && clientData.type !== "payment.get") return false;
  if (clientData.challenge !== Buffer.from(challenge).toString("base64url")) return false;
  if (typeof clientData.origin !== "string" || !policy.origins.includes(clientData.origin)) return false;

  // Secure Payment Confirmation: the browser itself showed the total, so it must be the approved one.
  if (clientData.type === "payment.get") {
    if (!spc) return false;
    const payment = clientData.payment as { total?: { currency?: string; value?: string }; payeeName?: string } | undefined;
    const total = payment?.total;
    if (!total || total.currency !== spc.currency) return false;
    if (toMinorUnits(String(total.value), spc.currency) !== spc.amount) return false;
    // ...and the payee the browser showed must be the merchant SPIN knows.
    if (spc.payeeName !== undefined && payment?.payeeName !== spc.payeeName) return false;
  }

  const authData = b64u(proof.authenticatorData);
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
  return p256.verify(b64u(proof.signature), signed, b64u(key.publicKey), { format: "der", lowS: false });
}

/**
 * True iff `proof` is `key`'s signature over the 32-byte `challenge`, under
 * the key's scheme. Never throws. `spc` is what a Secure Payment
 * Confirmation prompt must have shown (omit it to refuse SPC assertions).
 */
export function verifyKeySignature(
  key: PayerKey,
  challenge: Uint8Array,
  proof: KeyProof,
  webauthn?: WebAuthnPolicy,
  spc?: SpcExpectation,
): boolean {
  try {
    if (typeof proof?.signature !== "string") return false;
    switch (key.scheme) {
      case "ed25519":
        return verifyEd25519(key.publicKey, challenge, proof.signature);
      case "hybrid-ed25519-mldsa65": {
        const [edPub, pqPub] = key.publicKey.split(".");
        const [edSig, pqSig] = proof.signature.split(".");
        if (!edPub || !pqPub || !edSig || !pqSig) return false;
        // AND: a forgery must break both Ed25519 and ML-DSA-65.
        if (!verifyEd25519(edPub, challenge, edSig)) return false;
        return ml_dsa65.verify(b64u(pqSig), challenge, b64u(pqPub));
      }
      case "webauthn-es256":
        return verifyWebAuthn(proof, key, challenge, webauthn, spc);
      default:
        return false;
    }
  } catch {
    return false;
  }
}

/**
 * True iff `si` is signed by `key` under its scheme. Never throws: any
 * malformed input is simply invalid, so it's safe on attacker-controlled data.
 * Does not check revocation, nonces or that the intent matches a request;
 * PayEnvelopeService.create does all of that.
 */
export function verifySignedIntent(
  si: SignedIntent,
  key: PayerKey,
  webauthn?: WebAuthnPolicy,
  opts: { payeeName?: string } = {},
): boolean {
  try {
    if (!isWellFormedIntent(si.intent) || si.intent.payerId !== key.payerId) return false;
    return verifyKeySignature(key, intentChallenge(si.intent), si, webauthn, {
      amount: si.intent.amount,
      currency: si.intent.currency,
      payeeName: opts.payeeName,
    });
  } catch {
    return false;
  }
}

// ── Adding a device to an existing customer ─────────────────────────────────

/**
 * What an existing device signs to approve enrolling a new one. Without this,
 * anyone holding the integrator's API key could enroll their own device on a
 * real customer and then sign approvals as them.
 */
export interface DeviceEnrollment {
  v: 1;
  payerId: string;
  /** The key being added. */
  newKey: { keyId: string; scheme: IntentScheme; publicKey: string };
  /** ISO 8601; at most an hour ahead. */
  expiresAt: string;
  /** Single use (shares the payer's nonce space with intents). */
  nonce: string;
}

const ENROLL_PREFIX = "spin/enroll-device/v1\n";

export function enrollmentChallenge(e: DeviceEnrollment): Uint8Array {
  const canonical = JSON.stringify([e.v, e.payerId, e.newKey.keyId, e.newKey.scheme, e.newKey.publicKey, e.expiresAt, e.nonce]);
  return new Uint8Array(createHash("sha256").update(ENROLL_PREFIX + canonical, "utf8").digest());
}

export function isWellFormedEnrollment(e: unknown): e is DeviceEnrollment {
  if (!e || typeof e !== "object") return false;
  const x = e as Record<string, unknown>;
  const k = x.newKey as Record<string, unknown> | undefined;
  return (
    x.v === 1 &&
    typeof x.payerId === "string" && x.payerId.length > 0 &&
    !!k && typeof k.keyId === "string" && k.keyId.length > 0 &&
    (k.scheme === "ed25519" || k.scheme === "hybrid-ed25519-mldsa65" || k.scheme === "webauthn-es256") &&
    typeof k.publicKey === "string" && k.publicKey.length > 0 &&
    typeof x.expiresAt === "string" && !Number.isNaN(Date.parse(x.expiresAt)) &&
    typeof x.nonce === "string" && x.nonce.length >= MIN_NONCE_LENGTH && x.nonce.length <= 128
  );
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
