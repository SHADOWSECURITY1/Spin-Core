/**
 * Pay Envelope data model, independent of any database.
 *
 * UserId / KeyId are generic because the apps differ: SPIN-Envelope uses
 * string ids, SPIN-Vault uses integer ids.
 */

export type PayEnvelopeDecision = "APPROVE" | "DECLINE";

export type PayEnvelopeDeclineReason =
  | "EXPIRED"
  | "REPLAY"
  | "CONTEXT_MISMATCH"
  | "AMOUNT_OUT_OF_BOUNDS"
  | "UNKNOWN_PRESENTATION"
  | "INVALID_PRESENTATION"
  | "ALREADY_EXPIRED"
  /** An earlier attempt was declined, so the credential is burned: it leaked or was misused. */
  | "PREVIOUSLY_DECLINED";

export interface PayEnvelopeRecord<UserId = string, KeyId = string> {
  id: string;
  userId: UserId;
  payKeyId: KeyId;
  merchantId: string;
  /** Minor units (cents). */
  amount: number;
  /** ISO 4217. */
  currency: string;
  /** Allowed deviation from `amount`, in parts per million (50_000 = ±5%). Null = exact. */
  amountTolerancePpm: number | null;
  channel: string | null;
  /**
   * Keyed fingerprint of the card number ("d1:" + hex HMAC), for lookups.
   * The card number itself is never stored: it is recomputed from the
   * envelope's details and the HMAC secret when needed, so a copy of the
   * database contains no usable card numbers.
   */
  presentationPanDigest: string;
  createdAt: Date;
  expiresAt: Date;
  usedAt: Date | null;
  expiredAt: Date | null;
  decision: PayEnvelopeDecision | null;
  declineReason: PayEnvelopeDeclineReason | null;
  auditRef: string | null;
  idempotencyKey: string | null;
  receiptJws: string | null;
  metadata: Record<string, unknown> | null;
}

export type NewPayEnvelope<UserId = string, KeyId = string> = Omit<
  PayEnvelopeRecord<UserId, KeyId>,
  "usedAt" | "expiredAt" | "decision" | "declineReason" | "auditRef"
>;

export interface CreatePayEnvelopeInput {
  merchantId: string;
  amount: number;
  currency: string;
  ttlSeconds?: number;
  /** Fraction, e.g. 0.05 = ±5%. */
  amountTolerance?: number;
  channel?: string;
  idempotencyKey?: string;
  metadata?: Record<string, unknown>;
}

export interface CreatePayEnvelopeOutput {
  envelopeId: string;
  expiresAt: string;
  presentation: { pan: string };
  receiptJws: string;
}

export interface TransactionContext {
  merchantId: string;
  amount: number;
  currency: string;
  channel?: string;
}

export interface ResolvePayEnvelopeInput {
  presentation: { pan: string };
  txnContext: TransactionContext;
}

export interface ResolvePayEnvelopeOutput {
  decision: PayEnvelopeDecision;
  reasonCode?: PayEnvelopeDeclineReason;
  auditRef: string;
}

export type PayEnvelopeEventType = "created" | "resolved" | "declined" | "expired";

export interface PayEnvelopeEvent<UserId = string, KeyId = string> {
  envelopeId: string;
  userId: UserId;
  payKeyId: KeyId;
  eventType: PayEnvelopeEventType;
  eventData: Record<string, unknown>;
  merchantId: string | null;
  amount: number | null;
  currency: string | null;
}
