import type {
  NewPayEnvelope,
  PayEnvelopeDeclineReason,
  PayEnvelopeEvent,
  PayEnvelopeRecord,
} from "./types.js";

/**
 * Storage contract for Pay Envelopes. Each app implements this over its own
 * tables (see README for a Drizzle example) and must pass the conformance
 * suite in `@spin/core/testing`.
 *
 * The single-use guarantee lives in `claim`. It MUST be one atomic,
 * conditional write. A read followed by a separate write is exactly the bug
 * that let SPIN-Envelope approve one envelope five times: concurrent callers
 * all read "unused" before any of them writes.
 *
 * In SQL:
 *   UPDATE pay_envelopes
 *      SET used_at = $now, decision = 'APPROVE', audit_ref = $auditRef
 *    WHERE id = $id AND used_at IS NULL AND expired_at IS NULL AND decision IS NULL
 *      AND expires_at > $now
 *   RETURNING id
 */
export interface PayEnvelopeStore<UserId = string, KeyId = string> {
  findById(id: string): Promise<PayEnvelopeRecord<UserId, KeyId> | null>;

  /** Most recent envelope with this card-number fingerprint, if any. */
  findByPanDigest(digest: string): Promise<PayEnvelopeRecord<UserId, KeyId> | null>;

  /**
   * Idempotency keys are scoped to the API key that created the envelope.
   * Must never return another key's envelope.
   */
  findByIdempotencyKey(
    payKeyId: KeyId,
    idempotencyKey: string,
  ): Promise<PayEnvelopeRecord<UserId, KeyId> | null>;

  insert(envelope: NewPayEnvelope<UserId, KeyId>): Promise<void>;

  /**
   * Atomically mark the envelope APPROVED. Only succeeds while it is unused,
   * not declined (a decline burns it), not manually expired, and
   * `expiresAt > now`. Returns true iff this call changed the row.
   */
  claim(id: string, now: Date, auditRef: string): Promise<boolean>;

  /** Record a DECLINE. Must only touch envelopes that are still unused. */
  markDeclined(id: string, reason: PayEnvelopeDeclineReason, auditRef: string): Promise<void>;

  /**
   * Set expiredAt. Must only touch envelopes that are unused and not already
   * expired. Returns true iff this call changed the row.
   */
  markExpired(id: string, at: Date): Promise<boolean>;

  /** Optional audit event sink. Failures are reported, never thrown to callers. */
  recordEvent?(event: PayEnvelopeEvent<UserId, KeyId>): Promise<void>;
}
