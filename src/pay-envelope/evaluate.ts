import type {
  PayEnvelopeDeclineReason,
  PayEnvelopeRecord,
  TransactionContext,
} from "./types.js";

export type ResolutionPlan =
  /** Decline without writing anything. */
  | { action: "decline"; reason: PayEnvelopeDeclineReason; write: "none" }
  /** Decline and record that the envelope has lapsed. */
  | { action: "decline"; reason: "EXPIRED"; write: "expire" }
  /** Decline and record the decline on the envelope. */
  | { action: "decline"; reason: PayEnvelopeDeclineReason; write: "decline" }
  /** Every check passed: try to claim it atomically. */
  | { action: "claim" };

/** True if `amount` is within the envelope's tolerance. Exact integer math. */
export function amountWithinTolerance(
  expected: number,
  tolerancePpm: number | null,
  actual: number,
): boolean {
  if (!Number.isFinite(actual)) return false;
  if (!tolerancePpm) return actual === expected;
  return Math.abs(actual - expected) * 1_000_000 <= expected * tolerancePpm;
}

/**
 * Pure decision for a resolve request. Reading the envelope and deciding are
 * separate from the write on purpose: this decision is advisory, and the
 * store's atomic `claim` is what actually enforces single use.
 */
export function planResolution<U, K>(
  envelope: PayEnvelopeRecord<U, K>,
  txn: TransactionContext,
  now: Date,
): ResolutionPlan {
  if (envelope.expiredAt) return { action: "decline", reason: "ALREADY_EXPIRED", write: "none" };
  if (now.getTime() >= envelope.expiresAt.getTime()) {
    return { action: "decline", reason: "EXPIRED", write: "expire" };
  }
  if (envelope.usedAt) return { action: "decline", reason: "REPLAY", write: "none" };

  if (txn.merchantId !== envelope.merchantId || txn.currency !== envelope.currency) {
    return { action: "decline", reason: "CONTEXT_MISMATCH", write: "decline" };
  }
  // An envelope bound to a channel requires the request to state the same
  // channel. (Both apps used to skip the check when the request left it out,
  // so omitting `channel` bypassed the binding.)
  if (envelope.channel && txn.channel !== envelope.channel) {
    return { action: "decline", reason: "CONTEXT_MISMATCH", write: "decline" };
  }
  if (!amountWithinTolerance(envelope.amount, envelope.amountTolerancePpm, txn.amount)) {
    return { action: "decline", reason: "AMOUNT_OUT_OF_BOUNDS", write: "decline" };
  }
  return { action: "claim" };
}
