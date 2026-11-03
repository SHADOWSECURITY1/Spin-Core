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
  /** Decline and record the decline on the envelope: it's burned. */
  | { action: "decline"; reason: PayEnvelopeDeclineReason; write: "decline" }
  /** Decline and report the attempt, but don't burn: a wrong merchant presented it. */
  | { action: "decline"; reason: "CONTEXT_MISMATCH"; write: "flag" }
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
  // A burned number (misused at its own merchant) never works again; the
  // store's claim enforces this atomically too.
  if (envelope.decision === "DECLINE") return { action: "decline", reason: "PREVIOUSLY_DECLINED", write: "none" };

  // Another merchant presenting the number is declined and reported, but
  // doesn't burn it. Burning on a wrong merchant let anyone holding leaked
  // numbers and a merchant account destroy customers' payments, while
  // protecting nothing: the number only ever pays its own merchant.
  if (txn.merchantId !== envelope.merchantId) {
    return { action: "decline", reason: "CONTEXT_MISMATCH", write: "flag" };
  }
  // The right merchant with the wrong currency, channel or amount: the number
  // is being misused where it does work, so it never works again.
  if (txn.currency !== envelope.currency) {
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
