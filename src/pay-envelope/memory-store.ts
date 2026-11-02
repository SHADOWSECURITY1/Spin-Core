import type { PayEnvelopeStore } from "./store.js";
import type {
  NewPayEnvelope,
  PayEnvelopeDeclineReason,
  PayEnvelopeEvent,
  PayEnvelopeRecord,
} from "./types.js";

/**
 * In-process store for tests and local tooling. Not for production: data is
 * lost on restart and isn't shared between processes.
 *
 * Each method checks and writes without awaiting in between, so within one
 * process every operation is atomic.
 */
export class MemoryPayEnvelopeStore<UserId = string, KeyId = string>
  implements PayEnvelopeStore<UserId, KeyId>
{
  readonly envelopes = new Map<string, PayEnvelopeRecord<UserId, KeyId>>();
  readonly events: PayEnvelopeEvent<UserId, KeyId>[] = [];

  async findById(id: string) {
    const e = this.envelopes.get(id);
    return e ? { ...e } : null;
  }

  async findByPanDigest(digest: string) {
    let latest: PayEnvelopeRecord<UserId, KeyId> | null = null;
    for (const e of this.envelopes.values()) {
      if (e.presentationPanDigest === digest && (!latest || e.createdAt >= latest.createdAt)) latest = e;
    }
    return latest ? { ...latest } : null;
  }

  async findByIdempotencyKey(payKeyId: KeyId, idempotencyKey: string) {
    for (const e of this.envelopes.values()) {
      if (e.payKeyId === payKeyId && e.idempotencyKey === idempotencyKey) return { ...e };
    }
    return null;
  }

  async insert(envelope: NewPayEnvelope<UserId, KeyId>) {
    if (this.envelopes.has(envelope.id)) throw new Error(`Duplicate envelope id ${envelope.id}`);
    this.envelopes.set(envelope.id, {
      ...envelope,
      usedAt: null,
      expiredAt: null,
      decision: null,
      declineReason: null,
      auditRef: null,
    });
  }

  async claim(id: string, now: Date, auditRef: string) {
    const e = this.envelopes.get(id);
    if (!e || e.usedAt || e.expiredAt || e.decision || e.expiresAt.getTime() <= now.getTime()) return false;
    e.usedAt = now;
    e.decision = "APPROVE";
    e.declineReason = null;
    e.auditRef = auditRef;
    return true;
  }

  async markDeclined(id: string, reason: PayEnvelopeDeclineReason, auditRef: string) {
    const e = this.envelopes.get(id);
    if (!e || e.usedAt) return;
    e.decision = "DECLINE";
    e.declineReason = reason;
    e.auditRef = auditRef;
  }

  async markExpired(id: string, at: Date) {
    const e = this.envelopes.get(id);
    if (!e || e.usedAt || e.expiredAt) return false;
    e.expiredAt = at;
    return true;
  }

  async recordEvent(event: PayEnvelopeEvent<UserId, KeyId>) {
    this.events.push(event);
  }
}
