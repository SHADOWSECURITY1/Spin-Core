import { randomBytes } from "node:crypto";
import { isValidLuhn, projectPan } from "./luhn.js";
import { planResolution } from "./evaluate.js";
import { signReceipt } from "./receipt.js";
import {
  assertValidSecrets,
  resolvePayEnvelopeSecrets,
  type PayEnvelopeSecrets,
} from "./secrets.js";
import type { PayEnvelopeStore } from "./store.js";
import { softwarePanKeyring, type PanKeyring } from "./keyring.js";
import type {
  CreatePayEnvelopeInput,
  CreatePayEnvelopeOutput,
  PayEnvelopeEventType,
  PayEnvelopeRecord,
  ResolvePayEnvelopeInput,
  ResolvePayEnvelopeOutput,
} from "./types.js";

export const DEFAULT_TTL_SECONDS = 90;
export const MIN_TTL_SECONDS = 10;
export const MAX_TTL_SECONDS = 3600;
/** Visa test BIN. Replace with an issuer-owned range in production. */
export const DEFAULT_BIN = "411111";
const MAX_PAN_ATTEMPTS = 5;
/** Prefix of a stored card-number fingerprint (versioned). */
export const PAN_DIGEST_PREFIX = "d1:";

export class PayEnvelopeIdempotencyConflictError extends Error {
  constructor() {
    super("Idempotency key was already used with different envelope parameters");
    this.name = "PayEnvelopeIdempotencyConflictError";
  }
}

export interface PayEnvelopeServiceOptions<UserId, KeyId> {
  store: PayEnvelopeStore<UserId, KeyId>;
  /** Defaults to resolvePayEnvelopeSecrets(process.env), which fails closed. */
  secrets?: PayEnvelopeSecrets;
  /**
   * Where the card-number keys live. Defaults to softwarePanKeyring(secrets.hmac).
   * In production pass a remotePanKeyring (KMS/HSM); the HMAC secret is then
   * not needed. See keyring.ts.
   */
  keyring?: PanKeyring;
  bin6?: string;
  defaultTtlSeconds?: number;
  /** Injectable clock for tests. */
  now?: () => Date;
  /** Called when an audit event fails to record. Defaults to console.error. */
  onEventError?: (err: unknown) => void;
}

export interface EnvelopeOwner<UserId, KeyId> {
  userId: UserId;
  payKeyId: KeyId;
}

const newEnvelopeId = () => `env_${randomBytes(12).toString("base64url")}`;
const newAuditRef = () => `aud_${randomBytes(8).toString("base64url")}`;

export class PayEnvelopeService<UserId = string, KeyId = string> {
  private readonly store: PayEnvelopeStore<UserId, KeyId>;
  private readonly secrets: PayEnvelopeSecrets;
  private readonly keyring: PanKeyring;
  private readonly bin6: string;
  private readonly defaultTtlSeconds: number;
  private readonly now: () => Date;
  private readonly onEventError: (err: unknown) => void;

  constructor(opts: PayEnvelopeServiceOptions<UserId, KeyId>) {
    this.store = opts.store;
    const requireHmac = !opts.keyring;
    this.secrets = opts.secrets
      ? assertValidSecrets(opts.secrets, { requireHmac })
      : resolvePayEnvelopeSecrets(process.env, { requireHmac });
    this.keyring = opts.keyring ?? softwarePanKeyring(this.secrets.hmac);
    this.bin6 = opts.bin6 ?? DEFAULT_BIN;
    if (!/^\d{6}$/.test(this.bin6)) throw new Error("bin6 must be 6 digits");
    this.defaultTtlSeconds = opts.defaultTtlSeconds ?? DEFAULT_TTL_SECONDS;
    this.now = opts.now ?? (() => new Date());
    this.onEventError =
      opts.onEventError ?? ((err) => console.error("[pay-envelope] event error:", err));
  }

  async create(
    input: CreatePayEnvelopeInput,
    owner: EnvelopeOwner<UserId, KeyId>,
  ): Promise<CreatePayEnvelopeOutput> {
    if (!Number.isInteger(input.amount) || input.amount <= 0) {
      throw new RangeError("amount must be a positive integer (minor units)");
    }
    const tolerancePpm =
      input.amountTolerance === undefined || input.amountTolerance === 0
        ? null
        : Math.round(input.amountTolerance * 1_000_000);
    if (tolerancePpm !== null && (tolerancePpm < 0 || tolerancePpm > 1_000_000)) {
      throw new RangeError("amountTolerance must be between 0 and 1");
    }

    if (input.idempotencyKey) {
      const existing = await this.store.findByIdempotencyKey(owner.payKeyId, input.idempotencyKey);
      if (existing) {
        const same =
          existing.merchantId === input.merchantId &&
          existing.amount === input.amount &&
          existing.currency === input.currency &&
          existing.channel === (input.channel ?? null) &&
          existing.amountTolerancePpm === tolerancePpm;
        if (!same) throw new PayEnvelopeIdempotencyConflictError();
        return await this.toCreateOutput(existing);
      }
    }

    const createdAt = this.now();
    const ttl = Math.min(
      MAX_TTL_SECONDS,
      Math.max(MIN_TTL_SECONDS, input.ttlSeconds ?? this.defaultTtlSeconds),
    );
    const expiresAt = new Date(createdAt.getTime() + ttl * 1000);

    // The presentation PAN is derived from the envelope's context via HMAC,
    // so it can't be predicted without the secret. 9 digits of body means
    // collisions are possible; resolve looks envelopes up by PAN, so a PAN
    // already in use (even by a spent envelope) is never reissued.
    let envelopeId = "";
    let pan = "";
    let panDigest = "";
    for (let attempt = 0; ; attempt++) {
      if (attempt === MAX_PAN_ATTEMPTS) throw new Error("Could not allocate a unique presentation PAN");
      envelopeId = newEnvelopeId();
      pan = await this.derivePan({
        id: envelopeId,
        createdAt,
        merchantId: input.merchantId,
        currency: input.currency,
        amount: input.amount,
        channel: input.channel ?? null,
      });
      panDigest = await this.panDigest(pan);
      if (!(await this.store.findByPanDigest(panDigest))) break;
    }

    const receiptJws = signReceipt(
      this.secrets.jws,
      {
        envelopeId,
        action: "CREATE",
        merchantId: input.merchantId,
        amount: input.amount,
        currency: input.currency,
        expiresAt: expiresAt.toISOString(),
      },
      { now: createdAt },
    );

    await this.store.insert({
      id: envelopeId,
      userId: owner.userId,
      payKeyId: owner.payKeyId,
      merchantId: input.merchantId,
      amount: input.amount,
      currency: input.currency,
      amountTolerancePpm: tolerancePpm,
      channel: input.channel ?? null,
      presentationPanDigest: panDigest, // never the card number itself
      createdAt,
      expiresAt,
      idempotencyKey: input.idempotencyKey ?? null,
      receiptJws,
      metadata: input.metadata ?? null,
    });

    this.emit(envelopeId, owner, "created", {
      merchantId: input.merchantId,
      amount: input.amount,
      currency: input.currency,
    });

    return { envelopeId, expiresAt: expiresAt.toISOString(), presentation: { pan }, receiptJws };
  }

  /**
   * The authorization step: approve this card number for this transaction?
   *
   * `callerMerchantId` is who is actually asking, as established by the app
   * (the merchant that owns the authenticated API key, or later the card
   * network's verified merchant id). When given, it replaces whatever merchant
   * the request claims, so a caller can only ever authorize as itself: a
   * fraudster who knows a stolen number and its merchant can't pose as that
   * merchant. Apps that let callers resolve must pass it; without it the
   * claimed merchant is trusted (only for callers that are the network).
   */
  async resolve(
    input: ResolvePayEnvelopeInput,
    opts: { callerMerchantId?: string } = {},
  ): Promise<ResolvePayEnvelopeOutput> {
    const auditRef = newAuditRef();
    const now = this.now();
    const pan = input.presentation.pan;
    const txnContext =
      opts.callerMerchantId === undefined ? input.txnContext : { ...input.txnContext, merchantId: opts.callerMerchantId };

    if (!/^\d{16}$/.test(pan)) return { decision: "DECLINE", reasonCode: "INVALID_PRESENTATION", auditRef };

    const envelope = await this.store.findByPanDigest(await this.panDigest(pan));
    if (!envelope) return { decision: "DECLINE", reasonCode: "UNKNOWN_PRESENTATION", auditRef };

    const plan = planResolution(envelope, txnContext, now);
    if (plan.action === "decline") {
      if (plan.write === "expire") {
        if (await this.store.markExpired(envelope.id, now)) {
          this.emit(envelope.id, envelope, "expired", { reason: "TTL_EXCEEDED" });
        }
      } else if (plan.write === "decline") {
        await this.store.markDeclined(envelope.id, plan.reason, auditRef);
        this.emit(envelope.id, envelope, "declined", { reason: plan.reason, auditRef });
      }
      return { decision: "DECLINE", reasonCode: plan.reason, auditRef };
    }

    // The checks above read a snapshot that concurrent requests may share.
    // Only the store's atomic claim decides who wins; everyone else is a replay.
    if (!(await this.store.claim(envelope.id, now, auditRef))) {
      return { decision: "DECLINE", reasonCode: "REPLAY", auditRef };
    }
    this.emit(envelope.id, envelope, "resolved", {
      decision: "APPROVE",
      amount: txnContext.amount,
      auditRef,
    });
    return { decision: "APPROVE", auditRef };
  }

  /**
   * Manually expire an envelope. Pass `owner.payKeyId` to restrict this to the
   * API key that created it; other keys get "Envelope not found".
   */
  async expire(
    envelopeId: string,
    owner?: Pick<EnvelopeOwner<UserId, KeyId>, "payKeyId">,
  ): Promise<{ success: boolean; error?: string }> {
    const envelope = await this.store.findById(envelopeId);
    if (!envelope || (owner && envelope.payKeyId !== owner.payKeyId)) {
      return { success: false, error: "Envelope not found" };
    }
    if (envelope.expiredAt) return { success: false, error: "Already expired" };
    if (envelope.usedAt) return { success: false, error: "Already used" };
    if (!(await this.store.markExpired(envelope.id, this.now()))) {
      // Lost a race with an APPROVE or another expire.
      const latest = await this.store.findById(envelope.id);
      return { success: false, error: latest?.usedAt ? "Already used" : "Already expired" };
    }
    this.emit(envelope.id, envelope, "expired", { reason: "MANUAL" });
    return { success: true };
  }

  /** Pass `owner.payKeyId` to hide other keys' envelopes. */
  async getStatus(
    envelopeId: string,
    owner?: Pick<EnvelopeOwner<UserId, KeyId>, "payKeyId">,
  ): Promise<PayEnvelopeRecord<UserId, KeyId> | null> {
    const envelope = await this.store.findById(envelopeId);
    if (!envelope || (owner && envelope.payKeyId !== owner.payKeyId)) return null;
    return envelope;
  }

  /**
   * The card number for an envelope: an HMAC of its id, creation time and
   * context, projected into a Luhn-valid PAN under this service's BIN.
   * Deterministic, so it is recomputed when needed instead of stored.
   */
  private async derivePan(
    e: Pick<PayEnvelopeRecord<unknown, unknown>, "id" | "createdAt" | "merchantId" | "currency" | "amount" | "channel">,
  ): Promise<string> {
    const message = [e.id, e.createdAt.getTime(), e.merchantId, e.currency, e.amount, e.channel ?? ""].join("|");
    const digest = Buffer.from(await this.keyring.mac("pan-derive", Buffer.from(message, "utf8"))).toString("hex");
    const body9 = digest.replace(/[a-f]/g, (c) => String(parseInt(c, 16) % 10)).slice(0, 9);
    const pan = projectPan(this.bin6, body9);
    if (!isValidLuhn(pan)) throw new Error("PAN projection failed Luhn validation");
    return pan;
  }

  /** What the store keeps instead of the card number. Useless without the keyring. */
  private async panDigest(pan: string): Promise<string> {
    const mac = await this.keyring.mac("pan-fingerprint", Buffer.from(pan, "utf8"));
    return PAN_DIGEST_PREFIX + Buffer.from(mac).toString("hex");
  }

  /** For health checks and startup logs: where the card-number keys live. */
  get keyringDescription(): string {
    return this.keyring.description;
  }

  private async toCreateOutput(e: PayEnvelopeRecord<UserId, KeyId>): Promise<CreatePayEnvelopeOutput> {
    return {
      envelopeId: e.id,
      expiresAt: e.expiresAt.toISOString(),
      presentation: { pan: await this.derivePan(e) },
      receiptJws: e.receiptJws ?? "",
    };
  }

  private emit(
    envelopeId: string,
    owner: EnvelopeOwner<UserId, KeyId>,
    eventType: PayEnvelopeEventType,
    eventData: Record<string, unknown>,
  ): void {
    if (!this.store.recordEvent) return;
    this.store
      .recordEvent({
        envelopeId,
        userId: owner.userId,
        payKeyId: owner.payKeyId,
        eventType,
        eventData,
        merchantId: typeof eventData.merchantId === "string" ? eventData.merchantId : null,
        amount: typeof eventData.amount === "number" ? eventData.amount : null,
        currency: typeof eventData.currency === "string" ? eventData.currency : null,
      })
      .catch(this.onEventError);
  }
}
