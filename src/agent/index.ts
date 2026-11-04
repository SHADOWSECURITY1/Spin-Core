/**
 * @spin/core/agent: the AI agent's side of SPIN. An agent platform uses this
 * (directly, or through the MCP server in ./mcp.ts) to buy for a person under
 * the standing rule (mandate) that person signed.
 *
 * What the agent holds: nothing reusable. Its signing key lives in a cloud key
 * service (awsKmsSigner) or an HSM; this code only asks it to sign. Each
 * purchase returns a card number that works once, at one merchant, for the
 * exact amount, for a few minutes. A tricked or hijacked agent can only buy
 * what the person's rule already allows, and SPIN checks that on its server,
 * not here: the checks in this file only give the agent a clear answer before
 * it asks.
 *
 * Runs anywhere with fetch and Web Crypto (Node 20+, Deno, Bun, workers).
 */
import { p256 } from "@noble/curves/nist.js";
import {
  fromMinorUnits,
  toMinorUnits,
  type CustomerIntent,
  type Mandate,
} from "../pay-envelope/intent-format.js";
import { intentChallenge, newIntent, toBase64Url } from "../approval/index.js";

export { fromMinorUnits, toMinorUnits };

// ── Signers ──────────────────────────────────────────────────────────────────

/** Signs for the agent's enrolled key (scheme "ecdsa-p256"). Returns a DER or 64-byte compact ECDSA signature over SHA-256 of the challenge. */
export interface AgentSigner {
  /** The keyId the agent's key was enrolled under. */
  keyId: string;
  sign(challenge: Uint8Array): Promise<Uint8Array>;
}

/** The slice of AWS SDK v3's KMS client this needs: `new KMS({ region })` from @aws-sdk/client-kms. */
export interface KmsLike {
  sign(input: {
    KeyId: string;
    Message: Uint8Array;
    MessageType: "RAW";
    SigningAlgorithm: "ECDSA_SHA_256";
  }): Promise<{ Signature?: Uint8Array }>;
}

/**
 * The agent's key in AWS KMS (key spec ECC_NIST_P256, usage SIGN_VERIFY). The
 * private key never leaves KMS; give the agent's IAM role kms:Sign on this key
 * only. Enroll it with the SPKI from `GetPublicKey`.
 */
export function awsKmsSigner(p: { keyId: string; kmsKeyId: string; kms: KmsLike }): AgentSigner {
  return {
    keyId: p.keyId,
    async sign(challenge) {
      const out = await p.kms.sign({ KeyId: p.kmsKeyId, Message: challenge, MessageType: "RAW", SigningAlgorithm: "ECDSA_SHA_256" });
      if (!out.Signature) throw new Error("AWS KMS returned no signature");
      return out.Signature;
    },
  };
}

/**
 * A P-256 key held in memory. For development and tests only: in production
 * the key belongs in a key service, where a compromised agent can't copy it.
 */
export function p256Signer(keyId: string, privateKey: Uint8Array): AgentSigner {
  return { keyId, sign: async (challenge) => p256.sign(challenge, privateKey, { format: "der" }) };
}

/** A new in-memory P-256 key (development only), with its public key as the enrollment API takes it. */
export function generateDevAgentKey(): { privateKey: Uint8Array; publicKey: string; spki: string } {
  const privateKey = p256.utils.randomSecretKey();
  const raw = p256.getPublicKey(privateKey, false);
  const prefix = [0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00];
  const spki = new Uint8Array(prefix.length + raw.length);
  spki.set(prefix);
  spki.set(raw, prefix.length);
  return { privateKey, publicKey: toBase64Url(raw), spki: toBase64Url(spki) };
}

// ── The client ───────────────────────────────────────────────────────────────

/** A standing rule this agent may buy under, as SPIN reports it. Amounts in minor units. */
export interface AgentRule {
  mandateId: string;
  merchants: string[];
  currency: string;
  channel: "CNP" | "CP" | null;
  maxPerPurchase: number;
  maxPerDay: number;
  /** Spent under this rule in the last 24 hours. */
  spentLast24h: number;
  /** maxPerDay minus spentLast24h, never below 0. */
  remainingToday: number;
  expiresAt: string;
}

export interface Purchase {
  merchantId: string;
  /** Minor units (450 = $4.50). */
  amount: number;
  currency: string;
  channel?: "CNP" | "CP" | null;
}

export type BuyResult =
  | {
      ok: true;
      envelopeId: string;
      /** The card number. Works once, at `merchantId`, for exactly `amount`, until `expiresAt`. */
      pan: string;
      expiresAt: string;
      mandateId: string;
      /** SPIN's signed receipt, including the agent's signed purchase. */
      receiptJws: string;
    }
  | { ok: false; code: string; message: string };

export interface SpinAgentOptions {
  /** The Pay Envelope API base, e.g. https://spin.example/api/v1/pay */
  baseUrl: string;
  /** The platform's SPIN API key (sp_live_... or sp_test_...). Keep it out of the model's context. */
  apiKey: string;
  /** The person this agent buys for. */
  payerId: string;
  signer: AgentSigner;
  /** Always buy under this rule. Otherwise the agent picks the first active rule that fits each purchase. */
  mandateId?: string;
  fetch?: typeof fetch;
  now?: () => Date;
}

interface MandateView {
  mandateId: string;
  agentKeyId: string;
  merchants: string[];
  currency: string;
  maxPerPurchase: number;
  maxPerDay: number;
  channel: "CNP" | "CP" | null;
  expiresAt: string;
  revokedAt: string | null;
  spentLast24h: number;
}

export class SpinAgent {
  private readonly base: string;
  private readonly fetch: typeof fetch;
  private readonly now: () => Date;

  constructor(private readonly opts: SpinAgentOptions) {
    this.base = opts.baseUrl.replace(/\/+$/, "");
    this.fetch = opts.fetch ?? globalThis.fetch.bind(globalThis);
    this.now = opts.now ?? (() => new Date());
  }

  private async call(method: string, path: string, body?: unknown): Promise<{ status: number; json: any }> {
    const res = await this.fetch(this.base + path, {
      method,
      headers: { authorization: `Bearer ${this.opts.apiKey}`, ...(body === undefined ? {} : { "content-type": "application/json" }) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    let json: any = null;
    try {
      json = await res.json();
    } catch {
      // Not JSON: leave null.
    }
    return { status: res.status, json };
  }

  /** The active rules this agent's key may buy under, with what is left today. */
  async rules(): Promise<AgentRule[]> {
    const { status, json } = await this.call("GET", `/payers/${encodeURIComponent(this.opts.payerId)}/mandates`);
    if (status !== 200 || !Array.isArray(json?.mandates)) {
      throw new SpinAgentError(json?.error?.code ?? "rules_unavailable", json?.error?.message ?? `SPIN returned ${status}`);
    }
    const now = this.now().getTime();
    return (json.mandates as MandateView[])
      .filter((m) => m.agentKeyId === this.opts.signer.keyId && !m.revokedAt && Date.parse(m.expiresAt) > now)
      .filter((m) => !this.opts.mandateId || m.mandateId === this.opts.mandateId)
      .map((m) => ({
        mandateId: m.mandateId,
        merchants: m.merchants,
        currency: m.currency,
        channel: m.channel,
        maxPerPurchase: m.maxPerPurchase,
        maxPerDay: m.maxPerDay,
        spentLast24h: m.spentLast24h,
        remainingToday: Math.max(0, m.maxPerDay - m.spentLast24h),
        expiresAt: m.expiresAt,
      }));
  }

  /**
   * Buy once. Picks a rule that covers this purchase, signs it with the
   * agent's key, and asks SPIN for a card number. SPIN re-checks everything;
   * a refusal comes back as { ok: false, code, message }, never a throw.
   */
  async buy(p: Purchase): Promise<BuyResult> {
    const currency = p.currency.toUpperCase();
    const channel = p.channel ?? null;
    if (!Number.isSafeInteger(p.amount) || p.amount <= 0) {
      return { ok: false, code: "invalid_amount", message: "The amount must be a positive whole number of minor units." };
    }
    let rules: AgentRule[];
    try {
      rules = await this.rules();
    } catch (e) {
      if (e instanceof SpinAgentError) return { ok: false, code: e.code, message: e.message };
      throw e;
    }
    const fits = (r: AgentRule) =>
      r.merchants.includes(p.merchantId) &&
      r.currency === currency &&
      (r.channel === null || r.channel === channel) &&
      p.amount <= r.maxPerPurchase &&
      p.amount <= r.remainingToday;
    const rule = rules.find(fits);
    if (!rule) {
      return { ok: false, code: "no_matching_rule", message: explainNoRule(rules, { ...p, currency, channel }) };
    }
    const intent: CustomerIntent = newIntent({
      payerId: this.opts.payerId,
      merchantId: p.merchantId,
      amount: p.amount,
      currency,
      channel,
      mandateId: rule.mandateId,
      now: this.now(),
    });
    const signature = toBase64Url(await this.opts.signer.sign(intentChallenge(intent)));
    const { status, json } = await this.call("POST", "/envelopes", {
      merchantId: p.merchantId,
      amount: p.amount,
      currency,
      ...(channel ? { channel } : {}),
      signedIntent: { intent, keyId: this.opts.signer.keyId, signature },
    });
    if (status === 201 && typeof json?.presentation?.pan === "string") {
      return { ok: true, envelopeId: json.envelopeId, pan: json.presentation.pan, expiresAt: json.expiresAt, mandateId: rule.mandateId, receiptJws: json.receiptJws };
    }
    return { ok: false, code: json?.error?.code ?? `http_${status}`, message: json?.error?.message ?? `SPIN returned ${status}` };
  }

  /**
   * Step-up: ask the person to approve one purchase that's outside their
   * rules. The agent signs the request with its key; the person approves or
   * declines on their own device, through the platform's app. Then poll
   * checkApproval(). `note` is shown to the person as the agent's words.
   */
  async requestApproval(p: Purchase & { note?: string }): Promise<{ ok: true; requestId: string; expiresAt: string } | { ok: false; code: string; message: string }> {
    const currency = p.currency.toUpperCase();
    const channel = p.channel ?? null;
    if (!Number.isSafeInteger(p.amount) || p.amount <= 0) {
      return { ok: false, code: "invalid_amount", message: "The amount must be a positive whole number of minor units." };
    }
    const intent = newIntent({ payerId: this.opts.payerId, merchantId: p.merchantId, amount: p.amount, currency, channel, ttlSeconds: 600, now: this.now() });
    const signature = toBase64Url(await this.opts.signer.sign(intentChallenge(intent)));
    const { status, json } = await this.call("POST", `/payers/${encodeURIComponent(this.opts.payerId)}/approval-requests`, {
      signedIntent: { intent, keyId: this.opts.signer.keyId, signature },
      ...(p.note ? { note: p.note.slice(0, 140) } : {}),
    });
    if (status === 201 && typeof json?.requestId === "string") return { ok: true, requestId: json.requestId, expiresAt: json.expiresAt };
    return { ok: false, code: json?.error?.code ?? `http_${status}`, message: json?.error?.message ?? `SPIN returned ${status}` };
  }

  /**
   * Where a step-up request stands. Once the person approves, this collects
   * the single-use card number (once: a second call reports "collected").
   */
  async checkApproval(requestId: string): Promise<
    | { status: "pending"; expiresAt: string }
    | { status: "declined" | "expired" | "collected" }
    | ({ status: "approved" } & Extract<BuyResult, { ok: true }>)
    | { status: "error"; code: string; message: string }
  > {
    const id = encodeURIComponent(requestId);
    const got = await this.call("GET", `/approval-requests/${id}`);
    if (got.status !== 200) return { status: "error", code: got.json?.error?.code ?? `http_${got.status}`, message: got.json?.error?.message ?? `SPIN returned ${got.status}` };
    const st = got.json.status as string;
    if (st === "pending") return { status: "pending", expiresAt: got.json.expiresAt };
    if (st !== "approved") return { status: st as "declined" | "expired" | "collected" };
    const { status, json } = await this.call("POST", `/approval-requests/${id}/collect`, {});
    if (status === 201 && typeof json?.presentation?.pan === "string") {
      return { status: "approved", ok: true, envelopeId: json.envelopeId, pan: json.presentation.pan, expiresAt: json.expiresAt, mandateId: "", receiptJws: json.receiptJws };
    }
    return { status: "error", code: json?.error?.code ?? `http_${status}`, message: json?.error?.message ?? `SPIN returned ${status}` };
  }

  /** Whether a purchase's card number was charged, declined, or expired. */
  async status(envelopeId: string): Promise<{ ok: true; status: Record<string, unknown> } | { ok: false; code: string; message: string }> {
    const { status, json } = await this.call("GET", `/envelopes/${encodeURIComponent(envelopeId)}/status`);
    if (status === 200) return { ok: true, status: json };
    return { ok: false, code: json?.error?.code ?? `http_${status}`, message: json?.error?.message ?? `SPIN returned ${status}` };
  }
}

export class SpinAgentError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "SpinAgentError";
  }
}

/** Why no rule covers a purchase, in words an agent can pass on to the person. */
function explainNoRule(rules: AgentRule[], p: Purchase & { currency: string; channel: "CNP" | "CP" | null }): string {
  if (rules.length === 0) return "No active standing rule lets this agent buy. Ask the person to set one up.";
  const money = (n: number) => `${fromMinorUnits(n, p.currency)} ${p.currency}`;
  const atMerchant = rules.filter((r) => r.merchants.includes(p.merchantId));
  if (atMerchant.length === 0) return `No standing rule covers merchant "${p.merchantId}". Ask the person before buying there.`;
  const inCurrency = atMerchant.filter((r) => r.currency === p.currency);
  if (inCurrency.length === 0) return `The rules for "${p.merchantId}" are in ${atMerchant.map((r) => r.currency).join(", ")}, not ${p.currency}.`;
  const inChannel = inCurrency.filter((r) => r.channel === null || r.channel === p.channel);
  if (inChannel.length === 0) return `The rules for "${p.merchantId}" only allow ${inCurrency.map((r) => r.channel).join(", ")} payments.`;
  const maxPer = Math.max(...inChannel.map((r) => r.maxPerPurchase));
  if (p.amount > maxPer) return `${money(p.amount)} is over the per-purchase limit of ${money(maxPer)}. Ask the person to approve it.`;
  const left = Math.max(...inChannel.map((r) => r.remainingToday));
  return `${money(p.amount)} would go over today's limit: ${money(left)} is left in the last 24 hours. Ask the person, or wait.`;
}

export type { CustomerIntent, Mandate };
export { createSpinMcpHandler, MCP_SERVER_NAME, MCP_SERVER_VERSION } from "./mcp.js";
