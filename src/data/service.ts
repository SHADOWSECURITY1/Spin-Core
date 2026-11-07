/**
 * The key service: the only place a record key is ever unwrapped.
 *
 * It releases one record's key for one signed read request, and only when:
 *   - the reader's own device signed the request (a stolen password, cookie
 *     or API key signs nothing);
 *   - the request is fresh and never seen before (no replays);
 *   - the reader isn't frozen;
 *   - a read mandate, signed by an authority (never the reader), covers the
 *     collection and purpose and hasn't expired or been revoked;
 *   - the record isn't a decoy (touching one freezes the reader and alerts);
 *   - the mandate's hourly and daily read budgets have room.
 *
 * Every decision, yes or no, is written to the audit trail with a trace id.
 *
 * Run it apart from the app server: its own host, its own credentials, the
 * wrapping key in KMS/HSM. Then a hacked app server, like a hacked database,
 * can't read in bulk: it can only ask, and each ask needs a reader's device
 * signature and fits inside that reader's budget.
 *
 * Who can grant access is fixed configuration (`authorities`), and each
 * mandate pins the reader's exact key, so even someone who can write this
 * service's tables can't add a reader or swap a key. What they could do is
 * undo a revocation, a freeze or the read counts. So keep the store on the
 * key service's own database, out of the app server's reach.
 */
import { randomBytes } from "node:crypto";
import { verifyKeySignature, type IntentScheme, type KeyProof, type PayerKey, type WebAuthnPolicy } from "../pay-envelope/intent.js";
import {
  b64u,
  dataKeyFingerprint,
  encryptRecord,
  isWellFormedReadMandate,
  isWellFormedReadRequest,
  isWellFormedSealedRecord,
  readMandateChallenge,
  readRequestChallenge,
  wrapAad,
  type ReadMandate,
  type ReadRequest,
  type SealedRecord,
} from "./format.js";
import type { DataKeyring } from "./keyring.js";

export type { IntentScheme, KeyProof, WebAuthnPolicy };

/** A person's or service's enrolled device key. Same schemes as SPIN Pay's payer keys. */
export interface DataKey {
  /** The reader or authority this key belongs to. */
  ownerId: string;
  keyId: string;
  scheme: IntentScheme;
  /** base64url; format per scheme (see SPIN Pay's PayerKey). */
  publicKey: string;
  revokedAt: Date | null;
}

export interface SignedReadMandate extends KeyProof {
  mandate: ReadMandate;
  /** The authority device key that signed it. */
  keyId: string;
}

export interface SignedReadRequest extends KeyProof {
  request: ReadRequest;
}

export type ReadRejection =
  | "request_invalid"
  | "signature_invalid"
  | "request_expired"
  | "request_replayed"
  | "reader_frozen"
  | "mandate_invalid"
  | "mandate_mismatch"
  | "record_mismatch"
  | "limit_hourly"
  | "limit_daily"
  /** A decoy was touched. Deliberately vague to the caller; the audit says more. */
  | "denied"
  | "key_unavailable";

export type ReleaseResult =
  | { ok: true; recordKey: string; traceId: string }
  | { ok: false; reason: ReadRejection; traceId: string };

export interface ReadAuditEvent {
  traceId: string;
  at: Date;
  readerId: string | null;
  keyId: string | null;
  mandateId: string | null;
  collection: string | null;
  recordId: string | null;
  purpose: string | null;
  outcome: "released" | "refused";
  reason?: ReadRejection;
}

export interface DataAlert {
  type: "decoy_touched";
  at: Date;
  traceId: string;
  readerId: string;
  collection: string;
  recordId: string;
}

/**
 * The key service's state. Apps implement it over their own tables, kept away
 * from the data they protect. `useNonce` and `reserveRead` MUST be atomic
 * (unique index; a transaction holding the mandate's row lock).
 */
export interface DataAccessStore {
  findReaderKey(readerId: string, keyId: string): Promise<DataKey | null>;
  findMandate(mandateId: string): Promise<{ signed: SignedReadMandate; revokedAt: Date | null } | null>;
  /** Record the nonce as spent. False if it already was. */
  useNonce(readerId: string, nonce: string, expiresAt: Date): Promise<boolean>;
  /** Count this read if both budgets have room. */
  reserveRead(
    mandateId: string,
    limits: { hourSince: Date; perHour: number; daySince: Date; perDay: number },
  ): Promise<"ok" | "hour" | "day">;
  isFrozen(readerId: string): Promise<boolean>;
  freezeReader(readerId: string, reason: string, at: Date): Promise<void>;
  isDecoy(collection: string, recordId: string): Promise<boolean>;
  appendAudit(event: ReadAuditEvent): Promise<void>;
}

export interface DataKeyServiceOptions {
  store: DataAccessStore;
  keyring: DataKeyring;
  /**
   * The device keys allowed to sign read mandates (privacy officer, data
   * owner). Fixed configuration of the key service, deployed with it, never
   * read from a database: whoever can write tables must not be able to make
   * themselves an authority.
   */
  authorities: DataKey[];
  /** Required if any reader or authority key is a passkey. */
  webauthn?: WebAuthnPolicy;
  now?: () => Date;
  /** How old a read request may be. Default 2 minutes. */
  maxRequestAgeMs?: number;
  /** Called when a decoy is touched, after the reader is frozen. Don't let it throw. */
  onAlert?: (alert: DataAlert) => void | Promise<void>;
}

const FUTURE_SKEW_MS = 30_000;
const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;

function asPayerKey(k: DataKey): PayerKey {
  return { payerId: k.ownerId, keyId: k.keyId, scheme: k.scheme, publicKey: k.publicKey, revokedAt: k.revokedAt };
}

/** True iff `sm` is a well-formed mandate signed by `authority`, which is not the reader. Never throws. */
export function verifySignedReadMandate(sm: SignedReadMandate, authority: DataKey, webauthn?: WebAuthnPolicy): boolean {
  try {
    if (!isWellFormedReadMandate(sm.mandate)) return false;
    if (sm.keyId !== authority.keyId || authority.revokedAt) return false;
    // An authority can't grant itself read access: the signer must not be the reader.
    if (authority.ownerId === sm.mandate.readerId) return false;
    return verifyKeySignature(asPayerKey(authority), readMandateChallenge(sm.mandate), sm, webauthn);
  } catch {
    return false;
  }
}

export class DataKeyService {
  private readonly store: DataAccessStore;
  private readonly authorities: Map<string, DataKey>;
  private readonly keyring: DataKeyring;
  private readonly webauthn: WebAuthnPolicy | undefined;
  private readonly now: () => Date;
  private readonly maxAge: number;
  private readonly onAlert: DataKeyServiceOptions["onAlert"];

  constructor(opts: DataKeyServiceOptions) {
    this.store = opts.store;
    this.authorities = new Map((opts.authorities ?? []).map((k) => [k.keyId, k]));
    this.keyring = opts.keyring;
    this.webauthn = opts.webauthn;
    this.now = opts.now ?? (() => new Date());
    this.maxAge = opts.maxRequestAgeMs ?? 120_000;
    this.onAlert = opts.onAlert;
  }

  /** Seal a value for storage. The app server can seal without being able to read anything back. */
  async seal(collection: string, recordId: string, plaintext: Uint8Array | string): Promise<SealedRecord> {
    const { key, iv, ciphertext } = encryptRecord(collection, recordId, plaintext);
    try {
      const { kekId, wrapped } = await this.keyring.wrap(key, wrapAad(collection, recordId));
      return { v: 1, collection, recordId, kekId, wrappedKey: b64u.encode(wrapped), iv, ciphertext };
    } finally {
      key.fill(0);
    }
  }

  /**
   * Release the record key for one signed read of `record`. Never throws on
   * bad input: every refusal comes back as `{ ok: false, reason }` and is
   * audited.
   */
  async release(signed: SignedReadRequest, record: SealedRecord): Promise<ReleaseResult> {
    const traceId = `tr_${randomBytes(12).toString("base64url")}`;
    const at = this.now();
    const req = signed?.request;
    const wellFormed = isWellFormedReadRequest(req);
    const base: ReadAuditEvent = {
      traceId,
      at,
      readerId: wellFormed ? req.readerId : null,
      keyId: wellFormed ? req.keyId : null,
      mandateId: wellFormed ? req.mandateId : null,
      collection: wellFormed ? req.collection : null,
      recordId: wellFormed ? req.recordId : null,
      purpose: wellFormed ? req.purpose : null,
      outcome: "refused",
    };
    const refuse = async (reason: ReadRejection): Promise<ReleaseResult> => {
      await this.store.appendAudit({ ...base, reason });
      return { ok: false, reason, traceId };
    };

    if (!wellFormed || !isWellFormedSealedRecord(record)) return refuse("request_invalid");

    // 1. The reader's own device signed this exact request.
    const readerKey = await this.store.findReaderKey(req.readerId, req.keyId);
    if (!readerKey || readerKey.revokedAt || readerKey.ownerId !== req.readerId) return refuse("signature_invalid");
    if (!verifyKeySignature(asPayerKey(readerKey), readRequestChallenge(req), signed, this.webauthn)) {
      return refuse("signature_invalid");
    }

    // 2. Fresh, and never seen before.
    const issued = Date.parse(req.issuedAt);
    if (issued > at.getTime() + FUTURE_SKEW_MS || at.getTime() - issued > this.maxAge) return refuse("request_expired");
    if (!(await this.store.useNonce(req.readerId, req.nonce, new Date(issued + this.maxAge + FUTURE_SKEW_MS)))) {
      return refuse("request_replayed");
    }

    // 3. Not frozen.
    if (await this.store.isFrozen(req.readerId)) return refuse("reader_frozen");

    // 4. A valid mandate, granted by an authority, covering this read.
    const stored = await this.store.findMandate(req.mandateId);
    const m = stored?.signed.mandate;
    if (!stored || !m || stored.revokedAt || m.mandateId !== req.mandateId) return refuse("mandate_invalid");
    const authority = this.authorities.get(stored.signed.keyId);
    if (!authority || !verifySignedReadMandate(stored.signed, authority, this.webauthn)) return refuse("mandate_invalid");
    if (Date.parse(m.expiresAt) <= at.getTime()) return refuse("mandate_invalid");
    if (m.readerId !== req.readerId || m.readerKeyId !== req.keyId) return refuse("mandate_invalid");
    // The key that signed must be the very key the authority approved.
    if (m.readerKeyFingerprint !== dataKeyFingerprint(readerKey)) return refuse("mandate_invalid");
    if (!m.collections.includes(req.collection) || !m.purposes.includes(req.purpose)) return refuse("mandate_mismatch");

    // 5. The request is for this record.
    if (record.collection !== req.collection || record.recordId !== req.recordId) return refuse("record_mismatch");

    // 6. Decoys: no legitimate reader needs one. Freeze first, then alert.
    if (await this.store.isDecoy(req.collection, req.recordId)) {
      await this.store.freezeReader(req.readerId, `decoy ${req.collection}/${req.recordId} (${traceId})`, at);
      const result = await refuse("denied");
      try {
        await this.onAlert?.({ type: "decoy_touched", at, traceId, readerId: req.readerId, collection: req.collection, recordId: req.recordId });
      } catch {
        // An alerting fault must not undo the freeze or leak the key.
      }
      return result;
    }

    // 7. Budget.
    const budget = await this.store.reserveRead(m.mandateId, {
      hourSince: new Date(at.getTime() - HOUR_MS),
      perHour: m.maxPerHour,
      daySince: new Date(at.getTime() - DAY_MS),
      perDay: m.maxPerDay,
    });
    if (budget === "hour") return refuse("limit_hourly");
    if (budget === "day") return refuse("limit_daily");

    // 8. Unwrap. Fails closed.
    let recordKey: Uint8Array;
    try {
      recordKey = await this.keyring.unwrap(record.kekId, b64u.decode(record.wrappedKey), wrapAad(record.collection, record.recordId));
    } catch {
      return refuse("key_unavailable");
    }
    await this.store.appendAudit({ ...base, outcome: "released" });
    const out = b64u.encode(recordKey);
    recordKey.fill(0);
    return { ok: true, recordKey: out, traceId };
  }
}

/** In-memory DataAccessStore for tests and demos. */
export class MemoryDataAccessStore implements DataAccessStore {
  readonly readerKeys = new Map<string, DataKey>();
  readonly mandates = new Map<string, { signed: SignedReadMandate; revokedAt: Date | null }>();
  readonly nonces = new Set<string>();
  readonly reads: { mandateId: string; at: Date }[] = [];
  readonly frozen = new Map<string, { reason: string; at: Date }>();
  readonly decoys = new Set<string>();
  readonly audit: ReadAuditEvent[] = [];

  constructor(private readonly clock: () => Date = () => new Date()) {}

  addReaderKey(k: DataKey) {
    this.readerKeys.set(`${k.ownerId}\u0000${k.keyId}`, k);
  }
  addMandate(signed: SignedReadMandate) {
    this.mandates.set(signed.mandate.mandateId, { signed, revokedAt: null });
  }
  revokeMandate(mandateId: string, at = new Date()) {
    const m = this.mandates.get(mandateId);
    if (m) m.revokedAt = at;
  }
  plantDecoy(collection: string, recordId: string) {
    this.decoys.add(`${collection}\u0000${recordId}`);
  }
  unfreeze(readerId: string) {
    this.frozen.delete(readerId);
  }

  async findReaderKey(readerId: string, keyId: string) {
    return this.readerKeys.get(`${readerId}\u0000${keyId}`) ?? null;
  }
  async findMandate(mandateId: string) {
    const m = this.mandates.get(mandateId);
    return m ? { signed: m.signed, revokedAt: m.revokedAt } : null;
  }
  async useNonce(readerId: string, nonce: string) {
    const k = `${readerId}\u0000${nonce}`;
    if (this.nonces.has(k)) return false;
    this.nonces.add(k);
    return true;
  }
  // Check and record with no await in between: atomic.
  async reserveRead(mandateId: string, l: { hourSince: Date; perHour: number; daySince: Date; perDay: number }) {
    const mine = this.reads.filter((r) => r.mandateId === mandateId);
    if (mine.filter((r) => r.at >= l.daySince).length >= l.perDay) return "day" as const;
    if (mine.filter((r) => r.at >= l.hourSince).length >= l.perHour) return "hour" as const;
    this.reads.push({ mandateId, at: this.clock() });
    return "ok" as const;
  }
  async isFrozen(readerId: string) {
    return this.frozen.has(readerId);
  }
  async freezeReader(readerId: string, reason: string, at: Date) {
    this.frozen.set(readerId, { reason, at });
  }
  async isDecoy(collection: string, recordId: string) {
    return this.decoys.has(`${collection}\u0000${recordId}`);
  }
  async appendAudit(event: ReadAuditEvent) {
    this.audit.push(event);
  }
}
