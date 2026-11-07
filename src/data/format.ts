/**
 * Wire formats for SPIN Envelope for Data: sealed records, read mandates and
 * read requests, plus the portable crypto a reader needs to open a record.
 *
 * Portable on purpose (no node: imports): a reader's app or browser can seal,
 * build requests and open records with this file alone.
 */
import { gcm } from "@noble/ciphers/aes.js";
import { randomBytes } from "@noble/ciphers/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";

const enc = new TextEncoder();
const dec = new TextDecoder();

export const b64u = {
  encode: (b: Uint8Array): string => {
    let s = "";
    for (const x of b) s += String.fromCharCode(x);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
  decode: (s: string): Uint8Array => {
    if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("not base64url");
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  },
};

// ── Sealed records ───────────────────────────────────────────────────────────

/**
 * What the database stores in place of a sensitive value. The record key
 * (DEK) is random per record and stored only wrapped by a key the database
 * never holds, so a copy of this row is ciphertext and nothing else.
 */
export interface SealedRecord {
  v: 1;
  /** e.g. "patients". Bound into the ciphertext: a row moved to another collection won't open. */
  collection: string;
  /** The row's id. Bound into the ciphertext: a value swapped between rows won't open. */
  recordId: string;
  /** Which wrapping key wrapped `wrappedKey` (an id, never key material). */
  kekId: string;
  /** base64url: the record key, encrypted by the key service's wrapping key. */
  wrappedKey: string;
  /** base64url: 12-byte AES-GCM nonce for `ciphertext`. */
  iv: string;
  /** base64url: AES-256-GCM(recordKey, plaintext), tag included. */
  ciphertext: string;
}

export const MAX_ID_LENGTH = 200;

function isId(x: unknown): x is string {
  return typeof x === "string" && x.length > 0 && x.length <= MAX_ID_LENGTH && !x.includes("\u0000");
}

/** Additional data bound into a record's ciphertext. */
export function recordAad(collection: string, recordId: string): Uint8Array {
  return enc.encode(JSON.stringify(["spin/data-record/v1", collection, recordId]));
}

/** Additional data bound into a record key's wrapping: the key unwraps only for this record. */
export function wrapAad(collection: string, recordId: string): Uint8Array {
  return enc.encode(JSON.stringify(["spin/data-key/v1", collection, recordId]));
}

export function isWellFormedSealedRecord(r: unknown): r is SealedRecord {
  if (!r || typeof r !== "object") return false;
  const x = r as Record<string, unknown>;
  return (
    x.v === 1 &&
    isId(x.collection) &&
    isId(x.recordId) &&
    isId(x.kekId) &&
    typeof x.wrappedKey === "string" &&
    typeof x.iv === "string" &&
    typeof x.ciphertext === "string"
  );
}

/** Encrypt `plaintext` under a fresh record key. Returns the parts; wrapping the key is the keyring's job. */
export function encryptRecord(collection: string, recordId: string, plaintext: Uint8Array | string) {
  const key = randomBytes(32);
  const iv = randomBytes(12);
  const data = typeof plaintext === "string" ? enc.encode(plaintext) : plaintext;
  const ciphertext = gcm(key, iv, recordAad(collection, recordId)).encrypt(data);
  return { key, iv: b64u.encode(iv), ciphertext: b64u.encode(ciphertext) };
}

export class DataEnvelopeError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "DataEnvelopeError";
  }
}

/**
 * Open a sealed record with the record key the key service released.
 * Throws DataEnvelopeError if the key is wrong or the record was altered,
 * moved to another collection or swapped with another row.
 */
export function openRecord(record: SealedRecord, recordKey: Uint8Array | string): Uint8Array {
  if (!isWellFormedSealedRecord(record)) throw new DataEnvelopeError("Not a sealed record");
  try {
    const key = typeof recordKey === "string" ? b64u.decode(recordKey) : recordKey;
    return gcm(key, b64u.decode(record.iv), recordAad(record.collection, record.recordId)).decrypt(b64u.decode(record.ciphertext));
  } catch (err) {
    throw new DataEnvelopeError("Record did not open: wrong key, or the record was altered or moved", { cause: err });
  }
}

export function openRecordText(record: SealedRecord, recordKey: Uint8Array | string): string {
  return dec.decode(openRecord(record, recordKey));
}

// ── Read mandates ────────────────────────────────────────────────────────────

/**
 * A reader's signed limits: what they may read, why, and how fast. Signed by
 * an authority (the data owner's or an administrator's device), never by the
 * reader. The key service enforces it on every read, so a stolen login, a
 * hacked app server or a hijacked agent reads at most this much.
 */
export interface ReadMandate {
  v: 1;
  /** Random id, also its nonce. */
  mandateId: string;
  readerId: string;
  /** The reader's device key that must sign each read. */
  readerKeyId: string;
  /**
   * dataKeyFingerprint() of that key. Pins the exact key the authority
   * approved, so whoever can write the key tables can't swap in their own.
   */
  readerKeyFingerprint: string;
  collections: string[];
  /** e.g. ["treatment", "billing"]. Each read names one. */
  purposes: string[];
  maxPerHour: number;
  maxPerDay: number;
  /** ISO 8601. */
  expiresAt: string;
}

export const READ_MANDATE_PREFIX = "spin/read-mandate/v1\n";
export const MAX_MANDATE_ITEMS = 50;

export function canonicalReadMandate(m: ReadMandate): string {
  return JSON.stringify([m.v, m.mandateId, m.readerId, m.readerKeyId, m.readerKeyFingerprint, m.collections, m.purposes, m.maxPerHour, m.maxPerDay, m.expiresAt]);
}

/** The 32 bytes an authority's device signs to grant a read mandate. */
export function readMandateChallenge(m: ReadMandate): Uint8Array {
  return sha256(enc.encode(READ_MANDATE_PREFIX + canonicalReadMandate(m)));
}

function isIdList(x: unknown): x is string[] {
  return Array.isArray(x) && x.length >= 1 && x.length <= MAX_MANDATE_ITEMS && x.every(isId) && new Set(x).size === x.length;
}

function isLimit(x: unknown): x is number {
  return typeof x === "number" && Number.isInteger(x) && x >= 1 && x <= 1_000_000;
}

function isIsoDate(x: unknown): x is string {
  return typeof x === "string" && x.length <= 40 && !Number.isNaN(Date.parse(x));
}

export function isWellFormedReadMandate(m: unknown): m is ReadMandate {
  if (!m || typeof m !== "object") return false;
  const x = m as Record<string, unknown>;
  return (
    x.v === 1 &&
    isId(x.mandateId) &&
    isId(x.readerId) &&
    isId(x.readerKeyId) &&
    typeof x.readerKeyFingerprint === "string" && /^[A-Za-z0-9_-]{43}$/.test(x.readerKeyFingerprint) &&
    isIdList(x.collections) &&
    isIdList(x.purposes) &&
    isLimit(x.maxPerHour) &&
    isLimit(x.maxPerDay) &&
    (x.maxPerHour as number) <= (x.maxPerDay as number) &&
    isIsoDate(x.expiresAt)
  );
}

/** Fingerprint of a device key (scheme + public key), as a read mandate pins it. */
export function dataKeyFingerprint(key: { scheme: string; publicKey: string }): string {
  return b64u.encode(sha256(enc.encode(JSON.stringify(["spin/data-reader-key/v1", key.scheme, key.publicKey]))));
}

// ── Read requests ────────────────────────────────────────────────────────────

/** One read, for one record, for one stated purpose. Signed by the reader's device. */
export interface ReadRequest {
  v: 1;
  readerId: string;
  keyId: string;
  mandateId: string;
  collection: string;
  recordId: string;
  purpose: string;
  /** ISO 8601. The key service refuses stale or future-dated requests. */
  issuedAt: string;
  /** Random, single use. */
  nonce: string;
}

export const READ_REQUEST_PREFIX = "spin/read-request/v1\n";

export function canonicalReadRequest(r: ReadRequest): string {
  return JSON.stringify([r.v, r.readerId, r.keyId, r.mandateId, r.collection, r.recordId, r.purpose, r.issuedAt, r.nonce]);
}

/** The 32 bytes a reader's device signs for one read. */
export function readRequestChallenge(r: ReadRequest): Uint8Array {
  return sha256(enc.encode(READ_REQUEST_PREFIX + canonicalReadRequest(r)));
}

export function isWellFormedReadRequest(r: unknown): r is ReadRequest {
  if (!r || typeof r !== "object") return false;
  const x = r as Record<string, unknown>;
  return (
    x.v === 1 &&
    isId(x.readerId) &&
    isId(x.keyId) &&
    isId(x.mandateId) &&
    isId(x.collection) &&
    isId(x.recordId) &&
    isId(x.purpose) &&
    isIsoDate(x.issuedAt) &&
    typeof x.nonce === "string" && /^[A-Za-z0-9_-]{16,64}$/.test(x.nonce)
  );
}

/** Build a read request for the reader's device to sign. */
export function newReadRequest(p: {
  readerId: string;
  keyId: string;
  mandateId: string;
  collection: string;
  recordId: string;
  purpose: string;
  now?: Date;
}): ReadRequest {
  return {
    v: 1,
    readerId: p.readerId,
    keyId: p.keyId,
    mandateId: p.mandateId,
    collection: p.collection,
    recordId: p.recordId,
    purpose: p.purpose,
    issuedAt: (p.now ?? new Date()).toISOString(),
    nonce: b64u.encode(randomBytes(16)),
  };
}

/** A fresh random id, e.g. for a mandate. */
export function newId(prefix: string): string {
  return `${prefix}_${b64u.encode(randomBytes(16))}`;
}
