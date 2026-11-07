/**
 * SPIN Envelope for Data: each rule the key service enforces, one at a time.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import {
  DataEnvelopeError,
  DataKeyService,
  MemoryDataAccessStore,
  newId,
  newReadRequest,
  openRecordText,
  readMandateChallenge,
  readRequestChallenge,
  dataKeyFingerprint,
  remoteDataKeyring,
  softwareDataKeyring,
  type DataAlert,
  type ReadMandate,
  type SealedRecord,
  type SignedReadRequest,
} from "../src/data/index.js";
import { RP, ed25519Signer, passkeySigner, type SigningDevice } from "./helpers/data-device.js";

function setup(opts: { mandate?: Partial<ReadMandate>; reader?: SigningDevice; keyring?: ReturnType<typeof softwareDataKeyring> } = {}) {
  let now = new Date("2026-11-07T12:00:00Z");
  const clock = () => now;
  const store = new MemoryDataAccessStore(clock);
  const alerts: DataAlert[] = [];
  const admin = ed25519Signer("admin");
  const service = new DataKeyService({
    store,
    authorities: [admin.key],
    keyring: opts.keyring ?? softwareDataKeyring(randomBytes(32)),
    webauthn: RP,
    now: clock,
    onAlert: (a) => void alerts.push(a),
  });
  const reader = opts.reader ?? ed25519Signer("dr-lee");
  store.addReaderKey(reader.key);
  const mandate: ReadMandate = {
    v: 1,
    mandateId: newId("rm"),
    readerId: reader.key.ownerId,
    readerKeyId: reader.key.keyId,
    readerKeyFingerprint: dataKeyFingerprint(reader.key),
    collections: ["patients"],
    purposes: ["treatment"],
    maxPerHour: 5,
    maxPerDay: 20,
    expiresAt: new Date(now.getTime() + 30 * 86_400_000).toISOString(),
    ...opts.mandate,
  };
  store.addMandate({ mandate, keyId: admin.key.keyId, ...admin.prove(readMandateChallenge(mandate)) });

  const ask = (record: SealedRecord, over: { purpose?: string; device?: SigningDevice; mandateId?: string; collection?: string; recordId?: string } = {}): SignedReadRequest => {
    const device = over.device ?? reader;
    const request = newReadRequest({
      readerId: device.key.ownerId,
      keyId: device.key.keyId,
      mandateId: over.mandateId ?? mandate.mandateId,
      collection: over.collection ?? record.collection,
      recordId: over.recordId ?? record.recordId,
      purpose: over.purpose ?? "treatment",
      now,
    });
    return { request, ...device.prove(readRequestChallenge(request)) };
  };
  return { store, service, clock, admin, reader, mandate, alerts, ask, advance: (ms: number) => (now = new Date(now.getTime() + ms)) };
}

test("sealed rows hold no plaintext, and a signed read inside the mandate opens one", async () => {
  const s = setup();
  const row = await s.service.seal("patients", "p1", "Jane Doe, DOB 1980-02-03, diagnosis: asthma");
  assert.doesNotMatch(JSON.stringify(row), /Jane|asthma|1980/);
  const r = await s.service.release(s.ask(row), row);
  assert.ok(r.ok, JSON.stringify(r));
  assert.equal(openRecordText(row, r.recordKey), "Jane Doe, DOB 1980-02-03, diagnosis: asthma");
  assert.equal(s.store.audit.at(-1)?.outcome, "released");
  assert.equal(s.store.audit.at(-1)?.traceId, r.traceId);
});

test("a passkey reader works, and a passkey without user verification does not", async () => {
  const pk = setup({ reader: passkeySigner("nurse-kim") });
  const row = await pk.service.seal("patients", "p1", "x");
  assert.ok((await pk.service.release(pk.ask(row), row)).ok);

  const tap = setup({ reader: passkeySigner("nurse-kim", "pk", { flags: 0x01 }) });
  const row2 = await tap.service.seal("patients", "p1", "x");
  assert.equal((await tap.service.release(tap.ask(row2), row2)).ok, false);
});

test("values can't be swapped between rows or moved to another collection", async () => {
  const s = setup({ mandate: { collections: ["patients", "staff"] } });
  const a = await s.service.seal("patients", "p1", "A");
  const b = await s.service.seal("patients", "p2", "B");
  const r = await s.service.release(s.ask(a), a);
  assert.ok(r.ok);
  // B's ciphertext pasted into A's row: A's key doesn't open it.
  assert.throws(() => openRecordText({ ...a, iv: b.iv, ciphertext: b.ciphertext }, r.recordKey), DataEnvelopeError);
  // A's row relabeled as another record or collection: the key service won't unwrap it.
  for (const moved of [{ ...a, recordId: "p9" }, { ...a, collection: "staff" }]) {
    const res = await s.service.release(s.ask(moved), moved);
    assert.equal(res.ok, false);
    assert.equal(!res.ok && res.reason, "key_unavailable");
  }
  // A request for one record can't be used on another.
  const res = await s.service.release(s.ask(a, { recordId: "p2" }), a);
  assert.equal(!res.ok && res.reason, "record_mismatch");
});

test("only the reader's enrolled device can sign", async () => {
  const s = setup();
  const row = await s.service.seal("patients", "p1", "x");
  const stranger = ed25519Signer("dr-lee", "dr-lee-phone"); // same ids, different key
  assert.equal((await s.service.release(s.ask(row, { device: stranger }), row) as { reason: string }).reason, "signature_invalid");
  const unsigned = s.ask(row);
  unsigned.signature = "";
  assert.equal((await s.service.release(unsigned, row) as { reason: string }).reason, "signature_invalid");
  s.store.readerKeys.get("dr-lee\u0000dr-lee-phone")!.revokedAt = new Date();
  assert.equal((await s.service.release(s.ask(row), row) as { reason: string }).reason, "signature_invalid");
});

test("requests can't be replayed or used late", async () => {
  const s = setup();
  const row = await s.service.seal("patients", "p1", "x");
  const req = s.ask(row);
  assert.ok((await s.service.release(req, row)).ok);
  assert.equal((await s.service.release(req, row) as { reason: string }).reason, "request_replayed");
  const late = s.ask(row);
  s.advance(3 * 60_000);
  assert.equal((await s.service.release(late, row) as { reason: string }).reason, "request_expired");
});

test("the mandate decides collection, purpose, expiry and revocation", async () => {
  const s = setup();
  const row = await s.service.seal("patients", "p1", "x");
  assert.equal((await s.service.release(s.ask(row, { purpose: "marketing" }), row) as { reason: string }).reason, "mandate_mismatch");
  const staff = await s.service.seal("staff", "s1", "x");
  assert.equal((await s.service.release(s.ask(staff), staff) as { reason: string }).reason, "mandate_mismatch");
  assert.equal((await s.service.release(s.ask(row, { mandateId: "rm_unknown" }), row) as { reason: string }).reason, "mandate_invalid");
  s.store.revokeMandate(s.mandate.mandateId);
  assert.equal((await s.service.release(s.ask(row), row) as { reason: string }).reason, "mandate_invalid");

  const e = setup();
  const row2 = await e.service.seal("patients", "p1", "x");
  e.advance(31 * 86_400_000);
  assert.equal((await e.service.release(e.ask(row2), row2) as { reason: string }).reason, "mandate_invalid");
});

test("a reader can't grant themselves a mandate, even if listed as an authority", async () => {
  const s = setup();
  // Misconfiguration: the reader's own key is also an authority. Self-grants are still refused.
  const service = new DataKeyService({ store: s.store, authorities: [s.admin.key, s.reader.key], keyring: softwareDataKeyring(randomBytes(32)), now: s.clock });
  const self: ReadMandate = { ...s.mandate, mandateId: newId("rm"), maxPerHour: 1_000_000, maxPerDay: 1_000_000 };
  s.store.addMandate({ mandate: self, keyId: s.reader.key.keyId, ...s.reader.prove(readMandateChallenge(self)) });
  const row = await service.seal("patients", "p1", "x");
  assert.equal((await service.release(s.ask(row, { mandateId: self.mandateId }), row) as { reason: string }).reason, "mandate_invalid");
});

test("a mandate edited after signing, or signed by a key that isn't a configured authority, is refused", async () => {
  const s = setup();
  const row = await s.service.seal("patients", "p1", "x");
  const outsider = ed25519Signer("it-admin");
  const rogue: ReadMandate = { ...s.mandate, mandateId: newId("rm") };
  s.store.addMandate({ mandate: rogue, keyId: outsider.key.keyId, ...outsider.prove(readMandateChallenge(rogue)) });
  assert.equal((await s.service.release(s.ask(row, { mandateId: rogue.mandateId }), row) as { reason: string }).reason, "mandate_invalid");

  const stored = s.store.mandates.get(s.mandate.mandateId)!;
  stored.signed = { ...stored.signed, mandate: { ...stored.signed.mandate, maxPerHour: 999, maxPerDay: 999 } };
  assert.equal((await s.service.release(s.ask(row), row) as { reason: string }).reason, "mandate_invalid");
});

test("swapping the reader's enrolled key for another doesn't work: the mandate pins the key", async () => {
  const s = setup();
  const row = await s.service.seal("patients", "p1", "x");
  const impostor = ed25519Signer("dr-lee", "dr-lee-phone");
  s.store.addReaderKey(impostor.key); // overwrites the real key in the table
  assert.equal((await s.service.release(s.ask(row, { device: impostor }), row) as { reason: string }).reason, "mandate_invalid");
});

test("hourly and daily budgets cap reads", async () => {
  const s = setup({ mandate: { maxPerHour: 3, maxPerDay: 5 } });
  const rows = await Promise.all(Array.from({ length: 10 }, (_, i) => s.service.seal("patients", `p${i}`, `v${i}`)));
  const reasons: string[] = [];
  for (const row of rows.slice(0, 4)) {
    const r = await s.service.release(s.ask(row), row);
    reasons.push(r.ok ? "ok" : r.reason);
  }
  assert.deepEqual(reasons, ["ok", "ok", "ok", "limit_hourly"]);
  s.advance(61 * 60_000);
  for (const row of rows.slice(4, 7)) {
    const r = await s.service.release(s.ask(row), row);
    reasons.push(r.ok ? "ok" : r.reason);
  }
  assert.deepEqual(reasons.slice(4), ["ok", "ok", "limit_daily"]);
});

test("touching a decoy freezes the reader and raises an alert", async () => {
  const s = setup();
  const real = await s.service.seal("patients", "p1", "real");
  const decoy = await s.service.seal("patients", "p-decoy", "nothing here");
  s.store.plantDecoy("patients", "p-decoy");
  const r = await s.service.release(s.ask(decoy), decoy);
  assert.equal(!r.ok && r.reason, "denied");
  assert.equal(s.alerts.length, 1);
  assert.equal(s.alerts[0]?.readerId, "dr-lee");
  assert.equal((await s.service.release(s.ask(real), real) as { reason: string }).reason, "reader_frozen");
});

test("a keyring fault releases nothing", async () => {
  const keyring = remoteDataKeyring({
    description: "kms",
    wrap: async (key) => ({ kekId: "kms-1", wrapped: key.slice() }),
    unwrap: async () => {
      throw new Error("KMS unavailable");
    },
  });
  const s = setup({ keyring });
  const row = await s.service.seal("patients", "p1", "x");
  const r = await s.service.release(s.ask(row), row);
  assert.equal(!r.ok && r.reason, "key_unavailable");

  const short = remoteDataKeyring({ description: "kms", wrap: async (k) => ({ kekId: "k", wrapped: k }), unwrap: async () => new Uint8Array(5) });
  const s2 = setup({ keyring: short });
  const row2 = await s2.service.seal("patients", "p1", "x");
  assert.equal((await s2.service.release(s2.ask(row2), row2) as { reason: string }).reason, "key_unavailable");
});

test("garbage input is refused and audited, never thrown", async () => {
  const s = setup();
  const row = await s.service.seal("patients", "p1", "x");
  for (const bad of [null, {}, { request: { v: 2 } }, { request: "x" }] as unknown as SignedReadRequest[]) {
    const r = await s.service.release(bad, row);
    assert.equal(!r.ok && r.reason, "request_invalid");
  }
  assert.equal((await s.service.release(s.ask(row), { ...row, v: 9 } as unknown as SealedRecord) as { reason: string }).reason, "request_invalid");
  assert.ok(s.store.audit.every((e) => e.outcome === "refused" && e.traceId.startsWith("tr_")));
});

test("software keyring refuses short secrets", () => {
  assert.throws(() => softwareDataKeyring("too short"));
});
