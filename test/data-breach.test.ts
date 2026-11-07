/**
 * Breach test for SPIN Envelope for Data, modeled on the BOSSAI campaign
 * (Acronis TRU, Nov 2026): patient records reached through an open port,
 * account tables pulled by SQL injection, admin access through default
 * passwords and session secrets left in page code.
 *
 * The attacker gets, in escalating order:
 *   1. a full copy of the database: every sealed row, mandate, reader public
 *      key and audit event (SQL injection, open port, stolen backup);
 *   2. the app server: it can call the key service as often as it likes and
 *      replay every signed request it has ever relayed;
 *   3. worst case, a real doctor's unlocked phone, signing whatever it's told,
 *      run by an agent told to "extract all patient data".
 *
 * Required: (1) and (2) read nothing. (3) reads at most the mandate's hourly
 * budget, and less if it touches a decoy, which freezes it and raises an
 * alert. A positive control shows a legitimate reader still reads.
 *
 * Known limits, stated rather than hidden:
 *   - what a legitimate reader is allowed to read, they can see. The budget
 *     bounds it; nothing removes it.
 *   - in (2) the attacker also writes the key service's tables. That can't
 *     add access (authorities are configuration; mandates pin keys), but it
 *     could undo revocations, freezes and read counts. Keep that store on the
 *     key service's own database.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import {
  DataEnvelopeError,
  DataKeyService,
  MemoryDataAccessStore,
  b64u,
  dataKeyFingerprint,
  newId,
  newReadRequest,
  openRecordText,
  readMandateChallenge,
  readRequestChallenge,
  softwareDataKeyring,
  type DataAlert,
  type ReadMandate,
  type SealedRecord,
  type SignedReadRequest,
} from "../src/data/index.js";
import { RP, ed25519Signer, passkeySigner, type SigningDevice } from "./helpers/data-device.js";

const PATIENTS = 1_000;
const PER_HOUR = 20;

async function hospital() {
  let now = new Date("2026-11-07T08:00:00Z");
  const clock = () => now;
  const store = new MemoryDataAccessStore(clock);
  const alerts: DataAlert[] = [];
  // The privacy officer's passkey is the only authority, configured with the key service at deploy time.
  const admin = passkeySigner("privacy-officer");
  // The wrapping key lives with the key service (KMS/HSM in production), never in the app or database.
  const service = new DataKeyService({ store, authorities: [admin.key], keyring: softwareDataKeyring(randomBytes(32)), webauthn: RP, now: clock, onAlert: (a) => void alerts.push(a) });

  const grant = (reader: SigningDevice, over: Partial<ReadMandate> = {}) => {
    const mandate: ReadMandate = {
      v: 1,
      mandateId: newId("rm"),
      readerId: reader.key.ownerId,
      readerKeyId: reader.key.keyId,
      readerKeyFingerprint: dataKeyFingerprint(reader.key),
      collections: ["patients"],
      purposes: ["treatment"],
      maxPerHour: PER_HOUR,
      maxPerDay: 100,
      expiresAt: new Date(now.getTime() + 90 * 86_400_000).toISOString(),
      ...over,
    };
    store.addReaderKey(reader.key);
    store.addMandate({ mandate, keyId: admin.key.keyId, ...admin.prove(readMandateChallenge(mandate)) });
    return mandate;
  };

  const rows: SealedRecord[] = [];
  const secrets: string[] = [];
  for (let i = 0; i < PATIENTS; i++) {
    const secret = `patient-${i} | ECG 72bpm | SSN 900-${String(i).padStart(2, "0")}-${String(1000 + i)} | 12 Main St`;
    secrets.push(secret);
    rows.push(await service.seal("patients", `p${i}`, secret));
  }
  // Decoys scattered through the table. No real workflow reads them.
  for (const i of [3, 250, 777]) store.plantDecoy("patients", `p${i}`);

  const signedBy = (device: SigningDevice, mandateId: string, row: SealedRecord, purpose = "treatment"): SignedReadRequest => {
    const request = newReadRequest({ readerId: device.key.ownerId, keyId: device.key.keyId, mandateId, collection: row.collection, recordId: row.recordId, purpose, now });
    return { request, ...device.prove(readRequestChallenge(request)) };
  };

  return { store, service, alerts, rows, secrets, grant, signedBy, advance: (ms: number) => (now = new Date(now.getTime() + ms)) };
}

test("1. a full copy of the database reads nothing", async () => {
  const h = await hospital();
  const doctor = ed25519Signer("dr-chen");
  const m = h.grant(doctor);
  // Some normal activity, so the copy includes mandates and audit history.
  for (const i of [10, 11, 12]) assert.ok((await h.service.release(h.signedBy(doctor, m.mandateId, h.rows[i]!), h.rows[i]!)).ok);

  const dump = JSON.stringify({ rows: h.rows, mandates: [...h.store.mandates.values()], keys: [...h.store.readerKeys.values()], audit: h.store.audit });
  for (const s of h.secrets) {
    assert.ok(!dump.includes(s), "plaintext in the dump");
  }
  // Phrases with spaces: base64url ciphertext can't contain them by chance.
  assert.ok(!/ECG 72bpm|SSN 900-|12 Main St/.test(dump), "plaintext fragments in the dump");

  // Offline guessing at record keys: hopeless (2^256), but show that wrong keys fail rather than garble.
  let opened = 0;
  for (const row of h.rows.slice(0, 200)) {
    try {
      openRecordText(row, b64u.encode(randomBytes(32)));
      opened++;
    } catch (e) {
      assert.ok(e instanceof DataEnvelopeError);
    }
  }
  assert.equal(opened, 0);
});

test("2. the app server, with the key service on tap and every past request, reads nothing", async () => {
  const h = await hospital();
  const doctor = ed25519Signer("dr-chen");
  const m = h.grant(doctor);
  // Requests the server relayed earlier today.
  const captured: [SignedReadRequest, SealedRecord][] = [];
  for (const i of [20, 21, 22]) {
    const req = h.signedBy(doctor, m.mandateId, h.rows[i]!);
    assert.ok((await h.service.release(req, h.rows[i]!)).ok);
    captured.push([req, h.rows[i]!]);
  }
  h.advance(10_000);

  const attacker = ed25519Signer("dr-chen", "dr-chen-phone"); // same names, attacker's own key
  let released = 0;
  const attempts: [SignedReadRequest, SealedRecord][] = [];
  // Replays, and replays retargeted at other rows.
  for (const [req, row] of captured) {
    attempts.push([req, row]);
    attempts.push([req, h.rows[500]!]);
    attempts.push([{ ...req, request: { ...req.request, recordId: "p500" } }, h.rows[500]!]);
  }
  for (const row of h.rows.slice(100, 400)) {
    // Signed with the attacker's own key, posing as the doctor.
    attempts.push([h.signedBy(attacker, m.mandateId, row), row]);
    // Unsigned.
    const unsigned = h.signedBy(doctor, m.mandateId, row);
    attempts.push([{ ...unsigned, signature: "" }, row]);
  }
  // The server writes to the key tables: replaces the doctor's enrolled key with its own...
  h.store.addReaderKey(attacker.key);
  for (const row of h.rows.slice(450, 500)) attempts.push([h.signedBy(attacker, m.mandateId, row), row]);
  // ...and plants mandates of its own: one claiming the privacy officer's key, one signed by a key it made up.
  const fakeAdmin = ed25519Signer("fake-admin");
  for (const keyId of ["privacy-officer-passkey", fakeAdmin.key.keyId]) {
    const forged: ReadMandate = { ...m, mandateId: newId("rm"), readerKeyFingerprint: dataKeyFingerprint(attacker.key), maxPerHour: 1_000_000, maxPerDay: 1_000_000 };
    h.store.addMandate({ mandate: forged, keyId, ...fakeAdmin.prove(readMandateChallenge(forged)) });
    for (const row of h.rows.slice(400, 450)) attempts.push([h.signedBy(attacker, forged.mandateId, row), row]);
  }
  // ...and raises the real mandate's limits in place.
  const real = h.store.mandates.get(m.mandateId)!;
  real.signed = { ...real.signed, mandate: { ...real.signed.mandate, maxPerHour: 1_000_000, readerKeyFingerprint: dataKeyFingerprint(attacker.key) } };
  for (const row of h.rows.slice(500, 550)) attempts.push([h.signedBy(attacker, m.mandateId, row), row]);

  for (const [req, row] of attempts) if ((await h.service.release(req, row)).ok) released++;
  assert.equal(released, 0, `${released} of ${attempts.length} attacks released a key`);
});

test("3. a stolen, unlocked doctor's phone driven by an extraction agent gets a handful at most, then is frozen", async () => {
  const h = await hospital();
  const doctor = ed25519Signer("dr-chen");
  const m = h.grant(doctor);

  // "extract all patient data": walk the whole table, as fast as allowed, all day.
  const stolen: string[] = [];
  let lastReason = "";
  for (let hour = 0; hour < 24; hour++) {
    for (const row of h.rows) {
      const r = await h.service.release(h.signedBy(doctor, m.mandateId, row), row);
      if (r.ok) stolen.push(openRecordText(row, r.recordKey));
      else lastReason = r.reason;
      if (lastReason === "reader_frozen") break;
    }
    if (lastReason === "reader_frozen") break;
    h.advance(3_600_000);
  }
  // The walk hits decoy p3 after three real records: frozen, alerted, done.
  assert.ok(stolen.length <= PER_HOUR, `stole ${stolen.length}`);
  assert.equal(stolen.length, 3);
  assert.equal(lastReason, "reader_frozen");
  assert.equal(h.alerts.length, 1);
  assert.equal(h.alerts[0]?.recordId, "p3");

  // Without decoys, the hourly budget is the ceiling.
  const h2 = await hospital();
  for (const i of [3, 250, 777]) h2.store.decoys.delete(`patients\u0000p${i}`);
  const doc2 = ed25519Signer("dr-chen");
  const m2 = h2.grant(doc2);
  let got = 0;
  for (const row of h2.rows) if ((await h2.service.release(h2.signedBy(doc2, m2.mandateId, row), row)).ok) got++;
  assert.equal(got, PER_HOUR, "one hour of walking the table yields exactly the hourly budget");
  assert.ok(h2.store.audit.filter((e) => e.reason === "limit_hourly").length >= PATIENTS - PER_HOUR, "every refusal is on record");
});

test("positive control: a legitimate reader still reads, for the stated purpose", async () => {
  const h = await hospital();
  const nurse = passkeySigner("nurse-ortiz");
  const m = h.grant(nurse);
  const row = h.rows[42]!;
  const r = await h.service.release(h.signedBy(nurse, m.mandateId, row), row);
  assert.ok(r.ok);
  assert.equal(openRecordText(row, r.recordKey), h.secrets[42]);
  // The same nurse, the same record, a purpose she wasn't granted: refused.
  const r2 = await h.service.release(h.signedBy(nurse, m.mandateId, row, "research"), row);
  assert.equal(!r2.ok && r2.reason, "mandate_mismatch");
});
