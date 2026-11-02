import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  MemoryPayEnvelopeStore,
  MemoryPayerKeyStore,
  PayEnvelopeIntentError,
  PayEnvelopeService,
  p256PublicKeyFromSpki,
  verifyReceipt,
  verifySignedIntent,
} from "../src/index.js";
import { payerKeyStoreConformance } from "../src/testing/index.js";
import { RP, ed25519Device, hybridDevice, intentFor, passkeyDevice } from "./helpers/customer-device.js";

const secrets = { hmac: "h".repeat(64), jws: "j".repeat(64) };
const owner = { userId: "integrator", payKeyId: "key_live" };
const req = { merchantId: "coffee-co", amount: 450, currency: "USD", channel: "CNP" };

function setup(now = () => new Date()) {
  const payerKeys = new MemoryPayerKeyStore();
  const store = new MemoryPayEnvelopeStore();
  const service = new PayEnvelopeService({ store, secrets, payerKeys, webauthn: RP, now });
  return { payerKeys, store, service };
}

const rejects = (p: Promise<unknown>, code: string) =>
  assert.rejects(p, (e: unknown) => e instanceof PayEnvelopeIntentError && e.code === code);

for (const [name, make] of [
  ["native app key (Ed25519)", ed25519Device],
  ["post-quantum hybrid key (Ed25519 + ML-DSA-65)", hybridDevice],
  ["passkey (WebAuthn ES256)", passkeyDevice],
] as const) {
  test(`${name}: a signed approval creates exactly that credential, with the approval in the receipt`, async () => {
    const { payerKeys, service } = setup();
    const device = make("alice");
    payerKeys.add(device.key);
    const si = device.sign(intentFor("alice"));
    const env = await service.create(req, owner, { signedIntent: si, requireCustomerSignature: true });
    const claims = verifyReceipt(secrets.jws, env.receiptJws)!;
    assert.deepEqual(claims.customerApproval, si);
    // Anyone can re-check the customer's signature from the receipt, without trusting SPIN.
    assert.equal(verifySignedIntent(claims.customerApproval as typeof si, device.key, RP), true);
    assert.equal(
      (await service.resolve({ presentation: env.presentation, txnContext: req }, { callerMerchantId: "coffee-co" })).decision,
      "APPROVE",
    );
  });
}

test("hybrid: both halves must verify (a broken ML-DSA half fails even if Ed25519 is fine)", () => {
  const d = hybridDevice("alice");
  const si = d.sign(intentFor("alice"));
  const [ed, pq] = si.signature.split(".");
  const badPq = Buffer.from(pq!, "base64url");
  badPq[10] = badPq[10]! ^ 1;
  assert.equal(verifySignedIntent({ ...si, signature: `${ed}.${badPq.toString("base64url")}` }, d.key), false);
});

test("passkey: wrong origin, wrong rpId, or no user verification are rejected", () => {
  const d = passkeyDevice("alice");
  const i = intentFor("alice");
  assert.equal(verifySignedIntent(d.signWith(i, {}), d.key, RP), true);
  assert.equal(verifySignedIntent(d.signWith(i, { origin: "https://evil.example" }), d.key, RP), false);
  assert.equal(verifySignedIntent(d.signWith(i, { rpId: "evil.example" }), d.key, RP), false);
  assert.equal(verifySignedIntent(d.signWith(i, { flags: 0x01 }), d.key, RP), false, "user present but not verified");
  assert.equal(verifySignedIntent(d.signWith(i, { type: "webauthn.create" }), d.key, RP), false);
  assert.equal(verifySignedIntent(d.signWith(i, {}), d.key, undefined), false, "no WebAuthn policy configured");
});

test("Secure Payment Confirmation: the total the browser showed must be the approved amount", () => {
  const d = passkeyDevice("alice");
  const i = intentFor("alice"); // 450 USD
  assert.equal(verifySignedIntent(d.signWith(i, { type: "payment.get", total: { currency: "USD", value: "4.50" } }), d.key, RP), true);
  assert.equal(verifySignedIntent(d.signWith(i, { type: "payment.get", total: { currency: "USD", value: "4500.00" } }), d.key, RP), false);
  assert.equal(verifySignedIntent(d.signWith(i, { type: "payment.get", total: { currency: "EUR", value: "4.50" } }), d.key, RP), false);
  assert.equal(verifySignedIntent(d.signWith(i, { type: "payment.get" }), d.key, RP), false, "no total shown");
});

test("enrollment helper: a browser's SPKI passkey key converts to the stored form", () => {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const spki = publicKey.export({ type: "spki", format: "der" });
  const raw = p256PublicKeyFromSpki(spki);
  assert.equal(Buffer.from(raw!, "base64url").length, 65);
  const ed = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "der" });
  assert.equal(p256PublicKeyFromSpki(ed), null);
});

test("required: no signed intent, nothing created", async () => {
  const { store, service } = setup();
  await rejects(service.create(req, owner, { requireCustomerSignature: true }), "intent_required");
  assert.equal(store.envelopes.size, 0);
  // Not required (e.g. test keys): unchanged behaviour.
  await service.create(req, owner);
  assert.equal(store.envelopes.size, 1);
});

test("the request must match the approval exactly", async () => {
  const { payerKeys, service } = setup();
  const d = ed25519Device("alice");
  payerKeys.add(d.key);
  for (const change of [
    { amount: 451 },
    { merchantId: "m_other" },
    { currency: "EUR" },
    { channel: "CP" },
    { channel: undefined },
    { amountTolerance: 0.05 },
  ]) {
    await rejects(service.create({ ...req, ...change }, owner, { signedIntent: d.sign(intentFor("alice")) }), "intent_mismatch");
  }
});

test("a rejected request doesn't use up the approval; a used one can't be reused", async () => {
  const { payerKeys, service } = setup();
  const d = ed25519Device("alice");
  payerKeys.add(d.key);
  const si = d.sign(intentFor("alice"));
  await rejects(service.create({ ...req, amount: 999 }, owner, { signedIntent: si }), "intent_mismatch");
  await service.create(req, owner, { signedIntent: si });
  await rejects(service.create(req, owner, { signedIntent: si }), "intent_replayed");
});

test("expiry: past or too-distant approvals are rejected; the credential can't outlive the approval", async () => {
  const now = new Date("2026-11-02T12:00:00Z");
  const { payerKeys, service } = setup(() => now);
  const d = ed25519Device("alice");
  payerKeys.add(d.key);
  const at = (s: number) => new Date(now.getTime() + s * 1000).toISOString();
  await rejects(service.create(req, owner, { signedIntent: d.sign(intentFor("alice", { expiresAt: at(-1) }, now)) }), "intent_expired");
  await rejects(service.create(req, owner, { signedIntent: d.sign(intentFor("alice", { expiresAt: at(2 * 3600) }, now)) }), "intent_invalid");
  const env = await service.create({ ...req, ttlSeconds: 3600 }, owner, { signedIntent: d.sign(intentFor("alice", { expiresAt: at(120) }, now)) });
  assert.equal(env.expiresAt, at(120));
});

test("unknown, revoked, or another customer's key is rejected", async () => {
  const { payerKeys, service } = setup();
  const alice = ed25519Device("alice");
  const bob = ed25519Device("bob", "bobs-phone");
  payerKeys.add(alice.key);
  payerKeys.add(bob.key);
  // Bob's key signing an approval that claims to be Alice's.
  const forged = { ...bob.sign(intentFor("alice")), keyId: "bobs-phone" };
  await rejects(service.create(req, owner, { signedIntent: forged }), "intent_invalid");
  await rejects(service.create(req, owner, { signedIntent: { ...alice.sign(intentFor("alice")), keyId: "nope" } }), "intent_invalid");
  payerKeys.revoke("alice", "phone-1");
  await rejects(service.create(req, owner, { signedIntent: alice.sign(intentFor("alice")) }), "intent_invalid");
});

test("malformed input is invalid, never a crash; servers without a key store refuse", async () => {
  const { service } = setup();
  for (const bad of [{}, { intent: { v: 2 } }, { intent: null, keyId: 1, signature: 2 }]) {
    await rejects(service.create(req, owner, { signedIntent: bad as never }), "intent_invalid");
  }
  const plain = new PayEnvelopeService({ store: new MemoryPayEnvelopeStore(), secrets });
  const d = ed25519Device("alice");
  await rejects(plain.create(req, owner, { signedIntent: d.sign(intentFor("alice")) }), "intent_invalid");
});

test("idempotent retry of an approved request returns the same credential", async () => {
  const { payerKeys, service } = setup();
  const d = ed25519Device("alice");
  payerKeys.add(d.key);
  const si = d.sign(intentFor("alice"));
  const a = await service.create({ ...req, idempotencyKey: "order-9" }, owner, { signedIntent: si });
  const b = await service.create({ ...req, idempotencyKey: "order-9" }, owner, { signedIntent: si });
  assert.equal(b.envelopeId, a.envelopeId);
});

// The in-memory store passes the conformance suite apps must pass.
for (const c of payerKeyStoreConformance({
  makeStore: () => new MemoryPayerKeyStore(),
  addKey: async (s, k) => (s as MemoryPayerKeyStore).add(k),
  revokeKey: async (s, p, k, at) => (s as MemoryPayerKeyStore).revoke(p, k, at),
})) {
  test(`conformance (memory): ${c.name}`, c.run);
}

test("adding a device: an existing device's approval covers exactly that new key", async () => {
  const { generateKeyPairSync: gen, sign: nodeSign } = await import("node:crypto");
  const { enrollmentChallenge, verifyKeySignature } = await import("../src/index.js");
  const existing = gen("ed25519");
  const existingKey = {
    payerId: "alice",
    keyId: "phone-1",
    scheme: "ed25519" as const,
    publicKey: existing.publicKey.export({ type: "spki", format: "der" }).toString("base64url"),
    revokedAt: null,
  };
  const newPasskey = passkeyDevice("alice", "laptop");
  const enrollment = {
    v: 1 as const,
    payerId: "alice",
    newKey: { keyId: "laptop", scheme: newPasskey.key.scheme, publicKey: newPasskey.key.publicKey },
    expiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
    nonce: "enroll-0123456789abcdef",
  };
  const sig = nodeSign(null, enrollmentChallenge(enrollment), existing.privateKey).toString("base64url");
  assert.equal(verifyKeySignature(existingKey, enrollmentChallenge(enrollment), { signature: sig }), true);
  // Swapping in the attacker's key invalidates the approval.
  const attacker = ed25519Device("alice", "laptop");
  const swapped = { ...enrollment, newKey: { ...enrollment.newKey, publicKey: attacker.key.publicKey } };
  assert.equal(verifyKeySignature(existingKey, enrollmentChallenge(swapped), { signature: sig }), false);
  // An intent signature can't be passed off as an enrollment approval (different domain).
  const si = ed25519Device("alice").sign(intentFor("alice"));
  assert.equal(verifyKeySignature(existingKey, enrollmentChallenge(enrollment), { signature: si.signature }), false);
});
