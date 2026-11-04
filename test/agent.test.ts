/**
 * AI agents: an agent's key (P-256, as cloud key services sign) may create a
 * card number only under a mandate a person signed on their own device, and
 * only within it. The "hijacked agent" cases are a breach test: an attacker
 * who fully controls the agent and its key still can't leave the mandate.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes, sign as nodeSign } from "node:crypto";
import { p256 } from "@noble/curves/nist.js";
import {
  MemoryMandateStore,
  MemoryPayEnvelopeStore,
  MemoryPayerKeyStore,
  PayEnvelopeIntentError,
  PayEnvelopeService,
  canonicalIntent,
  enrollmentChallenge,
  intentChallenge,
  mandateChallenge,
  verifyReceipt,
  verifySignedIntent,
  verifySignedMandate,
  type CustomerIntent,
  type Mandate,
  type PayerKey,
  type SignedIntent,
  type SignedMandate,
} from "../src/index.js";
import { mandateStoreConformance } from "../src/testing/index.js";
import {
  approveMandate,
  describeMandate,
  mandateChallenge as kitMandateChallenge,
  newIntent,
  newMandate,
} from "../src/approval/index.js";

const secrets = { hmac: "h".repeat(64), jws: "j".repeat(64) };
const b64u = (b: Uint8Array | Buffer) => Buffer.from(b).toString("base64url");

/** A person's phone (Ed25519). */
function phone(payerId: string, keyId = "phone") {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const key: PayerKey = { payerId, keyId, scheme: "ed25519", publicKey: publicKey.export({ format: "der", type: "spki" }).toString("base64url"), revokedAt: null };
  const signBytes = (c: Uint8Array) => b64u(nodeSign(null, c, privateKey));
  return { key, signBytes };
}

/** An AI agent's key, P-256, as AWS KMS ECC_NIST_P256 signs (DER, over SHA-256 of the challenge). */
function agent(payerId: string, keyId = "agent-1") {
  const priv = p256.utils.randomSecretKey();
  const key: PayerKey = { payerId, keyId, scheme: "ecdsa-p256", publicKey: b64u(p256.getPublicKey(priv, false)), revokedAt: null, role: "agent" };
  const signBytes = (c: Uint8Array, format: "der" | "compact" = "der") => b64u(p256.sign(c, priv, { format }));
  const buy = (i: CustomerIntent, format: "der" | "compact" = "der"): SignedIntent => ({ intent: i, keyId, signature: signBytes(intentChallenge(i), format) });
  return { key, signBytes, buy };
}

function setup() {
  const payerKeys = new MemoryPayerKeyStore();
  const mandates = new MemoryMandateStore();
  const service = new PayEnvelopeService({ store: new MemoryPayEnvelopeStore(), secrets, payerKeys, mandates });
  const person = phone("alice");
  const bot = agent("alice");
  payerKeys.add(person.key);
  payerKeys.add(bot.key);
  const rule = (over: Partial<Mandate> = {}): SignedMandate => {
    const mandate: Mandate = {
      v: 1, payerId: "alice", agentKeyId: "agent-1", merchants: ["coffee-co", "books-co"], currency: "USD",
      maxPerPurchase: 2_000, maxPerDay: 5_000, channel: "CNP",
      expiresAt: new Date(Date.now() + 30 * 86_400_000).toISOString(), nonce: `mandate-${randomBytes(8).toString("hex")}`, ...over,
    };
    return { mandate, keyId: "phone", signature: person.signBytes(mandateChallenge(mandate)) };
  };
  const purchase = (m: SignedMandate, over: Partial<CustomerIntent> = {}): CustomerIntent => ({
    ...newIntent({ payerId: "alice", merchantId: "coffee-co", amount: 1_000, currency: "USD", channel: "CNP", mandateId: m.mandate.nonce }),
    ...over,
  });
  const create = (si: SignedIntent) =>
    service.create({ merchantId: si.intent.merchantId, amount: si.intent.amount, currency: si.intent.currency, channel: si.intent.channel ?? undefined }, { userId: "u", payKeyId: "k" }, { signedIntent: si, requireCustomerSignature: true });
  return { payerKeys, mandates, service, person, bot, rule, purchase, create };
}

const rejects = (p: Promise<unknown>, code: string) =>
  assert.rejects(p, (e: unknown) => e instanceof PayEnvelopeIntentError && e.code === code);

test("an agent's P-256 key (DER or compact signatures) signs purchases that verify; another key's don't", () => {
  const bot = agent("alice");
  const other = agent("alice", "agent-2");
  const i = newIntent({ payerId: "alice", merchantId: "coffee-co", amount: 450, currency: "USD", mandateId: "mandate-0123456789ab" });
  assert.equal(verifySignedIntent(bot.buy(i), bot.key), true);
  assert.equal(verifySignedIntent(bot.buy(i, "compact"), bot.key), true);
  assert.equal(verifySignedIntent({ ...bot.buy(i), keyId: "agent-1" }, other.key), false);
  assert.equal(verifySignedIntent({ ...bot.buy(i), intent: { ...i, amount: 4500 } }, bot.key), false, "the mandate id and amount are covered");
});

test("an approval to add an agent key can't be used to add it as a full device, and device enrollments keep their bytes", () => {
  const e = { v: 1 as const, payerId: "alice", newKey: { keyId: "agent-1", scheme: "ecdsa-p256" as const, publicKey: "pk", role: "agent" as const }, expiresAt: new Date(Date.now() + 60_000).toISOString(), nonce: "enroll-0123456789abcdef" };
  const { role: _r, ...asDevice } = e.newKey;
  assert.notDeepEqual(enrollmentChallenge(e), enrollmentChallenge({ ...e, newKey: asDevice }));
  const device = { ...e, newKey: { keyId: "phone-2", scheme: "ed25519" as const, publicKey: "pk" } };
  const expected = new Uint8Array(createHash("sha256").update("spin/enroll-device/v1\n" + JSON.stringify([1, "alice", "phone-2", "ed25519", "pk", device.expiresAt, device.nonce]), "utf8").digest());
  assert.deepEqual(enrollmentChallenge(device), expected);
});

test("intents without a mandate keep their original bytes, so existing approvals still verify", () => {
  const i = newIntent({ payerId: "alice", merchantId: "coffee-co", amount: 450, currency: "USD" });
  assert.equal(canonicalIntent(i), JSON.stringify([i.v, i.payerId, i.merchantId, i.amount, i.currency, i.channel, i.expiresAt, i.nonce]));
  assert.ok(!("mandateId" in i));
});

test("an agent buys within its mandate: card number created, approval in the receipt", async () => {
  const s = setup();
  const m = s.rule();
  s.mandates.add(m);
  const si = s.bot.buy(s.purchase(m));
  const out = await s.create(si);
  assert.match(out.presentation.pan, /^\d{16}$/);
  assert.deepEqual((verifyReceipt(secrets.jws, out.receiptJws) as unknown as { customerApproval: unknown }).customerApproval, si);
});

test("hijacked agent: no mandate, another merchant, too much, another currency or channel: nothing created", async () => {
  const s = setup();
  const m = s.rule();
  s.mandates.add(m);
  const { mandateId: _, ...noMandate } = s.purchase(m);
  await rejects(s.create(s.bot.buy(noMandate as CustomerIntent)), "mandate_required");
  await rejects(s.create(s.bot.buy(s.purchase(m, { merchantId: "thief-shop" }))), "mandate_mismatch");
  await rejects(s.create(s.bot.buy(s.purchase(m, { amount: 2_001 }))), "mandate_mismatch");
  await rejects(s.create(s.bot.buy(s.purchase(m, { currency: "EUR" }))), "mandate_mismatch");
  await rejects(s.create(s.bot.buy(s.purchase(m, { channel: "CP" }))), "mandate_mismatch");
  await rejects(s.create(s.bot.buy(s.purchase(m, { mandateId: "mandate-not-real-0123" }))), "mandate_invalid");
});

test("hijacked agent: the 24-hour cap holds, including against 20 simultaneous purchases", async () => {
  const s = setup();
  const m = s.rule();
  s.mandates.add(m);
  assert.ok(await s.create(s.bot.buy(s.purchase(m, { amount: 2_000 }))));
  assert.ok(await s.create(s.bot.buy(s.purchase(m, { amount: 2_000 }))));
  await rejects(s.create(s.bot.buy(s.purchase(m, { amount: 2_000 }))), "mandate_limit");
  assert.ok(await s.create(s.bot.buy(s.purchase(m, { amount: 1_000 }))), "up to exactly the cap");

  const m2 = s.rule();
  s.mandates.add(m2);
  const results = await Promise.allSettled(Array.from({ length: 20 }, () => s.create(s.bot.buy(s.purchase(m2, { amount: 1_000 })))));
  assert.equal(results.filter((r) => r.status === "fulfilled").length, 5);
});

test("hijacked agent: replaying a purchase is refused, and doesn't use up the allowance", async () => {
  const s = setup();
  const m = s.rule({ maxPerDay: 2_000 });
  s.mandates.add(m);
  const si = s.bot.buy(s.purchase(m, { amount: 1_000 }));
  await s.create(si);
  await rejects(s.create(si), "intent_replayed");
  assert.ok(await s.create(s.bot.buy(s.purchase(m, { amount: 1_000 }))), "the replay's reservation was released");
});

test("a revoked, expired or other agent's mandate doesn't work", async () => {
  const s = setup();
  const revoked = s.rule();
  s.mandates.add(revoked);
  s.mandates.revoke("alice", revoked.mandate.nonce);
  await rejects(s.create(s.bot.buy(s.purchase(revoked))), "mandate_invalid");

  const expired = s.rule({ expiresAt: new Date(Date.now() - 1_000).toISOString() });
  s.mandates.add(expired);
  await rejects(s.create(s.bot.buy(s.purchase(expired))), "mandate_invalid");

  const short = s.rule({ expiresAt: new Date(Date.now() + 60_000).toISOString() });
  s.mandates.add(short);
  await rejects(s.create(s.bot.buy(s.purchase(short, { expiresAt: new Date(Date.now() + 120_000).toISOString() }))), "mandate_invalid");

  const other = agent("alice", "agent-2");
  s.payerKeys.add(other.key);
  const mine = s.rule();
  s.mandates.add(mine);
  await rejects(s.create(other.buy(s.purchase(mine))), "mandate_invalid");
});

test("forged mandates: signed by the agent itself, or edited after signing, don't work", async () => {
  const s = setup();
  const byAgent = s.rule();
  const selfGranted: SignedMandate = { ...byAgent, keyId: "agent-1", signature: s.bot.signBytes(mandateChallenge(byAgent.mandate)) };
  assert.equal(verifySignedMandate(selfGranted, s.bot.key), false);
  s.mandates.add(selfGranted);
  await rejects(s.create(s.bot.buy(s.purchase(selfGranted))), "mandate_invalid");

  const raised = s.rule();
  const edited: SignedMandate = { ...raised, mandate: { ...raised.mandate, maxPerPurchase: 1_000_000, maxPerDay: 1_000_000 } };
  s.mandates.add(edited);
  await rejects(s.create(s.bot.buy(s.purchase(edited, { amount: 500_000 }))), "mandate_invalid");
});

test("revoking the person's device that signed a mandate revokes the mandate", async () => {
  const s = setup();
  const m = s.rule();
  s.mandates.add(m);
  s.payerKeys.revoke("alice", "phone");
  await rejects(s.create(s.bot.buy(s.purchase(m))), "mandate_invalid");
});

test("a person's own device signs without a mandate, and may not claim one", async () => {
  const s = setup();
  const i = newIntent({ payerId: "alice", merchantId: "coffee-co", amount: 450, currency: "USD", channel: "CNP" });
  assert.ok(await s.create({ intent: i, keyId: "phone", signature: s.person.signBytes(intentChallenge(i)) }));
  const m = s.rule();
  s.mandates.add(m);
  const claimed = s.purchase(m);
  await rejects(s.create({ intent: claimed, keyId: "phone", signature: s.person.signBytes(intentChallenge(claimed)) }), "intent_invalid");
});

test("a server without a mandate store refuses every agent purchase", async () => {
  const payerKeys = new MemoryPayerKeyStore();
  const bot = agent("alice");
  payerKeys.add(bot.key);
  const service = new PayEnvelopeService({ store: new MemoryPayEnvelopeStore(), secrets, payerKeys });
  const i = newIntent({ payerId: "alice", merchantId: "coffee-co", amount: 450, currency: "USD", mandateId: "mandate-0123456789ab" });
  await rejects(
    service.create({ merchantId: "coffee-co", amount: 450, currency: "USD" }, { userId: "u", payKeyId: "k" }, { signedIntent: bot.buy(i) }),
    "mandate_invalid",
  );
});

test("approval kit: the person's screen and signature come from the same mandate, never the agent's key", async () => {
  const m = newMandate({ payerId: "alice", agentKeyId: "agent-1", merchants: ["coffee-co"], currency: "USD", maxPerPurchase: 2_000, maxPerDay: 5_000, channel: "CNP" });
  assert.deepEqual(kitMandateChallenge(m), mandateChallenge(m));
  const d = describeMandate(m, { agentName: "Shopping assistant", merchantNames: { "coffee-co": "Coffee Co." }, locale: "en-US" });
  assert.equal(d.title, "Let Shopping assistant spend up to $50.00 a day");
  assert.ok(d.details.includes("Only at: Coffee Co."));
  const person = phone("alice");
  const signed = await approveMandate({ mandate: m, agentName: "Shopping assistant", keyId: "phone", confirm: async () => true, sign: async (c) => Buffer.from(person.signBytes(c), "base64url") });
  assert.equal(verifySignedMandate(signed!, person.key), true);
  await assert.rejects(approveMandate({ mandate: m, agentName: "x", keyId: "agent-1", confirm: async () => true, sign: async () => new Uint8Array(64) }));
});

for (const c of mandateStoreConformance({
  makeStore: () => new MemoryMandateStore(),
  addMandate: async (store, signed) => (store as MemoryMandateStore).add(signed),
  revokeMandate: async (store, payerId, id, at) => (store as MemoryMandateStore).revoke(payerId, id, at),
})) {
  test(`MemoryMandateStore ${c.name}`, c.run);
}

test("approval kit: approving an agent's key produces exactly what the server checks, and can't approve itself", async () => {
  const { enrollmentChallenge: serverChallenge, isWellFormedEnrollment, verifyKeySignature } = await import("../src/index.js");
  const { approveAgentEnrollment, describeAgentEnrollment, enrollmentChallenge: kitChallenge, newAgentEnrollment } = await import("../src/approval/index.js");
  const person = phone("alice");
  const bot = agent("alice");
  const e = newAgentEnrollment({ payerId: "alice", keyId: "agent-1", publicKey: bot.key.publicKey });
  assert.ok(isWellFormedEnrollment(e));
  assert.deepEqual(kitChallenge(e), serverChallenge(e));
  const device = { v: 1 as const, payerId: "alice", newKey: { keyId: "p2", scheme: "ed25519", publicKey: "pk" }, expiresAt: e.expiresAt, nonce: e.nonce };
  assert.deepEqual(kitChallenge(device), serverChallenge(device as never), "device enrollments too");
  assert.ok(Date.parse(e.expiresAt) - Date.now() <= 600_000);

  let shown: string | undefined;
  const approval = await approveAgentEnrollment({
    enrollment: e, agentName: "Shopping assistant", keyId: "phone",
    confirm: async (d) => { shown = d.title; return true; },
    sign: async (c) => Buffer.from(person.signBytes(c), "base64url"),
  });
  assert.equal(shown, "Add Shopping assistant as an AI agent");
  assert.ok(approval && verifyKeySignature(person.key, serverChallenge(approval.enrollment), approval));
  assert.match(describeAgentEnrollment(e, { agentName: "x" }).details[2]!, /fingerprint [0-9A-F]{2} [0-9A-F]{2} [0-9A-F]{2} [0-9A-F]{2}$/);

  assert.equal(await approveAgentEnrollment({ enrollment: e, agentName: "x", keyId: "phone", confirm: async () => false, sign: async () => new Uint8Array() }), null);
  await assert.rejects(approveAgentEnrollment({ enrollment: e, agentName: "x", keyId: "agent-1", confirm: async () => true, sign: async () => new Uint8Array() }));
  await assert.rejects(approveAgentEnrollment({ enrollment: { ...e, newKey: { ...e.newKey, role: undefined as never } }, agentName: "x", keyId: "phone", confirm: async () => true, sign: async () => new Uint8Array() }));
});
