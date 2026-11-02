import { test } from "node:test";
import assert from "node:assert/strict";
import {
  MemoryPayEnvelopeStore,
  PayEnvelopeService,
  PayEnvelopeIdempotencyConflictError,
  verifyReceipt,
  isValidLuhn,
} from "../src/index.js";

const secrets = { hmac: "h".repeat(64), jws: "j".repeat(64) };
const ownerA = { userId: "user_a", payKeyId: "key_a" };
const ownerB = { userId: "user_b", payKeyId: "key_b" };
const ctx = { merchantId: "m_1", amount: 5000, currency: "USD" };

function setup(now = () => new Date()) {
  const store = new MemoryPayEnvelopeStore();
  return { store, service: new PayEnvelopeService({ store, secrets, now }) };
}

test("create returns a Luhn-valid PAN and a verifiable receipt", async () => {
  const { service, store } = setup();
  const out = await service.create({ ...ctx }, ownerA);
  assert.ok(isValidLuhn(out.presentation.pan));
  assert.equal(verifyReceipt(secrets.jws, out.receiptJws)?.envelopeId, out.envelopeId);
  assert.equal(store.envelopes.size, 1);
});

test("eight simultaneous resolves of one envelope: exactly one APPROVE", async () => {
  const { service } = setup();
  const env = await service.create({ ...ctx }, ownerA);
  const results = await Promise.all(
    Array.from({ length: 8 }, () => service.resolve({ presentation: env.presentation, txnContext: ctx })),
  );
  assert.equal(results.filter((r) => r.decision === "APPROVE").length, 1);
  assert.ok(results.filter((r) => r.decision === "DECLINE").every((r) => r.reasonCode === "REPLAY"));
});

test("a racing mismatched request cannot overwrite the APPROVE", async () => {
  const { service, store } = setup();
  const env = await service.create({ ...ctx }, ownerA);
  const [good, bad] = await Promise.all([
    service.resolve({ presentation: env.presentation, txnContext: ctx }),
    service.resolve({ presentation: env.presentation, txnContext: { ...ctx, merchantId: "m_evil" } }),
  ]);
  assert.equal(good.decision, "APPROVE");
  assert.equal(bad.reasonCode, "CONTEXT_MISMATCH");
  const stored = store.envelopes.get(env.envelopeId)!;
  assert.equal(stored.decision, "APPROVE");
  assert.equal(stored.declineReason, null);
});

test("expire racing resolve: never both succeed", async () => {
  const { service } = setup();
  const env = await service.create({ ...ctx }, ownerA);
  const [r, e] = await Promise.all([
    service.resolve({ presentation: env.presentation, txnContext: ctx }),
    service.expire(env.envelopeId),
  ]);
  assert.ok(!(r.decision === "APPROVE" && e.success));
});

test("TTL: an envelope past expiresAt is declined as EXPIRED and recorded", async () => {
  let t = new Date("2026-11-01T12:00:00Z");
  const { service, store } = setup(() => t);
  const env = await service.create({ ...ctx, ttlSeconds: 30 }, ownerA);
  t = new Date(t.getTime() + 30_000);
  const r = await service.resolve({ presentation: env.presentation, txnContext: ctx });
  assert.equal(r.reasonCode, "EXPIRED");
  assert.ok(store.envelopes.get(env.envelopeId)!.expiredAt);
  const again = await service.resolve({ presentation: env.presentation, txnContext: ctx });
  assert.equal(again.reasonCode, "ALREADY_EXPIRED");
});

test("TTL is clamped to 10s..3600s", async () => {
  const t = new Date("2026-11-01T12:00:00Z");
  const { service } = setup(() => t);
  const short = await service.create({ ...ctx, ttlSeconds: 1 }, ownerA);
  const long = await service.create({ ...ctx, ttlSeconds: 999_999 }, ownerA);
  assert.equal(Date.parse(short.expiresAt) - t.getTime(), 10_000);
  assert.equal(Date.parse(long.expiresAt) - t.getTime(), 3_600_000);
});

test("amount tolerance and context binding", async () => {
  const { service } = setup();
  // Each check gets a fresh envelope: any decline burns the one it was made for.
  const check = async (txn: object) => {
    const env = await service.create({ ...ctx, amountTolerance: 0.05, channel: "CNP" }, ownerA);
    return service.resolve({ presentation: env.presentation, txnContext: { ...ctx, ...txn } });
  };
  assert.equal((await check({ amount: 5300, channel: "CNP" })).reasonCode, "AMOUNT_OUT_OF_BOUNDS");
  assert.equal((await check({ currency: "EUR", channel: "CNP" })).reasonCode, "CONTEXT_MISMATCH");
  assert.equal((await check({ amount: 5250 })).reasonCode, "CONTEXT_MISMATCH", "omitting channel bypassed the binding");
  assert.equal((await check({ amount: 5250, channel: "CNP" })).decision, "APPROVE");
});

test("a declined attempt burns the envelope: the right context afterwards is still declined", async () => {
  const { service, store } = setup();
  const env = await service.create({ ...ctx }, ownerA);
  const wrong = await service.resolve({ presentation: env.presentation, txnContext: { ...ctx, merchantId: "m_evil" } });
  assert.equal(wrong.reasonCode, "CONTEXT_MISMATCH");
  const right = await service.resolve({ presentation: env.presentation, txnContext: ctx });
  assert.equal(right.reasonCode, "PREVIOUSLY_DECLINED");
  assert.equal(store.envelopes.get(env.envelopeId)!.usedAt, null);
});

test("idempotent retry returns the same card number, recomputed (it isn't stored)", async () => {
  const { service, store } = setup();
  const a = await service.create({ ...ctx, idempotencyKey: "order-7" }, ownerA);
  const b = await service.create({ ...ctx, idempotencyKey: "order-7" }, ownerA);
  assert.equal(b.presentation.pan, a.presentation.pan);
  assert.ok(!JSON.stringify([...store.envelopes.values()]).includes(a.presentation.pan));
});

test("idempotency: same key and params returns the same envelope", async () => {
  const { service, store } = setup();
  const a = await service.create({ ...ctx, idempotencyKey: "order-1" }, ownerA);
  const b = await service.create({ ...ctx, idempotencyKey: "order-1" }, ownerA);
  assert.equal(a.envelopeId, b.envelopeId);
  assert.equal(store.envelopes.size, 1);
});

test("idempotency: another API key never gets someone else's envelope", async () => {
  const { service } = setup();
  const a = await service.create({ ...ctx, idempotencyKey: "order-1" }, ownerA);
  const b = await service.create({ ...ctx, idempotencyKey: "order-1" }, ownerB);
  assert.notEqual(b.envelopeId, a.envelopeId);
  assert.notEqual(b.presentation.pan, a.presentation.pan);
});

test("idempotency: reusing a key with different params is a conflict", async () => {
  const { service } = setup();
  await service.create({ ...ctx, idempotencyKey: "order-1" }, ownerA);
  await assert.rejects(
    service.create({ ...ctx, amount: 9999, idempotencyKey: "order-1" }, ownerA),
    PayEnvelopeIdempotencyConflictError,
  );
});

test("expire and getStatus can be scoped to the owning API key", async () => {
  const { service } = setup();
  const env = await service.create({ ...ctx }, ownerA);
  assert.equal(await service.getStatus(env.envelopeId, { payKeyId: "key_b" }), null);
  assert.deepEqual(await service.expire(env.envelopeId, { payKeyId: "key_b" }), {
    success: false,
    error: "Envelope not found",
  });
  assert.equal((await service.expire(env.envelopeId, { payKeyId: "key_a" })).success, true);
});

test("a PAN already in use is never reissued", async () => {
  const { service, store } = setup();
  const first = await service.create({ ...ctx }, ownerA);
  let lookups = 0;
  const realFind = store.findByPanDigest.bind(store);
  // Pretend the first two candidate PANs collide with the existing envelope.
  store.findByPanDigest = async (digest: string) =>
    ++lookups <= 2 ? store.envelopes.get(first.envelopeId)! : realFind(digest);
  const second = await service.create({ ...ctx }, ownerA);
  assert.equal(lookups, 3);
  assert.notEqual(second.envelopeId, first.envelopeId);
});

test("the service refuses weak secrets passed in code", () => {
  assert.throws(() => new PayEnvelopeService({ store: new MemoryPayEnvelopeStore(), secrets: { hmac: "x", jws: "y" } }));
});

test("audit events are recorded and event failures never break a request", async () => {
  const { service, store } = setup();
  const env = await service.create({ ...ctx }, ownerA);
  await service.resolve({ presentation: env.presentation, txnContext: ctx });
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(store.events.map((e) => e.eventType), ["created", "resolved"]);

  const errors: unknown[] = [];
  const failing = new MemoryPayEnvelopeStore();
  failing.recordEvent = async () => {
    throw new Error("events table down");
  };
  const svc = new PayEnvelopeService({ store: failing, secrets, onEventError: (e) => errors.push(e) });
  const e2 = await svc.create({ ...ctx }, ownerA);
  assert.equal((await svc.resolve({ presentation: e2.presentation, txnContext: ctx })).decision, "APPROVE");
  await new Promise((r) => setImmediate(r));
  assert.equal(errors.length, 2);
});
