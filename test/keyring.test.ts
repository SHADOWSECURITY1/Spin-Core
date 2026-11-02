import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac, randomBytes } from "node:crypto";
import {
  MemoryPayEnvelopeStore,
  PayEnvelopeConfigError,
  PayEnvelopeKeyringError,
  PayEnvelopeService,
  remotePanKeyring,
  resolvePayEnvelopeSecrets,
  softwarePanKeyring,
} from "../src/index.js";

const secrets = { hmac: "h".repeat(64), jws: "j".repeat(64) };
const owner = { userId: "u1", payKeyId: "k1" };
const ctx = { merchantId: "m1", amount: 1234, currency: "USD", channel: "CNP" };

/** A stand-in for KMS: the keys live only in this closure, never in env or secrets. */
function fakeKms() {
  const keys = { "pan-derive": randomBytes(32), "pan-fingerprint": randomBytes(32) };
  let calls = 0;
  const keyring = remotePanKeyring({
    description: "fake-kms",
    mac: async (purpose, data) => {
      calls++;
      return new Uint8Array(createHmac("sha256", keys[purpose]).update(data).digest());
    },
  });
  return { keyring, calls: () => calls };
}

test("software keyring reproduces 0.5 exactly: stored fingerprints and numbers keep working", async () => {
  const store = new MemoryPayEnvelopeStore();
  const service = new PayEnvelopeService({ store, secrets });
  const env = await service.create(ctx, owner);
  const rec = store.envelopes.get(env.envelopeId)!;
  // The 0.5 formulas, written out independently.
  const fpKey = createHmac("sha256", secrets.hmac).update("spin/pay-envelope/pan-digest/v1").digest();
  assert.equal(rec.presentationPanDigest, "d1:" + createHmac("sha256", fpKey).update(env.presentation.pan).digest("hex"));
  const body = createHmac("sha256", secrets.hmac)
    .update([rec.id, rec.createdAt.getTime(), rec.merchantId, rec.currency, rec.amount, rec.channel ?? ""].join("|"))
    .digest("hex")
    .replace(/[a-f]/g, (c) => String(parseInt(c, 16) % 10))
    .slice(0, 9);
  assert.equal(env.presentation.pan.slice(6, 15), body);
  assert.equal(service.keyringDescription, "software");
  // Same as passing the software keyring explicitly.
  const explicit = await softwarePanKeyring(secrets.hmac).mac("pan-fingerprint", Buffer.from(env.presentation.pan));
  assert.equal(rec.presentationPanDigest, "d1:" + Buffer.from(explicit).toString("hex"));
});

test("remote keyring: works end to end, and the HMAC secret is no longer required", async () => {
  const kms = fakeKms();
  const store = new MemoryPayEnvelopeStore();
  const service = new PayEnvelopeService({ store, secrets: { hmac: "", jws: secrets.jws }, keyring: kms.keyring });
  const env = await service.create({ ...ctx, idempotencyKey: "o1" }, owner);
  const again = await service.create({ ...ctx, idempotencyKey: "o1" }, owner);
  assert.equal(again.presentation.pan, env.presentation.pan, "idempotent retry recomputes via the keyring");
  assert.equal((await service.resolve({ presentation: env.presentation, txnContext: ctx })).decision, "APPROVE");
  assert.ok(kms.calls() >= 4);
  assert.equal(service.keyringDescription, "fake-kms");

  // From the environment: only the JWS secret is needed with a keyring.
  assert.doesNotThrow(() => resolvePayEnvelopeSecrets({ PAY_ENVELOPE_JWS_SECRET: secrets.jws }, { requireHmac: false }));
  assert.throws(() => resolvePayEnvelopeSecrets({ PAY_ENVELOPE_JWS_SECRET: secrets.jws }), PayEnvelopeConfigError);
  assert.throws(() => new PayEnvelopeService({ store, secrets: { hmac: "", jws: secrets.jws } }), PayEnvelopeConfigError);
});

test("a keyring fault fails closed: nothing is created or approved", async () => {
  const kms = fakeKms();
  const store = new MemoryPayEnvelopeStore();
  let down = false;
  let malformed = false;
  const keyring = remotePanKeyring({
    description: "flaky-kms",
    mac: async (purpose, data) => {
      if (down) throw new Error("KMS unavailable");
      if (malformed) return new Uint8Array(4);
      return kms.keyring.mac(purpose, data);
    },
  });
  const service = new PayEnvelopeService({ store, secrets, keyring });
  const env = await service.create(ctx, owner);

  down = true;
  await assert.rejects(service.create(ctx, owner), PayEnvelopeKeyringError);
  await assert.rejects(service.resolve({ presentation: env.presentation, txnContext: ctx }), PayEnvelopeKeyringError);
  down = false;
  malformed = true;
  await assert.rejects(service.resolve({ presentation: env.presentation, txnContext: ctx }), PayEnvelopeKeyringError);
  malformed = false;

  assert.equal(store.envelopes.size, 1);
  assert.equal(store.envelopes.get(env.envelopeId)!.usedAt, null);
  assert.equal((await service.resolve({ presentation: env.presentation, txnContext: ctx })).decision, "APPROVE");
});
