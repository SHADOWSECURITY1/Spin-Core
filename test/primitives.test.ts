import { test } from "node:test";
import assert from "node:assert/strict";
import {
  isValidLuhn,
  projectPan,
  resolvePayEnvelopeSecrets,
  PayEnvelopeConfigError,
  signReceipt,
  verifyReceipt,
  generatePayEnvelopeKey,
  validatePayEnvelopeKey,
  amountWithinTolerance,
  planResolution,
  type PayEnvelopeRecord,
} from "../src/index.js";

test("projectPan produces Luhn-valid 16-digit PANs", () => {
  const pan = projectPan("411111", "123456789");
  assert.equal(pan.length, 16);
  assert.ok(isValidLuhn(pan));
  assert.ok(isValidLuhn("4111111111111111"));
  assert.ok(!isValidLuhn("4111111111111112"));
  assert.throws(() => projectPan("41111", "123456789"));
});

const A = "a".repeat(64);
const B = "b".repeat(64);
const rejects = (env: Record<string, string | undefined>, re: RegExp) =>
  assert.throws(
    () => resolvePayEnvelopeSecrets(env),
    (e: unknown) => e instanceof PayEnvelopeConfigError && re.test((e as Error).message),
  );

test("secrets fail closed regardless of NODE_ENV", () => {
  rejects({}, /is not set/);
  rejects({ NODE_ENV: "development", REPL_ID: "x" }, /is not set/);
  rejects({ PAY_ENVELOPE_HMAC_SECRET: "short", PAY_ENVELOPE_JWS_SECRET: B }, /at least 32/);
  rejects({ PAY_ENVELOPE_HMAC_SECRET: "change_me_use_openssl_rand_hex_32", PAY_ENVELOPE_JWS_SECRET: B }, /placeholder/);
  rejects({ PAY_ENVELOPE_HMAC_SECRET: A, PAY_ENVELOPE_JWS_SECRET: A }, /different/);
  assert.deepEqual(resolvePayEnvelopeSecrets({ PAY_ENVELOPE_HMAC_SECRET: A, PAY_ENVELOPE_JWS_SECRET: B }), { hmac: A, jws: B });
});

test("dev opt-in gives random secrets and is refused in production", () => {
  const env = { PAY_ENVELOPE_DEV_SECRETS: "random" };
  assert.notEqual(resolvePayEnvelopeSecrets(env).hmac, resolvePayEnvelopeSecrets(env).hmac);
  rejects({ ...env, NODE_ENV: "production" }, /not allowed/);
});

test("receipts verify, and reject tampering, other keys, alg swaps and expiry", () => {
  const now = new Date("2026-11-01T12:00:00Z");
  const token = signReceipt(A, { envelopeId: "env_1", amount: 5000 }, { now });
  const claims = verifyReceipt(A, token, { now });
  assert.equal(claims?.envelopeId, "env_1");
  assert.equal(claims && claims.exp - claims.iat, 900);

  assert.equal(verifyReceipt(B, token, { now }), null, "verified with the wrong secret");
  const [h, body, sig] = token.split(".") as [string, string, string];
  const forged = Buffer.from(JSON.stringify({ envelopeId: "env_1", amount: 1, iat: 0, exp: 9e9 })).toString("base64url");
  assert.equal(verifyReceipt(A, `${h}.${forged}.${sig}`, { now }), null, "accepted a modified payload");
  const none = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
  assert.equal(verifyReceipt(A, `${none}.${body}.`, { now }), null, "accepted alg none");
  assert.equal(verifyReceipt(A, token, { now: new Date(now.getTime() + 900_000) }), null, "accepted an expired receipt");
  assert.equal(verifyReceipt(A, "not-a-jws", { now }), null);
});

test("API keys validate in constant time and tolerate malformed hashes", () => {
  const { key, keyHash, keyPrefix } = generatePayEnvelopeKey("test");
  assert.match(key, /^env_test_/);
  assert.ok(keyPrefix.endsWith("..."));
  assert.ok(validatePayEnvelopeKey(key, keyHash));
  assert.ok(!validatePayEnvelopeKey(`${key}x`, keyHash));
  assert.ok(!validatePayEnvelopeKey(key, "deadbeef"), "short stored hash should be false, not a throw");
});

test("amount tolerance uses exact integer math", () => {
  assert.ok(amountWithinTolerance(10_000, null, 10_000));
  assert.ok(!amountWithinTolerance(10_000, null, 10_001));
  assert.ok(amountWithinTolerance(10_000, 50_000, 10_500));
  assert.ok(amountWithinTolerance(10_000, 50_000, 9_500));
  assert.ok(!amountWithinTolerance(10_000, 50_000, 10_501));
  assert.ok(!amountWithinTolerance(10_000, 50_000, Number.NaN));
});

test("an envelope bound to a channel requires the request to state it", () => {
  const now = new Date();
  const env = {
    merchantId: "m",
    currency: "USD",
    amount: 100,
    amountTolerancePpm: null,
    channel: "CNP",
    expiresAt: new Date(now.getTime() + 60_000),
    expiredAt: null,
    usedAt: null,
  } as unknown as PayEnvelopeRecord;
  const txn = { merchantId: "m", currency: "USD", amount: 100 };
  assert.deepEqual(planResolution(env, txn, now), { action: "decline", reason: "CONTEXT_MISMATCH", write: "decline" });
  assert.deepEqual(planResolution(env, { ...txn, channel: "CP" }, now).action, "decline");
  assert.deepEqual(planResolution(env, { ...txn, channel: "CNP" }, now), { action: "claim" });
});
