/**
 * Conformance suite for PayEnvelopeStore implementations.
 *
 * Every app's database adapter must pass these against a real database
 * (PGlite works well in tests). They pin down the contract the service relies
 * on, above all that `claim` is atomic: the concurrency cases fail for any
 * store that reads and then writes in two steps.
 *
 * Runner-agnostic: each case is a plain async function that throws on failure.
 *
 *   import { test } from "node:test";
 *   import { payEnvelopeStoreConformance } from "@spin/core/testing";
 *   for (const c of payEnvelopeStoreConformance({ makeStore, ids })) test(c.name, c.run);
 */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import type { PayEnvelopeStore } from "../pay-envelope/store.js";
import type { NewPayEnvelope } from "../pay-envelope/types.js";

export interface ConformanceOptions<UserId, KeyId> {
  /** Return a store over an empty or isolated dataset. Called once per case. */
  makeStore: () => PayEnvelopeStore<UserId, KeyId> | Promise<PayEnvelopeStore<UserId, KeyId>>;
  /** Two distinct users and API keys in the store's id types. */
  ids: { userA: UserId; keyA: KeyId; userB: UserId; keyB: KeyId };
  /** How many concurrent claims to race. Default 8. */
  concurrency?: number;
}

export interface ConformanceCase {
  name: string;
  run: () => Promise<void>;
}

export function payEnvelopeStoreConformance<UserId, KeyId>(
  opts: ConformanceOptions<UserId, KeyId>,
): ConformanceCase[] {
  const { ids } = opts;
  const n = opts.concurrency ?? 8;
  // Timestamps at whole seconds so stores with coarse precision still compare exactly.
  const base = new Date(Math.floor(Date.now() / 1000) * 1000);
  const at = (seconds: number) => new Date(base.getTime() + seconds * 1000);

  let seq = 0;
  const envelope = (
    overrides: Partial<NewPayEnvelope<UserId, KeyId>> = {},
  ): NewPayEnvelope<UserId, KeyId> => {
    seq++;
    return {
      id: `env_conf_${randomBytes(6).toString("hex")}`,
      userId: ids.userA,
      payKeyId: ids.keyA,
      merchantId: "m_conformance",
      amount: 5000,
      currency: "USD",
      amountTolerancePpm: null,
      channel: null,
      presentationPan: `4111119${String(seq).padStart(8, "0")}${seq % 10}`.slice(0, 16),
      createdAt: at(0),
      expiresAt: at(90),
      idempotencyKey: null,
      receiptJws: "receipt",
      metadata: null,
      ...overrides,
    };
  };

  const withStore =
    (fn: (store: PayEnvelopeStore<UserId, KeyId>) => Promise<void>) => async () =>
      fn(await opts.makeStore());

  return [
    {
      name: "insert then read back by id, PAN and idempotency key",
      run: withStore(async (store) => {
        const e = envelope({ idempotencyKey: "idem-1", amountTolerancePpm: 50_000, channel: "CNP" });
        await store.insert(e);
        for (const found of [
          await store.findById(e.id),
          await store.findByPan(e.presentationPan),
          await store.findByIdempotencyKey(ids.keyA, "idem-1"),
        ]) {
          assert.ok(found, "envelope not found");
          assert.equal(found.id, e.id);
          assert.equal(found.amount, 5000);
          assert.equal(found.amountTolerancePpm, 50_000);
          assert.equal(found.channel, "CNP");
          assert.equal(found.expiresAt.getTime(), e.expiresAt.getTime());
          assert.equal(found.usedAt, null);
          assert.equal(found.expiredAt, null);
          assert.equal(found.decision, null);
        }
        assert.equal(await store.findById("env_missing"), null);
        assert.equal(await store.findByPan("4000000000000002"), null);
      }),
    },
    {
      name: "idempotency keys are scoped to the API key",
      run: withStore(async (store) => {
        await store.insert(envelope({ idempotencyKey: "order-1" }));
        assert.equal(
          await store.findByIdempotencyKey(ids.keyB, "order-1"),
          null,
          "another API key's envelope was returned for its idempotency key",
        );
      }),
    },
    {
      name: "claim succeeds once, then fails",
      run: withStore(async (store) => {
        const e = envelope();
        await store.insert(e);
        assert.equal(await store.claim(e.id, at(1), "aud_1"), true);
        assert.equal(await store.claim(e.id, at(2), "aud_2"), false);
        const after = await store.findById(e.id);
        assert.equal(after?.decision, "APPROVE");
        assert.equal(after?.auditRef, "aud_1");
        assert.equal(after?.usedAt?.getTime(), at(1).getTime());
      }),
    },
    {
      name: `${n} concurrent claims: exactly one wins`,
      run: withStore(async (store) => {
        const e = envelope();
        await store.insert(e);
        const results = await Promise.all(
          Array.from({ length: n }, (_, i) => store.claim(e.id, at(1), `aud_${i}`)),
        );
        assert.equal(results.filter(Boolean).length, 1, `${results.filter(Boolean).length} claims succeeded`);
        const winner = results.indexOf(true);
        assert.equal((await store.findById(e.id))?.auditRef, `aud_${winner}`);
      }),
    },
    {
      name: "claim fails at or after expiresAt",
      run: withStore(async (store) => {
        const e = envelope({ expiresAt: at(90) });
        await store.insert(e);
        assert.equal(await store.claim(e.id, at(90), "aud"), false);
        assert.equal(await store.claim(e.id, at(91), "aud"), false);
        assert.equal((await store.findById(e.id))?.usedAt, null);
      }),
    },
    {
      name: "claim fails after markExpired",
      run: withStore(async (store) => {
        const e = envelope();
        await store.insert(e);
        assert.equal(await store.markExpired(e.id, at(1)), true);
        assert.equal(await store.markExpired(e.id, at(2)), false, "expired twice");
        assert.equal(await store.claim(e.id, at(3), "aud"), false);
      }),
    },
    {
      name: "markDeclined and markExpired never touch a claimed envelope",
      run: withStore(async (store) => {
        const e = envelope();
        await store.insert(e);
        assert.equal(await store.claim(e.id, at(1), "aud_ok"), true);
        await store.markDeclined(e.id, "CONTEXT_MISMATCH", "aud_bad");
        assert.equal(await store.markExpired(e.id, at(2)), false);
        const after = await store.findById(e.id);
        assert.equal(after?.decision, "APPROVE");
        assert.equal(after?.declineReason, null);
        assert.equal(after?.auditRef, "aud_ok");
        assert.equal(after?.expiredAt, null);
      }),
    },
    {
      name: "markDeclined records the reason on an unused envelope",
      run: withStore(async (store) => {
        const e = envelope();
        await store.insert(e);
        await store.markDeclined(e.id, "AMOUNT_OUT_OF_BOUNDS", "aud_d");
        const after = await store.findById(e.id);
        assert.equal(after?.decision, "DECLINE");
        assert.equal(after?.declineReason, "AMOUNT_OUT_OF_BOUNDS");
      }),
    },
    {
      name: "concurrent claim and markExpired: never both succeed",
      run: withStore(async (store) => {
        const e = envelope();
        await store.insert(e);
        const [claimed, expired] = await Promise.all([
          store.claim(e.id, at(1), "aud"),
          store.markExpired(e.id, at(1)),
        ]);
        assert.ok(!(claimed && expired), "envelope was both claimed and expired");
        assert.ok(claimed || expired, "neither claim nor expire succeeded");
      }),
    },
  ];
}
