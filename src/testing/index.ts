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
import type { MandateStore, PayerKey, PayerKeyStore, SignedMandate } from "../pay-envelope/intent.js";

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
      presentationPanDigest: `d1:${randomBytes(32).toString("hex")}`,
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
          await store.findByPanDigest(e.presentationPanDigest),
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
        assert.equal(await store.findByPanDigest(`d1:${"0".repeat(64)}`), null);
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
      name: "claim fails after markDeclined (a decline burns the envelope)",
      run: withStore(async (store) => {
        const e = envelope();
        await store.insert(e);
        await store.markDeclined(e.id, "CONTEXT_MISMATCH", "aud_bad");
        assert.equal(await store.claim(e.id, at(1), "aud_ok"), false);
        const after = await store.findById(e.id);
        assert.equal(after?.decision, "DECLINE");
        assert.equal(after?.usedAt, null);
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

/**
 * Conformance for a PayerKeyStore (customer-signed intent). The property that
 * matters: an approval's nonce can be spent exactly once, even under
 * concurrency; otherwise one customer approval could create two credentials.
 *
 * `makeStore` returns an empty store; `addKey` enrolls a key in it the way the
 * app does (e.g. an INSERT into its payer-keys table).
 */
export function payerKeyStoreConformance(opts: {
  makeStore: () => Promise<PayerKeyStore> | PayerKeyStore;
  addKey: (store: PayerKeyStore, key: PayerKey) => Promise<void>;
  revokeKey: (store: PayerKeyStore, payerId: string, keyId: string, at: Date) => Promise<void>;
}): ConformanceCase[] {
  const key = (payerId: string, keyId: string): PayerKey => ({
    payerId,
    keyId,
    scheme: "ed25519",
    publicKey: randomBytes(44).toString("base64url"),
    revokedAt: null,
  });
  const later = () => new Date(Date.now() + 60_000);
  return [
    {
      name: "payer keys: enrolled keys are found by payer and key id, and only there",
      run: async () => {
        const store = await opts.makeStore();
        const k = key("alice", "phone-1");
        await opts.addKey(store, k);
        const found = await store.findKey("alice", "phone-1");
        assert.equal(found?.publicKey, k.publicKey);
        assert.equal(found?.scheme, "ed25519");
        assert.equal(found?.revokedAt, null);
        assert.equal(await store.findKey("bob", "phone-1"), null, "another payer's key id");
        assert.equal(await store.findKey("alice", "phone-2"), null);
      },
    },
    {
      name: "payer keys: an agent key keeps its role",
      run: async () => {
        const store = await opts.makeStore();
        await opts.addKey(store, { ...key("alice", "agent-1"), role: "agent" });
        await opts.addKey(store, key("alice", "phone-1"));
        assert.equal((await store.findKey("alice", "agent-1"))?.role, "agent");
        assert.notEqual((await store.findKey("alice", "phone-1"))?.role, "agent", "a person's device is never an agent");
      },
    },
    {
      name: "payer keys: revocation is visible",
      run: async () => {
        const store = await opts.makeStore();
        await opts.addKey(store, key("alice", "phone-1"));
        await opts.revokeKey(store, "alice", "phone-1", new Date());
        assert.ok((await store.findKey("alice", "phone-1"))?.revokedAt instanceof Date);
      },
    },
    {
      name: "payer keys: a nonce is spent once, per payer",
      run: async () => {
        const store = await opts.makeStore();
        assert.equal(await store.useNonce("alice", "n-0123456789abcdef", later()), true);
        assert.equal(await store.useNonce("alice", "n-0123456789abcdef", later()), false);
        assert.equal(await store.useNonce("bob", "n-0123456789abcdef", later()), true, "nonces are per payer");
      },
    },
    {
      name: "payer keys: 8 concurrent uses of one nonce: exactly one wins",
      run: async () => {
        const store = await opts.makeStore();
        const results = await Promise.all(
          Array.from({ length: 8 }, () => store.useNonce("alice", "n-race-0123456789", later())),
        );
        assert.equal(results.filter(Boolean).length, 1);
      },
    },
  ];
}

/**
 * Conformance suite for MandateStore implementations (standing rules for AI
 * agents). Above all, `reserveMandateSpend` must be atomic per mandate: the
 * concurrency case fails for any store that reads the total and then writes.
 */
export function mandateStoreConformance(opts: {
  makeStore: () => Promise<MandateStore> | MandateStore;
  addMandate: (store: MandateStore, signed: SignedMandate) => Promise<void>;
  revokeMandate: (store: MandateStore, payerId: string, mandateId: string, at: Date) => Promise<void>;
}): ConformanceCase[] {
  const signed = (payerId: string, nonce: string): SignedMandate => ({
    mandate: {
      v: 1,
      payerId,
      agentKeyId: "agent-1",
      merchants: ["coffee-co", "books-co"],
      currency: "USD",
      maxPerPurchase: 2_000,
      maxPerDay: 5_000,
      channel: "CNP",
      expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
      nonce,
    },
    keyId: "phone-1",
    signature: randomBytes(64).toString("base64url"),
  });
  const dayAgo = () => new Date(Date.now() - 86_400_000);
  return [
    {
      name: "mandates: stored exactly, found by payer and id, and only there",
      run: async () => {
        const store = await opts.makeStore();
        const m = signed("alice", "mandate-0123456789ab");
        await opts.addMandate(store, m);
        const found = await store.findMandate("alice", "mandate-0123456789ab");
        assert.deepEqual(found?.signed, m);
        assert.equal(found?.revokedAt, null);
        assert.equal(await store.findMandate("bob", "mandate-0123456789ab"), null, "another payer's mandate id");
      },
    },
    {
      name: "mandates: revocation is visible",
      run: async () => {
        const store = await opts.makeStore();
        await opts.addMandate(store, signed("alice", "mandate-revoke-01234"));
        await opts.revokeMandate(store, "alice", "mandate-revoke-01234", new Date());
        assert.ok((await store.findMandate("alice", "mandate-revoke-01234"))?.revokedAt instanceof Date);
      },
    },
    {
      name: "mandates: spending is reserved up to the cap, per mandate, and a release gives it back",
      run: async () => {
        const store = await opts.makeStore();
        const a = await store.reserveMandateSpend("m-a", 3_000, dayAgo(), 5_000);
        assert.ok(a);
        assert.equal(await store.reserveMandateSpend("m-a", 2_001, dayAgo(), 5_000), null);
        assert.ok(await store.reserveMandateSpend("m-b", 5_000, dayAgo(), 5_000), "another mandate has its own cap");
        await store.releaseMandateSpend(a!);
        assert.ok(await store.reserveMandateSpend("m-a", 5_000, dayAgo(), 5_000));
      },
    },
    {
      name: "mandates: 20 concurrent reservations never exceed the cap",
      run: async () => {
        const store = await opts.makeStore();
        const results = await Promise.all(Array.from({ length: 20 }, () => store.reserveMandateSpend("m-race", 1_000, dayAgo(), 5_000)));
        assert.equal(results.filter(Boolean).length, 5);
      },
    },
  ];
}
