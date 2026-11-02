/**
 * Breach test: steal everything, and none of it works.
 *
 * SPIN's thesis is that stolen payment data is useless. This test gives an
 * attacker, at the worst moment (while envelopes are still live):
 *
 *   1. a full copy of SPIN's database: every envelope record and audit event;
 *   2. every merchant's logs: each card number ever presented, with the
 *      transaction details it was presented with;
 *   3. unlimited guessing, aimed at live envelopes whose details the
 *      database copy reveals.
 *
 * and requires that not one attempt is approved. A positive control then
 * shows the live envelopes still work for their real owner, so the attacks
 * failed because of the design, not because everything is broken.
 *
 * Known limit (last test): the database copy PLUS the server's HMAC secret
 * lets an attacker recompute live card numbers. Closing that needs a second,
 * device-held half (SPIN's split-key design), which this test will then cover.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac, randomBytes } from "node:crypto";
import {
  MemoryPayEnvelopeStore,
  MemoryPayerKeyStore,
  PayEnvelopeIntentError,
  PayEnvelopeService,
  isValidLuhn,
  remotePanKeyring,
  type SignedIntent,
} from "../src/index.js";
import { RP, ed25519Device, intentFor, passkeyDevice } from "./helpers/customer-device.js";
import type { TransactionContext } from "../src/index.js";

const secrets = { hmac: randomBytes(32).toString("hex"), jws: randomBytes(32).toString("hex") };
const owner = { userId: "u_payer", payKeyId: "key_payer" };

/** Deterministic PRNG so a failure is reproducible. */
function prng(seed: number) {
  return () => {
    seed = (seed * 1_103_515_245 + 12_345) % 2 ** 31;
    return seed / 2 ** 31;
  };
}

/** Keys held outside the app (a stand-in for KMS/HSM): never in env, secrets or the database. */
function hardwareKeyring() {
  const keys = { "pan-derive": randomBytes(32), "pan-fingerprint": randomBytes(32) };
  return remotePanKeyring({
    description: "kms",
    mac: async (purpose, data) => new Uint8Array(createHmac("sha256", keys[purpose]).update(data).digest()),
  });
}

async function scenario(opts: { hardware?: boolean } = {}) {
  let now = new Date("2026-11-02T12:00:00Z");
  const store = new MemoryPayEnvelopeStore();
  const service = opts.hardware
    ? new PayEnvelopeService({ store, secrets: { hmac: "", jws: secrets.jws }, keyring: hardwareKeyring(), now: () => now })
    : new PayEnvelopeService({ store, secrets, now: () => now });
  const advance = (seconds: number) => (now = new Date(now.getTime() + seconds * 1000));

  const merchantLogs: { pan: string; context: TransactionContext }[] = [];
  const present = async (pan: string, context: TransactionContext) => {
    merchantLogs.push({ pan, context });
    return service.resolve({ presentation: { pan }, txnContext: context });
  };
  const ctx = (i: number): TransactionContext => ({
    merchantId: `m_shop_${i % 7}`,
    amount: 500 + i * 37,
    currency: i % 5 === 0 ? "EUR" : "USD",
    channel: i % 2 ? "CNP" : "CP",
  });
  const create = (i: number, ttlSeconds: number) => {
    const c = ctx(i);
    return service.create({ merchantId: c.merchantId, amount: c.amount, currency: c.currency, channel: c.channel, ttlSeconds }, owner);
  };

  // Ran out their time without being used (short TTL, created first).
  for (let i = 0; i < 10; i++) await create(i, 10);
  advance(15);
  for (let i = 0; i < 10; i++) {
    // Some are presented late, after expiry: the merchant now holds the number.
    const e = await create(100 + i, 10);
    advance(11);
    if (i % 2 === 0) assert.equal((await present(e.presentation.pan, ctx(100 + i))).reasonCode, "EXPIRED");
  }

  // Approved at the right merchant, then sitting in that merchant's logs.
  for (let i = 0; i < 20; i++) {
    const e = await create(200 + i, 3600);
    assert.equal((await present(e.presentation.pan, ctx(200 + i))).decision, "APPROVE");
  }

  // Presented at the wrong merchant (skimmed, or a compromised checkout): declined, and burned.
  for (let i = 0; i < 10; i++) {
    const e = await create(300 + i, 3600);
    const r = await present(e.presentation.pan, { ...ctx(300 + i), merchantId: "m_skimmer" });
    assert.equal(r.reasonCode, "CONTEXT_MISMATCH");
  }

  // Cancelled early by the payer.
  for (let i = 0; i < 5; i++) {
    const e = await create(400 + i, 3600);
    assert.equal((await service.expire(e.envelopeId)).success, true);
  }

  // Still live and unused: their numbers exist only on the payer's side.
  const live: { pan: string; context: TransactionContext }[] = [];
  for (let i = 0; i < 20; i++) {
    const e = await create(500 + i, 3600);
    live.push({ pan: e.presentation.pan, context: ctx(500 + i) });
  }

  // What the attacker steals: SPIN's whole database, as it would be dumped.
  const dump = JSON.stringify({ envelopes: [...store.envelopes.values()], events: store.events });
  const records = [...store.envelopes.values()];
  const contextsFromDump: TransactionContext[] = records.map((r) => ({
    merchantId: r.merchantId,
    amount: r.amount,
    currency: r.currency,
    channel: r.channel ?? undefined,
  }));

  return { service, store, merchantLogs, live, dump, records, contextsFromDump };
}

test("breach: steal SPIN's database, every merchant's logs, and guess. Nothing is approved", async () => {
  const { service, merchantLogs, live, dump, contextsFromDump } = await scenario();
  let attempts = 0;
  let approvals = 0;
  const attack = async (pan: string, context: TransactionContext) => {
    attempts++;
    const r = await service.resolve({ presentation: { pan }, txnContext: context });
    if (r.decision === "APPROVE") approvals++;
  };

  // 1. The database copy holds no live card number, in any field.
  for (const { pan } of live) assert.ok(!dump.includes(pan), "a live card number is stored in the database");
  const numbersInDump = [...new Set(dump.match(/\d{13,19}/g) ?? [])];
  for (const n of numbersInDump) for (const c of contextsFromDump) await attack(n, c);

  // 2. Every number any merchant ever saw: replayed with what that merchant
  //    logged, and with every context the database copy reveals.
  for (const { pan, context } of merchantLogs) {
    await attack(pan, context);
    for (const c of contextsFromDump) await attack(pan, c);
  }

  // 3. Guessing, aimed at the live envelopes: right BIN, valid checksum, and
  //    each live envelope's exact merchant, amount, currency and channel.
  const rand = prng(42);
  for (let g = 0; g < 20_000; g++) {
    const body = String(Math.floor(rand() * 1e9)).padStart(9, "0");
    const partial = "411111" + body;
    const check = [...Array(10).keys()].map(String).find((d) => isValidLuhn(partial + d))!;
    await attack(partial + check, live[g % live.length]!.context);
  }

  assert.ok(attempts > 20_000);
  assert.equal(approvals, 0, `${approvals} of ${attempts} attack attempts were approved`);

  // Positive control: the real owner's live numbers still work, once each.
  for (const { pan, context } of live) {
    assert.equal((await service.resolve({ presentation: { pan }, txnContext: context })).decision, "APPROVE");
    assert.equal((await service.resolve({ presentation: { pan }, txnContext: context })).reasonCode, "REPLAY");
  }
});

test("breach: a number seen at the wrong merchant stays dead, even with the right details", async () => {
  const { service, merchantLogs, contextsFromDump } = await scenario();
  const skimmed = merchantLogs.filter((l) => l.context.merchantId === "m_skimmer");
  assert.equal(skimmed.length, 10);
  for (const { pan } of skimmed) {
    // The attacker tries every real context in the database copy, so one of them is the right one.
    for (const c of contextsFromDump) {
      const r = await service.resolve({ presentation: { pan }, txnContext: c });
      assert.notEqual(r.decision, "APPROVE");
    }
  }
});

test("breach: stolen live numbers, their merchants, and the fraudster's own API key: they can't pose as the merchant", async () => {
  const { service, live } = await scenario();
  // Numbers stolen before use (e.g. from a compromised checkout page), with
  // every detail they're locked to. The fraudster has a valid SPIN account of
  // their own, so the app authenticates them as "m_fraudster".
  const stolen = live.slice(0, 10);
  const untouched = live.slice(10);
  for (const { pan, context } of stolen) {
    const r = await service.resolve({ presentation: { pan }, txnContext: context }, { callerMerchantId: "m_fraudster" });
    assert.notEqual(r.decision, "APPROVE", "a caller posed as another merchant");
    assert.equal(r.reasonCode, "CONTEXT_MISMATCH");
  }
  // The attempt burned them: even the real merchant can't use them now.
  for (const { pan, context } of stolen) {
    const r = await service.resolve({ presentation: { pan }, txnContext: context }, { callerMerchantId: context.merchantId });
    assert.equal(r.reasonCode, "PREVIOUSLY_DECLINED");
  }
  // Control: numbers nobody attacked work for their own merchant, once.
  for (const { pan, context } of untouched) {
    const r = await service.resolve({ presentation: { pan }, txnContext: context }, { callerMerchantId: context.merchantId });
    assert.equal(r.decision, "APPROVE");
  }
});

test("with keys in hardware, the database plus every secret on the app server recomputes nothing", async () => {
  const { live, records, dump } = await scenario({ hardware: true });
  // The attacker owns the app server: its database and its whole environment.
  const stolenSecrets = [secrets.jws, secrets.hmac];
  const candidates = new Set<string>();
  for (const key of stolenSecrets) {
    for (const r of records) {
      const msg = [r.id, r.createdAt.getTime(), r.merchantId, r.currency, r.amount, r.channel ?? ""].join("|");
      const body9 = createHmac("sha256", key).update(msg).digest("hex").replace(/[a-f]/g, (c) => String(parseInt(c, 16) % 10)).slice(0, 9);
      const partial = "411111" + body9;
      candidates.add(partial + [...Array(10).keys()].map(String).find((d) => isValidLuhn(partial + d))!);
    }
  }
  assert.equal(live.filter(({ pan }) => candidates.has(pan)).length, 0);
  assert.equal(live.filter(({ pan }) => dump.includes(pan)).length, 0);
  // What's left is asking the key service to fingerprint guesses: up to a
  // billion requests per fingerprint, each one rate-limited and logged by KMS.
});

test("known limit (software keyring): the database copy plus the server's HMAC secret recomputes live numbers", async () => {
  const { live, records } = await scenario();
  // An attacker who also holds PAY_ENVELOPE_HMAC_SECRET can redo the derivation.
  const recompute = (r: (typeof records)[number]) => {
    const digest = createHmac("sha256", secrets.hmac)
      .update([r.id, r.createdAt.getTime(), r.merchantId, r.currency, r.amount, r.channel ?? ""].join("|"))
      .digest("hex");
    const body9 = digest.replace(/[a-f]/g, (c) => String(parseInt(c, 16) % 10)).slice(0, 9);
    const partial = "411111" + body9;
    return partial + [...Array(10).keys()].map(String).find((d) => isValidLuhn(partial + d))!;
  };
  const recomputed = new Set(records.map(recompute));
  // Documented, not desired: today the secret is the only barrier. A device-held
  // half (split key) makes this test fail, at which point it should be inverted.
  assert.ok(live.every(({ pan }) => recomputed.has(pan)));
});

// ── Customer-signed intent (docs/design/customer-signed-intent.md) ──────────
// The attacker now holds the integrator's live API key, or controls its
// server: they can call create with anything they like.

function intentScenario() {
  const payerKeys = new MemoryPayerKeyStore();
  const store = new MemoryPayEnvelopeStore();
  const service = new PayEnvelopeService({ store, secrets, payerKeys, webauthn: RP });
  const alice = ed25519Device("alice");
  const alicePasskey = passkeyDevice("alice");
  payerKeys.add(alice.key);
  payerKeys.add(alicePasskey.key);
  const integrator = { userId: "integrator", payKeyId: "key_live" };
  const create = (input: object, signedIntent?: SignedIntent) =>
    service.create({ merchantId: "coffee-co", amount: 450, currency: "USD", channel: "CNP", ...input }, integrator, {
      signedIntent,
      requireCustomerSignature: true,
    });
  return { service, store, payerKeys, alice, alicePasskey, create };
}

const refused = async (p: Promise<unknown>) => {
  try {
    await p;
    return false;
  } catch (e) {
    return e instanceof PayEnvelopeIntentError;
  }
};

test("breach (signed intent): a stolen integrator API key alone creates nothing", async () => {
  const { store, create } = intentScenario();
  assert.ok(await refused(create({ merchantId: "m_attacker", amount: 450_000 })));
  // Signing with the attacker's own key, claiming to be Alice, is no better.
  const mallory = ed25519Device("alice", "phone-1"); // same ids, different key
  assert.ok(await refused(create({ merchantId: "m_attacker" }, mallory.sign(intentFor("alice", { merchantId: "m_attacker" })))));
  assert.equal(store.envelopes.size, 0);
});

test("breach (signed intent): Alice's approval of $4.50 to Coffee Co. can't become anything else", async () => {
  const { store, alice, alicePasskey, create } = intentScenario();
  for (const device of [alice, alicePasskey]) {
    const si = device.sign(intentFor("alice"));
    for (const changed of [
      { amount: 450_000 },
      { merchantId: "m_attacker" },
      { currency: "EUR" },
      { channel: "CP" },
      { amountTolerance: 1 },
    ]) {
      assert.ok(await refused(create(changed, si)), `accepted ${JSON.stringify(changed)}`);
    }
    // Editing the approval itself breaks the customer's signature.
    const edited = { ...si, intent: { ...si.intent, merchantId: "m_attacker", amount: 450_000 } };
    assert.ok(await refused(create({ merchantId: "m_attacker", amount: 450_000 }, edited)));
  }
  assert.equal(store.envelopes.size, 0);
});

test("breach (signed intent): one approval, one credential", async () => {
  const { store, alice, create } = intentScenario();
  const si = alice.sign(intentFor("alice"));
  await create({}, si);
  const replays = await Promise.all(Array.from({ length: 5 }, () => refused(create({}, si))));
  assert.ok(replays.every(Boolean));
  assert.equal(store.envelopes.size, 1);
});

test("breach (signed intent): SPIN's whole database (public keys, spent nonces, receipts) can't sign an approval", async () => {
  const { store, payerKeys, alice, create } = intentScenario();
  await create({}, alice.sign(intentFor("alice")));
  const dump = JSON.stringify({ keys: [...payerKeys.keys.values()], spent: [...payerKeys.spent.keys()], envelopes: [...store.envelopes.values()] });
  // Everything stored is public material: reusing any of it as a signature fails.
  const scraps = [...new Set(dump.match(/[A-Za-z0-9_-]{40,}/g) ?? [])];
  for (const scrap of scraps) {
    const forged = { intent: intentFor("alice", { merchantId: "m_attacker" }), keyId: "phone-1", signature: scrap };
    assert.ok(await refused(create({ merchantId: "m_attacker" }, forged)));
  }
  assert.equal(store.envelopes.size, 1);
});
