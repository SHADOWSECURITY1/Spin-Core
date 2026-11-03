/**
 * The agent SDK (@spin/core/agent) and its MCP server, against SPIN's real
 * decision code: a small stand-in for the Pay Envelope API built on
 * PayEnvelopeService, reached through a fetch function.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes, sign as nodeSign } from "node:crypto";
import { p256 } from "@noble/curves/nist.js";
import {
  MemoryMandateStore,
  MemoryPayEnvelopeStore,
  MemoryPayerKeyStore,
  PayEnvelopeIntentError,
  PayEnvelopeService,
  mandateChallenge,
  verifySignedIntent,
  type Mandate,
  type SignedIntent,
} from "../src/index.js";
import {
  SpinAgent,
  awsKmsSigner,
  createSpinMcpHandler,
  generateDevAgentKey,
  p256Signer,
  type KmsLike,
} from "../src/agent/index.js";

const secrets = { hmac: "h".repeat(64), jws: "j".repeat(64) };
const API_KEY = "sp_test_platform";

function world() {
  const payerKeys = new MemoryPayerKeyStore();
  const mandates = new MemoryMandateStore();
  const service = new PayEnvelopeService<string, string>({ store: new MemoryPayEnvelopeStore(), secrets, payerKeys, mandates });
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  payerKeys.add({ payerId: "alice", keyId: "phone", scheme: "ed25519", publicKey: publicKey.export({ format: "der", type: "spki" }).toString("base64url"), revokedAt: null });
  const dev = generateDevAgentKey();
  payerKeys.add({ payerId: "alice", keyId: "agent-1", scheme: "ecdsa-p256", publicKey: dev.publicKey, revokedAt: null, role: "agent" });
  const created: string[] = [];
  const setRule = (over: Partial<Mandate> = {}) => {
    const mandate: Mandate = {
      v: 1, payerId: "alice", agentKeyId: "agent-1", merchants: ["coffee-co"], currency: "USD",
      maxPerPurchase: 2_000, maxPerDay: 5_000, channel: null,
      expiresAt: new Date(Date.now() + 30 * 86_400_000).toISOString(), nonce: `mandate-${randomBytes(8).toString("hex")}`, ...over,
    };
    mandates.add({ mandate, keyId: "phone", signature: nodeSign(null, mandateChallenge(mandate), privateKey).toString("base64url") });
    return mandate.nonce;
  };
  const calls: string[] = [];
  /** The Pay Envelope API, as far as the agent uses it. */
  const fakeFetch: typeof fetch = async (input, init) => {
    const url = new URL(String(input));
    const method = init?.method ?? "GET";
    calls.push(`${method} ${url.pathname}`);
    const reply = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (new Headers(init?.headers).get("authorization") !== `Bearer ${API_KEY}`) return reply(401, { error: { code: "invalid_api_key", message: "bad key" } });
    let m: RegExpMatchArray | null;
    if (method === "GET" && (m = url.pathname.match(/^\/api\/v1\/pay\/payers\/([^/]+)\/mandates$/))) {
      const since = Date.now() - 86_400_000;
      return reply(200, {
        mandates: [...mandates.mandates.values()]
          .filter((s) => s.signed.mandate.payerId === m![1])
          .map((s) => ({
            mandateId: s.signed.mandate.nonce,
            ...s.signed.mandate,
            revokedAt: s.revokedAt?.toISOString() ?? null,
            spentLast24h: mandates.spend.filter((x) => x.mandateId === s.signed.mandate.nonce && x.at.getTime() >= since).reduce((a, x) => a + x.amount, 0),
          })),
      });
    }
    if (method === "POST" && url.pathname === "/api/v1/pay/envelopes") {
      const body = JSON.parse(String(init!.body));
      try {
        const out = await service.create(
          { merchantId: body.merchantId, amount: body.amount, currency: body.currency, channel: body.channel },
          { userId: "platform", payKeyId: "k" },
          { signedIntent: body.signedIntent as SignedIntent, requireCustomerSignature: true },
        );
        created.push(out.envelopeId);
        return reply(201, { ...out, mode: "simulation" });
      } catch (e) {
        if (e instanceof PayEnvelopeIntentError) return reply(e.code === "intent_replayed" ? 409 : 403, { error: { code: e.code, message: e.message } });
        throw e;
      }
    }
    if (method === "GET" && (m = url.pathname.match(/^\/api\/v1\/pay\/envelopes\/([^/]+)\/status$/))) {
      const e = await service.getStatus(m[1]!, { payKeyId: "k" });
      return e ? reply(200, { envelopeId: e.id, usedAt: e.usedAt?.toISOString() ?? null, expiredAt: null, decision: e.decision }) : reply(404, { error: { code: "not_found", message: "Envelope not found" } });
    }
    return reply(404, { error: { code: "not_found", message: "no route" } });
  };
  const agent = (over: Partial<ConstructorParameters<typeof SpinAgent>[0]> = {}) =>
    new SpinAgent({ baseUrl: "https://spin.test/api/v1/pay/", apiKey: API_KEY, payerId: "alice", signer: p256Signer("agent-1", dev.privateKey), fetch: fakeFetch, ...over });
  return { service, mandates, setRule, agent, dev, calls, created };
}

test("the agent buys within its rule; the card number works once, at that merchant, for that amount", async () => {
  const w = world();
  const ruleId = w.setRule();
  const a = w.agent();
  const rules = await a.rules();
  assert.equal(rules.length, 1);
  assert.equal(rules[0]!.remainingToday, 5_000);

  const r = await a.buy({ merchantId: "coffee-co", amount: 1_250, currency: "usd" });
  assert.ok(r.ok, JSON.stringify(r));
  assert.equal(r.mandateId, ruleId);
  const charge = (merchantId: string, amount: number) =>
    w.service.resolve({ presentation: { pan: r.pan }, txnContext: { merchantId, amount, currency: "USD" } }, { callerMerchantId: merchantId });
  assert.equal((await charge("thief-shop", 1_250)).decision, "DECLINE");
  assert.equal((await charge("coffee-co", 1_250)).decision, "APPROVE");
  assert.equal((await charge("coffee-co", 1_250)).decision, "DECLINE", "single use");
  assert.equal((await a.rules())[0]!.remainingToday, 3_750);

  const s = await a.status(r.envelopeId);
  assert.ok(s.ok && s.status.usedAt);
});

test("outside the rule, the agent gets a plain-language refusal and doesn't ask SPIN for a card", async () => {
  const w = world();
  w.setRule();
  const a = w.agent();
  const cases: [Parameters<SpinAgent["buy"]>[0], RegExp][] = [
    [{ merchantId: "thief-shop", amount: 100, currency: "USD" }, /No standing rule covers merchant "thief-shop"/],
    [{ merchantId: "coffee-co", amount: 100, currency: "EUR" }, /in USD, not EUR/],
    [{ merchantId: "coffee-co", amount: 2_001, currency: "USD" }, /over the per-purchase limit of 20.00 USD/],
  ];
  for (const [p, why] of cases) {
    const r = await a.buy(p);
    assert.ok(!r.ok && r.code === "no_matching_rule" && why.test(r.message), JSON.stringify(r));
  }
  assert.ok(!w.calls.some((c) => c.startsWith("POST")), "no card was requested");
  const none = await world().agent().buy({ merchantId: "coffee-co", amount: 100, currency: "USD" });
  assert.ok(!none.ok && /No active standing rule/.test(none.message));
});

test("the daily limit: three $20 purchases fit under $50 only twice", async () => {
  const w = world();
  w.setRule();
  const a = w.agent();
  assert.ok((await a.buy({ merchantId: "coffee-co", amount: 2_000, currency: "USD" })).ok);
  assert.ok((await a.buy({ merchantId: "coffee-co", amount: 2_000, currency: "USD" })).ok);
  const third = await a.buy({ merchantId: "coffee-co", amount: 2_000, currency: "USD" });
  assert.ok(!third.ok && /10.00 USD is left/.test(third.message), JSON.stringify(third));
});

test("SPIN's server has the last word: a rule revoked after the agent looked, or another agent's key, is refused there", async () => {
  const w = world();
  const ruleId = w.setRule();
  // The agent's view of the rules is stale: the person revoked it a moment ago.
  const a = w.agent();
  const stale = await a.rules();
  w.mandates.revoke("alice", ruleId);
  const sneaky = new SpinAgent({
    baseUrl: "https://spin.test/api/v1/pay", apiKey: API_KEY, payerId: "alice", signer: p256Signer("agent-1", w.dev.privateKey),
    fetch: async (input, init) => {
      if (String(input).endsWith("/mandates")) return new Response(JSON.stringify({ mandates: stale.map((r) => ({ ...r, agentKeyId: "agent-1", revokedAt: null })) }), { status: 200 });
      return (w.agent() as any).fetch(input, init);
    },
  });
  const r = await sneaky.buy({ merchantId: "coffee-co", amount: 100, currency: "USD" });
  assert.ok(!r.ok && r.code === "mandate_invalid", JSON.stringify(r));

  // A key that isn't the enrolled agent key: the rule isn't listed for it, and forcing the request still fails.
  w.setRule();
  const impostor = w.agent({ signer: p256Signer("agent-1", p256.utils.randomSecretKey()) });
  const r2 = await impostor.buy({ merchantId: "coffee-co", amount: 100, currency: "USD" });
  assert.ok(!r2.ok && r2.code === "intent_invalid", JSON.stringify(r2));
});

test("a wrong API key is reported, not thrown", async () => {
  const w = world();
  w.setRule();
  const r = await w.agent({ apiKey: "sp_test_wrong" }).buy({ merchantId: "coffee-co", amount: 100, currency: "USD" });
  assert.ok(!r.ok && r.code === "invalid_api_key");
});

test("awsKmsSigner asks KMS to sign the challenge (RAW, ECDSA_SHA_256), and the result verifies", async () => {
  const dev = generateDevAgentKey();
  const seen: unknown[] = [];
  const kms: KmsLike = {
    async sign(input) {
      seen.push(input);
      // What KMS does with MessageType RAW: SHA-256 the message, then sign; DER out.
      return { Signature: p256.sign(input.Message, dev.privateKey, { format: "der" }) };
    },
  };
  const signer = awsKmsSigner({ keyId: "agent-1", kmsKeyId: "arn:aws:kms:us-east-1:1:key/abc", kms });
  const { newIntent, intentChallenge } = await import("../src/approval/index.js");
  const intent = newIntent({ payerId: "alice", merchantId: "coffee-co", amount: 450, currency: "USD", mandateId: "mandate-0123456789ab" });
  const sig = Buffer.from(await signer.sign(intentChallenge(intent))).toString("base64url");
  assert.equal((seen[0] as any).MessageType, "RAW");
  assert.equal((seen[0] as any).SigningAlgorithm, "ECDSA_SHA_256");
  assert.equal(verifySignedIntent({ intent, keyId: "agent-1", signature: sig }, { payerId: "alice", keyId: "agent-1", scheme: "ecdsa-p256", publicKey: dev.publicKey, revokedAt: null, role: "agent" }), true);
  // The SPKI the dev helper reports is the one the enrollment API takes.
  assert.equal(Buffer.from(dev.spki, "base64url").subarray(-65).toString("base64url"), dev.publicKey);
});

test("MCP: initialize, list tools, buy with a decimal amount, refusals come back as tool errors", async () => {
  const w = world();
  w.setRule();
  const handle = createSpinMcpHandler(w.agent());
  const rpc = async (id: number, method: string, params?: object) => (await handle({ jsonrpc: "2.0", id, method, params })) as any;

  const init = await rpc(1, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1" } });
  assert.equal(init.result.protocolVersion, "2025-06-18");
  assert.ok(init.result.capabilities.tools);
  assert.equal(await handle({ jsonrpc: "2.0", method: "notifications/initialized" }), null);
  assert.equal((await rpc(9, "initialize", { protocolVersion: "1999-01-01" })).result.protocolVersion, "2025-06-18");

  const tools = (await rpc(2, "tools/list")).result.tools.map((t: { name: string }) => t.name);
  assert.deepEqual(tools, ["spin_rules", "spin_buy", "spin_purchase_status"]);

  const rules = (await rpc(3, "tools/call", { name: "spin_rules", arguments: {} })).result;
  assert.match(rules.content[0].text, /coffee-co: up to 20\.00 USD per purchase, 50\.00 of 50\.00 USD left/);

  const buy = (await rpc(4, "tools/call", { name: "spin_buy", arguments: { merchantId: "coffee-co", amount: "12.50", currency: "usd" } })).result;
  assert.equal(buy.isError, undefined, JSON.stringify(buy));
  assert.equal(buy.structuredContent.amount, "12.50");
  assert.match(buy.content[0].text, /works once, at coffee-co, for exactly 12\.50 USD/);
  const status = (await rpc(5, "tools/call", { name: "spin_purchase_status", arguments: { envelopeId: buy.structuredContent.envelopeId } })).result;
  assert.match(status.content[0].text, /not used yet/);

  const refused = (await rpc(6, "tools/call", { name: "spin_buy", arguments: { merchantId: "thief-shop", amount: "5", currency: "USD" } })).result;
  assert.equal(refused.isError, true);
  assert.match(refused.content[0].text, /SPIN refused \(no_matching_rule\)/);

  const bad = (await rpc(7, "tools/call", { name: "spin_buy", arguments: { merchantId: "coffee-co", amount: "12.505", currency: "USD" } })).result;
  assert.equal(bad.isError, true);
  assert.equal((await rpc(8, "tools/call", { name: "spin_transfer_all", arguments: {} })).error.code, -32602);
  assert.equal((await rpc(10, "resources/list")).error.code, -32601);
  assert.equal(((await handle({ nope: true })) as any).error.code, -32600);
});

test("MCP: the model never sees the API key or the signing key", async () => {
  const w = world();
  w.setRule();
  const handle = createSpinMcpHandler(w.agent());
  const out = JSON.stringify([
    await handle({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
    await handle({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
    await handle({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "spin_rules", arguments: {} } }),
    await handle({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "spin_buy", arguments: { merchantId: "coffee-co", amount: "1", currency: "USD" } } }),
  ]);
  assert.ok(!out.includes(API_KEY));
  assert.ok(!out.includes(Buffer.from(w.dev.privateKey).toString("hex")));
  assert.ok(!out.includes(Buffer.from(w.dev.privateKey).toString("base64url")));
});
