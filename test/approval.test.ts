/**
 * The approval kit (@spin/core/approval): the screen text and the signature
 * come from the same intent, and what it signs verifies on the server.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { intentChallenge as serverChallenge, verifySignedIntent, type PayerKey } from "../src/index.js";
import {
  approveIntent,
  approveWithSecurePaymentConfirmation,
  describeIntent,
  formatAmount,
  intentChallenge,
  newIntent,
  toBase64Url,
} from "../src/approval/index.js";
import { intentFor } from "./helpers/customer-device.js";

const coffee = { name: "Coffee Co.", verified: true, onSpinSince: "2026-03-15T00:00:00Z" };

function appKey(payerId: string) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const key: PayerKey = {
    payerId,
    keyId: "phone",
    scheme: "ed25519",
    publicKey: publicKey.export({ format: "der", type: "spki" }).toString("base64url"),
    revokedAt: null,
  };
  return { key, sign: async (c: Uint8Array) => new Uint8Array(nodeSign(null, c, privateKey)) };
}

test("the device computes the same challenge as the server, with no Node APIs", () => {
  for (const i of [intentFor("alice"), intentFor("bob", { merchantId: "café-ünïcode", channel: null, currency: "JPY", amount: 500 })]) {
    assert.deepEqual(intentChallenge(i), new Uint8Array(serverChallenge(i)));
  }
  assert.equal(toBase64Url(new Uint8Array([251, 255, 0])), Buffer.from([251, 255, 0]).toString("base64url"));
  assert.equal(toBase64Url(new Uint8Array([1, 2, 3, 4])), Buffer.from([1, 2, 3, 4]).toString("base64url"));
});

test("the screen says exactly what is signed, with warnings for new or unverified payees", () => {
  const i = intentFor("alice");
  const d = describeIntent(i, coffee, "en-US");
  assert.equal(d.title, "Pay $4.50 to Coffee Co.");
  assert.deepEqual(d.details, ["Verified business", "On SPIN since March 2026", "Online payment"]);
  assert.deepEqual(d.warnings, []);
  const scam = describeIntent(i, { name: "Gadget Outlet", verified: false, firstTime: true }, "en-US");
  assert.equal(scam.warnings.length, 2);
  assert.match(scam.warnings[0]!, /haven't paid Gadget Outlet before/);
  assert.match(scam.warnings[1]!, /hasn't verified Gadget Outlet/);
  assert.equal(formatAmount(500, "JPY", "en-US"), "¥500");
});

test("approveIntent: shown, then signed; the signature verifies on the server", async () => {
  const { key, sign } = appKey("alice");
  const intent = newIntent({ payerId: "alice", merchantId: "coffee-co", amount: 450, currency: "USD", channel: "CNP" });
  let shown = "";
  const si = await approveIntent({
    intent,
    payee: coffee,
    keyId: "phone",
    confirm: async (d) => ((shown = d.title), true),
    sign,
    locale: "en-US",
  });
  assert.equal(shown, "Pay $4.50 to Coffee Co.");
  assert.ok(si);
  assert.equal(verifySignedIntent(si as never, key), true);
  // Changing the intent after approval breaks the signature.
  assert.equal(verifySignedIntent({ ...(si as object), intent: { ...si!.intent, amount: 45000 } } as never, key), false);
});

test("approveIntent: if the customer declines, nothing is signed", async () => {
  let signed = false;
  const si = await approveIntent({
    intent: intentFor("alice"),
    payee: coffee,
    keyId: "phone",
    confirm: async () => false,
    sign: async () => ((signed = true), new Uint8Array(64)),
  });
  assert.equal(si, null);
  assert.equal(signed, false);
  await assert.rejects(approveIntent({ intent: { ...intentFor("alice"), amount: -1 }, payee: coffee, keyId: "k", confirm: async () => true, sign: async () => new Uint8Array() }));
});

test("Secure Payment Confirmation: the browser is asked to show the approved total and payee, over the intent's challenge", async () => {
  const intent = intentFor("alice");
  let captured: { methods: any[]; details: any } | null = null;
  const fake = {
    response: { signature: new Uint8Array([1]).buffer, authenticatorData: new Uint8Array([2]).buffer, clientDataJSON: new Uint8Array([3]).buffer },
  };
  (globalThis as any).PaymentRequest = class {
    constructor(methods: any[], details: any) {
      captured = { methods, details };
    }
    async show() {
      return { details: fake, complete: async () => {} };
    }
  };
  try {
    const si = await approveWithSecurePaymentConfirmation({
      intent,
      payee: coffee,
      keyId: "passkey-1",
      rpId: "pay.example.com",
      credentialId: new Uint8Array([9, 9]),
      instrument: { displayName: "SPIN card", icon: "https://pay.example.com/icon.png" },
    });
    const data = captured!.methods[0].data;
    assert.equal(captured!.methods[0].supportedMethods, "secure-payment-confirmation");
    assert.equal(data.payeeName, "Coffee Co.");
    assert.deepEqual(data.challenge, intentChallenge(intent));
    assert.deepEqual(captured!.details.total.amount, { currency: "USD", value: "4.50" });
    assert.deepEqual([si.signature, si.authenticatorData, si.clientDataJSON], ["AQ", "Ag", "Aw"]);
  } finally {
    delete (globalThis as any).PaymentRequest;
  }
});
