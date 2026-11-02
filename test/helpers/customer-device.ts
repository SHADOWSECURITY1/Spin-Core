/**
 * Test stand-ins for customer devices: a native app key (Ed25519, or the
 * post-quantum hybrid) and a passkey authenticator (WebAuthn ES256 / Secure
 * Payment Confirmation), producing the same bytes real devices do.
 */
import { createHash, generateKeyPairSync, randomBytes, sign as nodeSign, type KeyObject } from "node:crypto";
import { p256 } from "@noble/curves/nist.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { intentChallenge, type CustomerIntent, type PayerKey, type SignedIntent } from "../../src/index.js";

const b64u = (b: Uint8Array | Buffer) => Buffer.from(b).toString("base64url");

export function intentFor(payerId: string, over: Partial<CustomerIntent> = {}, now = new Date()): CustomerIntent {
  return {
    v: 1,
    payerId,
    merchantId: "coffee-co",
    amount: 450,
    currency: "USD",
    channel: "CNP",
    expiresAt: new Date(now.getTime() + 5 * 60_000).toISOString(),
    nonce: randomBytes(16).toString("hex"),
    ...over,
  };
}

export interface Device {
  key: PayerKey;
  sign(intent: CustomerIntent): SignedIntent;
}

export function ed25519Device(payerId: string, keyId = "phone-1"): Device {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    key: { payerId, keyId, scheme: "ed25519", publicKey: b64u(publicKey.export({ type: "spki", format: "der" })), revokedAt: null },
    sign: (intent) => ({ intent, keyId, signature: b64u(nodeSign(null, intentChallenge(intent), privateKey)) }),
  };
}

export function hybridDevice(payerId: string, keyId = "phone-pq"): Device {
  const ed = generateKeyPairSync("ed25519");
  const pq = ml_dsa65.keygen();
  const edPub = b64u(ed.publicKey.export({ type: "spki", format: "der" }));
  return {
    key: { payerId, keyId, scheme: "hybrid-ed25519-mldsa65", publicKey: `${edPub}.${b64u(pq.publicKey)}`, revokedAt: null },
    sign: (intent) => {
      const msg = intentChallenge(intent);
      const edSig = nodeSign(null, msg, ed.privateKey as KeyObject);
      return { intent, keyId, signature: `${b64u(edSig)}.${b64u(ml_dsa65.sign(msg, pq.secretKey))}` };
    },
  };
}

export const RP = { rpId: "pay.example.com", origins: ["https://pay.example.com"] };

/** A passkey authenticator. Options let tests produce the faulty assertions an attacker might send. */
export function passkeyDevice(
  payerId: string,
  keyId = "passkey-1",
): Device & {
  signWith(intent: CustomerIntent, o: { type?: string; origin?: string; rpId?: string; flags?: number; total?: { currency: string; value: string } }): SignedIntent;
} {
  const priv = p256.utils.randomSecretKey();
  const pub = p256.getPublicKey(priv, false); // 65-byte uncompressed point
  const signWith: ReturnType<typeof passkeyDevice>["signWith"] = (intent, o) => {
    const clientData: Record<string, unknown> = {
      type: o.type ?? "webauthn.get",
      challenge: b64u(intentChallenge(intent)),
      origin: o.origin ?? RP.origins[0],
    };
    if (o.total) clientData.payment = { rpId: RP.rpId, total: o.total };
    const clientDataJSON = Buffer.from(JSON.stringify(clientData), "utf8");
    const authData = Buffer.concat([
      createHash("sha256").update(o.rpId ?? RP.rpId).digest(),
      Buffer.from([o.flags ?? 0x05]), // user present + user verified
      Buffer.from([0, 0, 0, 1]), // sign count
    ]);
    const signed = Buffer.concat([authData, createHash("sha256").update(clientDataJSON).digest()]);
    const sig = p256.sign(signed, priv, { format: "der" });
    return { intent, keyId, signature: b64u(sig), authenticatorData: b64u(authData), clientDataJSON: b64u(clientDataJSON) };
  };
  return {
    key: { payerId, keyId, scheme: "webauthn-es256", publicKey: b64u(pub), revokedAt: null },
    sign: (intent) => signWith(intent, {}),
    signWith,
  };
}
