/**
 * Test stand-ins for the devices that sign read mandates and read requests:
 * a native app key (Ed25519) and a passkey (WebAuthn ES256), producing the
 * same bytes real devices do.
 */
import { createHash, generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { p256 } from "@noble/curves/nist.js";
import type { DataKey, KeyProof } from "../../src/data/index.js";

const b64u = (b: Uint8Array | Buffer) => Buffer.from(b).toString("base64url");

export const RP = { rpId: "records.example.com", origins: ["https://records.example.com"] };

export interface SigningDevice {
  key: DataKey;
  /** Sign a 32-byte challenge the way this device would. */
  prove(challenge: Uint8Array): KeyProof;
}

export function ed25519Signer(ownerId: string, keyId = `${ownerId}-phone`): SigningDevice {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    key: { ownerId, keyId, scheme: "ed25519", publicKey: b64u(publicKey.export({ type: "spki", format: "der" })), revokedAt: null },
    prove: (challenge) => ({ signature: b64u(nodeSign(null, challenge, privateKey)) }),
  };
}

export function passkeySigner(ownerId: string, keyId = `${ownerId}-passkey`, opts: { flags?: number } = {}): SigningDevice {
  const priv = p256.utils.randomSecretKey();
  const pub = p256.getPublicKey(priv, false);
  return {
    key: { ownerId, keyId, scheme: "webauthn-es256", publicKey: b64u(pub), revokedAt: null },
    prove: (challenge) => {
      const clientDataJSON = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: b64u(challenge), origin: RP.origins[0] }), "utf8");
      const authData = Buffer.concat([
        createHash("sha256").update(RP.rpId).digest(),
        Buffer.from([opts.flags ?? 0x05]), // user present + user verified
        Buffer.from([0, 0, 0, 1]),
      ]);
      const signed = Buffer.concat([authData, createHash("sha256").update(clientDataJSON).digest()]);
      return {
        signature: b64u(p256.sign(signed, priv, { format: "der" })),
        authenticatorData: b64u(authData),
        clientDataJSON: b64u(clientDataJSON),
      };
    },
  };
}
