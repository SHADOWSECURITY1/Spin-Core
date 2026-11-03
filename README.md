# @spin/core

The shared SPIN security core. One implementation of the security-critical
logic, used by SPIN, SPIN-Envelope and SPIN-Vault, instead of a copy in each.

- **Pay Envelope** (v0.1): single-use, short-lived, context-bound payment
  credentials. `import … from "@spin/core"` (Node).
- **Vault crypto** (v0.2–0.3): SPIN Vault's zero-knowledge files, hybrid
  post-quantum messaging and forward-secret messaging, one implementation for
  web, Node and React Native.
  `import … from "@spin/core/vault"`.

## What's in v0.1

| Export | What it does |
|---|---|
| `PayEnvelopeService` | create / resolve / expire / getStatus, over any store |
| `PayEnvelopeStore` | the storage contract each app implements over its own tables |
| `MemoryPayEnvelopeStore` | in-process store for tests and tooling |
| `resolvePayEnvelopeSecrets` | reads `PAY_ENVELOPE_HMAC_SECRET` / `PAY_ENVELOPE_JWS_SECRET`, fails closed |
| `signReceipt` / `verifyReceipt` | HS256 JWS receipts (same wire format the apps issue today, plus a verifier) |
| `generatePayEnvelopeKey` / `validatePayEnvelopeKey` | merchant API keys, stored as SHA-256 hashes |
| `planResolution`, `amountWithinTolerance`, Luhn helpers | the pure decision logic |
| `@spin/core/testing` → `payEnvelopeStoreConformance` | the suite every store must pass |

## Guarantees

- **Single use.** Approval goes through the store's atomic `claim`. Concurrent
  resolves of one envelope approve exactly once. The conformance suite fails
  any store that reads and then writes in two steps, the shape of the bug that
  let SPIN-Envelope approve one envelope five times.
- **Approvals can't be rewritten.** A racing declined request can't overwrite
  a recorded APPROVE. A manual expire can't succeed on a spent envelope.
- **Secrets fail closed.** Missing, short, placeholder or reused secrets throw,
  whatever `NODE_ENV` says. Local dev can opt in with
  `PAY_ENVELOPE_DEV_SECRETS=random` (refused in production).
- **Idempotency is per API key.** A reused idempotency key returns the original
  envelope only to the key that created it, and only with identical
  parameters. Otherwise it throws `PayEnvelopeIdempotencyConflictError`.
- **Context binding is strict.** An envelope created for a channel requires the
  resolve request to state the same channel. Merchant, currency and amount
  (within tolerance) must match.
- **Misuse at its own merchant burns the envelope** (0.5; narrowed in 0.9).
  A number presented by its own merchant with the wrong amount, currency or
  channel never works again: later attempts get `PREVIOUSLY_DECLINED`, and
  `claim` refuses declined envelopes atomically. **Another merchant**
  presenting it is declined and reported (a `declined` event with
  `burned: false` and `wrongMerchant`), but doesn't burn it: the number only
  ever pays its own merchant, and burning let anyone with leaked numbers and
  a merchant account destroy customers' payments.
- **No card numbers at rest** (0.5). The store keeps a keyed fingerprint
  (`presentationPanDigest`), never the number. The number is recomputed from
  the envelope's details and the HMAC secret when needed.
- **Breach-tested.** `test/breach.test.ts` gives an attacker SPIN's whole
  database, every merchant's logs and 20,000 targeted guesses while envelopes
  are live, and requires zero approvals. It also gives a fraudster live
  stolen numbers, the merchants they're locked to and their own valid API
  key: they can't pose as the merchant, and can't destroy the customers' payments.
- **Customer-signed intent** (0.8). `create(input, owner, { signedIntent,
  requireCustomerSignature })` creates a credential only from an approval the
  customer signed on an enrolled device (native key: Ed25519 or post-quantum
  Ed25519 + ML-DSA-65; web: passkey / Secure Payment Confirmation) for exactly
  that payee, amount, currency, channel and expiry, used once. The approval is
  embedded in the receipt as dispute evidence. Apps provide a `PayerKeyStore`
  (enrolled public keys, spent nonces) that passes
  `payerKeyStoreConformance`. Adding a device to an existing customer needs
  an existing device's signed approval (`enrollmentChallenge`,
  `verifyKeySignature`), so a stolen API key can't enroll an attacker's phone.
  Design: `docs/design/customer-signed-intent.md`.
- **Callers authorize only as themselves** (0.7). `resolve(input,
  { callerMerchantId })` takes the merchant from the app's authentication
  (the API key's merchant, or the card network's verified merchant id), not
  from the request. Apps that let API callers resolve must pass it.
- **Keys can live in hardware** (0.6). Card numbers and their fingerprints
  come from a `PanKeyring`. With `remotePanKeyring` (KMS/HSM), the breach test
  shows the database plus every secret on the app server recomputes nothing;
  an attacker can only ask the key service, which rate-limits and logs. With
  the default `softwarePanKeyring` (the HMAC secret in the environment), the
  database plus that secret can recompute live numbers: fine for the sandbox,
  not for production.

### Behaviour changes from the per-app copies

| Was | Now |
|---|---|
| Idempotency key looked up globally, so another merchant could get your envelope and PAN | Scoped to the API key; a mismatched reuse is a conflict |
| Omitting `channel` on resolve skipped the channel check | Required when the envelope is channel-bound |
| `expire` / `getStatus` worked on any envelope id | Pass `{ payKeyId }` to restrict to the owning key |
| TTL had a 10 s floor only | Clamped to 10 s – 3600 s |
| Amount tolerance: SPIN-Envelope stored ‰, SPIN-Vault ppm, floating-point compare | ppm everywhere, exact integer compare |
| A new PAN could collide with an existing one | Regenerated until unused |

## Approval kit (`@spin/core/approval`)

The customer's side of an approval, for browsers and React Native (no Node
APIs). The screen text and the signature come from the same intent, so what
the customer sees is what their device signs:

- `approveWithSecurePaymentConfirmation()`: the browser draws the payee and
  total itself; the server checks both (`PayEnvelopeService`'s `payeeName`
  option supplies the merchant's verified name). Chrome and Edge today.
- `approveIntent({ intent, payee, keyId, confirm, sign })`: everywhere else.
  `confirm` gets only `describeIntent()`'s text (amount, payee, verified,
  first-time warnings); `sign` gets only that intent's challenge.
- `newIntent()`, `intentChallenge()`, `formatAmount()`, `signWithPasskey()`.

Limits: see `docs/design/approval-screen.md`.

## Vault crypto (`@spin/core/vault`)

Zero-knowledge storage and messaging for SPIN Vault. No Node imports, so it
bundles for browsers and React Native (Hermes). Always import the subpath:
the package root contains Node-only code.

| | |
|---|---|
| Master key | PBKDF2-SHA256, 210 000 iterations. `deriveWebCryptoMasterKey()` gives a **non-extractable** Web Crypto key (web); `deriveMasterKeyBytes()` + `rawMasterKey()` give raw bytes for the OS secure store (mobile). Same key material, interchangeable ciphertexts. |
| Files | `encryptFile` / `decryptFile` / `rewrapFileDek`: per-file random AES-256-GCM DEK, sealed with the master key. |
| Identity | `generateX25519Identity`, `generateKyberKeyPair` + `wrapKyberSecretKey`, unwrap and rewrap (password change). |
| Messages | `encryptMessage` / `decryptMessage`: hybrid X25519 + ML-KEM-768. The DEK's wrapping key is HKDF of **both** shared secrets, so breaking one KEM isn't enough. |
| Forward secrecy | `ensurePrekeyPool` / `sendMessage` / `decryptIncoming` over an app-supplied `FsTransport`; underneath, a PQXDH-style handshake (3 × X25519 + 2 × ML-KEM-768 with one-time prekeys) into a symmetric-key ratchet. Read messages expire as the chain moves on. Session state is sealed with the master key for server storage. |

**Forward secrecy, identity and simultaneous starts (0.4).** Apps supply
`FsTransport.getIdentityKey(peerId)` (a pinned key if the app has one). A
handshake is accepted only if it names the sender's known identity key, and
the one-time prekey is deleted only after the first message decrypts, so a
forged handshake reads `[Unverified sender]` or `[Unreadable]` and costs
nothing. If both sides open a session at once, both converge on the one
opened by the lower identity key; the other stays receive-only, so every
first message still reads. Session state is now a small store (v2) that
still reads v1 sessions.

**Known limits:** no DH ratchet, so no post-compromise security; out-of-order
messages behind the chain are unreadable.

**Wire format: compatible.** Field names and encodings are what SPIN Vault
web and mobile already store; 0.4 adds a session id to `ratchetHeader` and
the v2 session store, and still reads everything written before. `test/fixtures/` holds payloads produced
by the real pre-`@spin/core` web and mobile code; the tests must keep opening
them. Changing the format means a new version label, not editing v1.

**React Native:** Hermes has no `crypto.getRandomValues`, and older Hermes
versions lack `TextEncoder`/`TextDecoder`. Load polyfills first in `index.js`:

```js
import 'react-native-get-random-values';
import 'fast-text-encoding';
```

Without a random source, `@spin/core/vault` throws rather than use a weak one.
`@spin/core`'s own code does its UTF-8 in plain JavaScript, but `@noble/curves`
2.x calls `TextEncoder` while loading. Bundlers without package `exports` support resolve
`@spin/core/vault` through `vault/package.json`.

## Install

Pinned to a commit (or a tag, once one exists), as a git dependency:

```json
"dependencies": {
  "@spin/core": "github:SHADOWSECURITY1/Spin-Core#<commit>"
}
```

The repo is public, so no token is needed. npm runs `prepare` on install,
which builds `dist/`. Upgrade by changing the pinned commit.

## Using it

```ts
import { PayEnvelopeService } from "@spin/core";

const payEnvelopes = new PayEnvelopeService<string, string>({ store: myStore });
// throws PayEnvelopeConfigError if the secrets are missing or weak

await payEnvelopes.create(input, { userId, payKeyId });
await payEnvelopes.resolve({ presentation: { pan }, txnContext });
await payEnvelopes.expire(id, { payKeyId });
```

### Writing a store (Drizzle + Postgres)

The only part that needs care is `claim`: one conditional `UPDATE`.

```ts
import { and, desc, eq, gt, isNull } from "drizzle-orm";
import type { PayEnvelopeStore } from "@spin/core";

export const drizzlePayEnvelopeStore: PayEnvelopeStore<string, string> = {
  async claim(id, now, auditRef) {
    const rows = await db
      .update(payEnvelopes)
      .set({ usedAt: now, decision: "APPROVE", declineReason: null, auditRef })
      .where(and(
        eq(payEnvelopes.id, id),
        isNull(payEnvelopes.usedAt),
        isNull(payEnvelopes.expiredAt),
        isNull(payEnvelopes.decision), // a decline burns the envelope
        gt(payEnvelopes.expiresAt, now),
      ))
      .returning({ id: payEnvelopes.id });
    return rows.length === 1;
  },
  async markDeclined(id, reason, auditRef) {
    await db.update(payEnvelopes)
      .set({ decision: "DECLINE", declineReason: reason, auditRef })
      .where(and(eq(payEnvelopes.id, id), isNull(payEnvelopes.usedAt)));
  },
  async markExpired(id, at) {
    const rows = await db.update(payEnvelopes)
      .set({ expiredAt: at })
      .where(and(eq(payEnvelopes.id, id), isNull(payEnvelopes.usedAt), isNull(payEnvelopes.expiredAt)))
      .returning({ id: payEnvelopes.id });
    return rows.length === 1;
  },
  async findByPanDigest(digest) {
    const [row] = await db.select().from(payEnvelopes)
      .where(eq(payEnvelopes.presentationPanDigest, digest))
      .orderBy(desc(payEnvelopes.createdAt)).limit(1);
    return row ? toRecord(row) : null;
  },
  async findByIdempotencyKey(payKeyId, key) {
    const [row] = await db.select().from(payEnvelopes)
      .where(and(eq(payEnvelopes.payKeyId, payKeyId), eq(payEnvelopes.idempotencyKey, key)))
      .limit(1);
    return row ? toRecord(row) : null;
  },
  // findById, insert, recordEvent: plain select / insert, mapping columns.
};
```

### Keeping the card-number keys in hardware

`PayEnvelopeService` takes a `keyring`. Without one it uses
`softwarePanKeyring(PAY_ENVELOPE_HMAC_SECRET)`, the same keys as 0.5. In
production, keep the keys in a key service so they can't be copied off the
server. AWS KMS, with two `HMAC_256` keys:

```ts
import { KMSClient, GenerateMacCommand } from "@aws-sdk/client-kms";
import { PayEnvelopeService, remotePanKeyring } from "@spin/core";

const kms = new KMSClient({});
const keyId = { "pan-derive": "alias/spin-pan-derive", "pan-fingerprint": "alias/spin-pan-fingerprint" };
const keyring = remotePanKeyring({
  description: "aws-kms",
  mac: async (purpose, data) =>
    (await kms.send(new GenerateMacCommand({ KeyId: keyId[purpose], Message: data, MacAlgorithm: "HMAC_SHA_256" }))).Mac!,
});
const service = new PayEnvelopeService({ store, keyring }); // PAY_ENVELOPE_HMAC_SECRET no longer needed
```

A keyring error fails closed (`PayEnvelopeKeyringError`): no envelope is
created and nothing is approved. Switching keyrings changes every number and
fingerprint, so envelopes live at the switch stop working (an hour at most).

Then prove it in the app's tests against a real Postgres (PGlite works):

```ts
import { test } from "node:test";
import { payEnvelopeStoreConformance } from "@spin/core/testing";

for (const c of payEnvelopeStoreConformance({
  makeStore: () => drizzlePayEnvelopeStore,
  ids: { userA: "u1", keyA: "k1", userB: "u2", keyB: "k2" },
})) test(c.name, c.run);
```

## Development

```sh
npm install
npm test        # node:test via tsx
npm run check   # tsc --noEmit
npm run build   # dist/
```

## Roadmap

1. **v0.1:** Pay Envelope
2. **v0.2:** Vault and messaging crypto (this release)
3. **v0.3:** Forward-secret messaging (ratchet + orchestration), shared by web and mobile
4. Post-quantum suite registry, crypto inventory, device-key proofs
5. One key-provider interface (env today, KMS/HSM later)

## License

[Business Source License 1.1](LICENSE). You can read, copy, modify and use
Spin-Core, including in production, except to offer a competing service:
one that issues, authorizes or validates payment credentials, or approves or
co-signs payments or digital-asset transfers, for others. Each version becomes
Apache-2.0 four years after its release. For other arrangements, email
info@spinpay.ai.

The approach is patent pending. This license grants no patent rights beyond
the use it permits.
