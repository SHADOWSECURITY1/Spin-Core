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

### Behaviour changes from the per-app copies

| Was | Now |
|---|---|
| Idempotency key looked up globally, so another merchant could get your envelope and PAN | Scoped to the API key; a mismatched reuse is a conflict |
| Omitting `channel` on resolve skipped the channel check | Required when the envelope is channel-bound |
| `expire` / `getStatus` worked on any envelope id | Pass `{ payKeyId }` to restrict to the owning key |
| TTL had a 10 s floor only | Clamped to 10 s – 3600 s |
| Amount tolerance: SPIN-Envelope stored ‰, SPIN-Vault ppm, floating-point compare | ppm everywhere, exact integer compare |
| A new PAN could collide with an existing one | Regenerated until unused |

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

**Forward secrecy, known limits (v1, unchanged):** no DH ratchet, so no
post-compromise security; out-of-order messages behind the chain are
unreadable; the responder doesn't check the handshake's initiator identity
against the sender's known key; and if both sides open a session at the same
moment, each keeps its own and the other's first messages read as
`[expired]`.

**Wire format: unchanged.** Field names and encodings are exactly what SPIN
Vault web and mobile already store. `test/fixtures/` holds payloads produced
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
  async findByPan(pan) {
    const [row] = await db.select().from(payEnvelopes)
      .where(eq(payEnvelopes.presentationPan, pan))
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
