# @spin/core

The shared SPIN security core. One implementation of the security-critical
logic, used by SPIN, SPIN-Envelope and SPIN-Vault, instead of a copy in each.

**v0.1** ships the **Pay Envelope**: single-use, short-lived, context-bound
payment credentials. Vault and messaging crypto, the post-quantum suite
registry, device-key proofs and the key provider follow in later versions.

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

## Install

Pinned to a tag, as a git dependency:

```json
"dependencies": {
  "@spin/core": "github:SHADOWSECURITY1/Spin-Core#v0.1.0"
}
```

The repo is private, so npm needs GitHub read access where it installs. On
Replit, add a secret holding a fine-grained token with read-only *Contents*
access to this repo, and point git at it once:

```sh
git config --global url."https://x-access-token:${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"
```

npm runs `prepare` on install, which builds `dist/`.

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

1. **v0.1:** Pay Envelope (this release)
2. Vault and messaging crypto (web and mobile share one implementation)
3. Post-quantum suite registry, crypto inventory, device-key proofs
4. One key-provider interface (env today, KMS/HSM later)
