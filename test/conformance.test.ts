import { test } from "node:test";
import assert from "node:assert/strict";
import { MemoryPayEnvelopeStore } from "../src/index.js";
import { payEnvelopeStoreConformance } from "../src/testing/index.js";

const ids = { userA: "user_a", keyA: "key_a", userB: "user_b", keyB: "key_b" };

for (const c of payEnvelopeStoreConformance({ makeStore: () => new MemoryPayEnvelopeStore(), ids })) {
  test(`MemoryPayEnvelopeStore: ${c.name}`, c.run);
}

/** Read, await, then write: the shape of the original SPIN-Envelope bug. */
class ReadThenWriteStore extends MemoryPayEnvelopeStore {
  override async claim(id: string, now: Date, auditRef: string) {
    const snapshot = await this.findById(id);
    if (!snapshot || snapshot.usedAt || snapshot.expiredAt || snapshot.expiresAt <= now) return false;
    await new Promise((r) => setImmediate(r));
    const e = this.envelopes.get(id)!;
    e.usedAt = now;
    e.decision = "APPROVE";
    e.auditRef = auditRef;
    return true;
  }
}

test("the conformance suite catches a store whose claim is not atomic", async () => {
  const cases = payEnvelopeStoreConformance({ makeStore: () => new ReadThenWriteStore(), ids });
  const concurrent = cases.find((c) => c.name.includes("concurrent claims"))!;
  await assert.rejects(concurrent.run(), /claims succeeded/);
});
