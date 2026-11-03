# Payments by AI agents: mandates

Status: in @spin/core 0.12 (2026-11-03). Builds on the customer-signed intent
(`customer-signed-intent.md`) and the approval kit (`approval-screen.md`).

## The problem

An AI agent that holds a card number can be tricked into leaking it, or
hijacked into spending it anywhere. Even with SPIN's single-use numbers, an
agent that can sign purchases freely can be steered into paying the wrong
merchant or paying too much.

## How it works

1. **The agent gets its own key**, enrolled to the person's account with role
   `agent`. It should live in a cloud key service or HSM: the `ecdsa-p256`
   scheme verifies what AWS KMS (`ECC_NIST_P256`), Google Cloud KMS and Azure
   Key Vault produce (DER or compact signatures over SHA-256).
2. **The person signs a mandate once**, on their own device: which agent key,
   which merchants (1 to 50), maximum per purchase, maximum per rolling 24
   hours, currency, channel, expiry. Challenge:
   `SHA-256("spin/mandate/v1\n" + canonicalMandate(m))`.
3. **The agent signs each purchase** with its key, naming the mandate
   (`intent.mandateId`, covered by the signature).
4. **`PayEnvelopeService.create` checks**, before the approval is spent:
   - the key is an agent key and the intent names a mandate (else `mandate_required`);
   - the mandate exists, isn't revoked or expired, names this agent, and is
     still signed by an active device of the same person (else `mandate_invalid`);
   - merchant, amount, currency and channel fit (else `mandate_mismatch`);
   - the amount fits the 24-hour cap, reserved atomically (else `mandate_limit`).

   A failed create gives the reservation back.

## Rules that keep it safe

- An agent key can only buy under a mandate. It can't sign a mandate (even
  for itself), and apps must not accept it for device enrollments or
  revocations.
- Adding an agent key needs an enrollment approval with `newKey.role:
  "agent"`, covered by the person's signature: an approval to add an agent
  can't be replayed to add a full device.
- A person's own device signs purchases without a mandate and may not claim one.
- Revoking the device that signed a mandate revokes the mandate.
- A mandate edited after signing fails its signature check on every purchase.
- Intents without a mandate keep their original bytes, so existing approvals
  are unaffected.

## Stores

`MandateStore`: `findMandate`, and `reserveMandateSpend` /
`releaseMandateSpend`, which must be atomic per mandate.
`mandateStoreConformance` (in `@spin/core/testing`) checks implementations,
including 20 simultaneous reservations against one cap. `PayerKeyStore`
implementations must keep each key's `role`.

## Not yet

- Step-up approval for purchases outside a mandate (a prompt on the person's
  phone) instead of a refusal.
- Mandates on the Stripe Issuing path (SPIN Pay's card intents).
- Merchant categories instead of a merchant list.
