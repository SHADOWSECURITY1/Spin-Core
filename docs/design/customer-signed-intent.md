# Step 2: customer-signed intent

Status: phase 1 core implemented in @spin/core 0.8.0 (2026-11-02): intent
format, the three signature schemes, `PayerKeyStore` + conformance suite,
create-time checks, approval in the receipt, breach tests 1-4. Next: SPIN Pay
enrollment endpoints, tables, per-key flag, docs, browser helper. Builds on
the Pay Envelope (0.7), the breach test, and the PanKeyring.

## The problem

SPIN Pay knows that **an API key** asked for a credential bound to a merchant
and amount. It cannot prove **the customer** agreed to that merchant and
amount. If the payer's server is breached or its API key leaks, an attacker
can mint perfectly valid credentials for their own merchant, and every later
check (merchant lock, exact amount, single use, burn on misuse) faithfully
protects the attacker's payment. This is the same failure as a disguised
transaction approved on a compromised screen.

## Goal

A credential can be created only from an approval the customer signed on
their own device, covering exactly that merchant, amount, currency, channel
and expiry, verifiable by anyone, later, as dispute evidence.

**Non-goals:** replacing card-network authentication (3-D Secure etc.);
protecting cards SPIN didn't issue; consumer UX beyond one confirmation per
payment.

## How it works

1. **Enroll a device (once).** The customer's device creates a key pair in its
   secure hardware (Secure Enclave / Android Keystore / TPM), unlocked by
   biometrics or PIN. SPIN stores **only the public key**, under a *payer* the
   integrator registers. Web: a **passkey** (WebAuthn). Native app: the
   existing `deviceKeyProof` schemes in SPIN Pay (`ed25519`, or the
   post-quantum `hybrid-ed25519-mldsa65`). A customer can enroll several
   devices; synced passkeys survive a lost phone.
2. **Approve (each payment).** The device shows **"Pay $4.50 to Coffee Co."**
   and the customer confirms with face, fingerprint or PIN. The device signs
   the **intent**:

   ```
   { v: 1, payerId, merchantId, amount, currency, channel, expiresAt, nonce }
   ```

   On the web this is **Secure Payment Confirmation** (W3C): the *browser*
   draws the merchant and amount, so a compromised page can't show $4.50 while
   the signature says $4,500.
3. **Create.** The integrator calls `POST /envelopes` with the request as
   today **plus** `signedIntent`. SPIN creates the credential only if:
   - the signature verifies against an enrolled, unrevoked key of `payerId`;
   - every field of the intent **equals** the request (merchant, amount,
     currency, channel), and the envelope expires no later than the intent;
   - the `nonce` is fresh (single use, stored) and the intent is unexpired.

   Otherwise: `403 intent_required` / `intent_mismatch`. Nothing is created.
4. **Authorize.** Unchanged: the payee merchant's own key (or later the card
   network) resolves, exactly once.
5. **Receipt.** The receipt SPIN signs now embeds the customer's signed
   intent: "this customer approved $4.50 to Coffee Co. at 14:01 on this
   device". That is evidence a merchant or bank can verify without trusting
   SPIN.

Per API key, `requireCustomerSignature` turns this on. Default on for live
keys, off for test keys during migration.

## What if the customer has no reception?

Signing never needs a connection: passkeys and device keys sign locally. What
needs a connection is getting the signed approval to SPIN. By situation:

| Situation | What happens |
|---|---|
| **Online purchase** (web or app) | The customer is online by definition. No issue. |
| **In person, phone has no signal** | **Relay through the merchant** (recommended). The phone signs locally and hands the signed approval to the merchant's terminal over NFC or a QR code. The terminal must be online to take any card payment, so it forwards the approval to SPIN. The phone never needs a connection. This is how Apple Pay works offline: the phone makes a one-time code, the terminal carries it. Needs terminal integration, so it comes with in-person support. |
| **In person, as a fallback** | **Offline allowance** (opt-in). While online, the customer pre-signs a small, capped mandate, e.g. up to $50 in total over 24 hours, optionally limited to merchant categories. SPIN honors payments within it without a per-payment signature. The risk is bounded by the cap, and it's revocable from any device. |
| **Phone dead or lost** | Another enrolled device or a synced passkey. Otherwise a different payment method, as with any card today. |

Recommendation: ship online flows first (all the sandbox supports today),
build the merchant relay together with in-person/terminal support, and offer
the offline allowance as opt-in with low default caps.

## Software that pays (AI agents, payment systems)

No human taps per payment. The "device" is the agent's or system's own key,
held in KMS/HSM, and a **standing mandate** signed once by a person bounds
what it can sign: merchants or categories, per-payment and daily caps, expiry.
SPIN checks each intent against the mandate. A stolen agent key is limited to
the mandate; a stolen integrator API key alone can create nothing.

## Threats

| Attacker has | Today | With signed intent |
|---|---|---|
| Integrator's API key | Mints credentials for any merchant | Nothing: no customer signature |
| Breached payer server (can call the API, alter checkout pages) | Same | Nothing the customer didn't approve; SPC shows the true amount |
| Replay of an old approval | n/a | Rejected: nonce used, intent expired |
| SPIN's database | Public keys only | Can verify, never forge |
| Customer's unlocked phone *and* biometrics | Out of scope | Out of scope (as with any wallet) |

## Breach test additions

1. A stolen integrator API key with no customer signature creates nothing.
2. A valid signature for $4.50 to Coffee Co. cannot create $4,500, another
   merchant, another currency, or a longer expiry.
3. The same signed intent cannot be used twice.
4. A full database copy (public keys) cannot produce a valid signature.
5. Offline allowance: spending stops exactly at the cap.

## Changes, by repo

- **spin-core:** `signedIntent` on `create`; a `PayerKeyStore` interface
  (enrolled public keys, revocation, used nonces) with a conformance suite;
  verifiers for WebAuthn/SPC assertions and the existing device-key schemes;
  the intent embedded in the receipt.
- **SPIN Pay:** payer and device enrollment endpoints, tables for payer keys
  and nonces, a per-key `requireCustomerSignature` flag, docs, and a small
  browser helper for passkey/SPC.

## Decisions (2026-11-02)

1. Phase 1 is online flows only. The merchant relay comes with in-person
   support; the offline allowance comes later, opt-in.
2. Offline allowance defaults, when built: $50 in total over 24 hours.
3. Test keys don't require signatures; live keys always do.
