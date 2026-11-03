# The approval screen

Status: approval kit in @spin/core 0.10 (`@spin/core/approval`). Red-team
findings #2 (scam merchants) and #3 (showing one payment and signing another).

## The problem

A customer-signed intent proves the customer's device signed exactly one
payment. It doesn't prove the customer **saw** that payment. Whoever draws the
approval screen decides what they see:

- **A tampered checkout page or app** shows "Pay $4.50 to Coffee Co." and asks
  the device to sign "$450 to Thief's Shop".
- **A scam merchant** gets an honest approval for a payment the customer
  shouldn't have made.

## What the kit does

1. **One source of truth.** `approveIntent()` derives the screen text from
   the intent (`describeIntent`) and signs that same frozen intent. An
   integrator can't pass separate display text, so a bug or a tampered page
   in the integrator's code can't split what's shown from what's signed.
2. **The browser draws it, where possible.**
   `approveWithSecurePaymentConfirmation()` uses Secure Payment Confirmation
   (W3C): the browser shows the payee and total in its own window, outside the
   page. SPIN's server checks the signed assertion's total equals the intent
   and, with the service's `payeeName` option, that the payee shown was the
   merchant's verified name. A compromised page can't change either.
   Chrome and Edge on desktop and Android today; elsewhere, use a passkey or
   app key with `approveIntent()`.
3. **Who is being paid.** The screen shows whether SPIN verified the business,
   how long it has been on SPIN, and warns when the customer has never paid
   it before or it isn't verified (SPIN Pay's merchant lookup supplies these).
   This doesn't stop a determined scam, but it makes the common ones visible.

## What it can't do

- **Malware controlling the customer's phone or browser** can draw anything
  and sign anything the device key will sign, in any app. Only a screen the
  operating system draws, outside every app, is beyond it:
  - Android Protected Confirmation (hardware-backed confirmation screen; some
    devices) could carry the description and have the key sign only what it
    displayed. Not built yet.
  - iOS has no equivalent today.
- **A customer who wants to pay a scammer** will approve it. SPIN stops
  stolen-data fraud, not persuasion; the warnings are the mitigation.

## Next

- Android Protected Confirmation for native app keys, where available.
- A SPIN-run approval app (separate from integrators' apps), so a compromised
  shopping app can't reach the approval screen at all.
