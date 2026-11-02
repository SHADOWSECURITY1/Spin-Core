# Crypto co-signer

Status: design (2026-11-02). Nothing built yet. It reuses the customer-signed
intent from Step 2 (`docs/design/customer-signed-intent.md`).

Decided: the first customers are **exchanges and company treasuries**, and
this is a **separate product** built on spin-core, not part of SPIN Pay.

## The problem

Crypto has no card numbers to make useless. What gets stolen is **the
ability to sign**: a hot-wallet key, or a signer tricked into approving a
transaction that isn't what it looks like. Once a transfer is on chain it
can't be reversed.

Treasuries already require several signatures (a multisig such as Safe, or
MPC custody). That doesn't help when every signer approves the same
disguised transaction. In February 2025 Bybit lost about $1.5B in ETH from a
Safe multisig cold wallet this way. Attackers changed what the Safe web app
showed, and the signers approved what looked like a routine transfer. In fact
it changed the wallet's contract logic and handed control to the attacker.

## Goal

A co-signer that adds its signature only to a transaction it has **decoded
itself** and found to be exactly what the customer's approvers signed for:
one asset, amount, recipient, chain and wallet, before an expiry, once. It
refuses everything else, however the transaction was displayed.

This is the SPIN idea applied to crypto. No standing permission is ever
granted: each signature covers exactly one transaction and is worthless for
any other.

**Non-goals:** holding customer funds; being able to move funds alone;
choosing which transactions a treasury should make (that's the customer's
policy, which SPIN enforces); DeFi, contract calls or swaps in phase 1.

## How it works (phase 1: Safe on EVM chains)

1. **Set up the wallet.** The customer's Safe has, for example, 2-of-3
   owners: the customer's operations key, **SPIN's co-signer key**, and the
   customer's cold backup key. SPIN's key is a secp256k1 key in **AWS KMS**
   (key spec `ECC_SECG_P256K1`), so it never exists outside hardware.
   - **SPIN can't move funds alone** (one signature of the two needed).
   - **A stolen operations key can't move funds alone.** It needs SPIN, and
     SPIN needs the approvers.
   - **If SPIN is down or gone,** operations key + cold backup still reach
     2-of-3, so the customer is never locked out.
2. **Enroll approvers.** The people who approve transfers enroll devices
   exactly as in Step 2: passkeys or app keys in secure hardware, with later
   devices approved by an existing one.
3. **Set the policy.** The customer sets, and approvers sign:
   - **Allowed recipients.** A new address becomes usable only after a delay
     (default 24 hours), and it's announced to every approver during that time.
     This stops address poisoning and fast drains to a fresh address.
   - **Assets:** the native coin plus listed token contracts.
   - **Caps:** per transfer and per 24 hours, per asset.
   - **Quorum:** how many approvers must sign, which may depend on the
     amount (for example 1 under $100k and 2 above).
4. **Approve a transfer.** Each approver's device shows **"Send 250,000 USDC
   to Kraken deposit 0x9a3…f71 on Ethereum from Treasury Safe"** and signs
   the intent:

   ```
   { v: 1, kind: "evm-transfer", orgId, chainId, safe, asset, to, amount, expiresAt, nonce }
   ```

   `asset` is `"native"` or a token contract address. `amount` is in base
   units, as a string.
5. **Co-sign.** The integrator sends SPIN the **full Safe transaction**
   (never just a hash) plus the signed intents. SPIN:
   - decodes the transaction. Phase 1 accepts exactly two shapes:
     - a native transfer (empty `data`);
     - an ERC-20 `transfer(to, amount)` on a listed token.
   - refuses:
     - `operation = 1` (delegatecall, which the Bybit attack used);
     - any other call data;
     - any change to owners, threshold, modules, guards or fallback handler;
     - a gas refund to anyone, or a non-zero `gasPrice`;
   - checks that the decoded asset, amount, recipient, chain and Safe
     **equal** each intent, that the intents meet the quorum and policy, and
     that every nonce is fresh;
   - computes the EIP-712 `SafeTx` hash **itself** (chain id, Safe address,
     Safe nonce) and signs that hash with the KMS key.

   Otherwise it refuses with a reason, and signs nothing.
6. **Receipt.** SPIN returns a signed receipt holding the approvals, the
   decoded transfer and the transaction hash. It's evidence for audit,
   verifiable without trusting SPIN.

Changes to the wallet itself (owners, threshold, modules) go through a
separate **governance intent**: a larger quorum and a mandatory delay (default
48 hours), announced to every approver.

## Threats

| Attacker has | Without SPIN | With the co-signer |
|---|---|---|
| Customer's operations (hot) key | Drains the wallet if it alone meets the threshold | Nothing: needs SPIN, which needs approvers |
| Compromised wallet web app (Bybit) | Signers approve a disguised transaction | Refused: SPIN decodes the real transaction; delegatecall and owner changes are refused |
| Integrator's API key or server | Can submit anything | Nothing without approver signatures |
| One approver's unlocked phone and biometrics | n/a | Bounded by policy: listed recipients only, caps, quorum above the threshold |
| Fresh address (poisoning, drain) | Sent immediately | Waits out the 24-hour delay, announced to every approver |
| Replay of an old approval or signature | Safe nonce stops on-chain replay | Intent nonce used; expired; Safe nonce bound into the hash |
| SPIN's database | n/a | Public keys and policy only; the signing key is in KMS |
| SPIN's servers fully compromised | n/a | Can sign anything, but SPIN's signature alone can't move funds |
| SPIN offline | n/a | Customer uses operations + cold key (2-of-3) |

## Breach test additions

1. A stolen operations key plus a stolen integrator API key moves nothing.
2. A Bybit-style transaction (delegatecall to an attacker contract, displayed
   as a transfer) is refused, and so is every owner, threshold, module or
   guard change without a governance intent.
3. An approval for 250,000 USDC to address A can't co-sign:
   - a different amount, recipient, token, chain or Safe;
   - a gas refund;
   - a second transaction.
4. A new recipient is refused until its delay ends.
5. Caps stop spending exactly at the limit; quorum is enforced by amount.
6. A full copy of SPIN's database can't produce a co-signature.

## Changes, by repo

- **spin-core** (`@spin/core/cosign`, new and pure, no network):
  - intent kinds `evm-transfer` and `evm-governance`;
  - Safe transaction decoding and EIP-712 `SafeTx` hashing (`@noble/hashes`
    keccak, `@noble/curves` secp256k1, already dependencies);
  - policy evaluation;
  - a `CosignStore` interface (approvers, policy, allowed-recipient delays,
    nonces, spend totals) with a conformance suite;
  - a `Secp256k1Signer` interface: a KMS signer for production and a software
    signer for tests;
  - the breach tests above.

  Approval signatures reuse Step 2's verifiers unchanged.
- **New service** (its own repo and site): org and approver enrollment,
  policy editor, approval app (approver devices), co-sign API, receipts,
  audit log, KMS key per customer.

## Later phases

- **Bitcoin:** multisig via PSBT, with SPIN as one key and the same decode,
  match and sign rule.
- **MPC custodians:** Fireblocks, BitGo and others let a customer require an
  external approval before signing. SPIN plugs in as that approver.
- **Solana** (Squads multisig) and other chains, on demand.
- **Contract calls:** an allowlist of decoded calls (e.g. staking deposits),
  each with its own intent kind.

## Decisions for the owner

1. Product name and domain.
2. First chains: Ethereum mainnet only, or also Base and Arbitrum?
3. Defaults: 24-hour new-recipient delay, 48-hour governance delay.
4. Legal: whether a co-signer that can't move funds alone is a money
   transmitter. FinCEN's 2019 guidance on convertible virtual currency treats
   multi-signature providers that only add a validating signature as
   generally not money transmitters; confirm with counsel, and check state
   rules (e.g. New York BitLicense).
5. Pricing (per wallet, per transfer, or a share of assets protected).
