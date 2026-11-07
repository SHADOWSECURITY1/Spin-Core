# SPIN Envelope for Data

Goal: a stolen copy of a database is worthless, and a compromised reader can
read only a little, slowly, and on the record.

Prompted by the BOSSAI campaign (Acronis TRU, Nov 2026): one operator with AI
agents took patient records from an open port, account tables through SQL
injection, and admin access through default passwords and a key left in page
code. Every loss was either a secret that worked for whoever held it, or a
database that handed readable rows to whoever reached it.

## Pieces

| Piece | What it does |
|---|---|
| Sealed record | Value encrypted with a random per-record key (AES-256-GCM). Collection and row id are bound in, so values can't be swapped or moved. |
| Data keyring | Wraps record keys. Lives in KMS/HSM with the key service; never in the app or database. |
| Read mandate | Signed by a configured authority. Names the reader, pins their device key by fingerprint, lists collections and purposes, caps reads per hour and per day, expires. |
| Read request | One record, one purpose, signed by the reader's device, fresh, single use. |
| Key service | The only place a record key is unwrapped. Checks all of the above, then decoys, then budget. Audits every decision. |
| Decoys | Rows no real workflow reads. Touching one freezes the reader and alerts. |

## Who can do what after a breach

| Attacker has | Result |
|---|---|
| Database, backups, audit log | Ciphertext only. |
| App server (can call the key service, replay what it relayed) | Nothing: requests need a reader's device signature; replays and retargeted requests are refused. |
| Write access to the key service's tables | Can't add a reader, swap a key or forge a mandate: authorities are configuration and mandates pin keys. Could undo revocations, freezes and read counts, so keep that store on the key service's own database. |
| A reader's unlocked device | At most the mandate's hourly budget, for the mandate's collections and purposes, until a decoy freezes it. Every read logged. |
| A reader's screen | What they're allowed to see. Nothing removes this; budgets bound it. |

## Not done yet

- Per-reader marking of the plaintext itself (trace ids are in the audit, not
  in the data).
- "Answers instead of data" (signed yes/no claims instead of records).
- Search and analytics over sealed fields.
- A Postgres store and a hosted key service; SPIN Pay integration and a demo.
- Lost-device recovery for readers (re-enrollment needs an authority-signed
  mandate for the new key; that path should get its own review).
