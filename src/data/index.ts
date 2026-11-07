/**
 * @spin/core/data: SPIN Envelope for Data. Make a stolen database worthless.
 *
 * Each sensitive value is sealed with its own key, and the database keeps
 * that key only wrapped by a key it never holds. A copy of the database,
 * a backup, an open port or a SQL injection returns ciphertext.
 *
 * Reading goes through the key service (DataKeyService), which releases one
 * record's key for one read signed by the reader's own device, inside a read
 * mandate an authority signed: which collections, for what purpose, how many
 * per hour and per day. Decoy records freeze any reader who touches them.
 * Every decision is audited.
 *
 * What it can't do: a legitimate reader sees plain data on their screen.
 * Mandates make that slow, narrow and traceable, not impossible.
 */
export * from "./format.js";
export * from "./keyring.js";
export * from "./service.js";
