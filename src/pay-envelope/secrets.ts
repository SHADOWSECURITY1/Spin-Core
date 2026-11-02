import { randomBytes } from "node:crypto";

export class PayEnvelopeConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PayEnvelopeConfigError";
  }
}

export interface PayEnvelopeSecrets {
  /** Keys the HMAC that derives each presentation PAN. */
  hmac: string;
  /** Signs receipts. */
  jws: string;
}

export const MIN_SECRET_LENGTH = 32;

/**
 * Resolve the Pay Envelope secrets from the environment.
 *
 * Fails closed: missing, short, placeholder or reused secrets throw a
 * PayEnvelopeConfigError, whatever NODE_ENV says. Both apps used to derive
 * secrets from a fixed string plus REPL_ID whenever NODE_ENV wasn't exactly
 * "production", which made receipts forgeable on any misconfigured deploy.
 *
 * Local development can opt in with PAY_ENVELOPE_DEV_SECRETS=random: fresh
 * random secrets per process (not derivable from the source). The opt-in is
 * refused when NODE_ENV=production.
 */
export function resolvePayEnvelopeSecrets(
  env: Record<string, string | undefined> = process.env,
  opts: { requireHmac?: boolean } = {},
): PayEnvelopeSecrets {
  // With a hardware keyring (see keyring.ts) the HMAC secret isn't used.
  const requireHmac = opts.requireHmac ?? true;
  const hmac = env.PAY_ENVELOPE_HMAC_SECRET;
  const jws = env.PAY_ENVELOPE_JWS_SECRET;

  if (!jws && (!hmac || !requireHmac) && env.PAY_ENVELOPE_DEV_SECRETS === "random") {
    if (env.NODE_ENV === "production") {
      throw new PayEnvelopeConfigError(
        "PAY_ENVELOPE_DEV_SECRETS=random is not allowed when NODE_ENV=production",
      );
    }
    console.warn(
      "[pay-envelope] Using random per-process secrets (PAY_ENVELOPE_DEV_SECRETS=random). " +
        "Envelopes and receipts will not survive a restart. Never use this in a deployment.",
    );
    return {
      hmac: randomBytes(32).toString("hex"),
      jws: randomBytes(32).toString("hex"),
    };
  }

  const problems: string[] = [];
  for (const [name, value] of [
    ["PAY_ENVELOPE_HMAC_SECRET", hmac],
    ["PAY_ENVELOPE_JWS_SECRET", jws],
  ] as const) {
    if (!value && name === "PAY_ENVELOPE_HMAC_SECRET" && !requireHmac) continue;
    if (!value) problems.push(`${name} is not set`);
    else if (value.length < MIN_SECRET_LENGTH)
      problems.push(`${name} must be at least ${MIN_SECRET_LENGTH} characters`);
    else if (/change_me|openssl/i.test(value))
      problems.push(`${name} is still the .env.example placeholder`);
  }
  if (hmac && jws && hmac === jws) {
    problems.push("PAY_ENVELOPE_HMAC_SECRET and PAY_ENVELOPE_JWS_SECRET must be different");
  }
  if (problems.length > 0) {
    throw new PayEnvelopeConfigError(
      `Pay Envelope is not configured: ${problems.join("; ")}. ` +
        "Generate each with `openssl rand -hex 32`.",
    );
  }
  return { hmac: hmac ?? "", jws: jws! };
}

/** Throws unless secrets passed in code meet the same bar as the env ones. */
export function assertValidSecrets(
  secrets: PayEnvelopeSecrets,
  opts: { requireHmac?: boolean } = {},
): PayEnvelopeSecrets {
  return resolvePayEnvelopeSecrets(
    {
      PAY_ENVELOPE_HMAC_SECRET: secrets.hmac || undefined,
      PAY_ENVELOPE_JWS_SECRET: secrets.jws,
    },
    opts,
  );
}
