#!/usr/bin/env node
/**
 * spin-mcp: SPIN's MCP server over stdio. Add it to an agent's MCP config:
 *
 *   { "command": "npx", "args": ["spin-mcp"], "env": { ...see below } }
 *
 * Environment:
 *   SPIN_BASE_URL       the Pay Envelope API, e.g. https://spin.example/api/v1/pay
 *   SPIN_API_KEY        the platform's SPIN API key
 *   SPIN_PAYER_ID       the person this agent buys for
 *   SPIN_AGENT_KEY_ID   the keyId the agent's key was enrolled under
 *   SPIN_MANDATE_ID     optional: always buy under this rule
 *   Signing key, one of:
 *     SPIN_AWS_KMS_KEY_ID      an AWS KMS ECC_NIST_P256 key (needs @aws-sdk/client-kms installed; AWS credentials as usual)
 *     SPIN_DEV_PRIVATE_KEY     a raw P-256 private key, hex. Development only.
 *
 * stdout carries only protocol messages; logs go to stderr.
 */
import { createInterface } from "node:readline";
import { SpinAgent, awsKmsSigner, p256Signer, type AgentSigner, type KmsLike } from "./index.js";
import { createSpinMcpHandler } from "./mcp.js";

function need(name: string): string {
  const v = process.env[name];
  if (!v) {
    process.stderr.write(`spin-mcp: set ${name}\n`);
    process.exit(2);
  }
  return v;
}

async function signerFromEnv(keyId: string): Promise<AgentSigner> {
  const kmsKeyId = process.env.SPIN_AWS_KMS_KEY_ID;
  if (kmsKeyId) {
    let mod: { KMS: new (cfg: object) => KmsLike };
    try {
      const name = "@aws-sdk/client-kms";
      mod = (await import(name)) as typeof mod;
    } catch {
      process.stderr.write("spin-mcp: SPIN_AWS_KMS_KEY_ID needs @aws-sdk/client-kms (npm install @aws-sdk/client-kms)\n");
      process.exit(2);
    }
    return awsKmsSigner({ keyId, kmsKeyId, kms: new mod.KMS({}) });
  }
  const dev = process.env.SPIN_DEV_PRIVATE_KEY;
  if (dev && /^[0-9a-fA-F]{64}$/.test(dev)) {
    process.stderr.write("spin-mcp: using an in-memory development key. Use SPIN_AWS_KMS_KEY_ID in production.\n");
    return p256Signer(keyId, Uint8Array.from(Buffer.from(dev, "hex")));
  }
  process.stderr.write("spin-mcp: set SPIN_AWS_KMS_KEY_ID (or SPIN_DEV_PRIVATE_KEY, 64 hex characters, for development)\n");
  process.exit(2);
}

async function main() {
  const agent = new SpinAgent({
    baseUrl: need("SPIN_BASE_URL"),
    apiKey: need("SPIN_API_KEY"),
    payerId: need("SPIN_PAYER_ID"),
    signer: await signerFromEnv(need("SPIN_AGENT_KEY_ID")),
    mandateId: process.env.SPIN_MANDATE_ID || undefined,
  });
  const handle = createSpinMcpHandler(agent);
  const send = (m: unknown) => process.stdout.write(JSON.stringify(m) + "\n");
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
  rl.on("line", async (line) => {
    if (!line.trim()) return;
    let msg: unknown;
    try {
      msg = JSON.parse(line);
    } catch {
      send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
      return;
    }
    const batch = Array.isArray(msg) ? msg : [msg];
    for (const m of batch) {
      const res = await handle(m);
      if (res) send(res);
    }
  });
}

main().catch((e) => {
  process.stderr.write(`spin-mcp: ${(e as Error).message}\n`);
  process.exit(1);
});
