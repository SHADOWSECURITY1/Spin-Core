/**
 * SPIN as an MCP server: three tools any MCP-capable agent can call to buy
 * under the person's standing rule. The model sees card numbers that work
 * once, at one merchant, for one amount, for a few minutes. It never sees the
 * API key or the signing key, which stay in this process and the key service.
 *
 * This file is the protocol handler (JSON-RPC 2.0, MCP tools), with no I/O.
 * ./mcp-cli.ts runs it over stdio; `npx spin-mcp`.
 */
import { fromMinorUnits, toMinorUnits } from "../pay-envelope/intent-format.js";
import type { SpinAgent } from "./index.js";

export const MCP_SERVER_NAME = "spin";
export const MCP_SERVER_VERSION = "0.13.0";
const PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"];

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

type JsonRpcResponse =
  | { jsonrpc: "2.0"; id: string | number | null; result: unknown }
  | { jsonrpc: "2.0"; id: string | number | null; error: { code: number; message: string } };

const TOOLS = [
  {
    name: "spin_rules",
    title: "What I may buy",
    description:
      "Lists the standing rules the person set for you: which merchants you may pay, in which currency, the limit per purchase, and how much is left in the last 24 hours. Check this before planning a purchase.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  {
    name: "spin_buy",
    title: "Get a single-use card number",
    description:
      "Gets a card number for ONE purchase: it works once, only at this merchant, only for this exact amount, and expires in minutes. Use it at checkout right away, and request a new one for each purchase. If SPIN refuses, the purchase is outside the person's rules: tell the person why and ask them; do not try to work around it.",
    inputSchema: {
      type: "object",
      properties: {
        merchantId: { type: "string", description: "The merchant's SPIN id, exactly as listed in spin_rules." },
        amount: { type: "string", pattern: "^\\d+(\\.\\d+)?$", description: 'The exact total to pay, as a decimal string, e.g. "12.50".' },
        currency: { type: "string", pattern: "^[A-Za-z]{3}$", description: 'ISO 4217 code, e.g. "USD".' },
        channel: { type: "string", enum: ["CNP", "CP"], description: "CNP for online, CP for in person. Omit if unsure." },
      },
      required: ["merchantId", "amount", "currency"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  },
  {
    name: "spin_purchase_status",
    title: "Check a purchase",
    description: "Whether a card number from spin_buy has been charged, declined or expired.",
    inputSchema: {
      type: "object",
      properties: { envelopeId: { type: "string", description: "The envelopeId spin_buy returned." } },
      required: ["envelopeId"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
] as const;

const text = (t: string, structured?: unknown, isError = false) => ({
  content: [{ type: "text", text: t }],
  ...(structured === undefined ? {} : { structuredContent: structured }),
  ...(isError ? { isError: true } : {}),
});

const str = (v: unknown) => (typeof v === "string" ? v : undefined);

/** Handles one JSON-RPC message. Returns the response, or null for notifications. */
export function createSpinMcpHandler(agent: SpinAgent) {
  async function callTool(name: string, args: Record<string, unknown>) {
    switch (name) {
      case "spin_rules": {
        const rules = await agent.rules();
        if (rules.length === 0) return text("No active standing rules. You can't buy anything until the person sets one up.", { rules });
        const lines = rules.map(
          (r) =>
            `- ${r.merchants.join(", ")}: up to ${fromMinorUnits(r.maxPerPurchase, r.currency)} ${r.currency} per purchase, ` +
            `${fromMinorUnits(r.remainingToday, r.currency)} of ${fromMinorUnits(r.maxPerDay, r.currency)} ${r.currency} left in the last 24 hours` +
            `${r.channel ? `, ${r.channel === "CNP" ? "online" : "in person"} only` : ""}; until ${r.expiresAt}.`,
        );
        return text(`You may buy:\n${lines.join("\n")}`, { rules });
      }
      case "spin_buy": {
        const merchantId = str(args.merchantId);
        const currency = str(args.currency)?.toUpperCase();
        const amountText = str(args.amount);
        const channel = args.channel === "CNP" || args.channel === "CP" ? args.channel : undefined;
        if (!merchantId || !currency || !/^[A-Z]{3}$/.test(currency) || !amountText) {
          return text("merchantId, amount (a decimal string) and currency are required.", undefined, true);
        }
        const amount = toMinorUnits(amountText, currency);
        if (amount === null || amount <= 0) return text(`"${amountText}" isn't a valid ${currency} amount.`, undefined, true);
        const r = await agent.buy({ merchantId, amount, currency, channel });
        if (!r.ok) return text(`SPIN refused (${r.code}): ${r.message}`, { ok: false, code: r.code }, true);
        return text(
          `Card number ${r.pan}. It works once, at ${merchantId}, for exactly ${fromMinorUnits(amount, currency)} ${currency}, until ${r.expiresAt}. ` +
            `Purchase id: ${r.envelopeId}.`,
          { ok: true, envelopeId: r.envelopeId, pan: r.pan, expiresAt: r.expiresAt, merchantId, amount: fromMinorUnits(amount, currency), currency },
        );
      }
      case "spin_purchase_status": {
        const id = str(args.envelopeId);
        if (!id) return text("envelopeId is required.", undefined, true);
        const r = await agent.status(id);
        if (!r.ok) return text(`SPIN refused (${r.code}): ${r.message}`, { ok: false, code: r.code }, true);
        const s = r.status;
        const state = s.usedAt ? `charged (${s.decision})` : s.expiredAt ? "expired" : s.decision ? String(s.decision) : "not used yet";
        return text(`Purchase ${id}: ${state}.`, s);
      }
      default:
        return null;
    }
  }

  return async function handle(msg: unknown): Promise<JsonRpcResponse | null> {
    const req = msg as JsonRpcRequest;
    const isRequest = req && typeof req === "object" && "id" in req && req.id !== undefined;
    const id = isRequest ? (req.id as string | number | null) : null;
    const ok = (result: unknown): JsonRpcResponse => ({ jsonrpc: "2.0", id, result });
    const err = (code: number, message: string): JsonRpcResponse => ({ jsonrpc: "2.0", id, error: { code, message } });
    if (!req || typeof req !== "object" || req.jsonrpc !== "2.0" || typeof req.method !== "string") {
      return err(-32600, "Invalid request");
    }
    if (!isRequest) return null; // notifications (initialized, cancelled): nothing to send back
    switch (req.method) {
      case "initialize": {
        const asked = str(req.params?.protocolVersion);
        return ok({
          protocolVersion: asked && PROTOCOL_VERSIONS.includes(asked) ? asked : PROTOCOL_VERSIONS[0],
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: MCP_SERVER_NAME, title: "SPIN payments", version: MCP_SERVER_VERSION },
          instructions:
            "Pay with SPIN: call spin_rules to see what the person allows, then spin_buy once per purchase for a single-use card number. Never reuse a card number, and never try to get around a refusal.",
        });
      }
      case "ping":
        return ok({});
      case "tools/list":
        return ok({ tools: TOOLS });
      case "tools/call": {
        const name = str(req.params?.name) ?? "";
        const args = (req.params?.arguments ?? {}) as Record<string, unknown>;
        if (!TOOLS.some((t) => t.name === name)) return err(-32602, `Unknown tool: ${name}`);
        try {
          return ok(await callTool(name, args));
        } catch (e) {
          return ok(text(`SPIN couldn't be reached: ${(e as Error).message}`, undefined, true));
        }
      }
      default:
        return err(-32601, `Method not found: ${req.method}`);
    }
  };
}
