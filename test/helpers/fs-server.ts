import type { FsTransport, PreKeyBundle, WrappedPrekeyUpload } from '../../src/vault/index.js';

/** In-memory stand-in for SPIN Vault's prekey / session / message endpoints. */
export function makeFsServer(dump?: {
  prekeys: Record<string, WrappedPrekeyUpload[]>;
  sessions: Record<string, { wrappedState: string; stateIv: string }>;
  messages: any[];
  identities: Record<string, { x25519: string; kyber: string }>;
}) {
  const prekeys = new Map<number, Map<string, WrappedPrekeyUpload>>();
  const sessions = new Map<string, { wrappedState: string; stateIv: string }>();
  const messages: any[] = dump ? [...dump.messages] : [];
  const identities = new Map<number, { x25519: string; kyber: string }>();
  if (dump) {
    for (const [o, rows] of Object.entries(dump.prekeys)) prekeys.set(Number(o), new Map(rows.map((r) => [r.keyId, r])));
    for (const [k, v] of Object.entries(dump.sessions)) sessions.set(k, v);
    for (const [k, v] of Object.entries(dump.identities)) identities.set(Number(k), v);
  }
  const transportFor = (me: number): FsTransport => ({
    async getPrekeyCount() { return prekeys.get(me)?.size ?? 0; },
    async uploadPrekeys(batch) {
      const m = prekeys.get(me) ?? new Map();
      for (const p of batch) m.set(p.keyId, p);
      prekeys.set(me, m);
    },
    async getPrekeyBundle(peer): Promise<PreKeyBundle | null> {
      const first = [...(prekeys.get(peer)?.values() ?? [])][0];
      const id = identities.get(peer);
      if (!first || !id) return null;
      return { identity: id, oneTime: { id: first.keyId, x25519: first.x25519Pub, kyber: first.kyberPub } };
    },
    async getPrekeyPrivate(keyId) { return prekeys.get(me)?.get(keyId) ?? null; },
    async deletePrekey(keyId) { prekeys.get(me)?.delete(keyId); },
    async getIdentityKey(peer) {
      const id = identities.get(peer);
      return id ? { x25519: id.x25519 } : null;
    },
    async getSession(peer) { return sessions.get(`${me}:${peer}`) ?? null; },
    async putSession(peer, wrappedState, stateIv) { sessions.set(`${me}:${peer}`, { wrappedState, stateIv }); },
    async postMessage(body: any) {
      const id = messages.length + 1;
      messages.push({ id, senderId: me, ...body });
      return { id };
    },
  });
  const inbox = (me: number, from: number) => messages.filter((m) => m.receiverId === me && m.senderId === from);
  return { prekeys, sessions, messages, identities, transportFor, inbox };
}
