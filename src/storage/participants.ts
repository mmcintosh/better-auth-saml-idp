// Logout participants (D-028): which SPs received an assertion in which IdP session.
import { sha256b64url } from "./pending";

export const PARTICIPANT_MODEL = "samlIdpSessionParticipant";

export interface Participant {
  spId: string;
  nameId: string;
  nameIdFormat: string;
  sessionIndex: string;
}

type Adapter = {
  create(a: { model: string; data: Record<string, unknown> }): Promise<unknown>;
  findOne(a: { model: string; where: { field: string; value: unknown }[] }): Promise<unknown>;
  findMany(a: { model: string; where: { field: string; value: unknown }[]; limit?: number }): Promise<unknown[]>;
  update(a: { model: string; where: { field: string; value: unknown }[]; update: Record<string, unknown> }): Promise<unknown>;
  deleteMany(a: { model: string; where: { field: string; value: unknown }[] }): Promise<unknown>;
};

/** Never the session id or token: a hash, namespaced away from SessionIndex. */
export const sessionKeyOf = (sessionId: string) => sha256b64url(`saml-idp:slo\u0000${sessionId}`);
/** The SessionIndex issued in assertions for this session (issue.ts uses the same). */
export const sessionIndexOf = async (sessionId: string) => `_${(await sha256b64url(`saml-idp:session\u0000${sessionId}`)).slice(0, 32)}`;

/** Record (or refresh: transient NameIDs change per assertion) that `p.spId` got an assertion. */
export async function recordParticipant(adapter: Adapter, sessionId: string, p: Participant, expiresAt: Date): Promise<void> {
  const sessionKey = await sessionKeyOf(sessionId);
  const key = await sha256b64url(`saml-idp:participant\u0000${sessionKey}\u0000${p.spId}`);
  try {
    await adapter.create({ model: PARTICIPANT_MODEL, data: { key, sessionKey, ...p, expiresAt } });
  } catch (e) {
    if (!(await adapter.findOne({ model: PARTICIPANT_MODEL, where: [{ field: "key", value: key }] }))) throw e;
    await adapter.update({ model: PARTICIPANT_MODEL, where: [{ field: "key", value: key }], update: { nameId: p.nameId, nameIdFormat: p.nameIdFormat, sessionIndex: p.sessionIndex, expiresAt } });
  }
}

export async function listParticipants(adapter: Adapter, sessionId: string): Promise<Participant[]> {
  const sessionKey = await sessionKeyOf(sessionId);
  const rows = (await adapter.findMany({ model: PARTICIPANT_MODEL, where: [{ field: "sessionKey", value: sessionKey }], limit: 200 })) as Participant[];
  return rows.map(({ spId, nameId, nameIdFormat, sessionIndex }) => ({ spId, nameId, nameIdFormat, sessionIndex }));
}

export async function forgetParticipants(adapter: Adapter, sessionId: string): Promise<void> {
  await adapter.deleteMany({ model: PARTICIPANT_MODEL, where: [{ field: "sessionKey", value: await sessionKeyOf(sessionId) }] });
}
