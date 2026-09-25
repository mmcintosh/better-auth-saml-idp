// Logout participants (D-028): which SPs received an assertion in which IdP session.
import { createHmac } from "node:crypto";
import { base64url, sha256b64url } from "./pending";

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
  updateMany(a: { model: string; where: { field: string; value: unknown }[]; update: Record<string, unknown> }): Promise<unknown>;
};

/** The session's expiry moved (Better Auth refreshed it): move its participants' along with it. */
export async function extendParticipants(adapter: Adapter, sessionId: string, expiresAt: Date): Promise<void> {
  await adapter.updateMany({ model: PARTICIPANT_MODEL, where: [{ field: "sessionKey", value: await sessionKeyOf(sessionId) }], update: { expiresAt } });
}

/** Never the session id or token: a hash, namespaced away from SessionIndex. */
export const sessionKeyOf = (sessionId: string) => sha256b64url(`saml-idp:slo\u0000${sessionId}`);
/**
 * The SessionIndex issued to one SP for one session: a keyed MAC over (session id, SP id).
 * Per SP, so SPs can't use it to link a user across SPs, and one SP's value can't
 * authenticate a LogoutRequest in another SP's name (review 2, R2-SLO-2).
 */
export const sessionIndexOf = (secret: string, sessionId: string, spId: string) =>
  `_${base64url(new Uint8Array(createHmac("sha256", secret).update(`saml-idp:session\u0000${sessionId}\u0000${spId}`).digest())).slice(0, 32)}`;

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

export const MAX_PARTICIPANTS = 200;

/** `truncated`: more than MAX_PARTICIPANTS rows exist (logout then reports PartialLogout). */
export async function listParticipants(adapter: Adapter, sessionId: string): Promise<{ participants: Participant[]; truncated: boolean }> {
  const sessionKey = await sessionKeyOf(sessionId);
  const rows = (await adapter.findMany({ model: PARTICIPANT_MODEL, where: [{ field: "sessionKey", value: sessionKey }], limit: MAX_PARTICIPANTS + 1 })) as Participant[];
  return {
    participants: rows.slice(0, MAX_PARTICIPANTS).map(({ spId, nameId, nameIdFormat, sessionIndex }) => ({ spId, nameId, nameIdFormat, sessionIndex })),
    truncated: rows.length > MAX_PARTICIPANTS,
  };
}

export async function forgetParticipants(adapter: Adapter, sessionId: string): Promise<void> {
  await adapter.deleteMany({ model: PARTICIPANT_MODEL, where: [{ field: "sessionKey", value: await sessionKeyOf(sessionId) }] });
}
