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

/**
 * Record (or refresh: transient NameIDs change per assertion) that `p.spId` got an assertion.
 * `userId` lets the host find a user's SPs after the session is gone (session.ended, D-043).
 */
export async function recordParticipant(adapter: Adapter, sessionId: string, userId: string, p: Participant, expiresAt: Date): Promise<void> {
  const sessionKey = await sessionKeyOf(sessionId);
  const key = await sha256b64url(`saml-idp:participant\u0000${sessionKey}\u0000${p.spId}`);
  try {
    await adapter.create({ model: PARTICIPANT_MODEL, data: { key, sessionKey, userId, ...p, expiresAt } });
  } catch (e) {
    if (!(await adapter.findOne({ model: PARTICIPANT_MODEL, where: [{ field: "key", value: key }] }))) throw e;
    await adapter.update({ model: PARTICIPANT_MODEL, where: [{ field: "key", value: key }], update: { userId, nameId: p.nameId, nameIdFormat: p.nameIdFormat, sessionIndex: p.sessionIndex, expiresAt } });
  }
}

export const MAX_PARTICIPANTS = 200;

type ParticipantRow = Participant & { userId?: string | null; endedAt?: Date | string | null; expiresAt: Date | string };

/**
 * A live session's participants, for Single Logout. `truncated`: more than MAX_PARTICIPANTS rows
 * exist (logout then reports PartialLogout). Rows of an already ended session are skipped.
 */
export async function listParticipants(adapter: Adapter, sessionId: string): Promise<{ participants: Participant[]; truncated: boolean }> {
  const sessionKey = await sessionKeyOf(sessionId);
  const all = (await adapter.findMany({ model: PARTICIPANT_MODEL, where: [{ field: "sessionKey", value: sessionKey }], limit: MAX_PARTICIPANTS + 1 })) as ParticipantRow[];
  const rows = all.filter((r) => !r.endedAt);
  return {
    participants: rows.slice(0, MAX_PARTICIPANTS).map(({ spId, nameId, nameIdFormat, sessionIndex }) => ({ spId, nameId, nameIdFormat, sessionIndex })),
    truncated: rows.length > MAX_PARTICIPANTS,
  };
}

/**
 * The session ended without Single Logout (D-043): mark its participant rows ended (kept until
 * they expire, so the host can still find and act on them) and return them.
 */
export async function endParticipants(adapter: Adapter, sessionId: string, endedAt: Date): Promise<{ participants: Participant[]; truncated: boolean }> {
  const sessionKey = await sessionKeyOf(sessionId);
  const all = (await adapter.findMany({ model: PARTICIPANT_MODEL, where: [{ field: "sessionKey", value: sessionKey }], limit: MAX_PARTICIPANTS + 1 })) as ParticipantRow[];
  const rows = all.filter((r) => !r.endedAt);
  // Every row is marked, even beyond the reporting cap.
  if (rows.length) await adapter.updateMany({ model: PARTICIPANT_MODEL, where: [{ field: "sessionKey", value: sessionKey }], update: { endedAt } });
  return {
    participants: rows.slice(0, MAX_PARTICIPANTS).map(({ spId, nameId, nameIdFormat, sessionIndex }) => ({ spId, nameId, nameIdFormat, sessionIndex })),
    truncated: all.length > MAX_PARTICIPANTS,
  };
}

export interface UserParticipant extends Participant {
  /** When the session ended without Single Logout; null while it is live. */
  endedAt: Date | null;
  expiresAt: Date;
}

/**
 * A user's SP sessions, live or ended but not yet expired (for the host's retry, D-043).
 * `truncated`: more than MAX_PARTICIPANTS rows exist, so the list isn't complete.
 */
export async function listUserParticipants(adapter: Adapter, userId: string, now = new Date()): Promise<{ participants: UserParticipant[]; truncated: boolean }> {
  const found = (await adapter.findMany({ model: PARTICIPANT_MODEL, where: [{ field: "userId", value: userId }], limit: MAX_PARTICIPANTS + 1 })) as ParticipantRow[];
  const participants = found
    .slice(0, MAX_PARTICIPANTS)
    // Exact match, as findRow does (R4-L8): a case-insensitive collation must not widen it.
    .filter((r) => r.userId === userId && new Date(r.expiresAt).getTime() > now.getTime())
    .map(({ spId, nameId, nameIdFormat, sessionIndex, endedAt, expiresAt }) => ({
      spId,
      nameId,
      nameIdFormat,
      sessionIndex,
      endedAt: endedAt ? new Date(endedAt) : null,
      expiresAt: new Date(expiresAt),
    }));
  return { participants, truncated: found.length > MAX_PARTICIPANTS };
}

/**
 * Session ids being ended by the plugin's own Single Logout, whose SPs are about to be told. The
 * session-delete hook skips them (it would otherwise report "not told" mid-chain). Entries are
 * consumed by the hook, and pruned after a minute in case it never runs.
 */
const endingBySlo = new Map<string, number>();
const ENDING_TTL_MS = 60_000;
export function markEndingBySlo(sessionId: string): void {
  const now = Date.now();
  for (const [id, at] of endingBySlo) if (now - at > ENDING_TTL_MS) endingBySlo.delete(id);
  endingBySlo.set(sessionId, now);
}
/** True only for a fresh marker: a stale one (the delete never happened) must not hide a later end. */
export function consumeEndingBySlo(sessionId: string): boolean {
  const at = endingBySlo.get(sessionId);
  endingBySlo.delete(sessionId);
  return at !== undefined && Date.now() - at <= ENDING_TTL_MS;
}

export async function forgetParticipants(adapter: Adapter, sessionId: string): Promise<void> {
  await adapter.deleteMany({ model: PARTICIPANT_MODEL, where: [{ field: "sessionKey", value: await sessionKeyOf(sessionId) }] });
}
