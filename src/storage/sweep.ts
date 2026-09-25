/**
 * Opportunistic cleanup of expired rows this plugin causes to exist:
 *  - `samlIdpSeenRequest` rows past their replay window;
 *  - expired `verification` rows. Better Auth 1.7 only sweeps these inside
 *    findVerificationValue, which the consume path never calls, so abandoned SSO attempts
 *    would otherwise accumulate forever. Expired verification values are invalid for every
 *    flow (consume and find both treat them as absent), so deleting them is safe.
 * Throttled per isolate/process; failures are logged, never fatal.
 */
import { PARTICIPANT_MODEL } from "./participants";
import { SEEN_MODEL } from "./seen";

const INTERVAL_MS = 60_000;
let last = 0;

type Adapter = {
  deleteMany(args: { model: string; where: { field: string; value: unknown; operator?: "lt" }[] }): Promise<unknown>;
};

export async function sweepExpired(adapter: Adapter, onError: (what: string, e: unknown) => void, now = Date.now(), opts: { participants?: boolean } = {}) {
  if (now - last < INTERVAL_MS) return;
  last = now;
  const where = [{ field: "expiresAt", value: new Date(now), operator: "lt" as const }];
  await adapter.deleteMany({ model: SEEN_MODEL, where }).catch((e) => onError("seen requests", e));
  await adapter.deleteMany({ model: "verification", where }).catch((e) => onError("verification values", e));
  if (opts.participants) await adapter.deleteMany({ model: PARTICIPANT_MODEL, where }).catch((e) => onError("logout participants", e));
}

/** Tests only. */
export function resetSweepThrottle() {
  last = 0;
}
