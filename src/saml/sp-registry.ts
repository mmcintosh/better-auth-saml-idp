import type { ResolvedServiceProvider } from "../types";

export interface SpRegistry {
  /** Look up an SP by the exact entity ID from an AuthnRequest `<Issuer>`. */
  byEntityId(entityId: string): ResolvedServiceProvider | undefined;
  byId(id: string): ResolvedServiceProvider | undefined;
  all(): readonly ResolvedServiceProvider[];
}

export function createSpRegistry(sps: ResolvedServiceProvider[]): SpRegistry {
  const byEntity = new Map(sps.map((sp) => [sp.entityId, sp]));
  const byId = new Map(sps.map((sp) => [sp.id, sp]));
  return {
    byEntityId: (entityId) => byEntity.get(entityId),
    byId: (id) => byId.get(id),
    all: () => sps,
  };
}

/**
 * Pick the ACS URL to post the Response to.
 * - A requested URL must equal one allow-listed URL exactly (no normalisation), else undefined.
 * - No requested URL: the first allow-listed URL.
 * Never returns a URL that is not in `sp.acsUrls`.
 */
export function resolveAcsUrl(sp: ResolvedServiceProvider, requested: string | undefined | null): string | undefined {
  if (requested === undefined || requested === null || requested === "") return sp.acsUrls[0];
  return sp.acsUrls.find((u) => u === requested);
}
