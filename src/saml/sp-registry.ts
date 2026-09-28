import type { ResolvedServiceProvider } from "../types";

export interface SpRegistry {
  /**
   * Look up an SP by the exact entity ID from an AuthnRequest `<Issuer>`, within one tenant
   * (D-052): `""` is the root IdP. An SP of another tenant is never found.
   */
  byEntityId(entityId: string, tenantId?: string): ResolvedServiceProvider | undefined;
  byId(id: string): ResolvedServiceProvider | undefined;
  all(): readonly ResolvedServiceProvider[];
}

const scoped = (tenantId: string, entityId: string) => `${tenantId}\u0000${entityId}`;

export function createSpRegistry(sps: ResolvedServiceProvider[]): SpRegistry {
  const byEntity = new Map(sps.map((sp) => [scoped(sp.tenantId ?? "", sp.entityId), sp]));
  const byId = new Map(sps.map((sp) => [sp.id, sp]));
  return {
    byEntityId: (entityId, tenantId = "") => byEntity.get(scoped(tenantId, entityId)),
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
