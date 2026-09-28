// Tenants (D-052): organizations with their own IdP identity, one `samlIdpTenant` row each. Looked
// up by the key in a request's URL or by an SP's organization id, and cached per isolate, misses
// too, for `tenants.cacheSeconds` (as stored SPs are, D-027), so a request naming an unknown
// tenant doesn't cost a database read each time. A tenant is used only while it is enabled and its
// organization is still the one it was made for (review 6 R6-1, D-053): same id and same
// `createdAt`. An organization deleted, even straight from the database, and an id handed out
// again to a new organization (serial ids on SQLite and D1 do that) both leave the tenant unused.
import { isEnabled } from "./sp-directory";

export const TENANT_MODEL = "samlIdpTenant";
/** Keys of deleted tenants, never used again (R6-2). */
export const RETIRED_KEY_MODEL = "samlIdpRetiredTenantKey";
/** A tenant key, as it may appear in a URL path segment. */
export const TENANT_KEY = /^[A-Za-z0-9_-]{1,64}$/;
const MAX_CACHE_ENTRIES = 2000;

export interface TenantRow {
  id: string;
  organizationId: string;
  tenantKey: string;
  /** The organization's `createdAt` when the tenant was made (R6-1). */
  organizationCreatedAt: Date | string | number;
  enabled: boolean | number | string;
  createdAt: Date;
  updatedAt: Date;
  updatedBy?: string | null;
}

/** What routing and issuance need: an enabled tenant. */
export interface Tenant {
  organizationId: string;
  tenantKey: string;
}

type Adapter = {
  findOne(args: { model: string; where: { field: string; value: unknown }[] }): Promise<unknown>;
};

export class TenantDirectory {
  private readonly cache = new Map<string, { tenant: Tenant | undefined; expires: number }>();

  constructor(
    private readonly cacheMs: number,
    private readonly now: () => number = Date.now,
  ) {}

  /** The enabled tenant whose key is in the URL; undefined for unknown, disabled or malformed keys alike. */
  async byKey(adapter: Adapter, tenantKey: string): Promise<Tenant | undefined> {
    if (!TENANT_KEY.test(tenantKey)) return undefined;
    return this.tenant(adapter, "tenantKey", tenantKey);
  }

  /** The enabled tenant of an organization (an SP's `tenant`). */
  async byOrganization(adapter: Adapter, organizationId: string): Promise<Tenant | undefined> {
    return this.tenant(adapter, "organizationId", organizationId);
  }

  /** After a write in this isolate; other isolates see it within `cacheSeconds`. */
  invalidate(): void {
    this.cache.clear();
  }

  /**
   * The row whose column is exactly `value`: a case-insensitive or PAD SPACE collation (MySQL)
   * would otherwise return tenant "acme" for the key "ACME " (as for stored SPs, review 2). Then
   * the tenant only if it's enabled and its organization is the one it was made for.
   */
  private async tenant(adapter: Adapter, field: "tenantKey" | "organizationId", value: string): Promise<Tenant | undefined> {
    const key = `${field}\u0000${value}`;
    const hit = this.cache.get(key);
    if (hit && hit.expires > this.now()) return hit.tenant;
    const found = (await adapter.findOne({ model: TENANT_MODEL, where: [{ field, value }] })) as TenantRow | null;
    const row = found && found[field] === value && isEnabled(found.enabled) ? found : null;
    const tenant = row && (await sameOrganization(adapter, row)) ? { organizationId: row.organizationId, tenantKey: row.tenantKey } : undefined;
    if (this.cacheMs > 0) {
      if (this.cache.size >= MAX_CACHE_ENTRIES) this.cache.clear();
      this.cache.set(key, { tenant, expires: this.now() + this.cacheMs });
    }
    return tenant;
  }
}

/** A date column as milliseconds; NaN for anything unreadable (which then matches nothing). */
export const instant = (value: unknown): number => (value instanceof Date || typeof value === "string" || typeof value === "number" ? new Date(value).getTime() : Number.NaN);

/** Is the tenant's organization still there, and the same one (not a new one given its id)? */
async function sameOrganization(adapter: Adapter, row: TenantRow): Promise<boolean> {
  const org = (await adapter.findOne({ model: "organization", where: [{ field: "id", value: row.organizationId }] })) as { id?: unknown; createdAt?: unknown } | null;
  if (!org || String(org.id) !== row.organizationId) return false;
  const bound = instant(row.organizationCreatedAt);
  return !Number.isNaN(bound) && instant(org.createdAt) === bound;
}
