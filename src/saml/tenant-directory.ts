// Tenants (D-052): organizations with their own IdP identity, one `samlIdpTenant` row each. Looked
// up by the key in a request's URL or by an SP's organization id, and cached per isolate, misses
// too, for `tenants.cacheSeconds` (as stored SPs are, D-027), so a request naming an unknown
// tenant doesn't cost a database read each time. A disabled tenant is returned (the API shows
// it); callers that route or issue treat it as absent.
import { isEnabled } from "./sp-directory";

export const TENANT_MODEL = "samlIdpTenant";
/** A tenant key, as it may appear in a URL path segment. */
export const TENANT_KEY = /^[A-Za-z0-9_-]{1,64}$/;
const MAX_CACHE_ENTRIES = 2000;

export interface TenantRow {
  id: string;
  organizationId: string;
  tenantKey: string;
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
  private readonly cache = new Map<string, { row: TenantRow | null; expires: number }>();

  constructor(
    private readonly cacheMs: number,
    private readonly now: () => number = Date.now,
  ) {}

  /** The enabled tenant whose key is in the URL; undefined for unknown, disabled or malformed keys alike. */
  async byKey(adapter: Adapter, tenantKey: string): Promise<Tenant | undefined> {
    if (!TENANT_KEY.test(tenantKey)) return undefined;
    return active(await this.row(adapter, "tenantKey", tenantKey));
  }

  /** The enabled tenant of an organization (an SP's `tenant`). */
  async byOrganization(adapter: Adapter, organizationId: string): Promise<Tenant | undefined> {
    return active(await this.row(adapter, "organizationId", organizationId));
  }

  /** After a write in this isolate; other isolates see it within `cacheSeconds`. */
  invalidate(): void {
    this.cache.clear();
  }

  /**
   * The row whose column is exactly `value`: a case-insensitive or PAD SPACE collation (MySQL)
   * would otherwise return tenant "acme" for the key "ACME " (as for stored SPs, review 2).
   */
  private async row(adapter: Adapter, field: "tenantKey" | "organizationId", value: string): Promise<TenantRow | null> {
    const key = `${field}\u0000${value}`;
    const hit = this.cache.get(key);
    if (hit && hit.expires > this.now()) return hit.row;
    const found = (await adapter.findOne({ model: TENANT_MODEL, where: [{ field, value }] })) as TenantRow | null;
    const row = found && found[field] === value ? found : null;
    if (this.cacheMs > 0) {
      if (this.cache.size >= MAX_CACHE_ENTRIES) this.cache.clear();
      this.cache.set(key, { row, expires: this.now() + this.cacheMs });
    }
    return row;
  }
}

const active = (row: TenantRow | null): Tenant | undefined =>
  row && isEnabled(row.enabled) ? { organizationId: row.organizationId, tenantKey: row.tenantKey } : undefined;
