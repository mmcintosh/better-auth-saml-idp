import { call, db, type Me, saml, useLoad } from "./lib.ts";

export interface TenantKey {
  kid: string;
  state: "next" | "active" | "previous" | "retired";
  certificate: string;
  notAfter: string;
  createdAt: string;
  activatedAt: string | null;
  activatableAt?: string;
}
export interface Tenant {
  organizationId: string;
  tenantKey: string;
  entityId: string;
  metadataUrl: string;
  ssoUrl: string;
  sloUrl: string | null;
  enabled: boolean;
  signing?: "own" | "shared";
  keys?: TenantKey[];
  warnings?: string[];
  createdAt: string;
}
export interface Org {
  id: string;
  name: string;
  slug: string;
  /** Host admins' view (/api/demo/organizations): its owners' emails and member count. */
  owners?: string[];
  memberCount?: number;
}

/**
 * The tenants this user can see, with organization names. Host admins see every tenant (the tenant
 * API). An organization's owners and admins see their own organizations' tenants (delegation's
 * read); plain members see none: tenants' details are for administrators.
 */
export function useTenants(me: Me) {
  return useLoad(async () => {
    if (me.samlAdmin) {
      const [{ tenants }, { organizations }] = await Promise.all([saml("/tenants"), call<{ organizations: Org[] }>("/api/demo/organizations")]);
      return { tenants: tenants as Tenant[], organizations };
    }
    const mine = ((await db.auth.organization.list()).data ?? []) as Org[];
    const tenants: Tenant[] = [];
    for (const org of mine) {
      try {
        tenants.push((await saml(`/tenants/get?organizationId=${encodeURIComponent(org.id)}`)).tenant);
      } catch {} // not a tenant, or not one this user administers
    }
    return { tenants, organizations: mine };
  }, [me.user?.id, me.samlAdmin]);
}

export const orgName = (organizations: Org[] | undefined, id: string | null | undefined) =>
  !id ? "Root IdP" : organizations?.find((o) => o.id === id)?.name ?? id;
