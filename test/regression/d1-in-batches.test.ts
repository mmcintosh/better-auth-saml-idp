// Fixed in D-061: `field IN (...)` lookups are read in batches. D1 allows 100 bound parameters
// per statement ("too many SQL variables"), so one IN with every id failed on workerd for the
// tenant list with per-tenant keys (100+ tenants) and for a user in 100+ organizations
// (issuance with organization attributes, and every delegated registry request).
import { describe, expect, it } from "vitest";
import { loadMemberships } from "../../src/organizations";
import { TENANT_MODEL } from "../../src/saml/tenant-directory";
import { ok, world } from "./tenant-world";

const MANY = 120;

describe("IN lookups on D1 with more than 100 values", () => {
  it("lists 120 tenants with per-tenant keys", async () => {
    const w = await world({ saml: { tenants: { enabled: true, keys: "per-tenant", cacheSeconds: 0 } } });
    // One tenant through the API (it gets a real key), the rest as rows: generating 120 keys is slow.
    await ok(w.tenants("/create", { organizationId: w.orgA.id }));
    for (let i = 0; i < MANY; i++) {
      const org = await w.org(`Many${i}`);
      const now = new Date();
      await w.ctx.adapter.create({
        model: TENANT_MODEL,
        data: { organizationId: String(org.id), tenantKey: `many-${w.t}-${i}`, organizationCreatedAt: now, enabled: true, createdAt: now, updatedAt: now },
      });
    }
    const listed = await ok(w.tenants(""));
    expect(listed.tenants).toHaveLength(MANY + 1);
    const a = listed.tenants.find((t: any) => t.organizationId === String(w.orgA.id));
    expect(a.keys).toHaveLength(1);
    expect(a.signing).toBe("own");
  });

  it("loads the memberships of a user in 120 organizations", async () => {
    const w = await world();
    for (let i = 0; i < MANY; i++) await w.join(String((await w.org(`Member${i}`)).id));
    expect(await loadMemberships(w.ctx.adapter, w.user.id)).toHaveLength(MANY);
  });
});
