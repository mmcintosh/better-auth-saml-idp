// Fixed in D-053 (a deleted tenant's key is retired, TENANT_KEY_RETIRED); kept as a regression
// test, and tenants.test.ts has the main suite's. Comments saying "today" describe dac64f3.
// Review 6 (D-052): a tenant's key is its entity ID and URLs, which the customer's SPs pin, and
// "never changes". But deleting a tenant frees the key, and the next tenant created with it, for
// another organization, gets the same entity ID, metadata URL and SSO/SLO URLs. SPs still
// configured for the first customer then trust the second one's Issuer (all tenants share the
// signing key in phase 1), exactly what the design refuses for slugs (§1).
// The same holds for a tenant still cached in another isolate for `tenants.cacheSeconds`.
import { describe, expect, it } from "vitest";
import { ok, world } from "./world";

describe("R6-2: a deleted tenant's key can be given to another organization", () => {
  it("tenant A (key acme) deleted; a tenant for organization B with key acme should be refused; today it gets A's entity ID", async () => {
    const w = await world();
    const first = await ok(w.tenants("/create", { organizationId: w.orgA.id, tenantKey: "acme" }));
    await ok(w.tenants("/delete", { organizationId: w.orgA.id }));
    const res = await w.tenants("/create", { organizationId: w.orgB.id, tenantKey: "acme" });
    if (res.status === 200) {
      const second = (await res.json()) as any;
      // The other organization now speaks as the first customer.
      expect(second.tenant.entityId).toBe(first.tenant.entityId);
    }
    expect(res.status, "a used tenant key was handed to another organization").toBe(409);
  });

});
