// Fixed in D-053; kept as a regression test (tenants.test.ts has the main suite's, including an
// organization deleted straight from the database). Comments saying "today" describe dac64f3.
// Review 6 (D-052): a tenant is bound to an organization id and nothing else. When that
// organization is deleted, the tenant stays enabled (metadata, URLs, SPs). With
// `generateId: "serial"` on SQLite or D1 (an INTEGER PRIMARY KEY without AUTOINCREMENT), the next
// organization created reuses the highest freed id, so whoever creates it (any user, by the
// organization plugin's default) owns the tenant's organization and is signed in to the
// tenant's SPs under the tenant's identity.
// Node only: the workerd test schema has text ids (the D1 case is the same SQLite rule).
import { describe, expect, it } from "vitest";
import { AUTH_BASE, isWorkerd } from "../support/host";
import { Browser } from "../support/sp";
import { authn, code, ok, urls, world } from "./tenant-world";

const SP = { entityId: "https://sp-b.test/sp", acs: "https://sp-b.test/acs" };
const post = (b: Browser, path: string, body: unknown) =>
  b.fetch(`${AUTH_BASE}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

describe.skipIf(isWorkerd)("R6-1: a deleted tenant organization's id, reused, inherits the tenant", () => {
  it("serial ids on SQLite: the owner deletes the organization, another user creates one and gets the tenant's assertions; they should get nothing", async () => {
    const w = await world({ auth: { advanced: { database: { generateId: "serial", validateSchema: true } } } });
    const victim = String(w.orgB.id); // the highest organization id
    await ok(w.tenants("/create", { organizationId: victim, tenantKey: "globex" }));
    // What a tenant SP may carry: a constant role for the customer's cloud console.
    await ok(w.sps("/create", { serviceProvider: { id: "sp-b", entityId: SP.entityId, acsUrls: [SP.acs], tenant: victim, attributes: { role: { value: "admin-role" } } } }));

    // The customer's owner deletes their organization through the organization plugin.
    const owner = new Browser(w.auth);
    const ownerUser = await owner.signUp();
    await w.join(victim, ownerUser.id, "owner");
    expect((await post(owner, "/organization/delete", { organizationId: victim })).status).toBe(200);

    // Fixed: deleting the organization through Better Auth disables its tenant (today: still
    // enabled, with its metadata served).
    expect((await w.auth.handler(new Request(urls("globex").metadata))).status).toBe(404);

    // Any user creates an organization (allowed by default) and gets the freed id.
    const other = new Browser(w.auth);
    await other.signUp();
    const created = (await (await post(other, "/organization/create", { name: "Mine", slug: `mine-${w.t}` })).json()) as { id: string };
    expect(created.id).toBe(victim);

    // Expected: nothing issued under the deleted customer's identity. Today: a signed Response
    // from "globex" with the customer's constant role, for a user the customer never admitted.
    const res = await other.fetch(await authn(urls("globex").sso, { issuer: SP.entityId, acsUrl: SP.acs }));
    expect(res.status, "an assertion was issued under the deleted organization's tenant").not.toBe(200);
    expect(await code(res)).toBeDefined();
  });
});
