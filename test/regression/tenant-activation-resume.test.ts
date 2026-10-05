// External review of 1.1.2 (D-065): key activation is several writes. Cut short after the active
// key moved to "previous", a retry found no active key and took the "first own key" branch: it
// retired the tenant's own old key at once and published the shared root certificate for a tenant
// that never used it. A retry now finishes the activation instead.
import { expect, it } from "vitest";
import { stateKeyOf, TENANT_KEY_MODEL } from "../../src/saml/tenant-keys";
import { ok, world } from "./tenant-world";

it("a retried activation, cut short after the active key moved to previous, keeps the tenant's own key and publishes no shared one", async () => {
  const w = await world({ saml: { tenants: { enabled: true, cacheSeconds: 0, keys: "per-tenant" } } });
  await ok(w.tenants("/create", { organizationId: w.orgA.id, tenantKey: `acme-${w.t}` }));
  await ok(w.tenants("/keys/rotate", { organizationId: w.orgA.id }));
  const keys = async () => ((await w.ctx.adapter.findMany({ model: TENANT_KEY_MODEL, where: [{ field: "tenantId", value: String(w.orgA.id) }] })) as { id: string; kid: string; state: string }[]);
  const before = await keys();
  const own = before.find((k) => k.state === "active")!;
  const next = before.find((k) => k.state === "next")!;
  // The interruption: the active key already moved to previous; the next one not yet active.
  await w.ctx.adapter.update({ model: TENANT_KEY_MODEL, where: [{ field: "id", value: own.id }], update: { state: "previous", stateKey: stateKeyOf(String(w.orgA.id), "previous") } });
  await ok(w.tenants("/keys/activate", { organizationId: w.orgA.id, force: true }));
  const after = Object.fromEntries((await keys()).map((k) => [k.kid, k.state]));
  expect(after[next.kid]).toBe("active");
  expect(after[own.kid]).toBe("previous");
  expect(Object.keys(after)).not.toContain("shared");
});
