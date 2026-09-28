// Review 6 (D-052): "denied events carry tenantId when the SP belongs to a tenant", and the audit
// log's tenantId column is "for filtering in SQL". Several refusals that name a tenant SP leave the
// tenant out, so their audit rows read as the root IdP's (tenantId NULL):
//   init.ts   IDP_INITIATED_NOT_ALLOWED
//   resume.ts IDP_INITIATED_NOT_ALLOWED, ACS_URL_NOT_ALLOWED, REAUTHENTICATION_REQUIRED
//   sso.ts    "SP changed tenant" (continuation)
//   slo.ts    LOGOUT_NOT_SUPPORTED (continuation and finish), "changed tenant" (continuation)
import { describe, expect, it, vi } from "vitest";
import { AUTH_BASE } from "../support/host";
import { authn, code, ok, urls, world } from "./world";

// Unique per test: on workerd the tests of a file share one D1 database.
const sp = (t: string) => ({ id: `sp-${t}`, entityId: `https://sp-a.test/${t}`, acs: "https://sp-a.test/acs" });

describe("R6-3: denied events and audit rows of tenant SPs without their tenant", () => {
  it("IdP-initiated SSO to a tenant SP that hasn't opted in: the denied event and audit row should say the tenant", async () => {
    const events: any[] = [];
    const w = await world({ saml: { auditLog: { enabled: true }, events: { onDenied: (e) => void events.push(e) } } });
    await ok(w.tenants("/create", { organizationId: w.orgA.id }));
    const SP = sp(w.t);
    await ok(w.sps("/create", { serviceProvider: { id: SP.id, entityId: SP.entityId, acsUrls: [SP.acs], tenant: w.orgA.id } }));
    await w.join(w.orgA.id);
    expect(await code(await w.browser.fetch(`${AUTH_BASE}/saml2/idp/init?sp=${SP.id}`))).toBe("IDP_INITIATED_NOT_ALLOWED");
    await vi.waitFor(() => expect(events.some((e) => e.code === "IDP_INITIATED_NOT_ALLOWED")).toBe(true));
    expect(events.find((e) => e.code === "IDP_INITIATED_NOT_ALLOWED").tenantId).toBe(w.orgA.id);
    await vi.waitFor(async () => {
      const rows = (await w.ctx.adapter.findMany({ model: "samlIdpAuditEvent", where: [{ field: "spId", value: SP.id }] })) as any[];
      expect(rows).toHaveLength(1);
      expect(rows[0].code).toBe("IDP_INITIATED_NOT_ALLOWED");
      expect(rows[0].tenantId).toBe(w.orgA.id);
    });
  });

  it("ForceAuthn at a tenant's URL resumed with the old session: REAUTHENTICATION_REQUIRED should say the tenant", async () => {
    const events: any[] = [];
    const w = await world({ saml: { events: { onDenied: (e) => void events.push(e) } } });
    await ok(w.tenants("/create", { organizationId: w.orgA.id }));
    const SP = sp(w.t);
    await ok(w.sps("/create", { serviceProvider: { id: SP.id, entityId: SP.entityId, acsUrls: [SP.acs], tenant: w.orgA.id } }));
    await w.join(w.orgA.id);
    // The user is signed in; ForceAuthn parks the request and sends them to the login page.
    const parked = await w.browser.fetch(await authn(urls(w.orgA.id).sso, { issuer: SP.entityId, acsUrl: SP.acs, forceAuthn: true }));
    expect(parked.status).toBe(302);
    const callback = new URL(parked.headers.get("location")!).searchParams.get("callbackURL")!;
    // They come back without signing in again (the session predates the request).
    expect(await code(await w.browser.fetch(callback))).toBe("REAUTHENTICATION_REQUIRED");
    await vi.waitFor(() => expect(events.some((e) => e.code === "REAUTHENTICATION_REQUIRED")).toBe(true));
    expect(events.find((e) => e.code === "REAUTHENTICATION_REQUIRED").tenantId).toBe(w.orgA.id);
  });
});
