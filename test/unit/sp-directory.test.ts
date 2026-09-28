import { describe, expect, it } from "vitest";
import { resolveOptions } from "../../src/options";
import { lookupKeyOf, SpDirectory } from "../../src/saml/sp-directory";
import { TenantDirectory } from "../../src/saml/tenant-directory";
import { baseOptions } from "../support/config";

const log = { error: () => {} };
const row = { id: "r1", spId: "s", entityId: "https://sp.example/md", config: JSON.stringify({ id: "s", entityId: "https://sp.example/md", acsUrls: ["https://sp.example/acs"] }), enabled: true, createdAt: new Date(), updatedAt: new Date() };

describe("SpDirectory lookups", () => {
  it("only returns a stored SP for exactly the requested value (case-insensitive / PAD SPACE collations)", async () => {
    const options = resolveOptions(baseOptions({ serviceProviders: [], registry: { enabled: true, cacheSeconds: 0 } }));
    // An adapter that matches case-insensitively and ignores trailing spaces, like some MySQL collations.
    const adapter = { findOne: async (a: any) => (String(a.where[0].value).trim().toLowerCase() === row.entityId.toLowerCase() || a.where[0].value === "s" ? row : null) };
    const dir = new SpDirectory([], options);
    expect(await dir.byEntityId(adapter, "https://sp.example/md", log, "")).toMatchObject({ id: "s" });
    expect(await dir.byEntityId(adapter, "HTTPS://SP.EXAMPLE/MD", log, "")).toBeUndefined();
    expect(await dir.byEntityId(adapter, "https://sp.example/md ", log, "")).toBeUndefined();
  });
});

describe("SpDirectory with tenants (D-052)", () => {
  const options = resolveOptions(baseOptions({ serviceProviders: [], registry: { enabled: true, cacheSeconds: 0 }, tenants: { enabled: true, cacheSeconds: 0 } }));
  const entityId = "urn:shared";
  const configIn = (tenant: string) => JSON.stringify({ id: "s", entityId, acsUrls: ["https://sp.example/acs"], tenant });
  /** An adapter holding one row, whatever it's asked for by lookup key or spId. */
  const holding = (r: Record<string, unknown>) => ({ findOne: async (a: any) => (a.where[0].field === "lookupKey" ? (a.where[0].value === r.lookupKey ? r : null) : r) });

  it("a row found by a tenant's lookup key is used only if it is that tenant's SP (a hand-edited key can't cross tenants)", async () => {
    // Tenant A's SP, filed under tenant B's lookup key.
    const forged = { ...row, entityId, config: configIn("org-a"), tenantId: "org-a", lookupKey: await lookupKeyOf("org-b", entityId) };
    const dir = new SpDirectory([], options);
    expect(await dir.byEntityId(holding(forged), entityId, log, "org-b")).toBeUndefined();
    // Filed correctly, it is found in its own tenant, and nowhere else.
    const honest = { ...forged, lookupKey: await lookupKeyOf("org-a", entityId) };
    expect(await dir.byEntityId(holding(honest), entityId, log, "org-a")).toMatchObject({ id: "s", tenantId: "org-a" });
    expect(await dir.byEntityId(holding(honest), entityId, log, "org-b")).toBeUndefined();
    expect(await dir.byEntityId(holding(honest), entityId, log, "")).toBeUndefined();
  });

  it("a row whose tenantId column disagrees with its config is ignored, found by id or not", async () => {
    const edited = { ...row, entityId, config: configIn("org-a"), tenantId: "org-b", lookupKey: await lookupKeyOf("org-a", entityId) };
    const dir = new SpDirectory([], options);
    expect(dir.fromRow(edited, log)).toBeUndefined();
    expect(await dir.byId(holding(edited), "s", log)).toBeUndefined();
  });

  it("SPs in code: an entity ID is looked up in one tenant only", () => {
    const withCode = resolveOptions(
      baseOptions({
        registry: { enabled: true },
        tenants: { enabled: true },
        serviceProviders: [
          { id: "a", entityId, acsUrls: ["https://sp.example/acs"], tenant: "org-a" },
          { id: "root", entityId: "urn:root-only", acsUrls: ["https://sp.example/acs"] },
        ],
      }),
    );
    const dir = new SpDirectory(withCode.serviceProviders, withCode);
    expect(dir.inCode("x", entityId, "org-a")).toBe(true);
    expect(dir.inCode("x", entityId, "org-b")).toBe(false);
    expect(dir.inCode("x", entityId, "")).toBe(false);
    expect(dir.inCode("x", "urn:root-only", "org-a")).toBe(false);
  });
});

describe("TenantDirectory (D-052)", () => {
  it("only an exactly matching, enabled row is a tenant (case-insensitive / PAD SPACE collations, disabled rows)", async () => {
    const tenantRow = { id: "t1", organizationId: "org-a", tenantKey: "acme", enabled: 1, createdAt: new Date(), updatedAt: new Date() };
    const adapter = { findOne: async (a: any) => (String(a.where[0].value).trim().toLowerCase() === String((tenantRow as any)[a.where[0].field]).toLowerCase() ? tenantRow : null) };
    const dir = new TenantDirectory(0);
    expect(await dir.byKey(adapter, "acme")).toEqual({ organizationId: "org-a", tenantKey: "acme" });
    expect(await dir.byKey(adapter, "ACME")).toBeUndefined();
    expect(await dir.byKey(adapter, "acme ")).toBeUndefined();
    expect(await dir.byOrganization(adapter, "ORG-A")).toBeUndefined();
    expect(await new TenantDirectory(0).byKey({ findOne: async () => ({ ...tenantRow, enabled: 0 }) }, "acme")).toBeUndefined();
  });
});
