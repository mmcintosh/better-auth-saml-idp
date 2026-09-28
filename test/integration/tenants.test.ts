// Multi-tenant IdP, phase 1 (D-052): an IdP identity per organization under the shared key.
// Both runtimes: on workerd the organization and tenant tables come from D1 migration 0007.
// Tenant SPs here are in code (so one entity ID can sit in two tenants on D1, whose test schema
// keeps the old entityId UNIQUE constraint); tenants-shared-entity.test.ts covers stored ones.
import { createHmac, createPrivateKey } from "node:crypto";
import { organization } from "better-auth/plugins";
import * as samlify from "samlify";
import { SignedXml } from "xml-crypto";
import { describe, expect, inject, it, vi } from "vitest";
import { samlIdp } from "../../src/index";
import { resolveOptions } from "../../src/options";
import { buildLogoutResponse, redirectBindingUrl } from "../../src/saml/logout";
import { decodeAuthnRequest, parseRedirectQuery, verifyMessageSignature } from "../../src/saml/request";
import { libxml2Validator } from "../../src/saml/validator";
import { base64url } from "../../src/storage/pending";
import type { SamlIdpOptions, ServiceProviderConfig } from "../../src/types";
import { baseOptions, IDP_ENTITY_ID, SP_ACS, SP_ENTITY_ID } from "../support/config";
import { AUTH_BASE, BASE_URL, createHost, createHostDatabase, isWorkerd } from "../support/host";
import { authnRequestXml, Browser, newRequestId, readAutoPost, redirectUrl, SSO_URL } from "../support/sp";

const keys = inject("keys");
const SECRET = "test-secret-that-is-at-least-32-characters-long";
const PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
const validator = libxml2Validator();
// One SP (AWS-like: one entity ID and ACS for every customer) registered in tenants A and B.
const AWS = { entityId: "urn:amazon:webservices", acs: "https://signin.aws.amazon.com/saml" };
const ONLY_A = { entityId: "https://only-a.test/sp", acs: "https://only-a.test/acs", slo: "https://only-a.test/slo" };
const ONLY_B = { entityId: "https://only-b.test/sp", acs: "https://only-b.test/acs", slo: "https://only-b.test/slo" };
const ROOT = { entityId: SP_ENTITY_ID, acs: SP_ACS, slo: "https://sp.test/slo" };

const canManage = ({ user }: { user: Record<string, unknown> }) => user.role === "admin";
const code = async (res: Response) => /<code>([A-Z_]+)<\/code>/.exec(await res.clone().text())?.[1];
const json = async (res: Response) => (await res.json()) as any;
const issuer = (xml: string) => /<saml:Issuer>([^<]+)<\/saml:Issuer>/.exec(xml)?.[1];
const spSigning = (pem: string) => ({ signatureAlgorithm: "rsa-sha256", digestAlgorithm: "sha256", keyObject: createPrivateKey(pem), certificate: "" }) as any;
const urls = (key: string) => ({
  sso: `${AUTH_BASE}/saml2/idp/sso/${key}`,
  slo: `${AUTH_BASE}/saml2/idp/slo/${key}`,
  metadata: `${AUTH_BASE}/saml2/idp/metadata/${key}`,
});
let n = 0;

type Orgs = { a: string; b: string; t: string };

/**
 * A host with tenants on and three organizations: A and B are tenants (created through the API
 * by an admin), C is a plain organization. `code` gives the SPs in code, which may name A and B.
 */
async function world(o: { code?: (orgs: Orgs) => ServiceProviderConfig[]; saml?: Partial<SamlIdpOptions>; logs?: string[] } = {}) {
  const t = `${Date.now().toString(36)}${n++}`;
  const database = await createHostDatabase();
  const saml = (sps: ServiceProviderConfig[]): Partial<SamlIdpOptions> => ({
    registry: { enabled: true, canManage, cacheSeconds: 0 },
    tenants: { enabled: true, cacheSeconds: 0 },
    singleLogout: { enabled: true },
    serviceProviders: sps,
    ...o.saml,
  });
  // A first host migrates (Node) and makes the organizations, whose ids the SPs in code need.
  const first = await createHost({ database, plugins: [organization()], saml: saml([]) });
  const firstCtx = (await first.auth.$context) as any;
  const org = (name: string) => firstCtx.adapter.create({ model: "organization", data: { name, slug: `${name.toLowerCase()}-${t}`, createdAt: new Date() } });
  const [orgA, orgB, orgC] = [await org("Acme"), await org("Globex"), await org("Initech")];
  const { auth } = await createHost({
    database,
    plugins: [organization()],
    saml: saml(o.code?.({ a: orgA.id, b: orgB.id, t }) ?? []),
    auth: o.logs ? { logger: { level: "info", log: (_l: string, m: string) => o.logs?.push(m) } } : {},
  });
  const ctx = (await auth.$context) as any;
  const admin = new Browser(auth);
  const adminUser = await admin.signUp();
  await ctx.adapter.update({ model: "user", where: [{ field: "id", value: adminUser.id }], update: { role: "admin" } });
  const tenants = (path: string, body?: unknown, as = admin) =>
    as.fetch(`${AUTH_BASE}/saml-idp/tenants${path}`, {
      method: body === undefined ? "GET" : "POST",
      headers: { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  const sps = (path: string, body?: unknown) =>
    admin.fetch(`${AUTH_BASE}/saml-idp/service-providers${path}`, {
      method: body === undefined ? "GET" : "POST",
      headers: { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  expect((await tenants("/create", { organizationId: orgA.id })).status).toBe(200);
  expect((await tenants("/create", { organizationId: orgB.id })).status).toBe(200);
  const browser = new Browser(auth);
  const user = await browser.signUp();
  const join = (orgId: string, role = "member") => ctx.adapter.create({ model: "member", data: { organizationId: orgId, userId: user.id, role, createdAt: new Date() } });
  return { auth, ctx, admin, browser, user, orgA, orgB, orgC, t, tenants, sps, join, A: urls(orgA.id), B: urls(orgB.id) };
}

/** Tenant A has AWS (persistent NameIDs) and ONLY_A; tenant B has AWS and ONLY_B; the root has ROOT. */
const standard = ({ a, b }: Orgs): ServiceProviderConfig[] => [
  { id: "aws-a", entityId: AWS.entityId, acsUrls: [AWS.acs], nameIdFormat: PERSISTENT, tenant: a },
  { id: "aws-b", entityId: AWS.entityId, acsUrls: [AWS.acs], nameIdFormat: PERSISTENT, tenant: b },
  { id: "only-a", entityId: ONLY_A.entityId, acsUrls: [ONLY_A.acs], tenant: a, spCertificates: keys.sp.certificate, singleLogoutService: { url: ONLY_A.slo }, allowIdpInitiated: true },
  { id: "only-b", entityId: ONLY_B.entityId, acsUrls: [ONLY_B.acs], tenant: b, spCertificates: keys.idpNext.certificate, singleLogoutService: { url: ONLY_B.slo, binding: "post" } },
  { id: "root", entityId: ROOT.entityId, acsUrls: [ROOT.acs], spCertificates: keys.sp.certificate, singleLogoutService: { url: ROOT.slo } },
];

/** An HTTP-Redirect AuthnRequest to `ssoUrl` (the root's by default). */
async function authn(ssoUrl: string, spec: Parameters<typeof authnRequestXml>[0] = {}, opts: Parameters<typeof redirectUrl>[1] = {}) {
  const url = await redirectUrl(authnRequestXml({ destination: ssoUrl, ...spec }).xml, opts);
  return url.replace(SSO_URL, ssoUrl);
}

/** Verify a Response as an SP configured with this IdP metadata would (samlify: signatures, Issuer, times). */
async function spAccepts(auth: { handler(r: Request): Promise<Response> }, metadataUrl: string, sp: { entityId: string; acs: string }, samlResponse: string) {
  samlify.setSchemaValidator({
    validate: async (xml: string) => {
      const r = await validator.validate(xml, "protocol");
      if (!r.valid) throw new Error(`ERR_SCHEMA: ${r.errors.join("; ")}`);
      return "SUCCESS_VALIDATE_XML";
    },
  });
  const idp = samlify.IdentityProvider({ metadata: await (await auth.handler(new Request(metadataUrl))).text() });
  const spApp = samlify.ServiceProvider({
    entityID: sp.entityId,
    wantAssertionsSigned: true,
    wantMessageSigned: true,
    assertionConsumerService: [{ Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", Location: sp.acs }],
    clockDrifts: [-60_000, 60_000],
  });
  return spApp.parseLoginResponse(idp, "post", { body: { SAMLResponse: samlResponse } });
}

describe("tenants: configuration (D-052)", () => {
  const tenantOpts = (over: Partial<SamlIdpOptions> = {}) => baseOptions({ registry: { enabled: true }, tenants: { enabled: true }, ...over });

  it("off by default, and an SP can't name a tenant without it", () => {
    expect(() => resolveOptions(baseOptions({ serviceProviders: [{ id: "s", entityId: "e", acsUrls: [SP_ACS], tenant: "org" }] }))).toThrow(/tenant: requires tenants.enabled/);
  });

  it("needs registry.enabled; per-tenant keys aren't available; delegation needs per-tenant keys", () => {
    expect(() => resolveOptions(baseOptions({ tenants: { enabled: true } }))).toThrow(/tenants.enabled: requires registry.enabled/);
    expect(() => resolveOptions(tenantOpts({ tenants: { enabled: true, keys: "per-tenant" as any } }))).toThrow(/"per-tenant" is not available/);
    // Multi-tenant design §5.1 (b): under a shared key, delegated SP management is a startup error.
    expect(() => resolveOptions(tenantOpts({ tenants: { enabled: true, delegation: { roles: ["owner"] } } as any }))).toThrow(/tenants.delegation: requires tenants.keys: "per-tenant"/);
    expect(() => resolveOptions(tenantOpts({ tenants: { enabled: true, keys: "shared", delegation: { roles: ["owner"] } } as any }))).toThrow(/tenants.delegation/);
    expect(() => resolveOptions(tenantOpts({ tenants: { enabled: true, keys: "shared" } }))).not.toThrow();
  });

  it("a tenant SP's members are its tenant's: an organization rule may only add roles", () => {
    const sp = (organization: Record<string, unknown>) => tenantOpts({ serviceProviders: [{ id: "s", entityId: "e", acsUrls: [SP_ACS], tenant: "org-a", organization } as any] });
    expect(() => resolveOptions(sp({ slug: "acme" }))).toThrow(/organization: a tenant SP's members are its tenant's/);
    expect(() => resolveOptions(sp({ id: "org-b" }))).toThrow(/organization: a tenant SP's members are its tenant's/);
    const ok = resolveOptions(sp({ id: "org-a", roles: ["admin"] }));
    expect(ok.serviceProviders[0]!.organization).toEqual({ id: "org-a", roles: ["admin"] });
    // Without a rule, membership is implied.
    expect(resolveOptions(tenantOpts({ serviceProviders: [{ id: "s", entityId: "e", acsUrls: [SP_ACS], tenant: "org-a" }] })).serviceProviders[0]!.organization).toEqual({ id: "org-a" });
  });

  it("entity IDs are unique per tenant: the same one in two tenants is allowed, and warned about; twice in one tenant is not", () => {
    const two = resolveOptions(tenantOpts({ serviceProviders: [{ id: "x", entityId: "e", acsUrls: [SP_ACS], tenant: "a" }, { id: "y", entityId: "e", acsUrls: [SP_ACS], tenant: "b" }] }));
    expect(two.warnings.join("\n")).toMatch(/serviceProviders.1: same entity ID and an ACS URL as SP x in tenant a/);
    // Different ACS URLs: no assertion for one can land at the other's, so no warning.
    const apart = resolveOptions(tenantOpts({ serviceProviders: [{ id: "x", entityId: "e", acsUrls: [SP_ACS], tenant: "a" }, { id: "y", entityId: "e", acsUrls: ["https://other.test/acs"], tenant: "b" }] }));
    expect(apart.warnings.join("\n")).not.toMatch(/same entity ID/);
    expect(() => resolveOptions(tenantOpts({ serviceProviders: [{ id: "x", entityId: "e", acsUrls: [SP_ACS], tenant: "a" }, { id: "y", entityId: "e", acsUrls: [SP_ACS], tenant: "a" }] }))).toThrow(
      /duplicate entityId "e" in tenant "a"/,
    );
  });

  it("at startup: needs the organization plugin and a pinned baseURL", async () => {
    const { betterAuth } = await import("better-auth");
    const { memoryAdapter } = await import("better-auth/adapters/memory");
    const start = (o: { baseURL?: string; plugins: unknown[] }) =>
      betterAuth({
        ...(o.baseURL ? { baseURL: o.baseURL } : {}),
        secret: SECRET,
        database: memoryAdapter({ user: [], session: [], account: [], verification: [] }),
        telemetry: { enabled: false },
        logger: { disabled: true },
        plugins: [...(o.plugins as any[]), samlIdp(baseOptions({ registry: { enabled: true }, tenants: { enabled: true } }))],
      }).$context;
    await expect(start({ baseURL: BASE_URL, plugins: [] })).rejects.toThrow(/requires Better Auth's organization plugin/);
    // No baseURL anywhere: entity IDs would follow the Host header.
    await expect(start({ plugins: [organization()] })).rejects.toThrow(/requires a pinned baseURL/);
    await expect(start({ baseURL: BASE_URL, plugins: [organization()] })).resolves.toBeDefined();
  });
});

describe("tenants: routing and isolation (D-052)", () => {
  it("one SP entity ID in tenants A and B: each tenant's URL answers with its own Issuer, and the SP verifies it against that tenant's metadata", async () => {
    const w = await world({ code: standard });
    await w.join(w.orgA.id);
    await w.join(w.orgB.id);
    const toA = await readAutoPost(await w.browser.fetch(await authn(w.A.sso, { issuer: AWS.entityId, acsUrl: AWS.acs })));
    const toB = await readAutoPost(await w.browser.fetch(await authn(w.B.sso, { issuer: AWS.entityId, acsUrl: AWS.acs })));
    expect(issuer(toA.xml)).toBe(w.A.metadata);
    expect(issuer(toB.xml)).toBe(w.B.metadata);
    expect(toA.xml).toContain(`<saml:Audience>${AWS.entityId}</saml:Audience>`);
    await spAccepts(w.auth, w.A.metadata, AWS, toA.samlResponse);
    await spAccepts(w.auth, w.B.metadata, AWS, toB.samlResponse);
    // Shared key (phase 1): only the Issuer check stops an SP pinned to A from taking B's assertion.
    await expect(spAccepts(w.auth, w.A.metadata, AWS, toB.samlResponse)).rejects.toThrow(/ERR_UNMATCH_ISSUER/);
    // Persistent NameIDs are per tenant: the two tenants can't link the person.
    const nameIdOf = (xml: string) => /<saml:NameID [^>]*>([^<]+)</.exec(xml)![1]!;
    const tenantNameId = (org: string) =>
      base64url(new Uint8Array(createHmac("sha256", SECRET).update(`saml-idp:persistent\u0000${org}\u0000${AWS.entityId}\u0000${w.user.id}`).digest()));
    expect(nameIdOf(toA.xml)).toBe(tenantNameId(w.orgA.id));
    expect(nameIdOf(toB.xml)).toBe(tenantNameId(w.orgB.id));
    expect(nameIdOf(toA.xml)).not.toBe(nameIdOf(toB.xml));
  });

  it("an SP is looked up in the URL's tenant only, in each direction, whatever its Issuer says", async () => {
    const w = await world({ code: standard });
    await w.join(w.orgA.id);
    await w.join(w.orgB.id);
    expect(await code(await w.browser.fetch(await authn(w.B.sso, { issuer: ONLY_A.entityId, acsUrl: ONLY_A.acs })))).toBe("UNKNOWN_SERVICE_PROVIDER");
    expect(await code(await w.browser.fetch(await authn(w.A.sso, { issuer: ONLY_B.entityId, acsUrl: ONLY_B.acs })))).toBe("UNKNOWN_SERVICE_PROVIDER");
    // Each is found in its own tenant.
    expect(issuer((await readAutoPost(await w.browser.fetch(await authn(w.A.sso, { issuer: ONLY_A.entityId, acsUrl: ONLY_A.acs })))).xml)).toBe(w.A.metadata);
    expect(issuer((await readAutoPost(await w.browser.fetch(await authn(w.B.sso, { issuer: ONLY_B.entityId, acsUrl: ONLY_B.acs })))).xml)).toBe(w.B.metadata);
  });

  it("the root URL finds root SPs only, and a tenant's URL never finds a root SP", async () => {
    const w = await world({ code: standard });
    await w.join(w.orgA.id);
    expect(await code(await w.browser.fetch(await authn(SSO_URL, { issuer: ONLY_A.entityId, acsUrl: ONLY_A.acs })))).toBe("UNKNOWN_SERVICE_PROVIDER");
    expect(await code(await w.browser.fetch(await authn(SSO_URL, { issuer: AWS.entityId, acsUrl: AWS.acs })))).toBe("UNKNOWN_SERVICE_PROVIDER");
    expect(await code(await w.browser.fetch(await authn(w.A.sso, { issuer: ROOT.entityId, acsUrl: ROOT.acs })))).toBe("UNKNOWN_SERVICE_PROVIDER");
    // The root IdP carries on next to the tenants, unchanged.
    const root = await readAutoPost(await w.browser.fetch(await authn(SSO_URL)));
    expect(issuer(root.xml)).toBe(IDP_ENTITY_ID);
    await spAccepts(w.auth, `${AUTH_BASE}/saml2/idp/metadata`, ROOT, root.samlResponse);
  });

  it("a request whose Destination is tenant A's URL is refused at tenant B's", async () => {
    const w = await world({ code: standard });
    await w.join(w.orgB.id);
    const res = await w.browser.fetch((await authn(w.A.sso, { issuer: AWS.entityId, acsUrl: AWS.acs })).replace(w.A.sso, w.B.sso));
    expect(await code(res)).toBe("INVALID_SAML_REQUEST");
  });

  it("replay: one request ID at A and at B is two requests (two SPs); a replay within A is refused", async () => {
    const w = await world({ code: standard });
    await w.join(w.orgA.id);
    await w.join(w.orgB.id);
    const id = newRequestId();
    expect((await w.browser.fetch(await authn(w.A.sso, { id, issuer: AWS.entityId, acsUrl: AWS.acs }))).status).toBe(200);
    expect((await w.browser.fetch(await authn(w.B.sso, { id, issuer: AWS.entityId, acsUrl: AWS.acs }))).status).toBe(200);
    expect(await code(await w.browser.fetch(await authn(w.A.sso, { id, issuer: AWS.entityId, acsUrl: AWS.acs })))).toBe("DUPLICATE_REQUEST_ID");
  });

  it("an unknown or disabled tenant looks like an unknown SP; re-enabled, it works again", async () => {
    const w = await world({ code: standard });
    await w.join(w.orgA.id);
    expect(await code(await w.browser.fetch(await authn(urls("nope").sso, { issuer: AWS.entityId, acsUrl: AWS.acs })))).toBe("UNKNOWN_SERVICE_PROVIDER");
    expect(await code(await w.browser.fetch(await authn(urls(w.orgC.id).sso, { issuer: AWS.entityId, acsUrl: AWS.acs })))).toBe("UNKNOWN_SERVICE_PROVIDER");
    expect((await w.tenants("/update", { organizationId: w.orgA.id, enabled: false })).status).toBe(200);
    expect(await code(await w.browser.fetch(await authn(w.A.sso, { issuer: AWS.entityId, acsUrl: AWS.acs })))).toBe("UNKNOWN_SERVICE_PROVIDER");
    // IdP-initiated SSO to its SP gets nothing either: never the root identity instead.
    expect(await code(await w.browser.fetch(`${AUTH_BASE}/saml2/idp/init?sp=only-a`))).toBe("UNKNOWN_SERVICE_PROVIDER");
    await w.tenants("/update", { organizationId: w.orgA.id, enabled: true });
    expect((await w.browser.fetch(await authn(w.A.sso, { issuer: AWS.entityId, acsUrl: AWS.acs }))).status).toBe(200);
  });

  it("HTTP-POST binding at a tenant's URL: cross-site POST accepted, re-entry at the same tenant URL, issued under the tenant", async () => {
    const w = await world({ code: standard });
    await w.join(w.orgA.id);
    const post = await w.browser.fetch(w.A.sso, {
      method: "POST",
      crossSite: true,
      headers: { "content-type": "application/x-www-form-urlencoded", origin: "https://only-a.test" },
      body: new URLSearchParams({ SAMLRequest: btoa(authnRequestXml({ issuer: ONLY_A.entityId, acsUrl: ONLY_A.acs, destination: w.A.sso }).xml) }).toString(),
    });
    expect(post.status).toBe(303);
    expect(post.headers.get("location")).toMatch(new RegExp(`^${w.A.sso}\\?cid=`));
    const form = await readAutoPost(await w.browser.follow(post));
    expect(issuer(form.xml)).toBe(w.A.metadata);
  });

  it("a POST continuation re-entered at another tenant's URL, or the root's, is refused", async () => {
    const w = await world({ code: standard });
    await w.join(w.orgA.id);
    await w.join(w.orgB.id);
    for (const other of [w.B.sso, SSO_URL]) {
      const post = await w.browser.fetch(w.A.sso, {
        method: "POST",
        crossSite: true,
        headers: { "content-type": "application/x-www-form-urlencoded", origin: "https://sp.test" },
        body: new URLSearchParams({ SAMLRequest: btoa(authnRequestXml({ issuer: AWS.entityId, acsUrl: AWS.acs, destination: w.A.sso }).xml) }).toString(),
      });
      const cid = new URL(post.headers.get("location")!).searchParams.get("cid");
      expect(await code(await w.browser.fetch(`${other}?cid=${cid}`)), other).toBe("UNKNOWN_SERVICE_PROVIDER");
    }
  });

  it("signed out: the login page is told the tenant; after sign-in the Response is the tenant's", async () => {
    const w = await world({ code: standard });
    await w.join(w.orgA.id);
    const anon = new Browser(w.auth);
    const res = await anon.fetch(await authn(w.A.sso, { issuer: AWS.entityId, acsUrl: AWS.acs }));
    const login = new URL(res.headers.get("location")!);
    expect(login.searchParams.get("tenant")).toBe(w.orgA.id);
    const resume = login.searchParams.get("callbackURL")!;
    expect(resume).toMatch(/\/saml2\/idp\/resume\?rid=/);
    await anon.signIn(w.user.email);
    expect(issuer((await readAutoPost(await anon.fetch(resume))).xml)).toBe(w.A.metadata);
  });

  it("IdP-initiated SSO (/init?sp=) to a tenant SP is issued under its tenant", async () => {
    const w = await world({ code: standard });
    await w.join(w.orgA.id);
    const form = await readAutoPost(await w.browser.fetch(`${AUTH_BASE}/saml2/idp/init?sp=only-a`));
    expect(issuer(form.xml)).toBe(w.A.metadata);
    expect(form.xml).not.toContain("InResponseTo");
  });

  it("a pending request whose SP has changed tenant by the time it resumes is refused", async () => {
    // Tenants are immutable through the API; a stored row edited by hand is the only way.
    const w = await world();
    const sp = { id: `mv-${w.t}`, entityId: `https://mv${w.t}.test/sp`, acsUrls: [`https://mv${w.t}.test/acs`], tenant: w.orgA.id };
    expect((await w.sps("/create", { serviceProvider: sp })).status).toBe(200);
    await w.join(w.orgA.id);
    await w.join(w.orgB.id);
    const anon = new Browser(w.auth);
    const res = await anon.fetch(await authn(w.A.sso, { issuer: sp.entityId, acsUrl: sp.acsUrls[0] }));
    const resume = new URL(res.headers.get("location")!).searchParams.get("callbackURL")!;
    const { lookupKeyOf } = await import("../../src/saml/sp-directory");
    await w.ctx.adapter.update({
      model: "samlIdpServiceProvider",
      where: [{ field: "spId", value: sp.id }],
      update: { tenantId: w.orgB.id, lookupKey: await lookupKeyOf(w.orgB.id, sp.entityId), config: JSON.stringify({ ...sp, tenant: w.orgB.id }) },
    });
    await anon.signIn(w.user.email);
    expect(await code(await anon.fetch(resume))).toBe("UNKNOWN_SERVICE_PROVIDER");
  });
});

describe("tenants: membership is mandatory (D-052, maintainer decision 2)", () => {
  it("only members of the tenant's organization sign in; with roles, only those roles", async () => {
    const w = await world({
      code: ({ a }) => [
        { id: "any-member", entityId: ONLY_A.entityId, acsUrls: [ONLY_A.acs], tenant: a },
        { id: "admins", entityId: "https://admins.test/sp", acsUrls: ["https://admins.test/acs"], tenant: a, organization: { id: a, roles: ["admin"] } },
      ],
    });
    expect(await code(await w.browser.fetch(await authn(w.A.sso, { issuer: ONLY_A.entityId, acsUrl: ONLY_A.acs })))).toBe("ACCESS_DENIED");
    await w.join(w.orgB.id); // another organization's membership doesn't count
    expect(await code(await w.browser.fetch(await authn(w.A.sso, { issuer: ONLY_A.entityId, acsUrl: ONLY_A.acs })))).toBe("ACCESS_DENIED");
    await w.join(w.orgA.id, "member");
    expect((await w.browser.fetch(await authn(w.A.sso, { issuer: ONLY_A.entityId, acsUrl: ONLY_A.acs }))).status).toBe(200);
    expect(await code(await w.browser.fetch(await authn(w.A.sso, { issuer: "https://admins.test/sp", acsUrl: "https://admins.test/acs" })))).toBe("ACCESS_DENIED");
  });

  it("organization attributes cover the tenant's organization only, never the user's others", async () => {
    const w = await world({
      code: ({ a }) => [{ id: "attrs", entityId: ONLY_A.entityId, acsUrls: [ONLY_A.acs], tenant: a, attributes: { orgs: { organization: "slugs" }, roles: { organization: "roles" } } }],
    });
    await w.join(w.orgA.id, "admin");
    await w.join(w.orgB.id, "owner");
    const { xml } = await readAutoPost(await w.browser.fetch(await authn(w.A.sso, { issuer: ONLY_A.entityId, acsUrl: ONLY_A.acs })));
    const values = (name: string) => [...new RegExp(`<saml:Attribute Name="${name}"[^>]*>([\\s\\S]*?)</saml:Attribute>`).exec(xml)![1]!.matchAll(/<saml:AttributeValue>([^<]*)</g)].map((m) => m[1]);
    expect(values("orgs")).toEqual([`acme-${w.t}`]);
    expect(values("roles")).toEqual(["admin"]);
    expect(xml).not.toContain("globex");
  });

  it("authorize() sees the SP's tenant", async () => {
    let seen: unknown;
    const authorize = ({ serviceProvider }: { serviceProvider: { tenantId: string | null } }) => {
      seen = serviceProvider.tenantId;
      return true;
    };
    const w = await world({ code: ({ a }) => [{ id: "z", entityId: ONLY_A.entityId, acsUrls: [ONLY_A.acs], tenant: a, authorize }] });
    await w.join(w.orgA.id);
    await readAutoPost(await w.browser.fetch(await authn(w.A.sso, { issuer: ONLY_A.entityId, acsUrl: ONLY_A.acs })));
    expect(seen).toBe(w.orgA.id);
  });
});

describe("tenants: metadata (D-052)", () => {
  it("each tenant's metadata: its entity ID (the metadata URL), its SSO and SLO URLs, the shared key, XSD-valid, no organization name", async () => {
    const w = await world({ code: standard });
    const res = await w.auth.handler(new Request(w.A.metadata));
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/samlmetadata+xml; charset=utf-8");
    const xml = await res.text();
    expect(await validator.validate(xml, "metadata")).toEqual({ valid: true });
    const md = samlify.IdentityProvider({ metadata: xml }).entityMeta;
    expect(md.getEntityID()).toBe(w.A.metadata);
    expect(md.getSingleSignOnService("redirect")).toBe(w.A.sso);
    expect(md.getSingleLogoutService("redirect")).toBe(w.A.slo);
    expect(xml.replace(/\s+/g, "")).toContain(keys.idp.certificate.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""));
    expect(xml).toContain(PERSISTENT); // tenant A's SPs in code use it
    expect(xml).toMatch(/WantAuthnRequestsSigned="false"/);
    for (const leak of ["Acme", "acme", "Organization"]) expect(xml).not.toContain(leak);
    // The root's metadata is unchanged beside it.
    const root = await (await w.auth.handler(new Request(`${AUTH_BASE}/saml2/idp/metadata`))).text();
    expect(samlify.IdentityProvider({ metadata: root }).entityMeta.getEntityID()).toBe(IDP_ENTITY_ID);
  });

  it("signed tenant metadata verifies and stays XSD-valid", async () => {
    const w = await world({ code: standard, saml: { signMetadata: true } });
    const xml = await (await w.auth.handler(new Request(w.B.metadata))).text();
    expect(await validator.validate(xml, "metadata")).toEqual({ valid: true });
    const sig = /<ds:Signature[\s\S]*?<\/ds:Signature>/.exec(xml)![0];
    const v = new SignedXml({ publicCert: keys.idp.certificate });
    v.loadSignature(sig);
    expect(v.checkSignature(xml)).toBe(true);
  });

  it("an unknown key, a disabled tenant and an organization that isn't a tenant all get the same 404", async () => {
    const w = await world({ code: standard });
    await w.tenants("/update", { organizationId: w.orgB.id, enabled: false });
    const answers = await Promise.all(
      [urls("no-such-tenant").metadata, w.B.metadata, urls(w.orgC.id).metadata, `${AUTH_BASE}/saml2/idp/metadata/bad%20key`].map(async (u) => {
        const r = await w.auth.handler(new Request(u));
        return `${r.status} ${r.headers.get("content-type")} ${await r.text()}`;
      }),
    );
    expect(new Set(answers).size).toBe(1);
    expect(answers[0]).toMatch(/^404 /);
  });
});

describe("tenants: Single Logout across tenants (D-052)", () => {
  /** The user signs in to ONLY_A (tenant A, Redirect), ONLY_B (tenant B, POST) and ROOT. */
  async function signedInEverywhere() {
    const w = await world({ code: standard });
    await w.join(w.orgA.id);
    await w.join(w.orgB.id);
    const a = await readAutoPost(await w.browser.fetch(await authn(w.A.sso, { issuer: ONLY_A.entityId, acsUrl: ONLY_A.acs })));
    await readAutoPost(await w.browser.fetch(await authn(w.B.sso, { issuer: ONLY_B.entityId, acsUrl: ONLY_B.acs })));
    await readAutoPost(await w.browser.fetch(await authn(SSO_URL)));
    const nameId = /<saml:NameID [^>]*>([^<]+)</.exec(a.xml)![1]!;
    const sessionIndex = /SessionIndex="([^"]+)"/.exec(a.xml)![1]!;
    const lr = (destination: string, id = `_lr${Date.now().toString(36)}${n++}`) => ({
      id,
      xml:
        `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id}" Version="2.0" IssueInstant="${new Date().toISOString().replace(/\.\d{3}Z$/, "Z")}" Destination="${destination}">` +
        `<saml:Issuer>${ONLY_A.entityId}</saml:Issuer><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${nameId}</saml:NameID>` +
        `<samlp:SessionIndex>${sessionIndex}</samlp:SessionIndex></samlp:LogoutRequest>`,
    });
    return { ...w, lr };
  }
  const postForm = (html: string) => ({
    xml: new TextDecoder().decode(Uint8Array.from(atob(/name="SAMLRequest" value="([^"]*)"/.exec(html)![1]!), (c) => c.charCodeAt(0))),
    relayState: /name="RelayState" value="([^"]*)"/.exec(html)![1]!,
  });
  const redirected = async (location: string, param: "SAMLRequest" | "SAMLResponse") => {
    const u = new URL(location);
    const raw = parseRedirectQuery(u.search.slice(1), param);
    const xml = await decodeAuthnRequest(raw);
    verifyMessageSignature(raw, xml, [keys.idp.certificate], { allowInsecureSha1: false });
    return { target: `${u.origin}${u.pathname}`, xml, relayState: raw.relayState };
  };

  it("logout from tenant A's SP reaches B's SP from B's identity and the root's from the root's, then answers A from A's", async () => {
    const w = await signedInEverywhere();
    const req = w.lr(w.A.slo);
    const first = await w.browser.fetch(redirectBindingUrl(w.A.slo, "SAMLRequest", req.xml, "rs-a", spSigning(keys.sp.privateKey)));
    // To B (POST binding): B's Issuer, signed with the (shared) key.
    const toB = postForm(await first.text());
    expect(issuer(toB.xml)).toBe(w.B.metadata);
    expect(toB.xml).toContain(`Destination="${ONLY_B.slo}"`);
    verifyMessageSignature({ binding: "post", samlRequest: "", relayState: undefined }, toB.xml, [keys.idp.certificate], { allowInsecureSha1: false });
    // B answers to B's SLO URL.
    const answerB = buildLogoutResponse({ issuer: ONLY_B.entityId, destination: w.B.slo, inResponseTo: /ID="([^"]+)"/.exec(toB.xml)![1]!, status: ["Success"], now: new Date() });
    const toRoot = await redirected((await w.browser.fetch(redirectBindingUrl(w.B.slo, "SAMLResponse", answerB, toB.relayState, spSigning(keys.idpNext.privateKey)))).headers.get("location")!, "SAMLRequest");
    expect(toRoot.target).toBe(ROOT.slo);
    expect(issuer(toRoot.xml)).toBe(IDP_ENTITY_ID);
    // The root SP answers at the root SLO URL; the final LogoutResponse goes to A from A.
    const answerRoot = buildLogoutResponse({ issuer: ROOT.entityId, destination: `${AUTH_BASE}/saml2/idp/slo`, inResponseTo: /ID="([^"]+)"/.exec(toRoot.xml)![1]!, status: ["Success"], now: new Date() });
    const done = await w.browser.fetch(redirectBindingUrl(`${AUTH_BASE}/saml2/idp/slo`, "SAMLResponse", answerRoot, toRoot.relayState, spSigning(keys.sp.privateKey)));
    const toA = await redirected(done.headers.get("location")!, "SAMLResponse");
    expect(toA.target).toBe(ONLY_A.slo);
    expect(issuer(toA.xml)).toBe(w.A.metadata);
    expect(toA.xml).toContain(`InResponseTo="${req.id}"`);
    expect(toA.xml).toMatch(/StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"\/>/);
    expect(toA.relayState).toBe("rs-a");
  });

  it("a participant's answer is checked against its own tenant's SLO URL: B's answer addressed to the root's is PartialLogout", async () => {
    const w = await signedInEverywhere();
    const first = await w.browser.fetch(redirectBindingUrl(w.A.slo, "SAMLRequest", w.lr(w.A.slo).xml, undefined, spSigning(keys.sp.privateKey)));
    const toB = postForm(await first.text());
    const wrong = buildLogoutResponse({ issuer: ONLY_B.entityId, destination: `${AUTH_BASE}/saml2/idp/slo`, inResponseTo: /ID="([^"]+)"/.exec(toB.xml)![1]!, status: ["Success"], now: new Date() });
    // Sent to the root's SLO URL (where its Destination points): the hop state is found, but the
    // answer isn't to the identity that asked.
    const toRoot = await redirected(
      (await w.browser.fetch(redirectBindingUrl(`${AUTH_BASE}/saml2/idp/slo`, "SAMLResponse", wrong, toB.relayState, spSigning(keys.idpNext.privateKey)))).headers.get("location")!,
      "SAMLRequest",
    );
    const answerRoot = buildLogoutResponse({ issuer: ROOT.entityId, destination: `${AUTH_BASE}/saml2/idp/slo`, inResponseTo: /ID="([^"]+)"/.exec(toRoot.xml)![1]!, status: ["Success"], now: new Date() });
    const done = await w.browser.fetch(redirectBindingUrl(`${AUTH_BASE}/saml2/idp/slo`, "SAMLResponse", answerRoot, toRoot.relayState, spSigning(keys.sp.privateKey)));
    expect((await redirected(done.headers.get("location")!, "SAMLResponse")).xml).toContain("status:PartialLogout");
  });

  it("a participant whose tenant was disabled since is skipped (PartialLogout), never sent a LogoutRequest from another identity", async () => {
    const w = await signedInEverywhere();
    await w.tenants("/update", { organizationId: w.orgB.id, enabled: false });
    const first = await w.browser.fetch(redirectBindingUrl(w.A.slo, "SAMLRequest", w.lr(w.A.slo).xml, undefined, spSigning(keys.sp.privateKey)));
    // Straight to the root SP: nothing went to B's.
    const toRoot = await redirected(first.headers.get("location")!, "SAMLRequest");
    expect(toRoot.target).toBe(ROOT.slo);
    const answerRoot = buildLogoutResponse({ issuer: ROOT.entityId, destination: `${AUTH_BASE}/saml2/idp/slo`, inResponseTo: /ID="([^"]+)"/.exec(toRoot.xml)![1]!, status: ["Success"], now: new Date() });
    const done = await w.browser.fetch(redirectBindingUrl(`${AUTH_BASE}/saml2/idp/slo`, "SAMLResponse", answerRoot, toRoot.relayState, spSigning(keys.sp.privateKey)));
    const toA = await redirected(done.headers.get("location")!, "SAMLResponse");
    expect(issuer(toA.xml)).toBe(w.A.metadata);
    expect(toA.xml).toContain("status:PartialLogout");
  });

  it("a participant's answer arriving at its tenant's URL after that tenant was disabled mid-chain: the chain goes on, and the originator is answered (review 6 I-4)", async () => {
    const w = await signedInEverywhere();
    const first = await w.browser.fetch(redirectBindingUrl(w.A.slo, "SAMLRequest", w.lr(w.A.slo).xml, undefined, spSigning(keys.sp.privateKey)));
    const toB = postForm(await first.text());
    // B's tenant is disabled while its SP handles the LogoutRequest; its answer comes back to B's URL.
    await w.tenants("/update", { organizationId: w.orgB.id, enabled: false });
    const answerB = buildLogoutResponse({ issuer: ONLY_B.entityId, destination: w.B.slo, inResponseTo: /ID="([^"]+)"/.exec(toB.xml)![1]!, status: ["Success"], now: new Date() });
    const next = await w.browser.fetch(redirectBindingUrl(w.B.slo, "SAMLResponse", answerB, toB.relayState, spSigning(keys.idpNext.privateKey)));
    const toRoot = await redirected(next.headers.get("location")!, "SAMLRequest");
    expect(toRoot.target).toBe(ROOT.slo);
    const answerRoot = buildLogoutResponse({ issuer: ROOT.entityId, destination: `${AUTH_BASE}/saml2/idp/slo`, inResponseTo: /ID="([^"]+)"/.exec(toRoot.xml)![1]!, status: ["Success"], now: new Date() });
    const done = await w.browser.fetch(redirectBindingUrl(`${AUTH_BASE}/saml2/idp/slo`, "SAMLResponse", answerRoot, toRoot.relayState, spSigning(keys.sp.privateKey)));
    const toA = await redirected(done.headers.get("location")!, "SAMLResponse");
    expect(issuer(toA.xml)).toBe(w.A.metadata);
    // B's answer can't be checked against a disabled tenant's identity: reported, not trusted.
    expect(toA.xml).toContain("status:PartialLogout");
    // A LogoutRequest at the disabled tenant's URL still finds nothing.
    expect(await code(await w.browser.fetch(redirectBindingUrl(w.B.slo, "SAMLRequest", w.lr(w.B.slo).xml, undefined, spSigning(keys.sp.privateKey))))).toBe("UNKNOWN_SERVICE_PROVIDER");
  });

  it("a POST LogoutRequest's continuation re-entered at another tenant's SLO URL is refused, and ends nothing", async () => {
    const w = await signedInEverywhere();
    const { signedPostMessage } = await import("../../src/saml/logout");
    const post = await w.browser.fetch(w.A.slo, {
      method: "POST",
      crossSite: true,
      headers: { "content-type": "application/x-www-form-urlencoded", origin: "https://only-a.test" },
      body: new URLSearchParams({ SAMLRequest: signedPostMessage(w.lr(w.A.slo).xml, "LogoutRequest", spSigning(keys.sp.privateKey)) }).toString(),
    });
    expect(post.status).toBe(303);
    const cid = new URL(post.headers.get("location")!).searchParams.get("cid");
    expect(new URL(post.headers.get("location")!).pathname).toBe(new URL(w.A.slo).pathname);
    expect(await code(await w.browser.fetch(`${w.B.slo}?cid=${cid}`))).toBe("UNKNOWN_SERVICE_PROVIDER");
    expect(await (await w.browser.fetch(`${AUTH_BASE}/get-session`)).json()).not.toBeNull();
  });

  it("an SP's LogoutRequest at another tenant's SLO URL finds nothing, and ends nothing", async () => {
    const w = await signedInEverywhere();
    const res = await w.browser.fetch(redirectBindingUrl(w.B.slo, "SAMLRequest", w.lr(w.B.slo).xml, undefined, spSigning(keys.sp.privateKey)));
    expect(await code(res)).toBe("UNKNOWN_SERVICE_PROVIDER");
    expect(await (await w.browser.fetch(`${AUTH_BASE}/get-session`)).json()).not.toBeNull();
  });
});

describe("tenants: events and the audit log (D-052)", () => {
  it("events and audit rows carry the tenant; the root IdP's don't", async () => {
    const events: any[] = [];
    const w = await world({
      code: standard,
      saml: { auditLog: { enabled: true }, events: { onAssertionIssued: (e) => void events.push(e), onDenied: (e) => void events.push(e), onSessionEnded: (e) => void events.push(e) } },
    });
    await w.join(w.orgA.id);
    await readAutoPost(await w.browser.fetch(await authn(w.A.sso, { issuer: ONLY_A.entityId, acsUrl: ONLY_A.acs })));
    await readAutoPost(await w.browser.fetch(await authn(SSO_URL)));
    await w.browser.fetch(await authn(w.A.sso, { issuer: "https://admins.test/none", acsUrl: ONLY_A.acs }));
    await vi.waitFor(() => expect(events.filter((e) => e.type === "assertion.issued")).toHaveLength(2));
    const [inTenant, atRoot] = events.filter((e) => e.type === "assertion.issued");
    expect(inTenant.tenantId).toBe(w.orgA.id);
    expect("tenantId" in atRoot).toBe(false);
    const rows = (await w.ctx.adapter.findMany({ model: "samlIdpAuditEvent", where: [{ field: "type", value: "assertion.issued" }] })) as any[];
    expect(rows.find((r) => r.spId === "only-a")?.tenantId).toBe(w.orgA.id);
    expect(rows.find((r) => r.spId === "root")?.tenantId ?? null).toBeNull();
    // A session ended outside Single Logout names each SP's tenant.
    await w.browser.fetch(`${AUTH_BASE}/sign-out`, { method: "POST", headers: { origin: BASE_URL, "content-type": "application/json" }, body: "{}" });
    await vi.waitFor(() => expect(events.some((e) => e.type === "session.ended")).toBe(true));
    const ended = events.find((e) => e.type === "session.ended");
    expect(ended.participants.find((p: any) => p.spId === "only-a").tenantId).toBe(w.orgA.id);
    expect("tenantId" in ended.participants.find((p: any) => p.spId === "root")).toBe(false);
  });
});

describe("tenants: the tenant API, host administrators only (D-052, maintainer decisions 1 and 3)", () => {
  it("create, list, get: the key defaults to the organization id; another can be chosen; the record has the tenant's URLs", async () => {
    const w = await world();
    // (On workerd, one D1 database serves the whole file: other tests' tenants are listed too.)
    const listed = (await json(await w.tenants(""))).tenants.map((x: any) => x.organizationId);
    expect(listed.filter((id: string) => [w.orgA.id, w.orgB.id, w.orgC.id].includes(id)).sort()).toEqual([w.orgA.id, w.orgB.id].sort());
    const a = (await json(await w.tenants(`/get?organizationId=${w.orgA.id}`))).tenant;
    expect(a).toEqual({
      organizationId: w.orgA.id,
      tenantKey: w.orgA.id,
      entityId: w.A.metadata,
      metadataUrl: w.A.metadata,
      ssoUrl: w.A.sso,
      sloUrl: w.A.slo,
      enabled: true,
      createdAt: expect.any(String),
      updatedAt: expect.any(String),
      updatedBy: expect.any(String),
    });
    const c = await w.tenants("/create", { organizationId: w.orgC.id, tenantKey: `initech-${w.t}` });
    expect(c.status).toBe(200);
    expect((await json(c)).tenant.entityId).toBe(urls(`initech-${w.t}`).metadata);
    expect((await w.auth.handler(new Request(urls(`initech-${w.t}`).metadata))).status).toBe(200);
    expect((await w.tenants("/get?organizationId=nope")).status).toBe(404);
  });

  it("refuses: an unknown organization, a bad key, the same organization or key twice", async () => {
    const w = await world();
    expect((await json(await w.tenants("/create", { organizationId: "no-such-org" }))).code).toBe("INVALID_TENANT");
    expect((await json(await w.tenants("/create", { organizationId: w.orgC.id, tenantKey: "has/slash" }))).code).toBe("INVALID_TENANT");
    expect((await json(await w.tenants("/create", { organizationId: w.orgA.id }))).code).toBe("TENANT_EXISTS");
    // Another organization's id, as a chosen key, would make a URL that looks like that organization's (review 6 I-3).
    expect((await json(await w.tenants("/create", { organizationId: w.orgC.id, tenantKey: w.orgA.id }))).code).toBe("INVALID_TENANT");
    const orgD = await w.ctx.adapter.create({ model: "organization", data: { name: "D", slug: `d-${w.t}`, createdAt: new Date() } });
    expect((await w.tenants("/create", { organizationId: w.orgC.id, tenantKey: `k-${w.t}` })).status).toBe(200);
    expect((await json(await w.tenants("/create", { organizationId: orgD.id, tenantKey: `k-${w.t}` }))).code).toBe("TENANT_EXISTS");
  });

  it("a deleted tenant's key is retired: never given to another organization, nor to the same one again (review 6 R6-2)", async () => {
    const w = await world();
    const key = `acme-${w.t}`;
    expect((await w.tenants("/create", { organizationId: w.orgC.id, tenantKey: key })).status).toBe(200);
    expect((await w.tenants("/delete", { organizationId: w.orgC.id })).status).toBe(200);
    const orgD = await w.ctx.adapter.create({ model: "organization", data: { name: "D", slug: `d-${w.t}`, createdAt: new Date() } });
    for (const organizationId of [orgD.id, w.orgC.id]) {
      const res = await w.tenants("/create", { organizationId, tenantKey: key });
      expect(res.status).toBe(409);
      expect((await json(res)).code).toBe("TENANT_KEY_RETIRED");
    }
    expect((await w.auth.handler(new Request(urls(key).metadata))).status).toBe(404);
    // The organization can be a tenant again, under a new key.
    expect((await w.tenants("/create", { organizationId: w.orgC.id, tenantKey: `${key}-2` })).status).toBe(200);
  });

  it("update changes only enabled: the key and organization are fixed (decision 3)", async () => {
    const w = await world();
    expect((await w.tenants("/update", { organizationId: w.orgA.id, tenantKey: "other", enabled: true })).status).toBe(400);
    expect((await w.tenants("/update", { organizationId: w.orgA.id })).status).toBe(400);
    const off = await json(await w.tenants("/update", { organizationId: w.orgA.id, enabled: false }));
    expect(off.tenant).toMatchObject({ enabled: false, tenantKey: w.orgA.id });
    expect((await w.tenants("/update", { organizationId: "nope", enabled: true })).status).toBe(404);
  });

  it("delete is refused while the tenant has SPs, in code or stored", async () => {
    const w = await world({ code: ({ a }) => [{ id: "in-code", entityId: ONLY_A.entityId, acsUrls: [ONLY_A.acs], tenant: a }] });
    expect((await json(await w.tenants("/delete", { organizationId: w.orgA.id }))).code).toBe("TENANT_HAS_SERVICE_PROVIDERS");
    const sp = { id: `s-${w.t}`, entityId: `https://s${w.t}.test/sp`, acsUrls: [`https://s${w.t}.test/acs`], tenant: w.orgB.id };
    expect((await w.sps("/create", { serviceProvider: sp })).status).toBe(200);
    expect((await json(await w.tenants("/delete", { organizationId: w.orgB.id }))).code).toBe("TENANT_HAS_SERVICE_PROVIDERS");
    await w.sps("/delete", { id: sp.id });
    expect((await w.tenants("/delete", { organizationId: w.orgB.id })).status).toBe(200);
    expect((await w.auth.handler(new Request(w.B.metadata))).status).toBe(404);
  });

  it("only the registry's managers: a signed-in user who isn't one gets 403 on every route", async () => {
    const w = await world();
    const someone = new Browser(w.auth);
    await someone.signUp();
    // Even the organization's own owner (phase 1: no delegation, design §5.1).
    const owner = await someone.signUp();
    await w.ctx.adapter.create({ model: "member", data: { organizationId: w.orgA.id, userId: owner.id, role: "owner", createdAt: new Date() } });
    for (const [path, body] of [["", undefined], [`/get?organizationId=${w.orgA.id}`, undefined], ["/create", { organizationId: w.orgC.id }], ["/update", { organizationId: w.orgA.id, enabled: false }], ["/delete", { organizationId: w.orgA.id }]] as const)
      expect((await w.tenants(path, body, someone)).status, path).toBe(403);
  });
});

describe("tenants: bound to their organization, not just its id (review 6 R6-1, D-053)", () => {
  const post = (b: Browser, path: string, body: unknown) =>
    b.fetch(`${AUTH_BASE}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

  it("an organization deleted through Better Auth: its tenant is disabled (listed so) and answers nothing", async () => {
    const w = await world({ code: standard });
    const owner = new Browser(w.auth);
    const ownerUser = await owner.signUp();
    await w.ctx.adapter.create({ model: "member", data: { organizationId: w.orgA.id, userId: ownerUser.id, role: "owner", createdAt: new Date() } });
    await w.join(w.orgA.id);
    expect((await post(owner, "/organization/delete", { organizationId: w.orgA.id })).status).toBe(200);
    expect((await json(await w.tenants(`/get?organizationId=${w.orgA.id}`))).tenant).toMatchObject({ enabled: false });
    expect((await w.auth.handler(new Request(w.A.metadata))).status).toBe(404);
    expect(await code(await w.browser.fetch(await authn(w.A.sso, { issuer: ONLY_A.entityId, acsUrl: ONLY_A.acs })))).toBe("UNKNOWN_SERVICE_PROVIDER");
    // B is untouched.
    expect((await w.auth.handler(new Request(w.B.metadata))).status).toBe(200);
  });

  it("an organization deleted straight from the database: its tenant answers nothing, by any route", async () => {
    const w = await world({ code: standard });
    await w.join(w.orgA.id);
    expect(issuer((await readAutoPost(await w.browser.fetch(await authn(w.A.sso, { issuer: ONLY_A.entityId, acsUrl: ONLY_A.acs })))).xml)).toBe(w.A.metadata);
    await w.ctx.adapter.delete({ model: "organization", where: [{ field: "id", value: w.orgA.id }] });
    expect((await w.auth.handler(new Request(w.A.metadata))).status).toBe(404);
    expect(await code(await w.browser.fetch(await authn(w.A.sso, { issuer: ONLY_A.entityId, acsUrl: ONLY_A.acs })))).toBe("UNKNOWN_SERVICE_PROVIDER");
    expect(await code(await w.browser.fetch(`${AUTH_BASE}/saml2/idp/init?sp=only-a`))).toBe("UNKNOWN_SERVICE_PROVIDER");
  });

  it.skipIf(isWorkerd)("serial ids (SQLite reuses a freed id): a new organization given a deleted one's id doesn't inherit its tenant", async () => {
    const database = await createHostDatabase();
    const serial = { advanced: { database: { generateId: "serial" as const } } };
    const saml = { registry: { enabled: true, canManage, cacheSeconds: 0 }, tenants: { enabled: true, cacheSeconds: 0 }, serviceProviders: [] };
    const { auth } = await createHost({ database, plugins: [organization()], saml, auth: serial });
    const ctx = (await auth.$context) as any;
    const admin = new Browser(auth);
    const adminUser = await admin.signUp();
    await ctx.adapter.update({ model: "user", where: [{ field: "id", value: adminUser.id }], update: { role: "admin" } });
    const api = (path: string, body: unknown) => post(admin, `/saml-idp${path}`, body);
    const org = await ctx.adapter.create({ model: "organization", data: { name: "Old", slug: `old-${n++}`, createdAt: new Date(Date.now() - 60_000) } });
    const id = String(org.id);
    expect((await api("/tenants/create", { organizationId: id, tenantKey: "old" })).status).toBe(200);
    const sp = { id: "old-sp", entityId: "https://old.test/sp", acsUrls: ["https://old.test/acs"], tenant: id };
    expect((await api("/service-providers/create", { serviceProvider: sp })).status).toBe(200);
    // Deleted in the database (no hook runs), and a new organization gets the same id.
    await ctx.adapter.delete({ model: "organization", where: [{ field: "id", value: id }] });
    const reused = await ctx.adapter.create({ model: "organization", data: { name: "New", slug: `new-${n++}`, createdAt: new Date() } });
    expect(String(reused.id)).toBe(id);
    const other = new Browser(auth);
    const otherUser = await other.signUp();
    await ctx.adapter.create({ model: "member", data: { organizationId: id, userId: otherUser.id, role: "owner", createdAt: new Date() } });
    expect((await auth.handler(new Request(urls("old").metadata))).status).toBe(404);
    expect(await code(await other.fetch(await authn(urls("old").sso, { issuer: sp.entityId, acsUrl: sp.acsUrls[0] })))).toBe("UNKNOWN_SERVICE_PROVIDER");
  });
});

describe("tenants: admin-plugin permissions (D-052)", () => {
  it("the tenant routes need `samlTenant`: managing SPs (`samlServiceProvider`) isn't enough", async () => {
    const { createAccessControl } = await import("better-auth/plugins/access");
    const { adminAc, defaultStatements } = await import("better-auth/plugins/admin/access");
    const { samlIdpStatements } = await import("../../src/access");
    const ac = createAccessControl({ ...defaultStatements, ...samlIdpStatements });
    const roles = {
      admin: ac.newRole({ ...adminAc.statements, samlServiceProvider: ["list", "read", "create", "update", "delete"], samlTenant: ["list", "read", "create", "update", "delete"] }),
      spAdmin: ac.newRole({ samlServiceProvider: ["list", "read", "create", "update", "delete"] }),
    };
    const database = await createHostDatabase();
    const saml = { registry: { enabled: true, permissions: true }, tenants: { enabled: true }, serviceProviders: [] };
    const { auth } = await createHost({ database, plugins: [organization()], adminOptions: { ac, roles }, saml });
    const ctx = (await auth.$context) as any;
    const org = await ctx.adapter.create({ model: "organization", data: { name: "P", slug: `p-${Date.now().toString(36)}${n++}`, createdAt: new Date() } });
    const as = async (role: string) => {
      const b = new Browser(auth);
      const u = await b.signUp();
      await ctx.adapter.update({ model: "user", where: [{ field: "id", value: u.id }], update: { role } });
      return (path: string, body?: unknown) =>
        b.fetch(`${AUTH_BASE}/saml-idp${path}`, { method: body ? "POST" : "GET", headers: { "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
    };
    const spAdmin = await as("spAdmin");
    expect((await spAdmin("/service-providers")).status).toBe(200);
    expect((await spAdmin("/tenants")).status).toBe(403);
    expect((await spAdmin("/tenants/create", { organizationId: org.id })).status).toBe(403);
    expect((await (await as("admin"))("/tenants/create", { organizationId: org.id })).status).toBe(200);
  });
});

describe("tenants: stored SPs through the registry API (D-052)", () => {
  it("an SP joins a tenant with `tenant`; records say which; the list filters by tenant in the query", async () => {
    const w = await world({ code: standard });
    const sp = { id: `st-${w.t}`, entityId: `https://st${w.t}.test/sp`, acsUrls: [`https://st${w.t}.test/acs`], tenant: w.orgA.id };
    const created = await json(await w.sps("/create", { serviceProvider: sp }));
    expect(created.serviceProvider).toMatchObject({ id: sp.id, tenantId: w.orgA.id, valid: true, issues: [] });
    await w.join(w.orgA.id);
    expect(issuer((await readAutoPost(await w.browser.fetch(await authn(w.A.sso, { issuer: sp.entityId, acsUrl: sp.acsUrls[0] })))).xml)).toBe(w.A.metadata);
    expect(await code(await w.browser.fetch(await authn(SSO_URL, { issuer: sp.entityId, acsUrl: sp.acsUrls[0] })))).toBe("UNKNOWN_SERVICE_PROVIDER");
    const inA = (await json(await w.sps(`?tenantId=${w.orgA.id}`))).serviceProviders.map((s: any) => s.id);
    expect(inA.sort()).toEqual(["aws-a", "only-a", sp.id].sort());
    const root = (await json(await w.sps("?tenantId="))).serviceProviders;
    expect(root.map((s: any) => s.id)).toEqual(["root"]);
    expect(root[0].tenantId).toBeNull();
  });

  it("refuses: a tenant that doesn't exist, a slug rule, and a change of tenant", async () => {
    const w = await world();
    const sp = { id: `r-${w.t}`, entityId: `https://r${w.t}.test/sp`, acsUrls: [`https://r${w.t}.test/acs`] };
    expect((await json(await w.sps("/create", { serviceProvider: { ...sp, tenant: w.orgC.id } }))).issues.join()).toMatch(/no tenant for organization/);
    expect((await json(await w.sps("/create", { serviceProvider: { ...sp, tenant: w.orgA.id, organization: { slug: "acme" } } }))).issues.join()).toMatch(/a tenant SP's members are its tenant's/);
    expect((await w.sps("/create", { serviceProvider: { ...sp, tenant: w.orgA.id } })).status).toBe(200);
    for (const tenant of [w.orgB.id, undefined])
      expect((await json(await w.sps("/update", { id: sp.id, serviceProvider: { ...sp, ...(tenant ? { tenant } : {}) } }))).issues.join()).toMatch(/tenant: can't be changed/);
  });

  it("the host administrator is warned when an SP overlaps one in another tenant (design §5.1 c)", async () => {
    const logs: string[] = [];
    const w = await world({ code: ({ a }) => [{ id: "aws-a", entityId: AWS.entityId, acsUrls: [AWS.acs], tenant: a }], logs });
    const sp = { id: `aws-${w.t}`, entityId: AWS.entityId, acsUrls: [AWS.acs], tenant: w.orgB.id };
    const created = await json(await w.sps("/create", { serviceProvider: sp }));
    expect(created.serviceProvider.warnings.join()).toMatch(new RegExp(`same entity ID and an ACS URL as SP aws-a in tenant ${w.orgA.id}`));
    expect(logs.join("\n")).toMatch(/registry: SP aws-.*same entity ID/);
    const listed = (await json(await w.sps(""))).serviceProviders;
    expect(listed.find((s: any) => s.id === "aws-a").warnings.join()).toMatch(new RegExp(`as SP ${sp.id} in tenant ${w.orgB.id}`));
  });

  it("enabling tenants on a registry with rows: they aren't found until the one-time backfill, then work as before", async () => {
    const t = `${Date.now().toString(36)}${n++}`;
    const database = await createHostDatabase();
    // Before: tenants off, one stored SP.
    const before = await createHost({ database, plugins: [organization()], saml: { registry: { enabled: true, canManage }, serviceProviders: [] } });
    const entityId = `https://old${t}.test/sp`;
    const acs = `https://old${t}.test/acs`;
    const config = { id: `old-${t}`, entityId, acsUrls: [acs] };
    const now = new Date();
    await ((await before.auth.$context) as any).adapter.create({
      model: "samlIdpServiceProvider",
      data: { spId: config.id, entityId, config: JSON.stringify(config), enabled: true, createdAt: now, updatedAt: now },
    });
    // The guide's steps for a populated table: add lookupKey by hand, nullable for now (Better Auth's
    // migrator won't add a required column to a table with rows), then let the migrator add the
    // rest (tenantId, the UNIQUE index, the tenant table). On D1, migration 0007 is those steps.
    if (!isWorkerd) {
      (database.db as { exec(sql: string): void }).exec("ALTER TABLE samlIdpServiceProvider ADD COLUMN lookupKey TEXT");
      const { getMigrations } = await import("better-auth/db/migration");
      const { hostOptions } = await import("../support/host");
      const opts = hostOptions(database, { plugins: [organization()], saml: { registry: { enabled: true, canManage }, tenants: { enabled: true }, serviceProviders: [] } });
      await (await getMigrations(opts as any)).runMigrations();
    }
    const { auth } = await createHost({ database, plugins: [organization()], saml: { registry: { enabled: true, canManage, cacheSeconds: 0 }, tenants: { enabled: true }, serviceProviders: [] } });
    const browser = new Browser(auth);
    await browser.signUp();
    expect(await code(await browser.fetch(await authn(SSO_URL, { issuer: entityId, acsUrl: acs })))).toBe("UNKNOWN_SERVICE_PROVIDER");
    const api = (auth.api as any).samlIdpBackfillServiceProviderKeys;
    const r = await api();
    expect(r.updated).toBeGreaterThanOrEqual(1);
    expect(r.skipped).toEqual([]);
    expect(issuer((await readAutoPost(await browser.fetch(await authn(SSO_URL, { issuer: entityId, acsUrl: acs })))).xml)).toBe(IDP_ENTITY_ID);
    expect((await api()).updated).toBe(0); // idempotent
  });

  it.skipIf(isWorkerd)("the backfill reads the table in pages: more rows than one page are all keyed (review 6 I-1)", async () => {
    const database = await createHostDatabase();
    const before = await createHost({ database, plugins: [organization()], saml: { registry: { enabled: true, canManage }, serviceProviders: [] } });
    const bctx = (await before.auth.$context) as any;
    const now = new Date();
    const count = 520; // the page is 500
    for (let i = 0; i < count; i++) {
      const config = { id: `pg-${i}`, entityId: `https://pg${i}.test/sp`, acsUrls: [`https://pg${i}.test/acs`] };
      await bctx.adapter.create({ model: "samlIdpServiceProvider", data: { spId: config.id, entityId: config.entityId, config: JSON.stringify(config), enabled: true, createdAt: now, updatedAt: now } });
    }
    const saml = { registry: { enabled: true, canManage, cacheSeconds: 0 }, tenants: { enabled: true }, serviceProviders: [] };
    (database.db as { exec(sql: string): void }).exec("ALTER TABLE samlIdpServiceProvider ADD COLUMN lookupKey TEXT");
    const { getMigrations } = await import("better-auth/db/migration");
    const { hostOptions } = await import("../support/host");
    await (await getMigrations(hostOptions(database, { plugins: [organization()], saml }) as any)).runMigrations();
    const { auth } = await createHost({ database, plugins: [organization()], saml });
    expect(await (auth.api as any).samlIdpBackfillServiceProviderKeys()).toEqual({ updated: count, skipped: [], failed: [] });
  });

  it("the backfill reports a row it can't write and carries on with the rest (review 6 I-1)", async () => {
    const t = `${Date.now().toString(36)}${n++}`;
    const database = await createHostDatabase();
    // Two rows saved before tenants, then the guide's steps 1 and 2 (as in the test above).
    const before = await createHost({ database, plugins: [organization()], saml: { registry: { enabled: true, canManage }, serviceProviders: [] } });
    const now = new Date();
    const ids = [`bf-a-${t}`, `bf-b-${t}`];
    for (const id of ids) {
      const config = { id, entityId: `https://${id}.test/sp`, acsUrls: [`https://${id}.test/acs`] };
      await ((await before.auth.$context) as any).adapter.create({
        model: "samlIdpServiceProvider",
        data: { spId: id, entityId: config.entityId, config: JSON.stringify(config), enabled: true, createdAt: now, updatedAt: now },
      });
    }
    const saml = { registry: { enabled: true, canManage, cacheSeconds: 0 }, tenants: { enabled: true }, serviceProviders: [] };
    if (!isWorkerd) {
      (database.db as { exec(sql: string): void }).exec("ALTER TABLE samlIdpServiceProvider ADD COLUMN lookupKey TEXT");
      const { getMigrations } = await import("better-auth/db/migration");
      const { hostOptions } = await import("../support/host");
      await (await getMigrations(hostOptions(database, { plugins: [organization()], saml }) as any)).runMigrations();
    }
    const { auth } = await createHost({ database, plugins: [organization()], saml });
    const ctx = (await auth.$context) as any;
    // The first row's write fails (as a UNIQUE clash would); the second is still keyed.
    const update = ctx.adapter.update;
    ctx.adapter.update = async (a: any) => {
      const row = await ctx.adapter.findOne({ model: "samlIdpServiceProvider", where: a.where });
      if (a.model === "samlIdpServiceProvider" && row?.spId === ids[0]) throw new Error("simulated write failure");
      return update(a);
    };
    const first = await (auth.api as any).samlIdpBackfillServiceProviderKeys();
    ctx.adapter.update = update;
    expect(first.failed).toContain(ids[0]);
    expect(first.failed).not.toContain(ids[1]);
    const keyed = (await ctx.adapter.findOne({ model: "samlIdpServiceProvider", where: [{ field: "spId", value: ids[1] }] })).lookupKey;
    expect(keyed).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const again = await (auth.api as any).samlIdpBackfillServiceProviderKeys();
    expect(again.failed).toEqual([]);
    expect(again.updated).toBeGreaterThanOrEqual(1);
  });
});

describe("tenants off: no tenant routes", () => {
  it("the tenant URLs don't exist", async () => {
    const { auth } = await createHost();
    for (const path of ["/saml2/idp/metadata/x", "/saml2/idp/sso/x", "/saml-idp/tenants"]) expect((await auth.handler(new Request(`${AUTH_BASE}${path}`))).status, path).toBe(404);
  });
});
