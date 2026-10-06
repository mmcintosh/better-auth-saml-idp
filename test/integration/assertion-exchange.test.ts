// Assertion exchange (D-071): an SP with `tokenExchange` has each assertion recorded at issuance,
// and `getSamlIdpExchange(ctx).verifyIssuedAssertion` vouches for it once, to the mapped client.
// Each refusal is produced with only its one defect. Both runtimes.
import { createPrivateKey } from "node:crypto";
import { SAML } from "@node-saml/node-saml";
import { DOMParser, XMLSerializer } from "@xmldom/xmldom";
import { organization } from "better-auth/plugins";
import { describe, expect, inject, it, vi } from "vitest";
import { AssertionExchangeError, getSamlIdpExchange, MAX_ASSERTION_BYTES, type SamlIdpExchange } from "../../src/index";
import { signElement } from "../../src/saml/response";
import { SP_ACS, SP_ENTITY_ID, type TestSamlOptions } from "../support/config";
import { AUTH_BASE, createHost, createHostDatabase, type HostDatabase } from "../support/host";
import { Browser, readAutoPost, SSO_URL } from "../support/sp";

const keys = inject("keys");
const CLIENT = "agent-client";
const SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
const PLAIN = { id: "plain-sp", entityId: "https://plain.test/sp", acs: "https://plain.test/acs" };

/** The Assertion out of a Response, as a client library hands it over: xmldom's serializer. */
function assertionOf(responseXml: string): string {
  const doc = new DOMParser().parseFromString(responseXml, "text/xml");
  const el = doc.getElementsByTagNameNS(SAML_NS, "Assertion")[0];
  if (!el) throw new Error("no Assertion");
  return new XMLSerializer().serializeToString(el as any);
}

const codeOf = (p: Promise<unknown>) =>
  p.then(
    () => "OK",
    (e) => (e instanceof AssertionExchangeError ? e.code : `THREW ${String(e)}`),
  );

const attacker = () => ({ keyObject: createPrivateKey(keys.sp.privateKey), certificate: keys.sp.certificate, signatureAlgorithm: "rsa-sha256", digestAlgorithm: "sha256" }) as any;
const ours = () => ({ keyObject: createPrivateKey(keys.idp.privateKey), certificate: keys.idp.certificate, signatureAlgorithm: "rsa-sha256", digestAlgorithm: "sha256" }) as any;
const unsign = (xml: string) => xml.replace(/<ds:Signature[\s\S]*?<\/ds:Signature>/, "");
/** Re-sign the Assertion (after editing it) with another key; its certificate goes in KeyInfo. */
const resign = (xml: string, signing = attacker()) =>
  signElement(unsign(xml), "/*[local-name(.)='Assertion']", { reference: "/*[local-name(.)='Assertion']/*[local-name(.)='Issuer']", action: "after" }, signing);
const attr = (xml: string, el: string, name: string) => new RegExp(`<saml:${el}[^>]* ${name}="([^"]+)"`).exec(xml)?.[1] as string;

async function setup(o: { saml?: TestSamlOptions; database?: HostDatabase; sps?: unknown[] } = {}) {
  const exchanged: any[] = [];
  const { auth, database } = await createHost({
    database: o.database,
    saml: {
      serviceProviders: (o.sps ?? [
        { id: "x-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], allowIdpInitiated: true, tokenExchange: { clientId: CLIENT } },
        { id: PLAIN.id, entityId: PLAIN.entityId, acsUrls: [PLAIN.acs], allowIdpInitiated: true },
      ]) as any,
      events: { onAssertionExchanged: (e) => void exchanged.push(e) },
      ...o.saml,
    },
  });
  const ctx = (await auth.$context) as any;
  const api = getSamlIdpExchange({ context: ctx }) as SamlIdpExchange;
  const browser = new Browser(auth);
  const user = await browser.signUp();
  const issue = async (sp = "x-sp", b = browser) => {
    const form = await readAutoPost(await b.fetch(`${AUTH_BASE}/saml2/idp/init?sp=${sp}`));
    return { response: form.xml, assertion: assertionOf(form.xml), samlResponse: form.samlResponse };
  };
  const exchange = (xml: string, clientId = CLIENT, now?: Date) => api.verifyIssuedAssertion({ context: ctx } as any, xml, { clientId, ...(now ? { now } : {}) });
  return { auth, ctx, database, api, browser, user, issue, exchange, exchanged };
}

describe("assertion exchange (D-071)", () => {
  it("round trip: verified once, with what an ID-JAG issuer needs; the second time is ALREADY_EXCHANGED; an event is emitted", async () => {
    const s = await setup();
    const { assertion } = await s.issue();
    const v = await s.exchange(assertion);
    expect(v).toMatchObject({
      issuer: "https://auth.test/api/auth/saml2/idp",
      tenantId: null,
      serviceProvider: { id: "x-sp", entityId: SP_ENTITY_ID },
      userId: s.user.id,
      nameId: s.user.email,
      nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
      authnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified",
    });
    expect(v.assertionId).toMatch(/^_[0-9a-f]{40}$/);
    expect(typeof v.sessionId).toBe("string");
    expect(v.notOnOrAfter.getTime()).toBeGreaterThan(Date.now());
    expect(v.authnInstant.getTime()).toBeLessThanOrEqual(Date.now());
    expect(await codeOf(s.exchange(assertion))).toBe("ALREADY_EXCHANGED");
    await vi.waitFor(() => expect(s.exchanged).toHaveLength(1));
    expect(s.exchanged[0]).toMatchObject({ type: "assertion.exchanged", spId: "x-sp", entityId: SP_ENTITY_ID, userId: s.user.id, assertionId: v.assertionId, clientId: CLIENT });
    expect(s.exchanged[0].tenantId).toBeUndefined();
  });

  it("the assertion as node-saml extracts it (getAssertionXml) verifies too", async () => {
    const s = await setup();
    const { samlResponse } = await s.issue();
    const sp = new SAML({ issuer: SP_ENTITY_ID, callbackUrl: SP_ACS, entryPoint: SSO_URL, idpCert: keys.idp.certificate, audience: SP_ENTITY_ID, wantAssertionsSigned: true, validateInResponseTo: "never" as any, acceptedClockSkewMs: 60_000 });
    const { profile } = await sp.validatePostResponseAsync({ SAMLResponse: samlResponse });
    const xml = profile?.getAssertionXml?.();
    expect(typeof xml).toBe("string");
    expect((await s.exchange(xml as string)).userId).toBe(s.user.id);
  });

  it("exchange is off unless an SP opts in, or tokenExchange.enabled: no capability on the context", async () => {
    const off = await setup({ sps: [{ id: PLAIN.id, entityId: PLAIN.entityId, acsUrls: [PLAIN.acs] }] });
    expect(getSamlIdpExchange({ context: off.ctx })).toBeUndefined();
    const on = await setup({ sps: [{ id: PLAIN.id, entityId: PLAIN.entityId, acsUrls: [PLAIN.acs] }], saml: { tokenExchange: { enabled: true } } });
    expect(getSamlIdpExchange({ context: on.ctx })?.version).toBe(1);
  });

  it("WRONG_CLIENT for another client, and it doesn't use the assertion up: the right client still can", async () => {
    const s = await setup();
    const { assertion } = await s.issue();
    expect(await codeOf(s.exchange(assertion, "another-client"))).toBe("WRONG_CLIENT");
    expect(await codeOf(s.exchange(assertion, ""))).toBe("WRONG_CLIENT");
    expect(await codeOf(s.exchange(assertion))).toBe("OK");
  });

  it("NOT_EXCHANGEABLE for an SP without tokenExchange (and nothing was recorded for it)", async () => {
    const s = await setup();
    const { assertion } = await s.issue(PLAIN.id);
    expect(await codeOf(s.exchange(assertion))).toBe("NOT_EXCHANGEABLE");
    const rows = (await s.ctx.adapter.findMany({ model: "verification", where: [] })) as { identifier: string }[];
    expect(rows.filter((r) => r.identifier.startsWith("saml-idp:exchange:"))).toHaveLength(0);
  });

  it("an assertion issued before its SP opted in has no record: ALREADY_EXCHANGED", async () => {
    const database = await createHostDatabase();
    const before = await setup({
      database,
      sps: [
        { id: "x-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], allowIdpInitiated: true },
        { id: "other", entityId: "https://other.test/sp", acsUrls: ["https://other.test/acs"], tokenExchange: { clientId: CLIENT } },
      ],
    });
    const { assertion } = await before.issue();
    const after = await setup({ database });
    expect(await codeOf(after.exchange(assertion))).toBe("ALREADY_EXCHANGED");
  });

  it("validity window: NotBefore − skew − 1 ms is NOT_YET_VALID, NotOnOrAfter + skew is EXPIRED (neither uses it up); 1 ms before that is fine", async () => {
    const s = await setup();
    const { assertion } = await s.issue();
    const notBefore = new Date(attr(assertion, "Conditions", "NotBefore")).getTime();
    const notOnOrAfter = new Date(attr(assertion, "Conditions", "NotOnOrAfter")).getTime();
    const skew = 60_000;
    expect(await codeOf(s.exchange(assertion, CLIENT, new Date(notBefore - skew - 1)))).toBe("NOT_YET_VALID");
    expect(await codeOf(s.exchange(assertion, CLIENT, new Date(notOnOrAfter + skew)))).toBe("EXPIRED");
    expect(await codeOf(s.exchange(assertion, CLIENT, new Date(notOnOrAfter + skew + 1)))).toBe("EXPIRED");
    expect(await codeOf(s.exchange(assertion, CLIENT, new Date(notOnOrAfter + skew - 1)))).toBe("OK");
    const second = (await s.issue()).assertion;
    expect(await codeOf(s.exchange(second, CLIENT, new Date(new Date(attr(second, "Conditions", "NotBefore")).getTime() - skew)))).toBe("OK");
  });

  it("only our signature on the Assertion itself: tampered, unsigned, re-signed by another key (its certificate in KeyInfo), foreign Issuer", async () => {
    const s = await setup();
    const { assertion } = await s.issue();
    const tampered = assertion.replace(`>${s.user.email}<`, ">mallory@example.com<");
    expect(await codeOf(s.exchange(tampered))).toBe("BAD_SIGNATURE");
    expect(await codeOf(s.exchange(unsign(assertion)))).toBe("BAD_SIGNATURE");
    const forged = resign(tampered);
    expect(forged).toContain("<ds:KeyInfo>");
    expect(await codeOf(s.exchange(forged))).toBe("BAD_SIGNATURE");
    const foreign = resign(assertion.replace(/<saml:Issuer>[^<]+</, "<saml:Issuer>https://evil.test/idp<"));
    expect(await codeOf(s.exchange(foreign))).toBe("NOT_OURS");
    // None of that burned the record.
    expect(await codeOf(s.exchange(assertion))).toBe("OK");
  });

  it("signature wrapping: a copy of the signed assertion moved inside an evil one, or its ID duplicated, is refused", async () => {
    const s = await setup();
    const { assertion } = await s.issue();
    const id = /ID="([^"]+)"/.exec(assertion)![1]!;
    const evil = assertion.replace(`>${s.user.email}<`, ">mallory@example.com<").replace(/<ds:Signature[\s\S]*?<\/ds:Signature>/, "");
    const wrapped = evil.replace(/<\/saml:Assertion>$/, `<saml:Advice>${assertion}</saml:Advice></saml:Assertion>`).replace(`ID="${id}"`, 'ID="_evil"');
    expect(await codeOf(s.exchange(wrapped))).not.toBe("OK");
    const duplicate = assertion.replace("<saml:Subject>", `<saml:Subject ID="${id}">`);
    expect(await codeOf(s.exchange(duplicate))).not.toBe("OK");
    const sigOnCopy = `<saml:Assertion xmlns:saml="${SAML_NS}" ID="_outer" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>https://auth.test/api/auth/saml2/idp</saml:Issuer>${assertion}</saml:Assertion>`;
    expect(await codeOf(s.exchange(sigOnCopy))).toBe("MALFORMED");
    expect(await codeOf(s.exchange(assertion))).toBe("OK");
  });

  it("strict input: a Response, an EncryptedAssertion, a DOCTYPE, oversize, deep nesting, garbage, a re-signed assertion with an extra Condition", async () => {
    const s = await setup();
    const { assertion, response } = await s.issue();
    expect(await codeOf(s.exchange(response))).toBe("MALFORMED");
    expect(await codeOf(s.exchange(`<saml:EncryptedAssertion xmlns:saml="${SAML_NS}"/>`))).toBe("MALFORMED");
    expect(await codeOf(s.exchange(`<!DOCTYPE x [<!ENTITY a "b">]>${assertion}`))).toBe("MALFORMED");
    expect(await codeOf(s.exchange(assertion.replace("<saml:Subject>", `<!--${"x".repeat(MAX_ASSERTION_BYTES)}--><saml:Subject>`)))).toBe("MALFORMED");
    expect(await codeOf(s.exchange(`${"<a>".repeat(101)}${"</a>".repeat(101)}`))).toBe("MALFORMED");
    expect(await codeOf(s.exchange("not xml"))).toBe("MALFORMED");
    expect(await codeOf(s.exchange(""))).toBe("MALFORMED");
    // Signed with our own key, so only the shape is wrong.
    const extra = resign(assertion.replace("</saml:AudienceRestriction>", "</saml:AudienceRestriction><saml:OneTimeUse/>"), ours());
    expect(await codeOf(s.exchange(extra))).toBe("MALFORMED");
    expect(await codeOf(s.exchange(assertion))).toBe("OK");
  });

  it("the record must match the assertion: one re-signed with our key but a changed NameID is NOT_OURS (and is used up)", async () => {
    const s = await setup();
    const { assertion } = await s.issue();
    const other = resign(assertion.replace(`>${s.user.email}<`, ">other@example.com<"), ours());
    expect(await codeOf(s.exchange(other))).toBe("NOT_OURS");
    expect(await codeOf(s.exchange(assertion))).toBe("ALREADY_EXCHANGED");
  });

  it("the principal is re-checked now: banned, email no longer verified, session revoked, user deleted → ACCOUNT_INACTIVE", async () => {
    const s = await setup();
    const update = (u: Record<string, unknown>) => s.ctx.adapter.update({ model: "user", where: [{ field: "id", value: s.user.id }], update: u });

    let a = (await s.issue()).assertion;
    await update({ banned: true });
    expect(await codeOf(s.exchange(a))).toBe("ACCOUNT_INACTIVE");
    await update({ banned: false });

    a = (await s.issue()).assertion;
    await update({ emailVerified: false });
    expect(await codeOf(s.exchange(a))).toBe("ACCOUNT_INACTIVE");
    await update({ emailVerified: true });

    a = (await s.issue()).assertion;
    await s.ctx.adapter.deleteMany({ model: "session", where: [{ field: "userId", value: s.user.id }] });
    expect(await codeOf(s.exchange(a))).toBe("ACCOUNT_INACTIVE");

    const b = new Browser(s.auth);
    const u2 = await b.signUp();
    a = (await s.issue("x-sp", b)).assertion;
    await s.ctx.internalAdapter.deleteUser(u2.id);
    expect(await codeOf(s.exchange(a))).toBe("ACCOUNT_INACTIVE");
  });

  it("single use across instances: 10 concurrent exchanges over 5 auth instances on one database → exactly one succeeds", async () => {
    const database = await createHostDatabase();
    const hosts = [await setup({ database })];
    for (let i = 1; i < 5; i++) hosts.push(await setup({ database }));
    const { assertion } = await hosts[0]!.issue();
    const codes = await Promise.all(Array.from({ length: 10 }, (_, i) => codeOf(hosts[i % 5]!.exchange(assertion))));
    expect(codes.filter((c) => c === "OK")).toHaveLength(1);
    expect(codes.filter((c) => c === "ALREADY_EXCHANGED")).toHaveLength(9);
  });

  it("a record that can't be written doesn't fail SSO; that assertion just isn't exchangeable", async () => {
    const s = await setup();
    const create = s.ctx.internalAdapter.createVerificationValue;
    const error = vi.spyOn(s.ctx.logger, "error");
    s.ctx.internalAdapter.createVerificationValue = (data: { identifier: string }) =>
      data.identifier.startsWith("saml-idp:exchange:") ? Promise.reject(new Error("database down")) : create(data);
    try {
      const { assertion } = await s.issue();
      expect(await codeOf(s.exchange(assertion))).toBe("ALREADY_EXCHANGED");
      expect(error.mock.calls.some((c) => String(c[0]).includes("as exchangeable"))).toBe(true);
    } finally {
      s.ctx.internalAdapter.createVerificationValue = create;
      error.mockRestore();
    }
  });

  it("verification makes no outbound request", async () => {
    const s = await setup();
    const { assertion } = await s.issue();
    const fetchSpy = vi.fn(() => {
      throw new Error("no fetch allowed");
    });
    vi.stubGlobal("fetch", fetchSpy);
    try {
      expect(await codeOf(s.exchange(assertion))).toBe("OK");
      expect(await codeOf(s.exchange(assertion))).toBe("ALREADY_EXCHANGED");
    } finally {
      vi.unstubAllGlobals();
    }
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe("assertion exchange with tenants (D-071, D-052)", () => {
  async function tenantWorld(keysMode: "shared" | "per-tenant") {
    const database = await createHostDatabase();
    const t = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
    const { auth } = await createHost({
      database,
      plugins: [organization()],
      saml: {
        serviceProviders: [{ id: "root-x", entityId: `https://x${t}.test/sp`, acsUrls: [`https://x${t}.test/acs`], allowIdpInitiated: true, tokenExchange: { clientId: CLIENT } }],
        registry: { enabled: true, canManage: ({ user }: { user: Record<string, unknown> }) => user.role === "admin", cacheSeconds: 0 },
        tenants: { enabled: true, keys: keysMode, cacheSeconds: 0, minPublishedSeconds: 0 },
        tokenExchange: { enabled: true },
      },
    });
    const ctx = (await auth.$context) as any;
    const api = getSamlIdpExchange({ context: ctx }) as SamlIdpExchange;
    const orgA = String((await ctx.adapter.create({ model: "organization", data: { name: "Acme", slug: `acme-${t}`, createdAt: new Date() } })).id);
    const admin = new Browser(auth);
    const adminUser = await admin.signUp();
    await ctx.adapter.update({ model: "user", where: [{ field: "id", value: adminUser.id }], update: { role: "admin" } });
    const call = (path: string, body: unknown) => admin.fetch(`${AUTH_BASE}/saml-idp${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    expect((await call("/tenants/create", { organizationId: orgA })).status).toBe(200);
    const spA = { id: `a-x-${t}`, entityId: `https://x${t}.test/sp`, acsUrls: [`https://x${t}.test/acs`], allowIdpInitiated: true, tenant: orgA, tokenExchange: { clientId: CLIENT } };
    const created = await call("/service-providers/create", { serviceProvider: spA });
    expect(created.status, await created.clone().text()).toBe(200);
    const browser = new Browser(auth);
    const user = await browser.signUp();
    const member = await ctx.adapter.create({ model: "member", data: { organizationId: orgA, userId: user.id, role: "member", createdAt: new Date() } });
    const issue = async (sp: string) => assertionOf((await readAutoPost(await browser.fetch(`${AUTH_BASE}/saml2/idp/init?sp=${sp}`))).xml);
    const exchange = (xml: string) => api.verifyIssuedAssertion({ context: ctx } as any, xml, { clientId: CLIENT });
    return { ctx, call, orgA, spA, user, member, issue, exchange, tenantIssuer: `${AUTH_BASE}/saml2/idp/metadata/${orgA}` };
  }

  for (const mode of ["shared", "per-tenant"] as const) {
    it(`${mode} keys: a tenant SP's assertion verifies with its tenant; leaving the organization, or the tenant being disabled, refuses it`, async () => {
      const w = await tenantWorld(mode);
      const v = await w.exchange(await w.issue(w.spA.id));
      expect(v).toMatchObject({ tenantId: w.orgA, issuer: w.tenantIssuer, serviceProvider: { id: w.spA.id } });

      let a = await w.issue(w.spA.id);
      await w.ctx.adapter.delete({ model: "member", where: [{ field: "id", value: w.member.id }] });
      expect(await codeOf(w.exchange(a))).toBe("ACCOUNT_INACTIVE");
      await w.ctx.adapter.create({ model: "member", data: { organizationId: w.orgA, userId: w.user.id, role: "member", createdAt: new Date() } });

      a = await w.issue(w.spA.id);
      expect((await w.call("/tenants/update", { organizationId: w.orgA, enabled: false })).status).toBe(200);
      expect(await codeOf(w.exchange(a))).toBe("NOT_OURS");
    });

    it(`${mode} keys: the root's assertion relabelled with the tenant's Issuer (re-signed with the root key) is refused`, async () => {
      const w = await tenantWorld(mode);
      const a = await w.issue("root-x");
      const relabelled = resign(a.replace(/<saml:Issuer>[^<]+</, `<saml:Issuer>${w.tenantIssuer}<`), ours());
      // Per-tenant keys: not the tenant's key. Shared key: the signature holds, but the record doesn't match.
      expect(await codeOf(w.exchange(relabelled))).toBe(mode === "per-tenant" ? "BAD_SIGNATURE" : "NOT_OURS");
    });
  }
});
