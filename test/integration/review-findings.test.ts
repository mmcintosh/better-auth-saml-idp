// Regression tests for the adversarial review (DECISIONS.md D-015). Each block reproduces the
// reviewer's failure scenario; each test failed (or could not be written) before its fix.
import { describe, expect, inject, it } from "vitest";
import { isBanned } from "../../src/endpoints/issue";
import { samlIdp } from "../../src/index";
import { resetSweepThrottle } from "../../src/storage/sweep";
import { NAMEID_FORMAT, type ServiceProviderConfig } from "../../src/types";
import { baseOptions, SP_ACS, SP_ENTITY_ID } from "../support/config";
import { createHost, isWorkerd, type HostOptions } from "../support/host";
import { authnRequestXml, Browser, postBinding, readAutoPost, redirectUrl, SSO_URL } from "../support/sp";

const keys = inject("keys");
const PPT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
const UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";

const sp = (over: Partial<ServiceProviderConfig> = {}): ServiceProviderConfig[] => [
  { id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], ...over },
];

async function host(options: HostOptions = {}) {
  const h = await createHost({ ...options, saml: { serviceProviders: sp(), ...options.saml } });
  return { ...h, ctx: await h.auth.$context, browser: new Browser(h.auth) };
}

const pageCode = async (res: Response) => /<code>([A-Z_]+)<\/code>/.exec(await res.clone().text())?.[1];
const statusOf = (xml: string) =>
  [...xml.matchAll(/<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:([A-Za-z]+)"/g)].map((m) => m[1]);
const nameIdOf = (xml: string) => /<saml:NameID [^>]*>([^<]+)</.exec(xml)?.[1];

describe("#1 only verified, first-party accounts receive assertions", () => {
  it("an unverified email is refused (sign-up alone must not let you assert any address)", async () => {
    const { browser } = await host();
    await browser.signUp("ceo@victim-corp.example", { verified: false });
    const res = await browser.fetch(await redirectUrl(authnRequestXml().xml));
    expect(res.status).toBe(403);
    expect(await pageCode(res)).toBe("EMAIL_NOT_VERIFIED");
    expect(await res.clone().text()).not.toContain("SAMLResponse");
  });

  it("can be relaxed explicitly with accountPolicy.requireEmailVerified: false", async () => {
    const { browser } = await host({ saml: { accountPolicy: { requireEmailVerified: false } } });
    await browser.signUp(undefined, { verified: false });
    expect((await browser.fetch(await redirectUrl(authnRequestXml().xml))).status).toBe(200);
  });

  it("an admin-impersonation session is refused", async () => {
    const { browser, ctx } = await host();
    await browser.signUp();
    const token = decodeURIComponent(/better-auth\.session_token=([^;.]+)/.exec(browser.cookieHeader())![1]!);
    await ctx.adapter.update({ model: "session", where: [{ field: "token", value: token }], update: { impersonatedBy: "admin-1" } });
    const res = await browser.fetch(await redirectUrl(authnRequestXml().xml));
    expect(res.status).toBe(403);
    expect(await pageCode(res)).toBe("SESSION_NOT_ALLOWED");
  });

  it.runIf(!isWorkerd)("an anonymous-plugin user is refused", async () => {
    const { browser, ctx } = await host({ auth: { user: { additionalFields: { isAnonymous: { type: "boolean", required: false } } } } });
    const user = await browser.signUp();
    await ctx.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { isAnonymous: true } });
    const res = await browser.fetch(await redirectUrl(authnRequestXml().xml));
    expect(await pageCode(res)).toBe("SESSION_NOT_ALLOWED");
  });
});

describe("#2 RelayState can't be smuggled past a Redirect-binding signature", () => {
  const signedHost = () => host({ saml: { serviceProviders: sp({ requireSignedAuthnRequests: true, spCertificate: keys.sp.certificate }) } });

  it("an extra percent-encoded Relay%53tate on a signed URL is rejected", async () => {
    const { browser } = await signedHost();
    await browser.signUp();
    const signed = await redirectUrl(authnRequestXml().xml, { sign: true });
    const res = await browser.fetch(`${signed}&Relay%53tate=${encodeURIComponent("https://evil.example/phish")}`);
    expect(res.status).toBe(400);
    expect(await res.text()).not.toContain("evil.example");
  });

  it("duplicate SAML parameters are rejected", async () => {
    const { browser } = await host();
    const url = await redirectUrl(authnRequestXml().xml, { relayState: "a" });
    expect((await browser.fetch(`${url}&RelayState=b`)).status).toBe(400);
    expect((await browser.fetch(`${url}&SAML%52equest=x`)).status).toBe(400);
  });

  it("an unsigned request still decodes an encoded RelayState name (nothing to verify)", async () => {
    const { browser } = await host();
    await browser.signUp();
    const base = (await redirectUrl(authnRequestXml().xml)).split("?")[0];
    const q = (await redirectUrl(authnRequestXml().xml)).split("?")[1];
    const form = await readAutoPost(await browser.fetch(`${base}?${q}&Relay%53tate=ok`));
    expect(form.relayState).toBe("ok");
  });
});

describe.runIf(!isWorkerd)("#3 replay protection does not depend on Better Auth's id generation", () => {
  it.each(["serial", "uuid"] as const)("generateId: %s — first request works, a replay is rejected", async (generateId) => {
    const { browser } = await host({ auth: { advanced: { database: { generateId, validateSchema: true } } } });
    await browser.signUp();
    const url = await redirectUrl(authnRequestXml().xml);
    expect((await browser.fetch(url)).status).toBe(200);
    const again = await browser.fetch(url);
    expect(again.status).toBe(400);
    expect(await pageCode(again)).toBe("DUPLICATE_REQUEST_ID");
  });
});

describe("#4 bans are recognised however the adapter returns booleans", () => {
  it.each([true, 1, "1", "true"])("banned = %j is banned", (banned) => {
    expect(isBanned({ banned }, new Date())).toBe(true);
  });
  it.each([false, 0, null, undefined])("banned = %j is not banned", (banned) => {
    expect(isBanned({ banned }, new Date())).toBe(false);
  });
});

describe("#6 HTTP-POST binding: the SP's cross-site POST carries no Lax cookies", () => {
  it("a signed-in user is answered without the login page (re-entry via a same-site GET)", async () => {
    const { browser } = await host();
    const user = await browser.signUp();
    const res = await browser.fetch(SSO_URL, {
      method: "POST",
      crossSite: true,
      headers: { "content-type": "application/x-www-form-urlencoded", origin: "https://sp.test" },
      body: new URLSearchParams({ SAMLRequest: btoa(authnRequestXml().xml) }).toString(),
    });
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toMatch(new RegExp(`^${SSO_URL}\\?cid=[A-Za-z0-9_-]{43}$`));
    expect(res.headers.getSetCookie()).toEqual([]); // nothing set on the cross-site leg
    const form = await readAutoPost(await browser.fetch(res.headers.get("location")!));
    expect(nameIdOf(form.xml)).toBe(user.email);
  });

  it("IsPassive over POST with a session succeeds; without one the SP gets NoPassive", async () => {
    const { browser, auth } = await host();
    await browser.signUp();
    const ok = await readAutoPost(await postBinding(browser, authnRequestXml({ isPassive: true }).xml));
    expect(statusOf(ok.xml)).toEqual(["Success"]);
    const fresh = new Browser(auth);
    const no = await readAutoPost(await postBinding(fresh, authnRequestXml({ isPassive: true }).xml));
    expect(statusOf(no.xml)).toEqual(["Responder", "NoPassive"]);
  });

  it("the re-entry link is single use", async () => {
    const { browser } = await host();
    await browser.signUp();
    const res = await browser.fetch(SSO_URL, {
      method: "POST",
      crossSite: true,
      headers: { "content-type": "application/x-www-form-urlencoded", origin: "https://sp.test" },
      body: new URLSearchParams({ SAMLRequest: btoa(authnRequestXml().xml) }).toString(),
    });
    const loc = res.headers.get("location")!;
    expect((await browser.fetch(loc)).status).toBe(200);
    const again = await browser.fetch(loc);
    expect(again.status).toBe(400);
    expect(await pageCode(again)).toBe("PENDING_REQUEST_NOT_FOUND");
  });

  it("a signed-out user is sent to sign in, with the binding cookie set on the same-site leg", async () => {
    const { browser } = await host();
    const res = await postBinding(browser, authnRequestXml().xml);
    expect(res.status).toBe(302);
    expect(new URL(res.headers.get("location")!).pathname).toBe("/sign-in");
    expect(browser.cookieHeader()).toMatch(/saml_idp_binding=/);
  });
});

describe("#7 the IdP's own URLs can't be steered by the Host header", () => {
  it("with baseURL pinned, metadata advertises the pinned SSO URL whatever the Host", async () => {
    const { auth } = await host({ saml: { baseURL: "https://auth.test/api/auth" } });
    for (const hostHeader of ["auth.test", "attacker.example"]) {
      const res = await auth.handler(
        new Request("https://auth.test/api/auth/saml2/idp/metadata", { headers: { host: hostHeader, "x-forwarded-host": hostHeader } }),
      );
      expect(await res.text()).toContain('Location="https://auth.test/api/auth/saml2/idp/sso"');
    }
  });
});

describe("#9 abandoned SSO attempts don't accumulate", () => {
  it("expired pending requests are swept on a later SSO request", async () => {
    const { browser, ctx } = await host();
    const r = await browser.fetch(await redirectUrl(authnRequestXml().xml));
    const rid = new URL(new URL(r.headers.get("location")!).searchParams.get("callbackURL")!).searchParams.get("rid")!;
    const identifier = `saml-idp:pending:${rid}`;
    await ctx.adapter.update({ model: "verification", where: [{ field: "identifier", value: identifier }], update: { expiresAt: new Date(Date.now() - 1000) } });
    resetSweepThrottle();
    await browser.fetch(await redirectUrl(authnRequestXml().xml));
    expect(await ctx.adapter.findOne({ model: "verification", where: [{ field: "identifier", value: identifier }] })).toBeNull();
  });
});

describe("#10 schema renames stay with their own plugin instance", () => {
  it("renaming the table in one samlIdp() does not change another's", () => {
    const renamed = samlIdp(baseOptions({ schema: { samlIdpSeenRequest: { modelName: "tenant_b_seen", fields: { spId: "tenant_sp" } } } }));
    const plain = samlIdp(baseOptions());
    expect((renamed.schema.samlIdpSeenRequest as { modelName?: string }).modelName).toBe("tenant_b_seen");
    expect((plain.schema.samlIdpSeenRequest as { modelName?: string }).modelName).toBeUndefined();
    expect((plain.schema.samlIdpSeenRequest.fields.spId as { fieldName?: string }).fieldName).toBeUndefined();
    expect(renamed.schema).not.toBe(plain.schema);
  });
});

describe("#11 NameID follows the configured format", () => {
  const SP2 = "https://other.test/sp";
  const twoSps = (format: string) =>
    host({
      saml: {
        serviceProviders: [
          { id: "a", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], nameIdFormat: format },
          { id: "b", entityId: SP2, acsUrls: ["https://other.test/acs"], nameIdFormat: format },
        ],
      },
    });

  it("persistent: opaque (not the email), stable per SP, different across SPs", async () => {
    const { browser } = await twoSps(NAMEID_FORMAT.persistent);
    const user = await browser.signUp();
    const first = nameIdOf((await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)))).xml)!;
    const second = nameIdOf((await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)))).xml)!;
    const other = nameIdOf(
      (await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml({ issuer: SP2, acsUrl: "https://other.test/acs" }).xml)))).xml,
    )!;
    expect(first).not.toContain(user.email);
    expect(first).not.toContain("@");
    expect(second).toBe(first);
    expect(other).not.toBe(first);
  });

  it("transient: a new value for every assertion", async () => {
    const { browser } = await twoSps(NAMEID_FORMAT.transient);
    await browser.signUp();
    const a = nameIdOf((await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)))).xml);
    const b = nameIdOf((await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)))).xml);
    expect(a).not.toBe(b);
  });
});

describe("#12 requested Subject and AuthnContext are honoured", () => {
  const subject = (nameId: string) => `<saml:Subject><saml:NameID Format="${NAMEID_FORMAT.emailAddress}">${nameId}</saml:NameID></saml:Subject>`;
  const rac = (comparison: string, ...refs: string[]) =>
    `<samlp:RequestedAuthnContext Comparison="${comparison}">${refs.map((r) => `<saml:AuthnContextClassRef>${r}</saml:AuthnContextClassRef>`).join("")}</samlp:RequestedAuthnContext>`;

  it("a Subject naming someone else → UnknownPrincipal, no assertion", async () => {
    const { browser } = await host();
    await browser.signUp();
    const form = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml({ inner: subject("victim@x.example") }).xml)));
    expect(statusOf(form.xml)).toEqual(["Responder", "UnknownPrincipal"]);
    expect(form.xml).not.toContain("<saml:Assertion");
  });

  it("a Subject naming the signed-in user succeeds", async () => {
    const { browser } = await host();
    const user = await browser.signUp();
    const form = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml({ inner: subject(user.email) }).xml)));
    expect(statusOf(form.xml)).toEqual(["Success"]);
  });

  it.each([
    ["exact, our class listed", UNSPECIFIED, rac("exact", PPT, UNSPECIFIED), "Success"],
    ["exact, MFA only", UNSPECIFIED, rac("exact", "https://refeds.org/profile/mfa"), "NoAuthnContext"],
    ["better (no ordering known)", UNSPECIFIED, rac("better", UNSPECIFIED), "NoAuthnContext"],
    ["exact PPT with the IdP configured for PPT", PPT, rac("exact", PPT), "Success"],
  ])("RequestedAuthnContext %s", async (_, ours, inner, expected) => {
    const { browser } = await host({ saml: { authnContextClassRef: ours } });
    await browser.signUp();
    const form = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml({ inner }).xml)));
    expect(statusOf(form.xml).at(-1)).toBe(expected);
    if (expected === "Success") expect(form.xml).toContain(`<saml:AuthnContextClassRef>${ours}</saml:AuthnContextClassRef>`);
  });

  it("an unsupported NameIDPolicy format → InvalidNameIDPolicy SAML status (not an error page)", async () => {
    const { browser } = await host();
    await browser.signUp();
    const form = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml({ nameIdFormat: NAMEID_FORMAT.persistent }).xml)));
    expect(statusOf(form.xml)).toEqual(["Responder", "InvalidNameIDPolicy"]);
  });
});

describe("#14 the R3 re-reads are each load-bearing", () => {
  function atomicCache() {
    const m = new Map<string, string>();
    return {
      get: async (k: string) => m.get(k) ?? null,
      set: async (k: string, v: string) => void m.set(k, v),
      delete: async (k: string) => void m.delete(k),
      getAndDelete: async (k: string) => {
        const v = m.get(k) ?? null;
        m.delete(k);
        return v;
      },
      increment: async (k: string) => {
        const n = Number(m.get(k) ?? 0) + 1;
        m.set(k, String(n));
        return n;
      },
    };
  }

  it("sessions only in secondary storage: a deleted user is refused by the user re-read alone", async () => {
    // No DB session rows at all, so the session re-check is skipped: only findUserById can refuse.
    const { browser, ctx } = await host({ cloudflare: { geolocationTracking: false }, auth: { secondaryStorage: atomicCache() } });
    const user = await browser.signUp();
    // (Better Auth doesn't even register a `session` table in this configuration.)
    await ctx.adapter.deleteMany({ model: "account", where: [{ field: "userId", value: user.id }] });
    await ctx.adapter.delete({ model: "user", where: [{ field: "id", value: user.id }] });
    const res = await browser.fetch(await redirectUrl(authnRequestXml().xml));
    expect(res.status).toBe(403);
    expect(await pageCode(res)).toBe("ACCOUNT_INACTIVE");
  });

  it("an expired DB session row is refused even while the cache still serves it", async () => {
    const { browser, ctx } = await host({ auth: { secondaryStorage: atomicCache(), session: { storeSessionInDatabase: true } } });
    await browser.signUp();
    const token = decodeURIComponent(/better-auth\.session_token=([^;.]+)/.exec(browser.cookieHeader())![1]!);
    await ctx.adapter.update({ model: "session", where: [{ field: "token", value: token }], update: { expiresAt: new Date(Date.now() - 1000) } });
    const res = await browser.fetch(await redirectUrl(authnRequestXml().xml));
    expect(res.status).toBe(403);
    expect(await pageCode(res)).toBe("ACCOUNT_INACTIVE");
  });
});

describe("smaller review items", () => {
  it("IssueInstant without a time zone is rejected", async () => {
    const { browser } = await host();
    const xml = authnRequestXml().xml.replace(/IssueInstant="([^"]+)Z"/, 'IssueInstant="$1"');
    expect((await browser.fetch(await redirectUrl(xml))).status).toBe(400);
  });

  it('ForceAuthn=" true " is honoured (xs:boolean collapses whitespace)', async () => {
    const { browser } = await host();
    await browser.signUp();
    const xml = authnRequestXml().xml.replace("<samlp:AuthnRequest ", '<samlp:AuthnRequest ForceAuthn=" true " ');
    const res = await browser.fetch(await redirectUrl(xml));
    expect(res.status).toBe(302); // sent to sign in again despite the session
  });

  it("an ID padded with whitespace is the same ID for replay purposes", async () => {
    const { browser } = await host();
    await browser.signUp();
    const { id, xml } = authnRequestXml();
    expect((await browser.fetch(await redirectUrl(xml))).status).toBe(200);
    const padded = await browser.fetch(await redirectUrl(xml.replace(`ID="${id}"`, `ID=" ${id} "`)));
    expect(await pageCode(padded)).toBe("DUPLICATE_REQUEST_ID");
  });

  it("assertions carry no xsi:type (its xs prefix would be outside the signature)", async () => {
    const { browser } = await host({ saml: { serviceProviders: sp({ attributes: (u) => ({ email: u.email }) }) } });
    await browser.signUp();
    const form = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)));
    expect(form.xml).not.toMatch(/xsi:type|xmlns:xs=/);
    expect(form.xml).toContain("<saml:AttributeValue>");
  });
});
