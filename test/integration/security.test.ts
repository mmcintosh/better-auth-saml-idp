// SPEC §7 security requirements + ADDENDUM-01 R1/R2/R3, on the R5 host
// (workerd: withCloudflare + Drizzle/D1; node: node:sqlite).
import { SAML } from "@node-saml/node-saml";
import { inject, describe, expect, it, vi } from "vitest";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { AUTH_BASE, createHost, createHostDatabase, type HostOptions } from "../support/host";
import {
  authnRequestXml,
  b64,
  Browser,
  postBinding,
  deflateRaw,
  readAutoPost,
  redirectUrl,
  SSO_URL,
  strictSp,
} from "../support/sp";

const keys = inject("keys");
type Sp = NonNullable<HostOptions["saml"]>["serviceProviders"];

function spConfig(over: Record<string, unknown> = {}): Sp {
  return [{ id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], ...over }] as Sp;
}

async function host(options: HostOptions = {}) {
  const h = await createHost({ ...options, saml: { serviceProviders: spConfig(), ...options.saml } });
  const ctx = await h.auth.$context;
  return { ...h, ctx, browser: new Browser(h.auth) };
}

const pageCode = async (res: Response) => /<code>([A-Z_]+)<\/code>/.exec(await res.clone().text())?.[1];
const hasAssertion = async (res: Response) => /SAMLResponse/.test(await res.clone().text());

/** Start SP-initiated SSO without a session; returns the resume URL. */
async function startPending(browser: Browser, spec = {}) {
  const { xml } = authnRequestXml(spec);
  const res = await browser.fetch(await redirectUrl(xml, { relayState: "rs" }));
  expect(res.status).toBe(302);
  return new URL(res.headers.get("location")!).searchParams.get("callbackURL")!;
}

describe("§7 unknown SP / ACS allow-list", () => {
  it("unknown issuer → 400, no response issued", async () => {
    const { browser } = await host();
    await browser.signUp();
    const { xml } = authnRequestXml({ issuer: "https://evil.test/sp" });
    const res = await browser.fetch(await redirectUrl(xml));
    expect(res.status).toBe(400);
    expect(await pageCode(res)).toBe("UNKNOWN_SERVICE_PROVIDER");
    expect(await hasAssertion(res)).toBe(false);
  });

  it("ACS URL not on the allow-list → 400, and the URL is never reflected", async () => {
    const { browser } = await host();
    await browser.signUp();
    const { xml } = authnRequestXml({ acsUrl: "https://evil.test/steal" });
    const res = await browser.fetch(await redirectUrl(xml));
    expect(res.status).toBe(400);
    expect(await pageCode(res)).toBe("ACS_URL_NOT_ALLOWED");
    expect(await res.text()).not.toContain("evil.test");
  });
});

describe("R1 pending requests: single use, expiry, concurrency", () => {
  it("a rid is consumed once; replaying it is refused", async () => {
    const { browser } = await host();
    const resume = await startPending(browser);
    await browser.signUp();
    const first = await browser.fetch(resume);
    expect(first.status).toBe(200);
    expect(await hasAssertion(first)).toBe(true);
    const again = await browser.fetch(resume);
    expect(again.status).toBe(400);
    expect(await pageCode(again)).toBe("PENDING_REQUEST_NOT_FOUND");
    expect(await hasAssertion(again)).toBe(false);
  });

  it("an expired rid is refused and issues nothing", async () => {
    const { browser, ctx } = await host();
    const resume = await startPending(browser);
    await browser.signUp();
    const rid = new URL(resume).searchParams.get("rid")!;
    await ctx.adapter.update({
      model: "verification",
      where: [{ field: "identifier", value: `saml-idp:pending:${rid}` }],
      update: { expiresAt: new Date(Date.now() - 1000) },
    });
    const res = await browser.fetch(resume);
    expect(res.status).toBe(400);
    expect(await pageCode(res)).toBe("PENDING_REQUEST_NOT_FOUND");
    expect(await hasAssertion(res)).toBe(false);
  });

  it("a rid is bound to the browser that started the flow", async () => {
    const { auth, browser } = await host();
    const resume = await startPending(browser);
    // A realistic attacker first starts a flow of their own, so they DO hold a valid, signed
    // binding cookie — just not the victim's. Only the hash comparison can stop them
    // (review finding #13: a cookie-less second browser proved nothing).
    const other = new Browser(auth);
    await startPending(other);
    expect(other.cookieHeader()).toMatch(/saml_idp_binding=/);
    await other.signUp();
    const res = await other.fetch(resume);
    expect(res.status).toBe(400);
    expect(await hasAssertion(res)).toBe(false);
  });

  it("without a session, resume sends the user to sign in and does not consume the rid", async () => {
    const { browser } = await host();
    const resume = await startPending(browser);
    const res = await browser.fetch(resume);
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toContain(encodeURIComponent(resume));
    await browser.signUp();
    expect((await browser.fetch(resume)).status).toBe(200);
  });

  it("10 parallel resumes of the same rid → exactly one SAML Response", async () => {
    const { browser } = await host();
    const resume = await startPending(browser);
    await browser.signUp();
    const results = await Promise.all(Array.from({ length: 10 }, () => browser.clone().fetch(resume)));
    const issued = (await Promise.all(results.map(hasAssertion))).filter(Boolean).length;
    const statuses = results.map((r) => r.status).sort();
    console.log("R1 concurrency (one auth instance):", JSON.stringify({ issued, statuses }));
    expect(issued).toBe(1);
    expect(statuses.filter((s) => s === 200)).toHaveLength(1);
    expect(statuses.filter((s) => s === 400)).toHaveLength(9);
  });

  it("10 parallel resumes spread over 5 independent auth instances on one database → exactly one", async () => {
    // consumeVerificationValue serialises consumes per instance with an in-process lock, so a
    // single-instance race cannot reach the database. Separate instances (like separate
    // isolates) race on the database's DELETE ... RETURNING itself.
    const database = await createHostDatabase();
    const hosts = await Promise.all(
      Array.from({ length: 5 }, () => createHost({ database, saml: { serviceProviders: spConfig() } })),
    );
    const browser = new Browser(hosts[0]!.auth);
    const resume = await startPending(browser);
    await browser.signUp();
    const results = await Promise.all(
      Array.from({ length: 10 }, (_, i) => {
        const b = browser.clone();
        (b as any).auth = hosts[i % 5]!.auth;
        return b.fetch(resume);
      }),
    );
    const issued = (await Promise.all(results.map(hasAssertion))).filter(Boolean).length;
    console.log("R1 concurrency (5 instances, shared DB):", JSON.stringify({ issued, statuses: results.map((r) => r.status).sort() }));
    expect(issued).toBe(1);
  });
});

describe("R2 AuthnRequest ID replay", () => {
  it("rejects a duplicate request ID sent later", async () => {
    const { browser } = await host();
    await browser.signUp();
    const { xml } = authnRequestXml();
    expect((await browser.fetch(await redirectUrl(xml))).status).toBe(200);
    const res = await browser.fetch(await redirectUrl(xml));
    expect(res.status).toBe(400);
    expect(await pageCode(res)).toBe("DUPLICATE_REQUEST_ID");
  });

  it("rejects one of two identical requests arriving concurrently", async () => {
    const { browser } = await host();
    await browser.signUp();
    const { xml } = authnRequestXml();
    const url = await redirectUrl(xml);
    const [a, b] = await Promise.all([browser.clone().fetch(url), browser.clone().fetch(url)]);
    const statuses = [a.status, b.status].sort();
    console.log("R2 concurrent duplicate:", JSON.stringify(statuses));
    expect(statuses).toEqual([200, 400]);
  });

  it("rejects concurrent duplicates across independent auth instances sharing the database", async () => {
    const database = await createHostDatabase();
    const [h1, h2] = await Promise.all([
      createHost({ database, saml: { serviceProviders: spConfig() } }),
      createHost({ database, saml: { serviceProviders: spConfig() } }),
    ]);
    const b1 = new Browser(h1.auth);
    const url = await redirectUrl(authnRequestXml().xml);
    const b2 = b1.clone();
    (b2 as any).auth = h2.auth;
    const statuses = (await Promise.all([b1.fetch(url), b2.fetch(url)])).map((r) => r.status).sort();
    expect(statuses).toEqual([302, 400]);
  });

  it("the same ID from a different SP is not a replay", async () => {
    const { browser } = await host({
      saml: {
        serviceProviders: [
          ...spConfig()!,
          { id: "other", entityId: "https://other.test/sp", acsUrls: ["https://other.test/acs"] },
        ] as Sp,
      },
    });
    await browser.signUp();
    const id = "_shared-id-123";
    expect((await browser.fetch(await redirectUrl(authnRequestXml({ id }).xml))).status).toBe(200);
    const other = authnRequestXml({ id, issuer: "https://other.test/sp", acsUrl: "https://other.test/acs" });
    expect((await browser.fetch(await redirectUrl(other.xml))).status).toBe(200);
  });
});

describe("R3 fresh user check before signing", () => {
  it("a user banned in the database after signing in is refused", async () => {
    const { browser, ctx } = await host();
    const resume = await startPending(browser);
    const user = await browser.signUp();
    // Direct DB write: the session stays valid, as with a lagging cache or an out-of-band ban.
    await ctx.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { banned: true } });
    const res = await browser.fetch(resume);
    expect(res.status).toBe(403);
    expect(await pageCode(res)).toBe("ACCOUNT_INACTIVE");
    expect(await hasAssertion(res)).toBe(false);
  });

  it("an expired ban does not block", async () => {
    const { browser, ctx } = await host();
    const user = await browser.signUp();
    await ctx.adapter.update({
      model: "user",
      where: [{ field: "id", value: user.id }],
      update: { banned: true, banExpires: new Date(Date.now() - 60_000) },
    });
    expect((await browser.fetch(await redirectUrl(authnRequestXml().xml))).status).toBe(200);
  });

  describe("with a session cache that outlives revocation (better-auth-cloudflare #61)", () => {
    // An atomic in-memory secondary storage stands in for KV. storeInDatabase keeps
    // verification on the database; the session is served from the cache first.
    function staleCache() {
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
    const cachedHost = () =>
      host({ auth: { secondaryStorage: staleCache(), session: { storeSessionInDatabase: true } } });

    it("a session deleted from the database but still cached is refused", async () => {
      const { browser, ctx } = await cachedHost();
      const resume = await startPending(browser);
      await browser.signUp();
      const token = decodeURIComponent(/better-auth\.session_token=([^;.]+)/.exec(browser.cookieHeader())![1]!);
      await ctx.adapter.delete({ model: "session", where: [{ field: "token", value: token }] });
      const res = await browser.fetch(resume);
      expect(res.status).toBe(403);
      expect(await pageCode(res)).toBe("ACCOUNT_INACTIVE");
    });

    it("a user deleted from the database while the session is still cached is refused", async () => {
      const { browser, ctx } = await cachedHost();
      const resume = await startPending(browser);
      const user = await browser.signUp();
      await ctx.adapter.deleteMany({ model: "session", where: [{ field: "userId", value: user.id }] });
      await ctx.adapter.deleteMany({ model: "account", where: [{ field: "userId", value: user.id }] });
      await ctx.adapter.delete({ model: "user", where: [{ field: "id", value: user.id }] });
      const res = await browser.fetch(resume);
      expect(res.status).toBe(403);
      expect(await hasAssertion(res)).toBe(false);
    });
  });
});

describe("§7 RelayState", () => {
  it("over the cap → 400 (default 1024 bytes)", async () => {
    const { browser } = await host();
    const res = await browser.fetch(await redirectUrl(authnRequestXml().xml, { relayState: "x".repeat(1025) }));
    expect(res.status).toBe(400);
    expect(await pageCode(res)).toBe("RELAY_STATE_TOO_LONG");
  });

  it("a Cloudflare-Access-sized RelayState (> 80 bytes) is accepted by default", async () => {
    const { browser } = await host();
    await browser.signUp();
    expect((await browser.fetch(await redirectUrl(authnRequestXml().xml, { relayState: "r".repeat(200) }))).status).toBe(200);
  });

  it("strict spec mode: relayStateMaxBytes 80 rejects 81 bytes", async () => {
    const { browser } = await host({ saml: { relayStateMaxBytes: 80 } });
    const res = await browser.fetch(await redirectUrl(authnRequestXml().xml, { relayState: "x".repeat(81) }));
    expect(res.status).toBe(400);
    expect(await pageCode(res)).toBe("RELAY_STATE_TOO_LONG");
  });

  it("counts bytes, not characters", async () => {
    const { browser } = await host({ saml: { relayStateMaxBytes: 80 } });
    const res = await browser.fetch(await redirectUrl(authnRequestXml().xml, { relayState: "é".repeat(41) }));
    expect(res.status).toBe(400);
  });

  it("is passed through opaquely and HTML-escaped in the form", async () => {
    const { browser } = await host();
    await browser.signUp();
    const evil = `"><script>alert(1)</script>&`;
    const res = await browser.fetch(await redirectUrl(authnRequestXml().xml, { relayState: evil }));
    const form = await readAutoPost(res);
    expect(form.relayState).toBe(evil);
    expect(form.html).not.toContain("<script>alert");
    expect(form.html).toContain("&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;&amp;");
  });

  it("respects a raised relayStateMaxBytes", async () => {
    const { browser } = await host({ saml: { relayStateMaxBytes: 200 } });
    await browser.signUp();
    expect((await browser.fetch(await redirectUrl(authnRequestXml().xml, { relayState: "x".repeat(150) }))).status).toBe(200);
  });
});

describe("§7 algorithms, validity, signatures", () => {
  it("signs Response and Assertion with RSA-SHA256 / SHA-256 by default; no SHA-1 anywhere", async () => {
    const { browser } = await host();
    await browser.signUp();
    const { xml } = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)));
    expect(xml.match(/<ds:SignatureMethod Algorithm="http:\/\/www\.w3\.org\/2001\/04\/xmldsig-more#rsa-sha256"\/>/g)).toHaveLength(2);
    expect(xml.match(/<ds:DigestMethod Algorithm="http:\/\/www\.w3\.org\/2001\/04\/xmlenc#sha256"\/>/g)).toHaveLength(2);
    expect(xml).not.toMatch(/sha1/i);
  });

  it.each([
    ["assertion only", { signResponse: false }, { message: false, assertion: true }, 1],
    ["response only", { signAssertion: false }, { message: true, assertion: false }, 1],
  ])("per-SP signing: %s, accepted by an SP that requires exactly that", async (_, over, want, signatures) => {
    const { auth, browser } = await host({ saml: { serviceProviders: spConfig(over) } });
    await browser.signUp();
    const form = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)));
    expect(form.xml.match(/<ds:Signature /g)).toHaveLength(signatures);
    const assertion = /<saml:Assertion [\s\S]*<\/saml:Assertion>/.exec(form.xml)![0];
    expect(assertion.includes("<ds:Signature ")).toBe(want.assertion);
    await expect((await strictSp(auth, { wantMessageSigned: want.message, wantAssertionsSigned: want.assertion })).verify(b64(form.xml))).resolves.toBeDefined();
    // ...and an SP that wants the missing signature refuses it. (samlify doesn't enforce its
    // want* settings when parsing a Response, so this uses node-saml, which does.)
    const nodeSaml = (w: typeof want) =>
      new SAML({
        issuer: SP_ENTITY_ID,
        callbackUrl: SP_ACS,
        audience: SP_ENTITY_ID,
        idpCert: keys.idp.certificate,
        entryPoint: SSO_URL,
        wantAssertionsSigned: w.assertion,
        wantAuthnResponseSigned: w.message,
        acceptedClockSkewMs: 60_000,
      }).validatePostResponseAsync({ SAMLResponse: b64(form.xml) });
    await expect(nodeSaml(want)).resolves.toBeDefined();
    await expect(nodeSaml({ message: true, assertion: true })).rejects.toThrow();
  });

  it("assertion validity is at most 5 minutes by default", async () => {
    const { browser } = await host();
    await browser.signUp();
    const { xml } = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)));
    const issue = new Date(/<saml:Assertion [^>]*IssueInstant="([^"]+)"/.exec(xml)![1]!).getTime();
    const until = new Date(/<saml:Conditions NotBefore="[^"]+" NotOnOrAfter="([^"]+)"/.exec(xml)![1]!).getTime();
    expect(until - issue).toBeLessThanOrEqual(300_000);
    expect(until - issue).toBeGreaterThan(0);
  });

  it("a strict SP rejects a response altered after signing", async () => {
    const { auth, browser } = await host();
    await browser.signUp();
    const form = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)));
    const tampered = b64(form.xml.replace(/<saml:NameID ([^>]*)>[^<]+</, "<saml:NameID $1>mallory@example.com<"));
    await expect((await strictSp(auth)).verify(tampered)).rejects.toBeDefined();
  });

  it("signs with the SHA-1 opt-in only when explicitly enabled", async () => {
    const { browser } = await host({
      saml: { signing: { privateKey: keys.idp.privateKey, certificate: keys.idp.certificate, signatureAlgorithm: "rsa-sha1", digestAlgorithm: "sha1", allowInsecureSha1: true } },
    });
    await browser.signUp();
    const { xml } = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)));
    expect(xml).toContain("xmldsig#rsa-sha1");
  });
});

describe("§7 auto-POST page", () => {
  it("has a nonce CSP, no form-action (it breaks SPs that redirect after the ACS), no-store, DENY framing, noscript", async () => {
    const { browser } = await host();
    await browser.signUp();
    const res = await browser.fetch(await redirectUrl(authnRequestXml().xml));
    const csp = res.headers.get("content-security-policy")!;
    const nonce = /script-src 'nonce-([^']+)'/.exec(csp)?.[1];
    expect(nonce).toBeTruthy();
    expect(csp).toContain("default-src 'none'");
    // Chromium enforces form-action on redirects after the submission; hosted SPs redirect
    // cross-site after their ACS (review finding #5, reproduced in e2e/browser/test-sp.spec).
    expect(csp).not.toContain("form-action");
    expect(csp).toContain("base-uri 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toContain("unsafe-inline");
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    const html = await res.text();
    expect(html).toContain(`<script nonce="${nonce}">document.forms[0].submit()</script>`);
    expect(html).toMatch(/<noscript>.*<button type="submit">Continue<\/button><\/noscript>/);
  });

  it("error pages carry the same headers and no payload", async () => {
    const { browser } = await host();
    const res = await browser.fetch(await redirectUrl(authnRequestXml({ issuer: "https://evil.test/sp" }).xml));
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("content-security-policy")).toContain("form-action 'none'");
  });
});

describe("§7 inbound request validation", () => {
  it("ProtocolBinding HTTP-Redirect (Auth0 sends its request binding there) is answered over HTTP-POST", async () => {
    const { browser } = await host();
    await browser.signUp();
    const xml = authnRequestXml({ extraAttrs: "" }).xml.replace(
      'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"',
      'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"',
    );
    const form = await readAutoPost(await browser.fetch(await redirectUrl(xml)));
    expect(form.xml).toContain("status:Success");
  });

  it("ProtocolBinding Artifact is refused (unsupported)", async () => {
    const { browser } = await host();
    const xml = authnRequestXml().xml.replace(
      'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"',
      'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"',
    );
    expect(await pageCode(await browser.fetch(await redirectUrl(xml)))).toBe("INVALID_SAML_REQUEST");
  });

  it.each([
    ["schema-invalid child element", { inner: "<samlp:Bogus/>" }],
    ["Destination for another IdP", { destination: "https://other-idp.test/sso" }],
    ["IssueInstant too old", { issueInstant: new Date(Date.now() - 10 * 60_000) }],
    ["IssueInstant in the future", { issueInstant: new Date(Date.now() + 10 * 60_000) }],
    ["two Issuers", { inner: `<saml:Issuer>${SP_ENTITY_ID}</saml:Issuer>` }],
  ])("rejects %s", async (_, spec) => {
    const { browser } = await host();
    await browser.signUp();
    const res = await browser.fetch(await redirectUrl(authnRequestXml(spec).xml));
    expect(res.status).toBe(400);
    expect(await pageCode(res)).toBe("INVALID_SAML_REQUEST");
    expect(await hasAssertion(res)).toBe(false);
  });

  it("rejects a DOCTYPE", async () => {
    const { browser } = await host();
    const { xml } = authnRequestXml();
    const res = await browser.fetch(await redirectUrl(`<!DOCTYPE x [<!ENTITY e "boom">]>${xml}`));
    expect(res.status).toBe(400);
  });

  it("rejects a message that is not an AuthnRequest", async () => {
    const { browser } = await host();
    const logout = `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_x" Version="2.0" IssueInstant="${new Date().toISOString()}"><saml:Issuer>${SP_ENTITY_ID}</saml:Issuer><saml:NameID>a</saml:NameID></samlp:LogoutRequest>`;
    const res = await browser.fetch(await redirectUrl(logout));
    expect(res.status).toBe(400);
  });

  it("stops inflating a DEFLATE bomb early", async () => {
    // A 400 alone would pass for any bad input: check it's the inflate cap that stopped it, and
    // quickly (review 4).
    const details: string[] = [];
    const { browser } = await host({ saml: { events: { onDenied: (e) => void details.push(e.detail ?? "") } } });
    const bomb = await deflateRaw(`<a>${" ".repeat(5_000_000)}</a>`);
    const t = performance.now();
    const res = await browser.fetch(await redirectUrl("", { deflated: bomb }));
    expect(performance.now() - t).toBeLessThan(1000);
    expect(res.status).toBe(400);
    await vi.waitFor(() => expect(details.join(" ")).toMatch(/inflated SAMLRequest exceeds 65536 bytes/));
  });

  it("rejects garbage base64", async () => {
    const { browser } = await host();
    const res = await browser.fetch(`${SSO_URL}?SAMLRequest=%%%not-base64`);
    expect(res.status).toBe(400);
  });
});

describe("§7 signed AuthnRequests", () => {
  const signedHost = () =>
    host({ saml: { serviceProviders: spConfig({ requireSignedAuthnRequests: true, spCertificate: keys.sp.certificate }) } });

  it("accepts a valid Redirect-binding signature", async () => {
    const { browser } = await signedHost();
    await browser.signUp();
    const res = await browser.fetch(await redirectUrl(authnRequestXml().xml, { sign: true, relayState: "r" }));
    expect(res.status).toBe(200);
  });

  it("accepts a signature from any of several SP certificates (SP key rotation)", async () => {
    const { browser } = await host({
      saml: { serviceProviders: spConfig({ requireSignedAuthnRequests: true, spCertificate: [keys.idpNext.certificate, keys.sp.certificate] }) },
    });
    await browser.signUp();
    expect((await browser.fetch(await redirectUrl(authnRequestXml().xml, { sign: true }))).status).toBe(200);
  });

  it("rejects a signature from a key that is not configured", async () => {
    const { browser } = await host({
      saml: { serviceProviders: spConfig({ requireSignedAuthnRequests: true, spCertificate: [keys.idpNext.certificate] }) },
    });
    const res = await browser.fetch(await redirectUrl(authnRequestXml().xml, { sign: true }));
    expect(res.status).toBe(400);
    expect(await pageCode(res)).toBe("UNSIGNED_SAML_REQUEST");
  });

  it("rejects an unsigned request", async () => {
    const { browser } = await signedHost();
    const res = await browser.fetch(await redirectUrl(authnRequestXml().xml));
    expect(res.status).toBe(400);
    expect(await pageCode(res)).toBe("UNSIGNED_SAML_REQUEST");
  });

  it("rejects a request whose RelayState was changed after signing", async () => {
    const { browser } = await signedHost();
    const url = (await redirectUrl(authnRequestXml().xml, { sign: true, relayState: "good" })).replace("RelayState=good", "RelayState=evil");
    const res = await browser.fetch(url);
    expect(res.status).toBe(400);
    expect(await pageCode(res)).toBe("UNSIGNED_SAML_REQUEST");
  });

  it("rejects a SHA-1 signature without the opt-in", async () => {
    const { browser } = await signedHost();
    const res = await browser.fetch(
      await redirectUrl(authnRequestXml().xml, { sign: true, sigAlg: "http://www.w3.org/2000/09/xmldsig#rsa-sha1" }),
    );
    expect(res.status).toBe(400);
  });

  it("rejects an unsigned POST-binding request when signatures are required", async () => {
    const { browser } = await signedHost();
    const res = await postBinding(browser, authnRequestXml().xml);
    expect(res.status).toBe(400);
    expect(await pageCode(res)).toBe("UNSIGNED_SAML_REQUEST");
  });
});

describe("§7 authorize()", () => {
  it("denial → clear 403 page, no assertion", async () => {
    const { browser } = await host({ saml: { serviceProviders: spConfig({ authorize: async () => false }) } });
    await browser.signUp();
    const res = await browser.fetch(await redirectUrl(authnRequestXml().xml));
    expect(res.status).toBe(403);
    expect(await pageCode(res)).toBe("ACCESS_DENIED");
    expect(await hasAssertion(res)).toBe(false);
    expect(await res.text()).toContain("You are not allowed to sign in to this application");
  });

  it("an authorize() that throws is a denial", async () => {
    const { browser } = await host({
      saml: { serviceProviders: spConfig({ authorize: async () => { throw new Error("db down"); } }) },
    });
    await browser.signUp();
    const res = await browser.fetch(await redirectUrl(authnRequestXml().xml));
    expect(res.status).toBe(403);
  });

  it("receives the fresh user, the session and the SP", async () => {
    let seen: any;
    const { browser } = await host({
      saml: { serviceProviders: spConfig({ authorize: async (c: any) => {
          seen = c;
          return true;
        }, }) },
    });
    const user = await browser.signUp();
    await browser.fetch(await redirectUrl(authnRequestXml().xml));
    expect(seen.user.id).toBe(user.id);
    expect(seen.session.userId).toBe(user.id);
    expect(seen.serviceProvider.id).toBe("test-sp");
  });
});

describe("IsPassive / ForceAuthn", () => {
  it("IsPassive without a session → signed SAML NoPassive Response to the SP, no login redirect", async () => {
    const { browser } = await host();
    const { id, xml } = authnRequestXml({ isPassive: true });
    const res = await browser.fetch(await redirectUrl(xml));
    expect(res.status).toBe(200);
    const form = await readAutoPost(res);
    expect(form.action).toBe(SP_ACS);
    expect(form.xml).toContain(`InResponseTo="${id}"`);
    expect(form.xml).toContain('<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:NoPassive"/>');
    expect(form.xml).not.toContain("<saml:Assertion");
    expect(form.xml).toContain("<ds:Signature");
  });

  it("IsPassive with a session succeeds silently", async () => {
    const { browser } = await host();
    await browser.signUp();
    const form = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml({ isPassive: true }).xml)));
    expect(form.xml).toContain("status:Success");
  });

  it("ForceAuthn requires a session created after the request", async () => {
    const { browser } = await host();
    const user = await browser.signUp();
    const res = await browser.fetch(await redirectUrl(authnRequestXml({ forceAuthn: true }).xml));
    expect(res.status).toBe(302);
    const resume = new URL(res.headers.get("location")!).searchParams.get("callbackURL")!;
    const stale = await browser.fetch(resume);
    expect(stale.status).toBe(401);
    expect(await pageCode(stale)).toBe("REAUTHENTICATION_REQUIRED");

    const res2 = await browser.fetch(await redirectUrl(authnRequestXml({ forceAuthn: true }).xml));
    const resume2 = new URL(res2.headers.get("location")!).searchParams.get("callbackURL")!;
    await new Promise((r) => setTimeout(r, 5));
    await browser.signIn(user.email);
    expect((await browser.fetch(resume2)).status).toBe(200);
  });
});

describe("§7 logging", () => {
  it("never logs the private key or SAML payloads, even at debug level", async () => {
    const lines: string[] = [];
    const logger = {
      level: "debug" as const,
      log: (level: string, message: string, ...args: unknown[]) => {
        lines.push(`${level} ${message} ${args.map((a) => (a instanceof Error ? a.stack : JSON.stringify(a))).join(" ")}`);
      },
    };
    const { browser } = await host({ auth: { logger } });
    const resume = await startPending(browser);
    await browser.signUp();
    const form = await readAutoPost(await browser.fetch(resume));
    await browser.fetch(await redirectUrl(authnRequestXml({ issuer: "https://evil.test/x" }).xml));
    const all = lines.join("\n");
    expect(lines.some((l) => l.includes("[saml-idp]"))).toBe(true);
    const keyBody = keys.idp.privateKey.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
    for (let i = 0; i + 40 <= keyBody.length; i += 200) expect(all).not.toContain(keyBody.slice(i, i + 40));
    expect(all).not.toContain(form.samlResponse.slice(0, 60));
    expect(all).not.toContain("evil.test");
    expect(all).not.toMatch(/SAMLRequest=/);
  });
});

void AUTH_BASE;
