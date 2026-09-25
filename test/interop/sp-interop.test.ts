// Phase 3 (amended): independent SP implementations must accept our assertions end to end.
//  - @better-auth/sso — Better Auth's own SAML SP (dogfooding; better-auth #6254)
//  - @node-saml/node-saml — a second, unrelated implementation with strict settings
// The IdP runs on the ADDENDUM-01 host (workerd: withCloudflare + D1/Drizzle; node: node:sqlite).
import { sso } from "@better-auth/sso";
import { SAML } from "@node-saml/node-saml";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { describe, expect, inject, it } from "vitest";
import { AUTH_BASE, createHost } from "../support/host";
import { Browser, readAutoPost, SSO_URL } from "../support/sp";

const keys = inject("keys");

// Better Auth SP
const BA_SP_BASE = "https://sp.test";
const BA_SP_ISSUER = `${BA_SP_BASE}/api/auth/sso/saml2/sp/metadata`;
const BA_SP_ACS = `${BA_SP_BASE}/api/auth/sso/saml2/sp/acs/our-idp`;

// node-saml SP
const NS_ISSUER = "https://node-saml.test/sp";
const NS_ACS = "https://node-saml.test/acs";

async function idp() {
  const host = await createHost({
    saml: {
      serviceProviders: [
        {
          id: "better-auth-sso",
          entityId: BA_SP_ISSUER,
          acsUrls: [BA_SP_ACS],
          attributes: (u) => ({ email: u.email, name: u.name }),
        },
        { id: "node-saml", entityId: NS_ISSUER, acsUrls: [NS_ACS], attributes: (u) => ({ email: u.email }) },
      ],
    },
  });
  const metadata = await (await host.auth.handler(new Request(`${AUTH_BASE}/saml2/idp/metadata`))).text();
  return { ...host, metadata };
}

describe("interop: @better-auth/sso as the SP", () => {
  it("a user signs in to a Better Auth SP through our IdP", async () => {
    const { auth: idpAuth, metadata } = await idp();

    const spAuth = betterAuth({
      baseURL: BA_SP_BASE,
      secret: "sp-secret-that-is-at-least-32-characters-long!!",
      database: memoryAdapter({ user: [], session: [], account: [], verification: [], ssoProvider: [] }),
      telemetry: { enabled: false },
      trustedOrigins: [BA_SP_BASE, "https://auth.test"],
      plugins: [
        sso({
          defaultSSO: [
            {
              domain: "example.com",
              providerId: "our-idp",
              samlConfig: {
                issuer: BA_SP_ISSUER,
                entryPoint: SSO_URL,
                idpMetadata: { metadata },
                callbackUrl: `${BA_SP_BASE}/dashboard`,
                wantAssertionsSigned: true,
              },
            },
          ],
        }),
      ],
    });

    const spBrowser = new Browser(spAuth);
    const idpBrowser = new Browser(idpAuth);

    // 1. The SP starts SSO and hands back the IdP URL.
    const start = await spBrowser.fetch(`${BA_SP_BASE}/api/auth/sign-in/sso`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: BA_SP_BASE },
      body: JSON.stringify({ providerId: "our-idp", callbackURL: `${BA_SP_BASE}/dashboard` }),
    });
    expect(start.status).toBe(200);
    const { url } = (await start.json()) as { url: string };
    expect(url.startsWith(SSO_URL)).toBe(true);

    // 2. IdP: no session → login → resume → auto-POST form.
    const toLogin = await idpBrowser.fetch(url);
    expect(toLogin.status).toBe(302);
    const resume = new URL(toLogin.headers.get("location")!).searchParams.get("callbackURL")!;
    const user = await idpBrowser.signUp("carol@example.com");
    const form = await readAutoPost(await idpBrowser.fetch(resume));
    expect(form.action).toBe(BA_SP_ACS);

    // 3. The browser posts the form to the SP's ACS.
    const acs = await spBrowser.fetch(form.action, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", origin: "https://auth.test" },
      body: new URLSearchParams({ SAMLResponse: form.samlResponse, ...(form.relayState ? { RelayState: form.relayState } : {}) }).toString(),
    });
    expect([302, 303]).toContain(acs.status);
    expect(acs.headers.get("location")).toContain("/dashboard");
    expect(acs.headers.get("location")).not.toContain("error");

    // 4. The SP now has a session for the same person.
    const session = await spBrowser.fetch(`${BA_SP_BASE}/api/auth/get-session`);
    const body = (await session.json()) as { user?: { email: string } } | null;
    expect(body?.user?.email).toBe(user.email);
  });
});

describe("interop: @node-saml/node-saml as the SP", () => {
  const nodeSaml = (idpCert: string) =>
    new SAML({
      issuer: NS_ISSUER,
      callbackUrl: NS_ACS,
      entryPoint: SSO_URL,
      idpCert,
      audience: NS_ISSUER,
      wantAssertionsSigned: true,
      wantAuthnResponseSigned: true,
      validateInResponseTo: "always" as any,
      acceptedClockSkewMs: 60_000,
      signatureAlgorithm: "sha256",
    });

  it("validates our Response, InResponseTo included", async () => {
    const { auth } = await idp();
    const sp = nodeSaml(keys.idp.certificate);
    const url = await sp.getAuthorizeUrlAsync("ns-relay", undefined, {});
    const browser = new Browser(auth);
    const user = await browser.signUp("dave@example.com");
    const res = await browser.fetch(url);
    expect(res.status).toBe(200);
    const form = await readAutoPost(res);
    expect(form.action).toBe(NS_ACS);
    expect(form.relayState).toBe("ns-relay");
    const { profile, loggedOut } = await sp.validatePostResponseAsync({ SAMLResponse: form.samlResponse });
    expect(loggedOut).toBe(false);
    expect(profile?.nameID).toBe(user.email);
    expect(profile?.issuer).toBe("https://auth.test/api/auth/saml2/idp");
    expect(profile?.email).toBe(user.email);
  });

  it("rejects our Response when configured with a different IdP certificate", async () => {
    const { auth } = await idp();
    const sp = nodeSaml(keys.sp.certificate);
    const browser = new Browser(auth);
    await browser.signUp();
    const form = await readAutoPost(await browser.fetch(await sp.getAuthorizeUrlAsync("", undefined, {})));
    await expect(sp.validatePostResponseAsync({ SAMLResponse: form.samlResponse })).rejects.toThrow();
  });
});
