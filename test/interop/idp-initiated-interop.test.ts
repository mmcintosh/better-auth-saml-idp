// IdP-initiated SSO (D-021): independent SPs accept our unsolicited Response only when they are
// configured for unsolicited Responses, which proves the Response really is unsolicited.
//  - @node-saml/node-saml: accepted with validateInResponseTo "never", rejected with "always"
//  - @better-auth/sso: accepted with saml.allowIdpInitiated, rejected without it
// (The strict samlify SP accepts it too: test/integration/idp-initiated.test.ts.)
import { sso } from "@better-auth/sso";
import { SAML } from "@node-saml/node-saml";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { describe, expect, inject, it } from "vitest";
import { AUTH_BASE, createHost } from "../support/host";
import { Browser, readAutoPost, SSO_URL } from "../support/sp";

const keys = inject("keys");

const BA_SP_BASE = "https://sp.test";
const BA_SP_ISSUER = `${BA_SP_BASE}/api/auth/sso/saml2/sp/metadata`;
const BA_SP_ACS = `${BA_SP_BASE}/api/auth/sso/saml2/sp/acs/our-idp`;
const NS_ISSUER = "https://node-saml.test/sp";
const NS_ACS = "https://node-saml.test/acs";
const init = (sp: string) => `${AUTH_BASE}/saml2/idp/init?sp=${sp}`;

async function idp() {
  const host = await createHost({
    saml: {
      authnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
      serviceProviders: [
        {
          id: "better-auth-sso",
          entityId: BA_SP_ISSUER,
          acsUrls: [BA_SP_ACS],
          allowIdpInitiated: true,
          attributes: (u) => ({ email: u.email, name: u.name }),
        },
        {
          id: "node-saml",
          entityId: NS_ISSUER,
          acsUrls: [NS_ACS],
          allowIdpInitiated: true,
          idpInitiatedRelayState: "/app/home",
          attributes: (u) => ({ email: u.email }),
        },
      ],
    },
  });
  const metadata = await (await host.auth.handler(new Request(`${AUTH_BASE}/saml2/idp/metadata`))).text();
  return { ...host, metadata };
}

describe("interop: IdP-initiated SSO with @node-saml/node-saml", () => {
  const nodeSaml = (validateInResponseTo: "never" | "always") =>
    new SAML({
      issuer: NS_ISSUER,
      callbackUrl: NS_ACS,
      entryPoint: SSO_URL,
      idpCert: keys.idp.certificate,
      audience: NS_ISSUER,
      wantAssertionsSigned: true,
      wantAuthnResponseSigned: true,
      validateInResponseTo: validateInResponseTo as any,
      acceptedClockSkewMs: 60_000,
    });

  it("accepts the unsolicited Response with validateInResponseTo: never", async () => {
    const { auth } = await idp();
    const browser = new Browser(auth);
    const user = await browser.signUp();
    const form = await readAutoPost(await browser.fetch(init("node-saml")));
    expect(form.action).toBe(NS_ACS);
    expect(form.relayState).toBe("/app/home");
    expect(form.xml).not.toContain("InResponseTo");
    const { profile, loggedOut } = await nodeSaml("never").validatePostResponseAsync({ SAMLResponse: form.samlResponse });
    expect(loggedOut).toBe(false);
    expect(profile?.nameID).toBe(user.email);
    expect(profile?.email).toBe(user.email);
    expect(profile?.inResponseTo).toBeUndefined();
  });

  it("rejects it with validateInResponseTo: always, because InResponseTo is missing", async () => {
    const { auth } = await idp();
    const browser = new Browser(auth);
    await browser.signUp();
    const form = await readAutoPost(await browser.fetch(init("node-saml")));
    await expect(nodeSaml("always").validatePostResponseAsync({ SAMLResponse: form.samlResponse })).rejects.toThrow(
      /^InResponseTo is missing from response$/,
    );
  });
});

describe("interop: IdP-initiated SSO with @better-auth/sso", () => {
  const spAuth = (metadata: string, allowIdpInitiated: boolean) =>
    betterAuth({
      baseURL: BA_SP_BASE,
      secret: "sp-secret-that-is-at-least-32-characters-long!!",
      database: memoryAdapter({ user: [], session: [], account: [], verification: [], ssoProvider: [] }),
      telemetry: { enabled: false },
      trustedOrigins: [BA_SP_BASE, "https://auth.test"],
      plugins: [
        sso({
          saml: { allowIdpInitiated },
          defaultSSO: [
            {
              domain: "example.com",
              providerId: "our-idp",
              samlConfig: {
                issuer: BA_SP_ISSUER,
                entryPoint: SSO_URL,
                idpMetadata: { metadata },
                callbackUrl: `${BA_SP_BASE}/dashboard`,
                idpInitiatedCallbackUrl: `${BA_SP_BASE}/launched`,
                wantAssertionsSigned: true,
              },
            },
          ],
        }),
      ],
    });

  async function launch(allowIdpInitiated: boolean) {
    const { auth, metadata } = await idp();
    const idpBrowser = new Browser(auth);
    const user = await idpBrowser.signUp();
    const form = await readAutoPost(await idpBrowser.fetch(init("better-auth-sso")));
    expect(form.action).toBe(BA_SP_ACS);
    expect(form.relayState).toBeUndefined();
    const sp = new Browser(spAuth(metadata, allowIdpInitiated));
    const acs = await sp.fetch(form.action, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", origin: "https://auth.test" },
      body: new URLSearchParams({ SAMLResponse: form.samlResponse }).toString(),
    });
    const session = (await (await sp.fetch(`${BA_SP_BASE}/api/auth/get-session`)).json()) as { user?: { email: string } } | null;
    return { user, acs, session };
  }

  it("signs the user in when the SP allows IdP-initiated SSO", async () => {
    const { user, acs, session } = await launch(true);
    expect([302, 303]).toContain(acs.status);
    expect(acs.headers.get("location")).toBe(`${BA_SP_BASE}/launched`);
    expect(session?.user?.email).toBe(user.email);
  });

  it("is rejected as unsolicited when the SP does not allow it", async () => {
    const { acs, session } = await launch(false);
    expect(acs.headers.get("location")).toContain("unsolicited_response");
    expect(session?.user).toBeUndefined();
  });
});
