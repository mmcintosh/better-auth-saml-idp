// Identity broker: one Better Auth instance runs @better-auth/sso (it *accepts* SAML sign-in from
// an upstream IdP, e.g. a customer's Okta) and this plugin (it *issues* SAML to downstream SPs).
// A user who signed in upstream reaches a downstream SP through the broker, end to end.
import { sso } from "@better-auth/sso";
import { SAML } from "@node-saml/node-saml";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { describe, expect, inject, it } from "vitest";
import { samlIdp } from "../../src/index";
import { AUTH_BASE, createHost } from "../support/host";
import { Browser, readAutoPost, SSO_URL } from "../support/sp";

const keys = inject("keys");

const BROKER = "https://broker.test";
const BROKER_AUTH = `${BROKER}/api/auth`;
const BROKER_SP_ISSUER = `${BROKER_AUTH}/sso/saml2/sp/metadata`;
const BROKER_ACS = `${BROKER_AUTH}/sso/saml2/sp/acs/upstream`;
const BROKER_IDP = `${BROKER_AUTH}/saml2/idp`;
const APP_ISSUER = "https://app.test/sp";
const APP_ACS = "https://app.test/acs";

async function setUp(brokerSaml: Record<string, unknown> = {}, opts: { trustProvider?: boolean } = {}) {
  // The upstream IdP (standing in for a customer's Okta): this plugin on the usual test host.
  const upstream = await createHost({
    saml: { serviceProviders: [{ id: "broker", entityId: BROKER_SP_ISSUER, acsUrls: [BROKER_ACS], attributes: (u) => ({ email: u.email, name: u.name }) }] },
  });
  const upstreamMetadata = await (await upstream.auth.handler(new Request(`${AUTH_BASE}/saml2/idp/metadata`))).text();

  // The broker vouches for addresses only from providers it trusts: this one asserts verified
  // addresses only. @better-auth/sso creates users unverified, so mark them on first sign-in.
  const brokerRef: { auth?: { $context: Promise<any> } } = {};
  const provisionUser = async ({ user, provider }: { user: { id: string }; provider: { providerId: string } }) => {
    if (provider.providerId !== "upstream") return;
    await (await brokerRef.auth!.$context).internalAdapter.updateUser(user.id, { emailVerified: true });
  };
  const broker = betterAuth({
    baseURL: BROKER,
    secret: "broker-secret-that-is-at-least-32-characters-long",
    database: memoryAdapter({ user: [], session: [], account: [], verification: [], ssoProvider: [], samlIdpSeenRequest: [] }),
    telemetry: { enabled: false },
    trustedOrigins: [BROKER, "https://auth.test"],
    plugins: [
      sso({
        ...(opts.trustProvider ? { provisionUser } : {}),
        defaultSSO: [
          {
            domain: "example.com",
            providerId: "upstream",
            samlConfig: {
              issuer: BROKER_SP_ISSUER,
              entryPoint: SSO_URL,
              idpMetadata: { metadata: upstreamMetadata },
              callbackUrl: `${BROKER}/`,
              wantAssertionsSigned: true,
            },
          },
        ],
      }),
      samlIdp({
        entityId: BROKER_IDP,
        baseURL: BROKER,
        loginPage: "/sign-in",
        signing: { privateKey: keys.idpNext.privateKey, certificate: keys.idpNext.certificate },
        serviceProviders: [{ id: "app", entityId: APP_ISSUER, acsUrls: [APP_ACS], attributes: (u) => ({ email: u.email }) }],
        ...brokerSaml,
      }),
    ],
  });

  const app = new SAML({
    issuer: APP_ISSUER,
    callbackUrl: APP_ACS,
    entryPoint: `${BROKER_IDP}/sso`,
    idpCert: keys.idpNext.certificate,
    audience: APP_ISSUER,
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: true,
    validateInResponseTo: "always" as any,
    acceptedClockSkewMs: 60_000,
    signatureAlgorithm: "sha256",
    // How the user authenticated is decided upstream; the app doesn't demand a class here.
    disableRequestedAuthnContext: true,
  });
  brokerRef.auth = broker as any;
  return { upstream, broker, app };
}

/** The downstream app → broker → (login page picks SSO) upstream → broker → app. */
async function brokeredSignIn(brokerSaml: Record<string, unknown> = {}, opts: { trustProvider?: boolean } = {}) {
  const { upstream, broker, app } = await setUp(brokerSaml, opts);
  const brokerBrowser = new Browser(broker);
  const upstreamBrowser = new Browser(upstream.auth);

  // 1. The app sends the user to the broker, who isn't signed in there: to the login page.
  const toLogin = await brokerBrowser.fetch(await app.getAuthorizeUrlAsync("app-relay", undefined, {}));
  expect(toLogin.status).toBe(302);
  const resume = new URL(toLogin.headers.get("location")!).searchParams.get("callbackURL")!;
  expect(resume).toContain(`${BROKER_IDP}/resume?rid=`);

  // 2. The broker's login page offers "sign in with your company": @better-auth/sso, coming
  //    back to the pending SAML request afterwards.
  const start = await brokerBrowser.fetch(`${BROKER_AUTH}/sign-in/sso`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: BROKER },
    body: JSON.stringify({ providerId: "upstream", callbackURL: resume }),
  });
  expect(start.status).toBe(200);
  const { url } = (await start.json()) as { url: string };

  // 3. Upstream: sign in, and its assertion goes back to the broker's ACS.
  const upstreamLogin = await upstreamBrowser.fetch(url);
  const upstreamResume = new URL(upstreamLogin.headers.get("location")!).searchParams.get("callbackURL")!;
  const user = await upstreamBrowser.signUp(`broker-${Date.now()}@example.com`);
  const toBroker = await readAutoPost(await upstreamBrowser.fetch(upstreamResume));
  expect(toBroker.action).toBe(BROKER_ACS);
  const acs = await brokerBrowser.fetch(toBroker.action, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", origin: "https://auth.test" },
    body: new URLSearchParams({ SAMLResponse: toBroker.samlResponse, ...(toBroker.relayState ? { RelayState: toBroker.relayState } : {}) }).toString(),
  });
  expect([302, 303]).toContain(acs.status);

  // 4. Back at the broker's pending request, now signed in: the broker issues to the app.
  return { app, user, brokerBrowser, acs, resume, broker };
}

describe("identity broker: @better-auth/sso upstream + this plugin downstream, one Better Auth", () => {
  it("sessions created by @better-auth/sso have an unverified email, so the default policy refuses them", async () => {
    const { brokerBrowser, resume } = await brokeredSignIn();
    const res = await brokerBrowser.fetch(resume);
    expect(/<code>([A-Z_]+)<\/code>/.exec(await res.text())?.[1]).toBe("EMAIL_NOT_VERIFIED");
  });

  it("recommended: the broker marks users from its trusted provider verified (provisionUser); the default policy holds", async () => {
    const { app, user, brokerBrowser, resume } = await brokeredSignIn({}, { trustProvider: true });
    const form = await readAutoPost(await brokerBrowser.fetch(resume));
    const { profile } = await app.validatePostResponseAsync({ SAMLResponse: form.samlResponse });
    expect(profile?.nameID).toBe(user.email);
  });

  it("or: the broker trusts every upstream address (accountPolicy), and the upstream user reaches the downstream app", async () => {
    // The upstream IdP only asserts verified addresses; the broker trusts that (documented choice).
    const { app, user, brokerBrowser, acs, resume } = await brokeredSignIn({ accountPolicy: { requireEmailVerified: false } });
    expect(acs.headers.get("location")).toBe(resume);
    const form = await readAutoPost(await brokerBrowser.fetch(resume));
    expect(form.action).toBe(APP_ACS);
    expect(form.relayState).toBe("app-relay");
    const { profile } = await app.validatePostResponseAsync({ SAMLResponse: form.samlResponse });
    expect(profile?.nameID).toBe(user.email);
    expect(profile?.issuer).toBe(BROKER_IDP);
  });
});
