// R4-2 (Medium): with Better Auth's cookie cache on and sessions only in secondary storage (KV),
// a revoked session still got assertions until the cache expired. The issuing endpoints now read
// the session store, not the cookie cache, and the pre-signing re-read covers secondary storage.
import { describe, expect, it } from "vitest";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { AUTH_BASE, createHost } from "../support/host";
import { authnRequestXml, Browser, redirectUrl } from "../support/sp";

const SP = { id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS] as [string], allowIdpInitiated: true };
const hasAssertion = async (res: Response) => /name="SAMLResponse"/.test(await res.clone().text());

function kv() {
  const m = new Map<string, string>();
  return {
    get: async (k: string) => m.get(k) ?? null,
    set: async (k: string, v: string) => void m.set(k, v),
    delete: async (k: string) => void m.delete(k),
  };
}

async function revokedButCached(storeSessionInDatabase: boolean) {
  const { auth } = await createHost({
    saml: { serviceProviders: [SP] },
    auth: { secondaryStorage: kv(), session: { storeSessionInDatabase, cookieCache: { enabled: true, maxAge: 300 } } },
    cloudflare: { geolocationTracking: false },
  });
  const browser = new Browser(auth);
  await browser.signUp();
  await browser.fetch(`${AUTH_BASE}/get-session`); // populate the cache cookie
  expect(browser.cookieHeader()).toMatch(/session_data/);
  // Revoke the way sign-out, admin revocation or SLO would.
  const token = decodeURIComponent(/better-auth\.session_token=([^;.]+)/.exec(browser.cookieHeader())![1]!);
  await ((await auth.$context) as any).internalAdapter.deleteSession(token);
  return browser;
}

describe("R4-2: revoked between reading the session and signing", () => {
  it("the re-read right before signing sees secondary storage, not just the database", async () => {
    // A store that revokes the session right after its first read: the endpoint's session read
    // succeeds, and only the pre-signing re-read can notice.
    const m = new Map<string, string>();
    let armed: string | undefined;
    const store = {
      get: async (k: string) => {
        const v = m.get(k) ?? null;
        if (armed && k === armed) {
          m.delete(k);
          armed = undefined;
        }
        return v;
      },
      set: async (k: string, v: string) => void m.set(k, v),
      delete: async (k: string) => void m.delete(k),
    };
    const { auth } = await createHost({ saml: { serviceProviders: [SP] }, auth: { secondaryStorage: store }, cloudflare: { geolocationTracking: false } });
    const browser = new Browser(auth);
    await browser.signUp();
    const token = decodeURIComponent(/better-auth\.session_token=([^;.]+)/.exec(browser.cookieHeader())![1]!);
    expect(m.has(token)).toBe(true);
    armed = token;
    const res = await browser.fetch(await redirectUrl(authnRequestXml().xml));
    expect(await hasAssertion(res)).toBe(false);
    expect(/<code>([A-Z_]+)<\/code>/.exec(await res.text())?.[1]).toBe("ACCOUNT_INACTIVE");
  });
});

describe("R4-2: a revoked session gets no assertion, whatever the cookie cache says", () => {
  for (const storeSessionInDatabase of [false, true])
    describe(`sessions in secondary storage${storeSessionInDatabase ? " and the database" : " only"}`, () => {
      it("SP-initiated SSO sends the user to sign in", async () => {
        const browser = await revokedButCached(storeSessionInDatabase);
        const res = await browser.fetch(await redirectUrl(authnRequestXml().xml));
        expect(await hasAssertion(res)).toBe(false);
        expect(res.status).toBe(302);
      });

      it("IdP-initiated SSO sends the user to sign in", async () => {
        const browser = await revokedButCached(storeSessionInDatabase);
        const res = await browser.fetch(`${AUTH_BASE}/saml2/idp/init?sp=test-sp`);
        expect(await hasAssertion(res)).toBe(false);
      });
    });
});
