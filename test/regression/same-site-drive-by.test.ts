// R4-L4 (Low): the sign-out-everywhere drive-by check only looked at `Sec-Fetch-Site: cross-site`,
// so a sibling subdomain (same-site) could sign the user out of every SP without a click.
import { describe, expect, it } from "vitest";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { AUTH_BASE, createHost } from "../support/host";
import { Browser } from "../support/sp";

const nav = (site: string, user?: boolean) => ({
  "sec-fetch-site": site,
  "sec-fetch-mode": "navigate",
  "sec-fetch-dest": "document",
  ...(user ? { "sec-fetch-user": "?1" } : {}),
});

describe("R4-L4: same-site drive-bys get the confirmation page too", () => {
  it("logout: cross-site and same-site without a click confirm; same-origin, typed and clicked go through", async () => {
    const { auth } = await createHost({ saml: { singleLogout: { enabled: true }, serviceProviders: [{ id: "a", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS] }] } });
    const signedIn = async (b: Browser) => (await (await b.fetch(`${AUTH_BASE}/get-session`)).json()) !== null;
    const logout = async (headers: Record<string, string>) => {
      const b = new Browser(auth);
      await b.signUp();
      const res = await b.fetch(`${AUTH_BASE}/saml2/idp/logout?returnTo=/`, { headers });
      return { status: res.status, stillSignedIn: await signedIn(b) };
    };
    expect(await logout(nav("cross-site"))).toEqual({ status: 200, stillSignedIn: true });
    expect(await logout(nav("same-site"))).toEqual({ status: 200, stillSignedIn: true });
    for (const h of [nav("same-origin"), nav("none"), nav("same-site", true), nav("cross-site", true)])
      expect(await logout(h)).toEqual({ status: 302, stillSignedIn: false });
  });
});
