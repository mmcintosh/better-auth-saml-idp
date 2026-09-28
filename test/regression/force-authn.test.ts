// R4-L5 (Low): with ForceAuthn, the host's login page got no signal. A page that sends signed-in
// users straight to callbackURL (as the guide describes) turned every ForceAuthn request into
// REAUTHENTICATION_REQUIRED. The login URL now carries prompt=login.
import { describe, expect, it } from "vitest";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { createHost } from "../support/host";
import { authnRequestXml, Browser, redirectUrl } from "../support/sp";

describe("R4-L5: ForceAuthn tells the login page to ask for credentials", () => {
  it("prompt=login with ForceAuthn, signed in or not; absent otherwise", async () => {
    const { auth } = await createHost({ saml: { serviceProviders: [{ id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS] }] } });
    const login = async (b: Browser, forceAuthn: boolean) => new URL((await b.fetch(await redirectUrl(authnRequestXml({ forceAuthn }).xml))).headers.get("location")!);
    const anonymous = new Browser(auth);
    expect((await login(anonymous, true)).searchParams.get("prompt")).toBe("login");
    expect((await login(anonymous, false)).searchParams.get("prompt")).toBeNull();
    const signedIn = new Browser(auth);
    await signedIn.signUp();
    const url = await login(signedIn, true);
    expect(url.searchParams.get("prompt")).toBe("login");
    expect(url.searchParams.get("callbackURL")).toMatch(/\/saml2\/idp\/resume\?rid=/);
  });
});
