// Second review 4 report, R4-7: an AuthnRequest's <Subject><NameID> is copied into the parked request (a `verification` row)
// with no length limit of its own, so an unauthenticated sender can store nearly 64 KiB per request
// for `pendingRequestTtlSeconds` (10 minutes), 60× what the other parked fields allow (RelayState is
// capped at 1 KiB). SAML Core §8.3 bounds persistent and transient identifiers at 256 characters,
// and no NameID format the IdP issues exceeds an email address; a 1 KiB cap loses nothing.
import { describe, expect, it } from "vitest";
import { createHost } from "../support/host";
import { authnRequestXml, Browser, redirectUrl } from "../support/sp";

const code = async (res: Response) => /<code>([A-Z_]+)<\/code>/.exec(await res.clone().text())?.[1];

describe("R4-7: Subject NameID size", () => {
  it("refuses a Subject NameID far larger than any identifier the IdP could match", async () => {
    const { auth } = await createHost();
    const browser = new Browser(auth); // not signed in: the request is parked for login
    const nameId = "x".repeat(40_000);
    const res = await browser.fetch(await redirectUrl(authnRequestXml({ inner: `<saml:Subject><saml:NameID>${nameId}</saml:NameID></saml:Subject>` }).xml));
    expect(res.status).toBe(400); // today: 302 to the login page, with a ~40 KB verification row behind it
    expect(await code(res)).toBe("INVALID_SAML_REQUEST");
    const rows = (await (await auth.$context).adapter.findMany({ model: "verification" })) as { value: string }[];
    expect(rows.filter((r) => r.value.length > 4096)).toEqual([]);
  });
});
