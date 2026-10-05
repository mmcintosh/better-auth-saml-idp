// External review of 1.1.2 (D-065): /saml2/idp/init answered an unknown SP id and one that hasn't
// opted in to IdP-initiated SSO differently, so anyone could list the SP ids. Both now get the same
// answer (the difference stays in the logs and onDenied). An opted-in SP stays observable: that's
// what opting in means, and the docs say so.
import { expect, it } from "vitest";
import { AUTH_BASE, createHost } from "../support/host";
import { Browser } from "../support/sp";

it("an unknown SP id and a known one that hasn't opted in get the same answer", async () => {
  const { auth } = await createHost({ saml: { serviceProviders: [{ id: "known", entityId: "https://known.test/sp", acsUrls: ["https://known.test/acs"] }] } });
  const browser = new Browser(auth);
  const answer = async (sp: string) => {
    const res = await browser.fetch(`${AUTH_BASE}/saml2/idp/init?sp=${sp}`);
    return [res.status, /<code>([A-Z_]+)<\/code>/.exec(await res.text())?.[1]];
  };
  expect(await answer("known")).toEqual(await answer("unknown"));
});
