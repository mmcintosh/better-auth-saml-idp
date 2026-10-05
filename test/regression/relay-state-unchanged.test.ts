// External review of 1.1.2 (D-065): the POST form escaped RelayState as XML, which drops characters
// XML can't carry and rewrites line endings, so an opaque RelayState came back altered. The form now
// HTML-escapes it only, and a RelayState with control characters (which a browser's form submission
// would alter anyway) is refused at the door.
import { describe, expect, it } from "vitest";
import { autoPostResponse } from "../../src/saml/post-form";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { createHost } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, redirectUrl } from "../support/sp";

describe("D-065: RelayState comes back as it was sent", () => {
  it("characters outside XML's range, such as U+FFFD and U+2028, survive the form", async () => {
    const relayState = "a�b c<&>\"'";
    const html = await autoPostResponse("https://sp.test/acs", "UkVT", relayState).text();
    const value = /name="RelayState" value="([^"]*)"/.exec(html)![1]!;
    const decoded = value.replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n))).replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, "&");
    expect(decoded).toBe(relayState);
  });

  it("a RelayState with control characters is refused, not altered", async () => {
    const { auth } = await createHost({ saml: { serviceProviders: [{ id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS] }] } });
    const browser = new Browser(auth);
    await browser.signUp();
    const res = await browser.fetch(await redirectUrl(authnRequestXml().xml, { relayState: "a\u0001b\r\nc" }));
    expect(res.status).toBe(400);
    expect(await readAutoPost(res).catch(() => null)).toBeNull();
  });
});
