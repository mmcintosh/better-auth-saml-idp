// External review of 1.1.2 (D-065): events and the audit log took the left-most X-Forwarded-For
// entry, unvalidated, which any client can set. Better Auth itself refuses a multi-value header
// without trustedProxies, and checks the format. The plugin now reads the IP the way it does.
import { describe, expect, it, vi } from "vitest";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { createHost } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, redirectUrl } from "../support/sp";

/** The IP header the test host reads (cf-connecting-ip), set by the client. */
async function issuedIp(xff: string) {
  const events: { ipAddress?: string }[] = [];
  const { auth } = await createHost({
    saml: { serviceProviders: [{ id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS] }], events: { onAssertionIssued: (e) => void events.push(e) } },
  });
  const browser = new Browser(auth);
  await browser.signUp();
  await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml), { headers: { "cf-connecting-ip": xff } }));
  await vi.waitFor(() => expect(events).toHaveLength(1));
  return events[0]!.ipAddress;
}

describe("D-065: the event IP is read the way Better Auth reads it", () => {
  it("a client-supplied chain isn't trusted without trustedProxies", async () => {
    expect(await issuedIp("203.0.113.9, 198.51.100.7")).not.toBe("203.0.113.9");
  });
  it("a value that isn't an IP is never recorded", async () => {
    expect(await issuedIp("not-an-ip <b>x</b>")).toBeUndefined();
  });
  it("a single, valid IP is recorded", async () => {
    expect(await issuedIp("203.0.113.9")).toBe("203.0.113.9");
  });
});
