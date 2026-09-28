// Second review 4 report, R4-3: D-038 and docs/guide/observability.md say the audit table can't be grown at will because
// refusals that name neither an SP nor a user aren't stored. But a refusal that names a *public*
// SP is stored even when nobody is signed in and nothing was signed: `GET /saml2/idp/init?sp=<id>`
// for any SP without allowIdpInitiated (`IDP_INITIATED_NOT_ALLOWED`), or an unsigned AuthnRequest
// naming a registered Issuer with an unregistered ACS URL (`ACS_URL_NOT_ALLOWED`). SP ids and entity
// IDs are public (they're in every SP's metadata and login link), so anyone can add a row per
// request, each carrying their chosen User-Agent, until the retention sweep 90 days later.
import { describe, expect, it } from "vitest";
import { AUDIT_MODEL } from "../../src/events";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { AUTH_BASE, createHost } from "../support/host";
import { authnRequestXml, Browser, redirectUrl } from "../support/sp";

const code = async (res: Response) => /<code>([A-Z_]+)<\/code>/.exec(await res.clone().text())?.[1];

describe("R4-3: audit-log growth from unauthenticated requests", () => {
  it("a refusal that names an SP but no user, from an unauthenticated and unsigned request, isn't stored", async () => {
    const { auth } = await createHost({ saml: { auditLog: { enabled: true }, serviceProviders: [{ id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS] }] } });
    const browser = new Browser(auth); // never signs in
    for (let i = 0; i < 5; i++) {
      const init = await browser.fetch(`${AUTH_BASE}/saml2/idp/init?sp=test-sp`);
      expect(await code(init)).toBe("IDP_INITIATED_NOT_ALLOWED");
      const sso = await browser.fetch(await redirectUrl(authnRequestXml({ acsUrl: "https://sp.test/not-registered" }).xml));
      expect(await code(sso)).toBe("ACS_URL_NOT_ALLOWED");
    }
    await new Promise((r) => setTimeout(r, 300)); // the writes run in the background
    const rows = (await (await auth.$context).adapter.findMany({ model: AUDIT_MODEL })) as { code: string | null; userId: string | null; spId: string | null }[];
    // Today: 10 rows, all spId "test-sp", userId null.
    expect(rows.filter((r) => r.userId === null)).toEqual([]);
  });
});
