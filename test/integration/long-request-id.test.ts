// Found live with Salesforce (D-042): its AuthnRequest IDs are ~300 characters, and the old
// 256-character cap refused every Salesforce sign-in with INVALID_SAML_REQUEST.
import { describe, expect, it } from "vitest";
import { parseLogoutRequest } from "../../src/saml/logout";
import { MAX_SAML_ID_LENGTH } from "../../src/saml/request";
import { libxml2Validator } from "../../src/saml/validator";
import { createHost } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, redirectUrl } from "../support/sp";

/** A real Salesforce AuthnRequest ID (Developer Edition, 2026-09-27): 296 characters. */
const SALESFORCE_ID =
  "_2CAAAAaF07lT8MDAwMDAwMDAwMDAwMDAwAAABBiVwyMk1fyk8K4y_quLTPGVAV7UM8ZErk2U7crXBmsr6if0LA1gDz537I5bQEPOKt6d7fCpvC0MYcN0Oy44u8g8RcaRL8qdaFGw4KYHHTiDgBbkpE2KVmQ333t_4lnyR0oXtce4_V3coXoDad7CFOR4V_wmmOz4hyu5yM_tdEqL4UPsdi1H5S_wLV1SJU5WtD5iZKUvOzhicd5rChb15zb8uMkVunuakspm0nnWwXtj5a8q8X6nexjkYkCUD3IxeQA";
const code = async (res: Response) => /<code>([A-Z_]+)<\/code>/.exec(await res.clone().text())?.[1];

describe("long SAML request IDs (Salesforce)", () => {
  it("the fixture is Salesforce's real length, over the old cap", () => {
    expect(SALESFORCE_ID.length).toBe(296);
  });

  it("Salesforce's ID signs in, and the Response answers it (InResponseTo)", async () => {
    const { auth } = await createHost();
    const browser = new Browser(auth);
    await browser.signUp();
    const { xml } = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml({ id: SALESFORCE_ID }).xml)));
    expect(xml).toContain(`InResponseTo="${SALESFORCE_ID}"`);
  });

  it(`an ID of exactly ${MAX_SAML_ID_LENGTH} is accepted; one more is refused`, async () => {
    const { auth } = await createHost();
    const browser = new Browser(auth);
    await browser.signUp();
    const longest = `_${"a".repeat(MAX_SAML_ID_LENGTH - 1)}`;
    const { xml } = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml({ id: longest }).xml)));
    expect(xml).toContain(`InResponseTo="${longest}"`);
    expect(await code(await browser.fetch(await redirectUrl(authnRequestXml({ id: `${longest}b` }).xml)))).toBe("INVALID_SAML_REQUEST");
  });

  it("LogoutRequests take the same IDs", async () => {
    const lr = (id: string) =>
      `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id}" Version="2.0" IssueInstant="2026-09-26T00:00:00Z" Destination="https://idp.test/slo">` +
      `<saml:Issuer>https://sp.test/metadata</saml:Issuer><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">a@b.test</saml:NameID>` +
      `<samlp:SessionIndex>_s</samlp:SessionIndex></samlp:LogoutRequest>`;
    const opts = { now: new Date("2026-09-26T00:00:30Z"), clockSkewSeconds: 60, sloUrl: "https://idp.test/slo" };
    expect((await parseLogoutRequest(lr(SALESFORCE_ID), libxml2Validator(), opts)).id).toBe(SALESFORCE_ID);
    await expect(parseLogoutRequest(lr(`_${"a".repeat(MAX_SAML_ID_LENGTH)}`), libxml2Validator(), opts)).rejects.toThrow(/oversized ID/);
  });
});
