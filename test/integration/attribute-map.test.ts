// Declarative attributes end to end: a strict SP reads what the map produced.
import { describe, expect, it } from "vitest";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { createHost } from "../support/host";
import { authnRequestXml, b64, Browser, readAutoPost, redirectUrl, strictSp } from "../support/sp";

async function issue(attributes: unknown, logs: string[] = []) {
  const { auth } = await createHost({
    saml: { serviceProviders: [{ id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], attributes: attributes as any }] },
    auth: { logger: { level: "warn", log: (_level: string, message: string) => logs.push(message) } },
  });
  const browser = new Browser(auth);
  await browser.signUp(undefined);
  const form = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)));
  return { form, parsed: await (await strictSp(auth)).verify(b64(form.xml)) };
}

describe("declarative attribute map", () => {
  it("fields, additional fields, name parts and constants reach the SP", async () => {
    const { parsed } = await issue({
      mail: "email",
      role: "role", // admin plugin's additional field
      verified: "emailVerified",
      givenName: { field: "name", part: "first" },
      org: { value: "Acme" },
      tiers: { value: ["gold", "a&b <c>"] },
    });
    expect(parsed.extract.attributes).toMatchObject({ role: "user", verified: "true", org: "Acme", tiers: ["gold", "a&b <c>"] });
    expect(parsed.extract.attributes!.mail).toMatch(/@example\.com$/);
    expect(typeof parsed.extract.attributes!.givenName).toBe("string");
  });

  it("a mapped field the user lacks is left out and warned about once", async () => {
    const logs: string[] = [];
    const { form } = await issue({ email: "email", dept: "department" }, logs);
    expect(form.xml).not.toContain('Name="dept"');
    expect(form.xml).toContain('Name="email"');
    expect(logs.filter((m) => /no field "department"/.test(m))).toHaveLength(1);
  });
});
