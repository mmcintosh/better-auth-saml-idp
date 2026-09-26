// R4-L9 (Low): attribute maps can read additional user fields, which Better Auth lets users set
// themselves by default (input: true). The SP would then trust a value the user chose.
import { describe, expect, it } from "vitest";
import { userWritableMappedFields } from "../../src/attributes";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { AUTH_BASE, BASE_URL, createHost, isWorkerd } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, redirectUrl } from "../support/sp";

describe("R4-L9: user-writable mapped fields", () => {
  it("are found: additional fields without input: false; not core fields or input: false", () => {
    const fields = { department: { type: "string" }, costCenter: { type: "string", input: false } };
    expect(userWritableMappedFields({ d: "department", c: { field: "costCenter" }, e: "email", n: { field: "name", part: "first" } }, fields)).toEqual(["department"]);
    expect(userWritableMappedFields({ e: "email" }, undefined)).toEqual([]);
  });

  it.skipIf(isWorkerd)("are warned about at startup; the user really can set them, and input: false stops that", async () => {
    const run = async (input: boolean | undefined) => {
      const logs: string[] = [];
      const { auth } = await createHost({
        saml: { serviceProviders: [{ id: `sp-${input}`, entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], attributes: { dept: "department" } }] },
        auth: {
          user: { additionalFields: { department: { type: "string", required: false, ...(input === undefined ? {} : { input }) } } },
          logger: { level: "warn", log: (_l: string, m: string) => logs.push(m) },
        },
      });
      const browser = new Browser(auth);
      await browser.signUp();
      await browser.fetch(`${AUTH_BASE}/update-user`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: BASE_URL },
        body: JSON.stringify({ department: "Payroll Admins" }),
      });
      const { xml } = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)));
      return { warned: logs.some((m) => /the user can change themselves \(department\)/.test(m)), sent: xml.includes("Payroll Admins") };
    };
    expect(await run(undefined)).toEqual({ warned: true, sent: true });
    expect(await run(false)).toEqual({ warned: false, sent: false });
  });
});
