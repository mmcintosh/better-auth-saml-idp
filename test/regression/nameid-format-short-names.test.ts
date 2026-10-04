// D-063 (found live with Google Workspace): `nameIdFormat` documented as `emailAddress`,
// `persistent` or `transient`, but compared as given against the URN in an AuthnRequest's
// NameIDPolicy. An SP configured as the README shows was refused with InvalidNameIDPolicy whenever
// it named its format, as Google Workspace always does ("Couldn't sign you in"). The refusal was
// also only logged at debug level, so nothing showed why.
import { afterEach, describe, expect, it, vi } from "vitest";
import { resolveOptions } from "../../src/options";
import { NAMEID_FORMAT } from "../../src/types";
import { baseOptions, SP_ACS, SP_ENTITY_ID } from "../support/config";
import { createHost } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, redirectUrl } from "../support/sp";

const statusOf = (xml: string) => [...xml.matchAll(/<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:([A-Za-z]+)"/g)].map((m) => m[1]);
const nameIdFormatOf = (xml: string) => /<saml:NameID [^>]*Format="([^"]+)"/.exec(xml)?.[1];

afterEach(() => vi.restoreAllMocks());

describe("D-063: nameIdFormat short names", () => {
  it("an SP set to \"emailAddress\" signs in an SP that asks for the emailAddress URN (Google Workspace)", async () => {
    const { auth } = await createHost({ saml: { serviceProviders: [{ id: "google", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], nameIdFormat: "emailAddress" }] } });
    const browser = new Browser(auth);
    await browser.signUp();
    const form = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml({ nameIdFormat: NAMEID_FORMAT.emailAddress }).xml)));
    expect(statusOf(form.xml)).toEqual(["Success"]);
    expect(nameIdFormatOf(form.xml)).toBe(NAMEID_FORMAT.emailAddress);
  });

  it("every short name stands for its URN", () => {
    for (const short of ["emailAddress", "persistent", "transient", "unspecified"] as const) {
      const [sp] = resolveOptions(baseOptions({ serviceProviders: [{ id: "sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], nameIdFormat: short }] })).serviceProviders;
      expect(sp!.nameIdFormat).toBe(NAMEID_FORMAT[short]);
    }
  });

  it("a full URN is kept, and anything else is kept with a warning (an SP stored that way still loads)", () => {
    const custom = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName";
    const r = resolveOptions(
      baseOptions({
        serviceProviders: [
          { id: "a", entityId: "https://a.test", acsUrls: ["https://a.test/acs"], nameIdFormat: custom },
          { id: "b", entityId: "https://b.test", acsUrls: ["https://b.test/acs"], nameIdFormat: "email" },
        ],
      }),
    );
    expect(r.serviceProviders.map((s) => s.nameIdFormat)).toEqual([custom, "email"]);
    expect(r.warnings).toEqual(expect.arrayContaining([expect.stringMatching(/serviceProviders\.1\.nameIdFormat: "email" isn't a NameID format/)]));
    expect(r.warnings.some((w) => w.includes("serviceProviders.0.nameIdFormat"))).toBe(false);
  });

  it("a SAML status refusal is logged as a warning, with its reason", async () => {
    const { auth } = await createHost({ saml: { serviceProviders: [{ id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS] }] } });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const browser = new Browser(auth);
    await browser.signUp();
    const form = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml({ nameIdFormat: NAMEID_FORMAT.persistent }).xml)));
    expect(statusOf(form.xml)).toEqual(["Responder", "InvalidNameIDPolicy"]);
    expect(warn.mock.calls.flat().join(" ")).toMatch(/SAML status Responder\/InvalidNameIDPolicy for SP test-sp: The requested NameID format is not available/);
  });
});
