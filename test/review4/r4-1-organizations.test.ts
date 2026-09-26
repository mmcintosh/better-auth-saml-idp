// R4-1 (High): organization slugs and names are chosen by whoever creates the organization, and
// by default any user can. `only` limits organization attributes to known organizations, rules
// by id can't be claimed, and a warning names what could be.
import { organization } from "better-auth/plugins";
import { describe, expect, it } from "vitest";
import { claimableOrganizationUse } from "../../src/organizations";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { AUTH_BASE, createHost, isWorkerd } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, redirectUrl } from "../support/sp";

const SP = { id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS] as [string] };
const code = async (res: Response) => /<code>([A-Z_]+)<\/code>/.exec(await res.clone().text())?.[1];
const values = (xml: string, name: string) =>
  [...(new RegExp(`Name="${name}"[^>]*>(.*?)</saml:Attribute>`, "s").exec(xml)?.[1] ?? "").matchAll(/<saml:AttributeValue>([^<]*)</g)].map((m) => m[1]);

async function createOrg(browser: Browser, slug: string) {
  const res = await browser.fetch(`${AUTH_BASE}/organization/create`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name: slug.toUpperCase(), slug }),
  });
  expect(res.status, await res.clone().text()).toBe(200);
  return ((await res.json()) as { id: string }).id;
}

describe.skipIf(isWorkerd)("R4-1: user-created organizations can't satisfy what the host meant for real ones", () => {
  it("attributes with `only` carry only the listed organizations, not ones the user made", async () => {
    const { auth } = await createHost({
      plugins: [organization()],
      saml: {
        serviceProviders: [
          {
            ...SP,
            attributes: {
              groups: { organization: "slugs", only: ["acme"] },
              orgRoles: { organization: "roles", only: ["acme"] },
              everything: { organization: "slugs" }, // no allow-list: what R4-1 exploited
            },
          },
        ],
      },
    });
    const admin = new Browser(auth);
    await admin.signUp();
    const acme = await createOrg(admin, "acme");
    const user = new Browser(auth);
    const u = await user.signUp();
    const ctx = await auth.$context;
    await ctx.adapter.create({ model: "member", data: { organizationId: acme, userId: u.id, role: "member", createdAt: new Date() } });
    await createOrg(user, "sp-admins"); // the claim
    const { xml } = await readAutoPost(await user.fetch(await redirectUrl(authnRequestXml().xml)));
    expect(values(xml, "groups")).toEqual(["acme"]);
    expect(values(xml, "orgRoles")).toEqual(["acme:member"]);
    expect(values(xml, "everything").sort()).toEqual(["acme", "sp-admins"]); // documented: unfiltered is claimable
  });

  it("a rule by id can't be satisfied by creating an organization with the same slug", async () => {
    const { auth } = await createHost({ plugins: [organization()], saml: { serviceProviders: [{ ...SP, organization: { id: "org_real_acme" } }] } });
    const attacker = new Browser(auth);
    await attacker.signUp();
    await createOrg(attacker, "acme");
    expect(await code(await attacker.fetch(await redirectUrl(authnRequestXml().xml)))).toBe("ACCESS_DENIED");
  });

  it("warns when users can create organizations and an SP relies on something claimable; not when they can't", async () => {
    const run = async (orgOptions: Parameters<typeof organization>[0], sp: Record<string, unknown>) => {
      const logs: string[] = [];
      await createHost({
        plugins: [organization(orgOptions)],
        saml: { serviceProviders: [{ ...SP, id: `sp-${Math.random().toString(36).slice(2)}`, ...sp }] },
        auth: { logger: { level: "warn", log: (_l: string, m: string) => logs.push(m) } },
      }).then(({ auth }) => auth.$context);
      return logs.filter((m) => /users can create organizations/.test(m));
    };
    expect(await run({}, { organization: { slug: "acme" } })).toHaveLength(1);
    expect(await run({}, { attributes: { groups: { organization: "slugs" } } })).toHaveLength(1);
    expect(await run({ allowUserToCreateOrganization: false }, { organization: { slug: "acme" } })).toHaveLength(0);
    expect(await run({}, { organization: { id: "org_1" }, attributes: { groups: { organization: "slugs", only: ["org_1"] } } })).toHaveLength(0);
  });
});

describe("R4-1: what counts as claimable", () => {
  it("slug rules and unfiltered organization attributes; not id rules or `only` lists", () => {
    expect(claimableOrganizationUse({ organization: { slug: "acme" } })).toHaveLength(1);
    expect(claimableOrganizationUse({ organization: { id: "o1" } })).toEqual([]);
    expect(claimableOrganizationUse({ attributeMap: { g: { organization: "names" }, e: "email" } })).toHaveLength(1);
    expect(claimableOrganizationUse({ attributeMap: { g: { organization: "names", only: ["o1"] } } })).toEqual([]);
  });
});
