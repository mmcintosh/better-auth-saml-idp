// Second review 4 report, R4-4: `{ organization: "names" | "slugs" | "ids" }` attribute sources send EVERY organization the
// user belongs to, and Better Auth's organization plugin lets any user create organizations by
// default (`allowUserToCreateOrganization: true`), becoming their owner. So a user can put any
// group name they like into their own assertion: create an organization called "Administrators"
// (names aren't unique) and every SP that maps groups from organization names receives it. Roles
// are already scoped to the SP's organization (D-031); slugs, names and ids should be too when the
// SP has one, and the unscoped form should be documented as user-controlled unless organization
// creation is restricted.
import { organization } from "better-auth/plugins";
import { describe, expect, it } from "vitest";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { AUTH_BASE, createHost, isWorkerd } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, redirectUrl } from "../support/sp";

const values = (xml: string, name: string) =>
  [...(new RegExp(`<saml:Attribute Name="${name}"[^>]*>([\\s\\S]*?)</saml:Attribute>`).exec(xml)?.[1] ?? "").matchAll(/<saml:AttributeValue>([^<]*)</g)].map((m) => m[1]).sort();

describe.skipIf(isWorkerd)("R4-4: organization attributes are user-controlled group claims", () => {
  it("an SP scoped to an organization doesn't receive organizations the user created for themselves", async () => {
    const { auth } = await createHost({
      plugins: [organization()],
      saml: {
        serviceProviders: [
          { id: "sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], organization: { slug: "acme" }, attributes: { groups: { organization: "names" }, groupSlugs: { organization: "slugs" }, groupIds: { organization: "ids" } } },
        ],
      },
    });
    const ctx = (await auth.$context) as any;
    const browser = new Browser(auth);
    const user = await browser.signUp();
    // The host's admin created acme and added the user as a plain member.
    const acme = await ctx.adapter.create({ model: "organization", data: { name: "Acme", slug: "acme", createdAt: new Date() } });
    await ctx.adapter.create({ model: "member", data: { organizationId: acme.id, userId: user.id, role: "member", createdAt: new Date() } });
    // The user, through the organization plugin's own API and its default policy, creates one named like a privileged group.
    const created = await browser.fetch(`${AUTH_BASE}/organization/create`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "Administrators", slug: "administrators" }),
    });
    expect(created.status).toBe(200);

    const { xml } = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)));
    // Today: ["Acme", "Administrators"], ["acme", "administrators"], both ids.
    expect(values(xml, "groups")).toEqual(["Acme"]);
    expect(values(xml, "groupSlugs")).toEqual(["acme"]);
    expect(values(xml, "groupIds")).toEqual([acme.id]);
  });
});
