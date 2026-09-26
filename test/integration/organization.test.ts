// Organization plugin integration (D-031). Node only: the organization plugin adds tables and a
// session column the workerd D1 test schema doesn't carry; the code path is the same adapter calls.
import { organization } from "better-auth/plugins";
import { describe, expect, it, vi } from "vitest";
import { SP_ACS, SP_ENTITY_ID } from "../support/config";
import { createHost, isWorkerd } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, redirectUrl } from "../support/sp";

async function host(sp: Record<string, unknown>, o: { withPlugin?: boolean; authorize?: (c: any) => boolean; onDenied?: (e: any) => void } = {}) {
  const { auth } = await createHost({
    plugins: o.withPlugin === false ? [] : [organization()],
    saml: {
      serviceProviders: [{ id: "sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], ...(o.authorize ? { authorize: o.authorize } : {}), ...sp } as any],
      ...(o.onDenied ? { events: { onDenied: o.onDenied } } : {}),
    },
  });
  const ctx = (await auth.$context) as any;
  const browser = new Browser(auth);
  const user = await browser.signUp();
  const org = async (slug: string, role: string, name = slug.toUpperCase()) => {
    const o = await ctx.adapter.create({ model: "organization", data: { name, slug, createdAt: new Date() } });
    await ctx.adapter.create({ model: "member", data: { organizationId: o.id, userId: user.id, role, createdAt: new Date() } });
    return o;
  };
  return { browser, org };
}
const sso = async (browser: Browser) => browser.fetch(await redirectUrl(authnRequestXml().xml));
const code = async (res: Response) => /<code>([A-Z_]+)<\/code>/.exec(await res.clone().text())?.[1];

describe.skipIf(isWorkerd)("organization plugin", () => {
  it("an SP limited to an organization admits its members only", async () => {
    const { browser, org } = await host({ organization: { slug: "acme" } });
    expect(await code(await sso(browser))).toBe("ACCESS_DENIED");
    await org("acme", "member");
    expect((await sso(browser)).status).toBe(200);
  });

  it("…and, with roles, only members holding one of them (multi-role members too)", async () => {
    const { browser, org } = await host({ organization: { slug: "acme", roles: ["admin"] } });
    await org("acme", "member");
    expect(await code(await sso(browser))).toBe("ACCESS_DENIED");
    const { browser: b2, org: org2 } = await host({ organization: { slug: "acme", roles: ["admin"] } });
    await org2("acme", "member,admin");
    expect((await sso(b2)).status).toBe(200);
  });

  it("organization attributes: with a rule, the SP's organization only, unless `only` lists more (review 4)", async () => {
    const { browser, org } = await host({
      organization: { slug: "acme" },
      attributes: {
        email: "email",
        groups: { organization: "slugs" },
        orgNames: { organization: "names" },
        roles: { organization: "roles" },
        partners: { organization: "slugs", only: ["acme", "globex"] },
      },
    });
    await org("acme", "admin,member");
    await org("globex", "owner");
    await org("administrators", "owner"); // one the user could have created themselves
    const { xml } = await readAutoPost(await sso(browser));
    const values = (name: string) => [...new RegExp(`<saml:Attribute Name="${name}"[^>]*>([\\s\\S]*?)</saml:Attribute>`).exec(xml)![1]!.matchAll(/<saml:AttributeValue>([^<]*)</g)].map((m) => m[1]);
    expect(values("groups")).toEqual(["acme"]);
    expect(values("orgNames")).toEqual(["ACME"]);
    expect(values("roles").sort()).toEqual(["admin", "member"]);
    expect(values("partners").sort()).toEqual(["acme", "globex"]);
  });

  it("without an organization rule, roles are qualified by organization", async () => {
    const { browser, org } = await host({ attributes: { roles: { organization: "roles" } } });
    await org("acme", "admin");
    await org("globex", "owner");
    const { xml } = await readAutoPost(await sso(browser));
    expect([...xml.matchAll(/<saml:AttributeValue>([^<]*)</g)].map((m) => m[1]).sort()).toEqual(["acme:admin", "globex:owner"]);
  });

  it("authorize() receives the memberships", async () => {
    let seen: any;
    const { browser, org } = await host({}, {
      authorize: (c) => {
        seen = c.organizations;
        return true;
      },
    });
    await org("acme", "member");
    await sso(browser);
    expect(seen).toEqual([expect.objectContaining({ slug: "acme", name: "ACME", roles: ["member"] })]);
  });

  it("an SP that requires an organization fails closed without the organization plugin", async () => {
    // Without the plugin, memberships are empty and the rule would deny anyway; check that it's
    // the explicit guard that refuses, so the guard can't be removed unnoticed (review 4).
    const details: string[] = [];
    const { browser } = await host({ organization: { slug: "acme" } }, { withPlugin: false, onDenied: (e) => void details.push(e.detail ?? "") });
    expect(await code(await sso(browser))).toBe("ACCESS_DENIED");
    await vi.waitFor(() => expect(details.join(" ")).toMatch(/organization plugin isn't installed/));
  });

  it("the rule needs exactly one of slug and id", async () => {
    await expect(host({ organization: { roles: ["admin"] } })).rejects.toThrow(/exactly one of slug and id/);
    await expect(host({ organization: { slug: "a", id: "b" } })).rejects.toThrow(/exactly one of slug and id/);
  });
});
