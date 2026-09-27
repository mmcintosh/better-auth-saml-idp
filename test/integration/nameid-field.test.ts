// Roadmap D4: `nameId: { field }` for code and stored SPs, refused for fields users can set.
import { describe, expect, it } from "vitest";
import { nameIdFieldProblem, nameIdFromField } from "../../src/nameid";
import { resolveOptions, resolveStoredServiceProvider, SamlIdpConfigError } from "../../src/options";
import { baseOptions, SP_ACS, SP_ENTITY_ID } from "../support/config";
import { AUTH_BASE, BASE_URL, createHost, isWorkerd } from "../support/host";
import { authnRequestXml, Browser, readAutoPost, redirectUrl } from "../support/sp";

const nameIdOf = (xml: string) => /<saml:NameID[^>]*>([^<]*)<\/saml:NameID>/.exec(xml)?.[1];
const code = async (res: Response) => /<code>([A-Z_]+)<\/code>/.exec(await res.clone().text())?.[1];

describe("nameIdFieldProblem: only fields users can't set", () => {
  const plugins = [{ schema: { user: { fields: { role: { type: "string", input: false }, nickname: { type: "string" } } } } }];
  const additionalFields = { employeeId: { type: "string", input: false }, department: { type: "string" } };
  it.each([
    ["id", undefined],
    ["email", undefined],
    ["employeeId", undefined],
    ["role", undefined], // a plugin field with input: false (the admin plugin's role)
    ["department", /users can set themselves/],
    ["nickname", /users can set themselves/],
    ["name", /not a user field this server can vouch for/], // core, editable through /update-user
    ["image", /not a user field this server can vouch for/],
    ["unknownField", /not a user field this server can vouch for/],
  ])("%s", (field, problem) => {
    const p = nameIdFieldProblem(field, { user: { additionalFields }, plugins });
    if (problem === undefined) expect(p).toBeUndefined();
    else expect(p).toMatch(problem);
  });

  it("a field declared twice counts as writable if either declaration allows input", () => {
    expect(nameIdFieldProblem("role", { user: { additionalFields: { role: { input: true } } }, plugins })).toMatch(/users can set themselves/);
  });
});

describe("nameIdFromField", () => {
  const user = { id: "u1", email: "a@x.test", name: "A", emailVerified: true, createdAt: new Date(), updatedAt: new Date() } as any;
  it.each([
    [" E-042 ", "E-042"],
    [42, "42"],
    ["", ""],
    [null, ""],
    [undefined, ""],
    [Number.NaN, ""],
    [{ a: 1 }, ""],
    [new Date(0), ""],
  ])("%s → %j", (value, want) => {
    expect(nameIdFromField({ ...user, f: value }, "f")).toBe(want);
  });
});

describe("options: nameId { field }", () => {
  const sp = (nameId: unknown) => ({ id: "s", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], nameId });
  it("code SPs take a function or { field }; stored SPs take { field }", () => {
    expect(resolveOptions(baseOptions({ serviceProviders: [sp({ field: "employeeId" }) as any] })).serviceProviders[0]!.nameIdField).toBe("employeeId");
    expect(resolveOptions(baseOptions({ serviceProviders: [sp(() => "x") as any] })).serviceProviders[0]!.nameIdField).toBeUndefined();
    const stored = resolveStoredServiceProvider(sp({ field: "employeeId" }), resolveOptions(baseOptions()));
    expect(stored.issues).toEqual([]);
    expect(stored.serviceProvider?.nameIdField).toBe("employeeId");
  });

  it("rejects bad shapes", () => {
    expect(() => resolveOptions(baseOptions({ serviceProviders: [sp({ field: "bad field" }) as any] }))).toThrow(/nameId/);
    expect(() => resolveOptions(baseOptions({ serviceProviders: [sp({ field: "id", lower: true }) as any] }))).toThrow(/nameId/);
    expect(resolveStoredServiceProvider(sp("id"), resolveOptions(baseOptions())).issues.join()).toMatch(/nameId/);
  });
});

describe("NameID from a field, end to end", () => {
  it("the user id (a core field users can't change)", async () => {
    const { auth } = await createHost({ saml: { serviceProviders: [{ id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], nameId: { field: "id" } }] } });
    const browser = new Browser(auth);
    const user = await browser.signUp();
    const { xml } = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)));
    expect(nameIdOf(xml)).toBe(user.id);
  });

  it("a code SP naming a user-writable field stops startup", async () => {
    await expect(
      (async () => {
        const { auth } = await createHost({ saml: { serviceProviders: [{ id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], nameId: { field: "name" } }] } });
        await auth.$context;
        await auth.handler(new Request(`${AUTH_BASE}/saml2/idp/metadata`));
      })(),
    ).rejects.toThrow(SamlIdpConfigError);
  });

  it.skipIf(isWorkerd)("an additional field with input: false; a user without a value is denied", async () => {
    const { auth } = await createHost({
      saml: { serviceProviders: [{ id: "test-sp", entityId: SP_ENTITY_ID, acsUrls: [SP_ACS], nameId: { field: "employeeId" } }] },
      auth: { user: { additionalFields: { employeeId: { type: "string", required: false, input: false } } } },
    });
    const browser = new Browser(auth);
    const user = await browser.signUp();
    expect(await code(await browser.fetch(await redirectUrl(authnRequestXml().xml)))).toBe("ACCESS_DENIED");
    const ctx = await auth.$context;
    await ctx.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { employeeId: "E-042" } });
    const { xml } = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml().xml)));
    expect(nameIdOf(xml)).toBe("E-042");
  });

  describe("stored SPs", () => {
    const canManage = ({ user }: { user: Record<string, unknown> }) => user.role === "admin";
    async function adminHost() {
      const { auth } = await createHost({
        saml: { serviceProviders: [], registry: { enabled: true, canManage, cacheSeconds: 0 } as any },
      });
      const browser = new Browser(auth);
      const user = await browser.signUp();
      const ctx = await auth.$context;
      await ctx.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { role: "admin" } });
      const api = (path: string, body: unknown) =>
        browser.fetch(`${AUTH_BASE}/saml-idp/service-providers${path}`, {
          method: "POST",
          headers: { "content-type": "application/json", origin: BASE_URL },
          body: JSON.stringify(body),
        });
      return { auth, browser, user, ctx, api };
    }
    const tag = () => Math.random().toString(36).slice(2, 8);

    it("the registry refuses a user-writable field, and accepts a safe one", async () => {
      const { api, browser, user } = await adminHost();
      const id = `n${tag()}`;
      const sp = (field: string) => ({ id, entityId: `https://${id}.test/sp`, acsUrls: [`https://${id}.test/acs`], nameId: { field } });
      const bad = await api("/create", { serviceProvider: sp("name") });
      expect(bad.status).toBe(400);
      expect(((await bad.json()) as any).issues.join()).toMatch(/nameId.field "name"/);
      expect((await api("/create", { serviceProvider: sp("id") })).status).toBe(200);
      const { xml } = await readAutoPost(await browser.fetch(await redirectUrl(authnRequestXml({ issuer: `https://${id}.test/sp`, acsUrl: `https://${id}.test/acs` }).xml)));
      expect(nameIdOf(xml)).toBe(user.id);
    });

    it("a stored row with an unsafe field (edited by hand) is reported invalid and never issues", async () => {
      const { api, browser, ctx } = await adminHost();
      const id = `n${tag()}`;
      const sp = { id, entityId: `https://${id}.test/sp`, acsUrls: [`https://${id}.test/acs`], nameId: { field: "id" } };
      expect((await api("/create", { serviceProvider: sp })).status).toBe(200);
      await ctx.adapter.update({ model: "samlIdpServiceProvider", where: [{ field: "spId", value: id }], update: { config: JSON.stringify({ ...sp, nameId: { field: "name" } }) } });
      const got = (await (await browser.fetch(`${AUTH_BASE}/saml-idp/service-providers/get?id=${id}`)).json()) as any;
      expect(got.serviceProvider.valid).toBe(false);
      expect(got.serviceProvider.issues.join()).toMatch(/nameId.field "name"/);
      const res = await browser.fetch(await redirectUrl(authnRequestXml({ issuer: sp.entityId, acsUrl: sp.acsUrls[0] }).xml));
      expect(await code(res)).toBe("INTERNAL_ERROR");
      expect(await res.clone().text()).not.toContain("SAMLResponse");
    });
  });
});
