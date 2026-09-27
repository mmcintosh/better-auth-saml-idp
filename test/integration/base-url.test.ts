// API decision 6 (D-040): samlIdp({ baseURL }) follows Better Auth's own baseURL rule, so hosts
// can put the same value in both places.
import { describe, expect, it } from "vitest";
import { withBasePath } from "../../src/saml/idp";
import { createHost } from "../support/host";

describe("withBasePath: Better Auth's rule", () => {
  it.each([
    ["https://auth.test", undefined, "https://auth.test/api/auth"],
    ["https://auth.test/", undefined, "https://auth.test/api/auth"],
    ["https://auth.test", "/auth", "https://auth.test/auth"],
    ["https://auth.test", "auth/", "https://auth.test/auth"],
    ["https://auth.test", "/", "https://auth.test"],
    ["https://auth.test/api/auth", undefined, "https://auth.test/api/auth"],
    ["https://auth.test/api/auth/", "/other", "https://auth.test/api/auth"],
    ["https://auth.test/custom/auth", undefined, "https://auth.test/custom/auth"],
  ])("%s with basePath %s → %s", (url, basePath, want) => {
    expect(withBasePath(url, basePath)).toBe(want);
  });
});

async function metadataSso(saml: Record<string, unknown>, auth: Record<string, unknown> = {}) {
  const logs: string[] = [];
  const { auth: a } = await createHost({ saml, auth: { ...auth, logger: { level: "warn", log: (_l: string, m: string) => logs.push(m) } } });
  const basePath = (auth.basePath as string | undefined) ?? "/api/auth";
  const xml = await (await a.handler(new Request(`https://auth.test${basePath}/saml2/idp/metadata`, { headers: { host: "attacker.example" } }))).text();
  return { location: /SingleSignOnService[^>]*Location="([^"]+)"/.exec(xml)?.[1], logs };
}

describe("samlIdp({ baseURL }) takes the same value as betterAuth({ baseURL })", () => {
  it("the site origin, as Better Auth takes it: basePath is added, and no warning", async () => {
    const { location, logs } = await metadataSso({ baseURL: "https://auth.test" });
    expect(location).toBe("https://auth.test/api/auth/saml2/idp/sso");
    expect(logs.filter((m) => /baseURL/.test(m))).toEqual([]);
  });

  it("with a custom basePath", async () => {
    const { location, logs } = await metadataSso({ baseURL: "https://auth.test" }, { basePath: "/auth" });
    expect(location).toBe("https://auth.test/auth/saml2/idp/sso");
    expect(logs.filter((m) => /baseURL/.test(m))).toEqual([]);
  });

  it("the full URL with basePath still works (the form used before decision 6)", async () => {
    expect((await metadataSso({ baseURL: "https://auth.test/api/auth" })).location).toBe("https://auth.test/api/auth/saml2/idp/sso");
  });

  it("a value that disagrees with Better Auth's is used, with a warning at startup", async () => {
    const { location, logs } = await metadataSso({ baseURL: "https://idp.test" });
    expect(location).toBe("https://idp.test/api/auth/saml2/idp/sso");
    expect(logs.some((m) => /samlIdp baseURL resolves to https:\/\/idp\.test\/api\/auth but Better Auth's is https:\/\/auth\.test\/api\/auth/.test(m))).toBe(true);
  });
});
