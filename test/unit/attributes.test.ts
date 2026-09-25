import { describe, expect, it } from "vitest";
import { compileAttributeMap } from "../../src/attributes";
import { resolveOptions, SamlIdpConfigError } from "../../src/options";
import { baseOptions } from "../support/config";

const user = {
  id: "u1",
  email: "ada@example.com",
  emailVerified: true,
  name: "  Ada King Lovelace ",
  createdAt: new Date("2026-01-02T03:04:05Z"),
  updatedAt: new Date("2026-01-02T03:04:05Z"),
  image: null,
  role: "admin, billing,,",
  tags: ["a", "", "b"],
  loginCount: 7,
  profile: { nested: true },
} as any;

describe("compileAttributeMap", () => {
  it("maps fields, constants, splits and name parts", () => {
    const f = compileAttributeMap({
      email: "email",
      verified: "emailVerified",
      created: "createdAt",
      count: "loginCount",
      groups: { field: "role", split: "," },
      tags: "tags",
      firstName: { field: "name", part: "first" },
      lastName: { field: "name", part: "last" },
      org: { value: "Acme" },
      audiences: { value: ["x", "y"] },
    });
    expect(f(user)).toEqual({
      email: "ada@example.com",
      verified: "true",
      created: "2026-01-02T03:04:05.000Z",
      count: "7",
      groups: ["admin", "billing"],
      tags: ["a", "b"],
      firstName: "Ada",
      lastName: "King Lovelace",
      org: "Acme",
      audiences: ["x", "y"],
    });
  });

  it("leaves out null, empty, object-valued and missing fields, reporting the missing ones", () => {
    const missing: string[] = [];
    const f = compileAttributeMap({ image: "image", profile: "profile", nope: "doesNotExist", last: { field: "email", part: "last" } });
    expect(f(user, (field) => missing.push(field))).toEqual({});
    expect(missing).toEqual(["doesNotExist"]);
  });

  it("returns a fresh copy of constant arrays", () => {
    const f = compileAttributeMap({ a: { value: ["x"] } });
    (f(user).a as string[]).push("mutated");
    expect(f(user).a).toEqual(["x"]);
  });

  it("doesn't read inherited properties", () => {
    const f = compileAttributeMap({ p: "constructor", q: "toString" });
    const missing: string[] = [];
    expect(f(user, (x) => missing.push(x))).toEqual({});
    expect(missing).toEqual(["constructor", "toString"]);
  });
});

describe("resolveOptions: attribute maps", () => {
  const issues = (attributes: unknown) => {
    try {
      resolveOptions(baseOptions({ serviceProviders: [{ id: "s", entityId: "https://sp.test/md", acsUrls: ["https://sp.test/acs"], attributes } as any] }));
      return [];
    } catch (e) {
      if (e instanceof SamlIdpConfigError) return e.issues;
      throw e;
    }
  };

  it("accepts a map and keeps it for diagnostics; a function still works", () => {
    const map = { email: "email", g: { field: "role", split: "," } };
    const r = resolveOptions(baseOptions({ serviceProviders: [{ id: "s", entityId: "https://sp.test/md", acsUrls: ["https://sp.test/acs"], attributes: map as any }] }));
    expect(r.serviceProviders[0]!.attributeMap).toEqual(map);
    expect(issues((u: any) => ({ email: u.email }))).toEqual([]);
  });

  it.each([
    [{ email: "e-mail" }, /user field name/],
    [{ email: "__proto__.x" }, /user field name/],
    [{ email: { field: "email", part: "middle" } }, /part/],
    [{ email: { field: "email", extra: 1 } }, /./],
    [{ email: { value: [] } }, /./],
    [{ "": "email" }, /./],
    [{ email: 42 }, /./],
  ])("rejects %j", (map, re) => {
    const found = issues(map);
    expect(found.length).toBeGreaterThan(0);
    expect(found.join("\n")).toMatch(re);
  });
});
